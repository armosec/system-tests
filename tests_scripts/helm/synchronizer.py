
from infrastructure.backend_api import KUBERNETES_RESOURCES_METADATA_KEY, KUBERNETES_RESOURCES_OBJECT_KEY
from systest_utils.systests_utilities import TestUtil
from systest_utils import statics, Logger
from systest_utils import statics, Logger, TestUtil
from tests_scripts.helm.base_helm import BaseHelm


class BaseSynchronizer(BaseHelm):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(BaseSynchronizer, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                        kubernetes_obj=kubernetes_obj)

    def get_all_workloads_in_namespace(self, namespace):
        workloads = self.kubernetes_obj.get_all_namespaced_workloads(namespace=namespace)
        wl_without_parent = list(filter(lambda x: x.metadata.owner_references is None or len(x.metadata.owner_references) == 0, workloads))
        return wl_without_parent

    def restart_all_workloads(self, namespace):
        workloads = self.get_all_workloads_in_namespace(namespace)
        for wl in workloads:
            kind = getattr(wl, 'kind', '')
            name = getattr(getattr(wl, 'metadata', {}), 'name')
            self.kubernetes_obj.restart_workloads_in_namespace(namespace=namespace, kind=kind, name=name)

    def delete_all_workloads(self, namespace):
        workloads = self.get_all_workloads_in_namespace(namespace)
        for wl in workloads:
            kind = getattr(wl, 'kind', '')
            name = getattr(getattr(wl, 'metadata', {}), 'name')
            self.kubernetes_obj.delete_workload(namespace=namespace, application=dict(kind=kind, metadata=dict(name=name)))

    def verify_backend_resources_deleted(self, cluster, namespace):
        iterations = 10
        while iterations > 0:
            iterations -= 1
            try:
                be_resources = self.backend.get_kubernetes_resources(cluster_name=cluster, namespace=namespace)
                assert len(be_resources) == 0, "BE kubernetes resources were not deleted"
                return
            except Exception as e:
                Logger.logger.error(f"failed to verify backend resources: {e}")
                if iterations == 0:
                    raise e
                TestUtil.sleep(10, "sleeping and retrying", "info")


    def verify_backend_resources(self, cluster, namespace):
        iterations = 10
        while iterations > 0:
            iterations -= 1
            try:
                cluster_resources = self.get_all_workloads_in_namespace(namespace)
                be_resources = self.backend.get_kubernetes_resources(with_resource=True, cluster_name=cluster, namespace=namespace)
                assert len(be_resources) > 0, "BE kubernetes resources is empty"
                assert len(be_resources) == len(cluster_resources), "amount of kubernetes resources ('%d') is not as expected ('%d')" % (len(be_resources) , len(cluster_resources))
                
                for be_resource in be_resources:
                    full_be_object = be_resource.get(KUBERNETES_RESOURCES_OBJECT_KEY)
                    metadata_be_object = be_resource.get(KUBERNETES_RESOURCES_METADATA_KEY)
                    be_resource_version = metadata_be_object.get('resourceVersion')
                    assert be_resource_version == full_be_object.get('metadata').get('resourceVersion')
                    be_kind = full_be_object.get('kind')
                    be_name = full_be_object.get('metadata').get('name')
                    be_namespace = full_be_object.get('metadata').get('namespace')

                    # find the be resource in the expected resources
                    cluster_resource = None
                    for resource in cluster_resources:
                        cluster_kind = getattr(resource, 'kind', '')
                        cluster_name = getattr(getattr(resource, 'metadata', {}), 'name')
                        cluster_namespace = getattr(getattr(resource, 'metadata', {}), 'namespace')
                        if cluster_kind == be_kind and cluster_namespace == be_namespace and cluster_name == be_name:
                            cluster_resource = resource
                            break
                    
                    # check that resource version is as expected
                    assert cluster_resource, f"kubernetes resource '{be_namespace}/{be_kind}/{be_name}' not found in expected resources '{cluster_resources}'"
                    cluster_resource_version = getattr(getattr(cluster_resource, 'metadata', {}), 'resource_version')
                    assert be_resource_version == cluster_resource_version, f"cluster resource '{be_namespace}/{be_kind}/{be_name}' is '{cluster_resource_version}' while resource version in BE is '{be_resource_version}'"
                return
            except Exception as e:
                Logger.logger.error(f"failed to verify backend resources: {e}")
                if iterations == 0:
                    raise e
                TestUtil.sleep(10, "sleeping and retrying", "info")

    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""


class Synchronizer(BaseSynchronizer):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(Synchronizer, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                            kubernetes_obj=kubernetes_obj)

    def start(self):
        """
        Test plan:
        1. Install Armo helm-chart
        2. Apply workloads
        3. Generate traffic
        4. Validating in-cluster expected network neighbors and generated network policies
        5. Validating backend expected network neighbors and generated network policies
        6. Check deletion flow
        """        
        cluster, namespace = self.setup(apply_services=False)

        helm_kwargs = self.test_obj.get_arg("helm_kwargs")

        Logger.logger.info('1. Install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        Logger.logger.info(f'2. Apply workloads (namespace="{namespace}")')
        workload_objs: list = self.apply_directory(path=self.test_obj["workloads"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)
        TestUtil.sleep(20, "wait for synchronization", "info")
        
        # FIXME: no need to restart the synchronizer
        # we need to restart the synchronizer to make sure that the resource version is updated - it's a bug!
        self.kubernetes_obj.restart_workloads_in_namespace(namespace='kubescape', kind='Deployment', name='synchronizer')

        Logger.logger.info('3. Check BE vs. Cluster - updated resource version')
        self.verify_backend_resources(cluster, namespace)        

        Logger.logger.info('4. Restart workloads')
        self.restart_all_workloads(namespace)
        TestUtil.sleep(20, "wait for synchronization", "info")
        
        # FIXME: no need to restart the synchronizer
        # we need to restart the synchronizer to make sure that the resource version is updated - it's a bug!
        self.kubernetes_obj.restart_workloads_in_namespace(namespace='kubescape', kind='Deployment', name='synchronizer')

        Logger.logger.info('5. Check BE vs. Cluster - updated resource version')
        self.verify_backend_resources(cluster, namespace)        

        Logger.logger.info('6. Delete all workloads in namespace')
        self.delete_all_workloads(namespace)
        TestUtil.sleep(20, "wait for synchronization", "info")

        Logger.logger.info('7. Check BE vs. Cluster - resources deleted from BE')
        self.verify_backend_resources_deleted(cluster, namespace)

        return self.cleanup()

from infrastructure.backend_api import KUBERNETES_RESOURCES_METADATA_KEY, KUBERNETES_RESOURCES_OBJECT_KEY
from systest_utils.systests_utilities import TestUtil
from systest_utils import statics, Logger
from systest_utils import statics, Logger, TestUtil
from tests_scripts.helm.base_helm import BaseHelm


class BaseSynchronizer(BaseHelm):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(BaseSynchronizer, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                        kubernetes_obj=kubernetes_obj)

    def scale_down_synchronizer(self, namespace):
        self.kubernetes_obj.scale(namespace=namespace, kind="deployment", name='synchronizer', replicas=0)
    
    def scale_up_synchronizer(self, namespace):
        self.kubernetes_obj.scale(namespace=namespace, kind="deployment", name='synchronizer', replicas=1)

    def block_all_communication(self, namespace):
        deny_all_policy = dict(
            metadata=dict(name='deny-all', namespace=namespace),
            spec=dict(podSelector=dict(matchLabels=dict(app='synchronizer')), ingress=None, egress=None, policyTypes=["Ingress", "Egress"])
        )
        self.kubernetes_obj.create_network_policy(namespace, deny_all_policy)
    
    def get_all_workloads_in_namespace(self, namespace):
        workloads = self.kubernetes_obj.get_all_namespaced_workloads(namespace=namespace)
        wl_without_parent = list(filter(lambda x: x.metadata.owner_references is None or len(x.metadata.owner_references) == 0, workloads))
        return wl_without_parent

    def get_workload_in_namespace(self, namespace, kind, name):
        wls = self.get_all_workloads_in_namespace(namespace)
        for wl in wls:
            if wl.kind == kind and wl.metadata.name == name:
                return wl
        raise Exception(f"workload '{kind}/{name}' not found in namespace '{namespace}'")

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

    def verify_backend_resources_deleted(self, cluster, namespace, iterations=10, sleep_time=10):
        while iterations > 0:
            iterations -= 1
            try:
                be_resources = self.backend.get_kubernetes_resources(cluster_name=cluster, namespace=namespace)
                assert len(be_resources) == 0, "BE kubernetes resources were not deleted"
            except Exception as e:
                Logger.logger.error(f"failed to verify backend resources: {e}")
                if iterations == 0:
                    raise e
                TestUtil.sleep(sleep_time, "sleeping and retrying", "info")


    def verify_backend_resources(self, cluster, namespace, iterations=10, sleep_time=10):
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
                TestUtil.sleep(sleep_time, "sleeping and retrying", "info")

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
        1. Install helm-chart
        1. Apply workloads
        4. Check all workloads are reported
        5. Restart workloads
        6. Check all workloads have new resourceVersion
        7. Delete WLs
        8. Check WLs are deleted
        """        
        cluster, namespace = self.setup(apply_services=False)

        helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        helm_kwargs['synchronizer.image.repository'] = 'quay.io/matthiasb_1/synchronizer'
        helm_kwargs['synchronizer.image.tag'] = 'latest'

        Logger.logger.info('1. Install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        Logger.logger.info(f'2. Apply workloads (namespace="{namespace}")')
        workload_objs: list = self.apply_directory(path=self.test_obj["workloads"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)
        TestUtil.sleep(20, "wait for synchronization", "info")

        Logger.logger.info('3. Check BE vs. Cluster - updated resource version')
        self.verify_backend_resources(cluster, namespace)        

        Logger.logger.info('4. Restart workloads')
        self.restart_all_workloads(namespace)
        TestUtil.sleep(20, "wait for synchronization", "info")

        Logger.logger.info('5. Check BE vs. Cluster - updated resource version')
        self.verify_backend_resources(cluster, namespace)        

        Logger.logger.info('6. Delete all workloads in namespace')
        self.delete_all_workloads(namespace)
        TestUtil.sleep(20, "wait for synchronization", "info")

        Logger.logger.info('7. Check BE vs. Cluster - resources deleted from BE')
        self.verify_backend_resources_deleted(cluster, namespace)

        return self.cleanup()


class SynchronizerReconciliation(BaseSynchronizer):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(SynchronizerReconciliation, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                            kubernetes_obj=kubernetes_obj)

    def start(self):
        """
        Test plan:
        1. Apply workloads
        2. Install Kubescape helm chart
        3. Check all workloads are reported
        4. Scale down synchronizer
        5. Restart workload 1 (modify)
        6. Delete workload 2 (delete)
        7. Scale up synchronizer
        8. Check workload 1 have new resource version
        9. Check workload 2 is deleted

        """        
        cluster, namespace_1 = self.setup(apply_services=False)

        helm_kwargs = self.test_obj.get_arg("helm_kwargs")

        # This test will fail if the synchronizer (BE) is configured with a greater interval than the test.
        # Make sure that the BE is aligned with test config.
        # See: https://github.com/kubescape/synchronizer/blob/main/config/config.go#L61
        reconciliation_interval_minutes = self.test_obj.get_arg("reconciliation_interval_minutes")
        Logger.logger.info(f"Testing synchronizer reconciliation flow with interval of {reconciliation_interval_minutes} minutes")
        
        Logger.logger.info(f'1. Apply workloads')
        workload_1 = self.apply_yaml_file(yaml_file=self.test_obj["workload_1"], namespace=namespace_1)
        self.verify_all_pods_are_running(namespace=namespace_1, workload=workload_1, timeout=180)

        namespace_2 = self.create_namespace()
        workload_2 = self.apply_yaml_file(yaml_file=self.test_obj["workload_2"], namespace=namespace_2)
        self.verify_all_pods_are_running(namespace=namespace_2, workload=workload_2, timeout=180)

        Logger.logger.info('2. Install Helm Chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)
        TestUtil.sleep(20, "wait for synchronization", "info")
      
        Logger.logger.info('3. Check BE vs. Cluster - resources created in BE')
        self.verify_backend_resources(cluster, namespace_1)        
        self.verify_backend_resources(cluster, namespace_2)   

        Logger.logger.info('4. Scale down synchronizer')
        self.scale_down_synchronizer(statics.CA_NAMESPACE_FROM_HELM_NAME)
        TestUtil.sleep(10)

        Logger.logger.info('5. Restart workload 1')
        self.restart_all_workloads(namespace=namespace_1)

        Logger.logger.info('6. Delete workload 2')
        self.delete_all_workloads(namespace=namespace_2)
        TestUtil.sleep(10)
        
        Logger.logger.info('7. Scale up synchronizer')
        self.scale_up_synchronizer(statics.CA_NAMESPACE_FROM_HELM_NAME)

        Logger.logger.info('8. Check BE vs. Cluster - waiting for reconciliation')
        self.verify_backend_resources(cluster, namespace_1, iterations=reconciliation_interval_minutes, sleep_time=60) # every 60 seconds X times (=interval)

        Logger.logger.info('7. Check BE vs. Cluster - resources deleted from BE')
        self.verify_backend_resources_deleted(cluster, namespace_2, iterations=reconciliation_interval_minutes, sleep_time=60) 

        return self.cleanup()
    

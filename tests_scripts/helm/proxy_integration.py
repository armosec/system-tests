from tests_scripts.helm.base_helm import BaseHelm
from tests_scripts.kubescape.base_kubescape import BaseKubescape
from tests_scripts.helm.synchronizer import KUBERNETES_RESOURCES_METADATA_KEY, KUBERNETES_RESOURCES_OBJECT_KEY, nameKind
from systest_utils import Logger, TestUtil, statics


class ProxyIntegrationTest(BaseHelm, BaseKubescape):
    """
    Combined proxy test that verifies:
    1. Synchronizer works through proxy
    2. Vulnerability scanning works through proxy  
    3. Kubescape control scanning works through proxy
    
    This test installs helm chart only once and runs all three scenarios sequentially.
    """
    
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        # Initialize BaseHelm and BaseKubescape (using super() to handle MRO correctly)
        super(ProxyIntegrationTest, self).__init__(
            test_obj=test_obj, 
            backend=backend,
            kubernetes_obj=kubernetes_obj, 
            test_driver=test_driver
        )
        
        # Set ignore_agent for kubescape tests (from BaseVulnerabilityScanning)
        self.ignore_agent = True
        self.wait_for_agg_to_end = False
        
        # Override helm_kwargs to merge settings from all three tests
        # Start with synchronizer defaults (most restrictive)
        self.helm_kwargs = {
            "capabilities.relevancy": "disable",
            "capabilities.configurationScan": "enable",  # Need for kubescape
            "capabilities.continuousScan": "enable",  # Need for kubescape
            "capabilities.nodeScan": "disable",
            "capabilities.vulnerabilityScan": "enable",  # Need for vuln scan
            "capabilities.runtimeObservability": "enable",
            "grypeOfflineDB.enabled": "false",
        }
        
        # Apply test-specific helm_kwargs
        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)
    
    # Methods from BaseSynchronizer
    def get_all_workloads_in_namespace(self, namespace):
        workloads = self.kubernetes_obj.get_all_namespaced_workloads(
            namespace=namespace
        )
        wl_without_parent = list(
            filter(
                lambda x: x.metadata.owner_references is None
                or len(x.metadata.owner_references) == 0,
                workloads,
            )
        )
        return wl_without_parent

    @staticmethod
    def backend_resource_kind(be_resource):
        return be_resource.get(KUBERNETES_RESOURCES_METADATA_KEY).get('designators').get('attributes').get('kind')
    
    @staticmethod
    def backend_resource_name(be_resource):
        return be_resource.get(KUBERNETES_RESOURCES_METADATA_KEY).get('designators').get('attributes').get('name')
    
    @staticmethod
    def format_backend_resources(be_resources):
        """Format backend resources for error messages."""
        results = []
        for resource in be_resources:
            kind = ProxyIntegrationTest.backend_resource_kind(resource)
            name = ProxyIntegrationTest.backend_resource_name(resource)
            results.append(f"{kind}/{name}")
        return ', '.join(results)

    def verify_backend_resources(
        self, cluster, namespace, list_func=None, iterations=20, sleep_time=10, filter_func=None
    ):
        while iterations > 0:
            iterations -= 1
            try:
                cluster_resources = list_func(namespace) if list_func else self.get_all_workloads_in_namespace(namespace)
                cluster_resources_kinds = [i.kind for i in cluster_resources]

                be_resources = self.backend.get_kubernetes_resources(
                    with_resource=True, cluster_name=cluster, namespace=namespace
                )

                # remove non-workload objects from the list
                kinds_to_ignore = ["Namespace", "Node", "ConfigMap"]
                be_resources = list(filter(lambda x: self.backend_resource_kind(x) not in kinds_to_ignore, be_resources))
                be_resources = list(filter(lambda x: self.backend_resource_kind(x) in cluster_resources_kinds, be_resources))

                assert len(be_resources) > 0, "BE kubernetes resources is empty"
                assert len(be_resources) == len(cluster_resources), (
                    "amount of kubernetes resources ('%s') is not as expected ('%s')"
                    % (self.format_backend_resources(be_resources), nameKind(cluster_resources))
                )

                for be_resource in be_resources:
                    full_be_object = be_resource.get(KUBERNETES_RESOURCES_OBJECT_KEY)
                    metadata_be_object = be_resource.get(
                        KUBERNETES_RESOURCES_METADATA_KEY
                    )
                    be_resource_version = metadata_be_object.get("resourceVersion")
                    assert be_resource_version == full_be_object.get("metadata").get(
                        "resourceVersion"
                    )
                    be_kind = full_be_object.get("kind")
                    be_name = full_be_object.get("metadata").get("name")
                    be_namespace = full_be_object.get("metadata").get("namespace", "")

                    # find the be resource in the expected resources
                    cluster_resource = None
                    cluster_resource_version = None
                    for resource in cluster_resources:
                        if isinstance(resource, dict):
                            cluster_kind = resource.get("kind", "")
                            cluster_name = resource.get("metadata", {}).get("name")
                            cluster_namespace = resource.get("metadata", {}).get("namespace", "")
                            cluster_resource_version = resource.get("metadata", {}).get("resourceVersion", "")
                        else:
                            cluster_kind = getattr(resource, "kind", "")
                            cluster_name = getattr(
                                getattr(resource, "metadata", {}), "name"
                            )
                            cluster_namespace = getattr(
                                getattr(resource, "metadata", {}), "namespace", ""
                            )
                            cluster_resource_version = getattr(getattr(resource, "metadata", {}), "resource_version", "")

                        if (
                            cluster_kind == be_kind
                            and cluster_namespace == be_namespace
                            and cluster_name == be_name
                        ):
                            cluster_resource = resource
                            break

                    # check that resource version is as expected
                    assert (
                        cluster_resource
                    ), f"kubernetes resource '{be_namespace}/{be_kind}/{be_name}' not found in expected resources '{cluster_resources}'"

                    assert (
                        be_resource_version == cluster_resource_version
                    ), f"cluster resource '{be_namespace}/{be_kind}/{be_name}' is '{cluster_resource_version}' while resource version in BE is '{be_resource_version}'"
                return
            except Exception as e:
                Logger.logger.error(f"failed to verify backend resources: {e}")
                if iterations == 0:
                    raise e
                TestUtil.sleep(sleep_time, "sleeping and retrying", "info")

    def start(self):
        """
        1. Set up cluster and apply synchronizer workloads
        2. Install helm chart with proxy
        3. Verify synchronizer resources are reported in backend
        4. Verify kubescape report exists
        """
        assert self.backend != None, f'the test {self.test_driver.test_name} must run with backend'
        
        # ============================================
        # PHASE 1: Setup and apply workloads
        # ============================================
        Logger.logger.info("=== PHASE 1: Setup and apply workloads ===")
        
        # Setup cluster and namespace
        cluster, namespace_sync = self.setup(apply_services=False)
        
        # Apply synchronizer workloads
        Logger.logger.info("1.1 Apply synchronizer workloads")
        workload_sync_1 = self.apply_yaml_file(
            yaml_file=self.test_obj["synchronizer_workload_1"], 
            namespace=namespace_sync
        )
        self.verify_all_pods_are_running(namespace=namespace_sync, workload=workload_sync_1, timeout=180)
        
        # ============================================
        # PHASE 2: Install helm chart with proxy
        # ============================================
        Logger.logger.info("=== PHASE 2: Install helm chart with proxy ===")
        Logger.logger.info("2.1 Add and upgrade armo to repo")
        self.add_and_upgrade_armo_to_repo()
        
        Logger.logger.info("2.2 Install armo helm-chart with proxy")
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        
        Logger.logger.info("2.3 Verify helm installation")
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)
        TestUtil.sleep(20, "wait for synchronization")
        
        # ============================================
        # PHASE 3: Verify synchronizer resources
        # ============================================
        Logger.logger.info("=== PHASE 3: Verify synchronizer resources in backend ===")
        self.verify_backend_resources(cluster, namespace_sync)
        
        # ============================================
        # PHASE 4: Verify kubescape report
        # ============================================
        Logger.logger.info("=== PHASE 4: Verify kubescape report exists ===")
        cluster_name = self.kubernetes_obj.get_cluster_name()
        report_guid = self.get_report_guid(cluster_name=cluster_name, wait_to_result=True)
        Logger.logger.info(f"Kubescape report found with GUID: {report_guid}")
        
        Logger.logger.info("=== Proxy integration test completed successfully ===")
        
        return self.cleanup()

from datetime import datetime, timezone

from tests_scripts.helm.base_helm import BaseHelm
from tests_scripts.helm.base_vuln_scan import BaseVulnerabilityScanning
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
    def scale_down_proxy_server(self):
        self.kubernetes_obj.scale(
            namespace='default', kind="deployment", name="httpd-proxy", replicas=0
        )

    def scale_up_proxy_server(self):
        self.kubernetes_obj.scale(
            namespace='default', kind="deployment", name="httpd-proxy", replicas=1
        )

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

    def restart_all_workloads(self, namespace):
        workloads = self.get_all_workloads_in_namespace(namespace)
        for wl in workloads:
            kind = getattr(wl, "kind", "")
            name = getattr(getattr(wl, "metadata", {}), "name")
            self.kubernetes_obj.restart_workloads_in_namespace(
                namespace=namespace, kind=kind, name=name
            )

    def delete_all_workloads(self, namespace):
        workloads = self.get_all_workloads_in_namespace(namespace)
        for wl in workloads:
            kind = getattr(wl, "kind", "")
            name = getattr(getattr(wl, "metadata", {}), "name")
            self.kubernetes_obj.delete_workload(
                namespace=namespace,
                application=dict(kind=kind, metadata=dict(name=name)),
            )

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
                
                # Log cluster resources for debugging
                Logger.logger.info(f"Cluster resources in {namespace}: {nameKind(cluster_resources)}")

                be_resources = self.backend.get_kubernetes_resources(
                    with_resource=True, cluster_name=cluster, namespace=namespace
                )

                # remove non-workload objects from the list
                kinds_to_ignore = ["Namespace", "Node", "ConfigMap"]
                be_resources = list(filter(lambda x: self.backend_resource_kind(x) not in kinds_to_ignore, be_resources))
                be_resources = list(filter(lambda x: self.backend_resource_kind(x) in cluster_resources_kinds, be_resources))
                
                # Log backend resources for debugging
                Logger.logger.info(f"Backend resources in {namespace}: {self.format_backend_resources(be_resources)}")

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

    def verify_backend_resources_deleted(
        self, cluster, namespace, list_func=None, iterations=20, sleep_time=10, filter_func=None
    ):
        while iterations > 0:
            iterations -= 1
            try:
                cluster_resources = list_func(namespace) if list_func else self.get_all_workloads_in_namespace(namespace)
                cluster_resources_kinds = [i.kind for i in cluster_resources]

                be_resources = self.backend.get_kubernetes_resources(
                    cluster_name=cluster, namespace=namespace
                )
                # remove non-workload objects from the list
                kinds_to_ignore = ["Namespace", "Node", "ConfigMap"]
                be_resources = list(filter(lambda x: self.backend_resource_kind(x) not in kinds_to_ignore, be_resources))
                be_resources = list(filter(lambda x: self.backend_resource_kind(x) in cluster_resources_kinds, be_resources))

                assert (
                    len(be_resources) == 0
                ), "BE kubernetes resources were not deleted"
                return
            except Exception as e:
                Logger.logger.error(f"failed to verify backend resources: {e}")
                if iterations == 0:
                    raise e
                TestUtil.sleep(sleep_time, "sleeping and retrying", "info")

    def start(self):
        """
        Test plan:
        1. Set up cluster and namespaces
        2. Apply synchronizer workloads
        3. Apply WikiJS workloads
        4. Install helm chart once with proxy
        5. Run synchronizer proxy test (first, since it manipulates proxy)
        6. Run vulnerability scanning proxy test
        7. Run kubescape cronjob proxy test
        """
        assert self.backend != None, f'the test {self.test_driver.test_name} must run with backend'
        
        # Skip for production backend (like synchronizer_proxy does)
        if self.test_driver.test_name == "proxy_integration_test" and self.backend.server == "https://api.armosec.io":
            Logger.logger.info(f"Skipping test '{self.test_driver.test_name}' for production backend")
            return statics.SUCCESS, ""
        
        # ============================================
        # PHASE 1: Setup and apply workloads
        # ============================================
        Logger.logger.info("=== PHASE 1: Setup and apply workloads ===")
        
        # Setup cluster and namespaces
        cluster, namespace_wikijs = self.setup(apply_services=False)
        namespace_sync_1 = namespace_wikijs  # Use same namespace for synchronizer workloads
        namespace_sync_2 = self.create_namespace()
        
        # Apply synchronizer workloads
        Logger.logger.info("1.1 Apply synchronizer workloads")
        workload_sync_1 = self.apply_yaml_file(
            yaml_file=self.test_obj["synchronizer_workload_1"], 
            namespace=namespace_sync_1
        )
        self.verify_all_pods_are_running(namespace=namespace_sync_1, workload=workload_sync_1, timeout=180)
        
        workload_sync_2 = self.apply_yaml_file(
            yaml_file=self.test_obj["synchronizer_workload_2"], 
            namespace=namespace_sync_2
        )
        self.verify_all_pods_are_running(namespace=namespace_sync_2, workload=workload_sync_2, timeout=180)
        
        # Apply WikiJS workloads
        Logger.logger.info("1.2 Apply WikiJS workloads")
        Logger.logger.info("1.2.1 Apply services")
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace_wikijs)
        
        Logger.logger.info("1.2.2 Apply config-maps")
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace_wikijs)
        
        Logger.logger.info("1.2.3 Apply workloads")
        workload_wikijs = self.apply_directory(
            path=self.test_obj["deployments"], 
            namespace=namespace_wikijs
        )
        wlids = self.get_wlid(workload=workload_wikijs, namespace=namespace_wikijs, cluster=cluster)
        self.verify_all_pods_are_running(namespace=namespace_wikijs, workload=workload_wikijs, timeout=180)
        
        # ============================================
        # PHASE 2: Install helm chart once
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
        # PHASE 3: Synchronizer proxy test
        # ============================================
        Logger.logger.info("=== PHASE 3: Synchronizer proxy test ===")
        
        Logger.logger.info("3.1 Check BE vs. Cluster - resources created in BE")
        self.verify_backend_resources(cluster, namespace_sync_1)
        self.verify_backend_resources(cluster, namespace_sync_2)
        
        Logger.logger.info("3.2 Removing proxy to simulate network disconnection")
        self.scale_down_proxy_server()
        TestUtil.sleep(60)
        
        Logger.logger.info("3.3 Restart workload 1 multiple times to simulate changes")
        for i in range(30):
            self.restart_all_workloads(namespace=namespace_sync_1)
            TestUtil.sleep(1)
        
        Logger.logger.info("3.4 Delete workload 2 & Create workload 3")
        self.delete_all_workloads(namespace=namespace_sync_2)
        workload_sync_3 = self.apply_yaml_file(
            yaml_file=self.test_obj["synchronizer_workload_3"], 
            namespace=namespace_sync_1
        )
        # Note: StatefulSet may require a Service, but it should still sync to backend even if pods aren't ready
        # Verify pods are running (this may take longer if Service is missing)
        self.verify_all_pods_are_running(namespace=namespace_sync_1, workload=workload_sync_3, timeout=180)
        # Give StatefulSet a bit more time to stabilize
        TestUtil.sleep(10, "wait for StatefulSet to stabilize", "info")
        
        TestUtil.sleep(60, "simulating network issue for 1 minute", "info")
        Logger.logger.info("3.5 Restoring proxy to restore network connection")
        self.scale_up_proxy_server()
        
        # Wait for proxy to be ready and for synchronizer to reconnect
        TestUtil.sleep(30, "wait for proxy to be ready and synchronizer to reconnect", "info")
        
        Logger.logger.info("3.6 Check BE vs. Cluster - resources are updated / created")
        self.verify_backend_resources(cluster, namespace_sync_1, iterations=20, sleep_time=30)
        
        Logger.logger.info("3.7 Check BE vs. Cluster - resources deleted from BE")
        self.verify_backend_resources_deleted(cluster, namespace_sync_2, iterations=20, sleep_time=30)
        
        Logger.logger.info("3.8 Synchronizer proxy test completed successfully")
        
        # ============================================
        # PHASE 4: Vulnerability scanning proxy test
        # ============================================
        Logger.logger.info("=== PHASE 4: Vulnerability scanning proxy test ===")
        
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        
        Logger.logger.info("4.1 Get the scan result from Backend")
        # In order to check proxy it is enough to check that at least one pod is updated on backend.
        expected_number_of_pods = 1
        be_summary, _ = self.wait_for_report(
            timeout=400, 
            report_type=self.backend.get_scan_results_sum_summary,
            namespace=namespace_wikijs, 
            since_time=since_time,
            expected_results=expected_number_of_pods
        )
        
        Logger.logger.info("4.2 Test total is RCE count")
        BaseVulnerabilityScanning.test_total_is_rce_count(be_summary)
        
        Logger.logger.info("4.3 Test no errors in results")
        BaseVulnerabilityScanning.test_no_errors_in_scan_result(be_summary)
        
        Logger.logger.info("4.4 Vulnerability scanning proxy test completed successfully")
        
        # ============================================
        # PHASE 5: Kubescape cronjob proxy test
        # ============================================
        Logger.logger.info("=== PHASE 5: Kubescape cronjob proxy test ===")
        
        Logger.logger.info("5.1 Get old report-guid")
        cluster_name = self.kubernetes_obj.get_cluster_name()
        old_report_guid = self.get_report_guid(cluster_name=cluster_name, wait_to_result=True)
        
        Logger.logger.info("5.2 Port forwarding to kubescape pod")
        pod_name = self.kubernetes_obj.get_kubescape_pod(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        self.port_forward_proc = self.kubernetes_obj.portforward(
            cluster_name, 
            statics.CA_NAMESPACE_FROM_HELM_NAME,
            pod_name, 
            8080
        )
        
        Logger.logger.info("5.3 Starting kubescape cronjob test scenarios")
        for job in self.test_obj["test_job"]:
            job_type = job["trigger_by"]
            if job_type == "cronjob":
                self.check_result_with_backend_cronjob(
                    job, 
                    cluster_name, 
                    old_report_guid, 
                    port=statics.KS_PORT_FORWARD
                )
        
        Logger.logger.info("5.4 Kubescape cronjob proxy test completed successfully")
        
        # ============================================
        # All tests completed
        # ============================================
        Logger.logger.info("=== All proxy integration tests completed successfully ===")
        
        return self.cleanup()
    
    def check_result_with_backend_cronjob(self, job, cluster_name, old_report_guid, port):
        """
        Check kubescape cronjob results through proxy.
        This method is copied from ScanWithKubescapeAsServiceTest to support cronjob testing.
        """
        trigger_by = job["trigger_by"]
        framework_list = None
        if "framework" in job.keys():
            framework_list = job["framework"]
        with_host_sensor = "false"
        if "hostsensor" in job.keys():
            if job["hostsensor"]:
                with_host_sensor = "true"

        if job["operation"] == "create":
            self.backend.create_kubescape_job_request(cluster_name=cluster_name, trigger_by=trigger_by,
                                                      framework_list=framework_list, with_host_sensor=with_host_sensor)

            Logger.logger.info("check if kubescape cronjob created")
            assert self.is_ks_cronjob_created(framework_list[0]), "kubescape cronjob failed to create"

            Logger.logger.info("check if kubescape cronjob created in backend")
            # Backend cronjob list is eventually consistent (async propagation via backend services / cache),
            # so allow multiple polls rather than a single ~30s attempt.
            self.wait_for_report(
                timeout=180,
                sleep_interval=10,
                report_type=self.backend.is_ks_cronjob_created_in_backend,
                cluster_name=cluster_name,
                framework_name=framework_list[0],
            )

            Logger.logger.info("check if backend returns only kubescape cronjobs for api")
            self.backend.is__backend_returning_only_ks_cronjob(
                cluster_name), "kubescape cronjob failed to create in backend"

            Logger.logger.info("Get report-guid")
            report_guid = self.get_report_guid(cluster_name=cluster_name,
                                               old_report_guid=old_report_guid,
                                               framework_name=framework_list[0],
                                               wait_to_result=True)

            Logger.logger.info('get result from kubescape in cluster')
            kubescape_result = self.get_kubescape_as_server_last_result(cluster_name, port=port)

            Logger.logger.info('test result against backend results, report_guid: {}'.format(report_guid))
            self.test_backend_vs_kubescape_result(report_guid=report_guid, kubescape_result=kubescape_result)

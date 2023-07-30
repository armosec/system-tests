from systest_utils import statics, Logger, TestUtil
from datetime import datetime, timezone

from systest_utils.wlid import Wlid

from tests_scripts.helm.base_vulnerability_scanning import BaseVulnerabilityScanning

DEFAULT_BRANCH = "release"

class RelevantCVEs(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevantCVEs, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                           kubernetes_obj=kubernetes_obj)

    def start(self):
        cluster, namespace = self.setup(apply_services=False)

        # P1 install helm-chart (armo)
        #  1.1 add and update armo in repo
        # Logger.logger.info('install armo helm-chart')
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        self.add_and_upgrade_armo_to_repo()


        # # 1.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)


        # P2 apply workload
        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)
        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)
        Logger.logger.info('apply secrets')
        self.apply_directory(path=self.test_obj[("secrets", None)], namespace=namespace)
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        # P3 verify results in storage
        # 3 test SBOM and CVEs created as expected in the storage
        Logger.logger.info('Get the scan result from local Storage')
        # 3.1 test SBOM created in the storage
        SBOMs, _ = self.wait_for_report(timeout=1200, report_type=self.get_SBOM_from_storage,
                                         SBOMKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        # 3.2 test SBOM created as expected result in the storage
        self.validate_expected_SBOM(SBOMs, self.test_obj["expected_SBOMs"])
        # 3.3 test CVEs created in the storage
        CVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_CVEs_from_storage,
                                       CVEsKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        # 3.4 test CVES created as expected result in the storage
        self.validate_expected_CVEs(CVEs, self.test_obj["expected_CVEs"])

        # 3.5 test filtered SBOM created in the storage
        filteredSBOM, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_SBOM_from_storage,
                                               filteredSBOMKeys=self.get_filtered_data_keys(
                                                   pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod',
                                                                                                     namespace=namespace),
                                                   namespace=namespace))
        # 3.6 test filtered CVEs created as expected result in the storage
        self.validate_expected_filtered_SBOMs(filteredSBOM, self.test_obj["expected_filtered_SBOMs"], namespace=namespace)
        # 3.7 test filtered SBOM created in the storage
        
        filteredCVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_CVEs_from_storage, filteredCVEsKEys=self.get_filtered_data_keys(pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod', namespace=namespace), namespace=namespace))
        # 3.8 test filtered CVEs created as expected result in the storage
        self.validate_expected_filtered_CVEs(filteredCVEs, self.test_obj["expected_filtered_CVEs"], namespace=namespace)

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        return self.cleanup()
    
class RelevantCVEsBackendTest(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevantCVEsBackendTest, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                           kubernetes_obj=kubernetes_obj)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'

        cluster, namespace = self.setup(apply_services=False)

        # P1 install helm-chart (armo)
        #  1.1 add and update armo in repo
        # Logger.logger.info('install armo helm-chart')
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        self.add_and_upgrade_armo_to_repo()

        # # 1.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # P2 apply workload
        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)
        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)
        Logger.logger.info('apply secrets')
        self.apply_directory(path=self.test_obj[("secrets", None)], namespace=namespace)
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        CVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_CVEs_from_storage,
                                       CVEsKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        
        filteredCVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_CVEs_from_storage, filteredCVEsKEys=self.get_filtered_data_keys(pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod', namespace=namespace), namespace=namespace))

        Logger.logger.info('Get the scan result from Backend')
        expected_number_of_pods = self.get_expected_number_of_pods(
            namespace=namespace)
        be_summary, _ = self.wait_for_report(timeout=1200, report_type=self.backend.get_scan_results_sum_summary,
                                            namespace=namespace, since_time=since_time,
                                            expected_results=expected_number_of_pods)
        self.test_no_errors_in_scan_result(be_summary)

        # # 4.2 get container scan id
        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)
        # # 4.3 get CVEs for containers

        self.test_cve_result(since_time=since_time, containers_scan_id=containers_scan_id,
                                                    be_summary=be_summary, storage_CVEs={statics.ALL_CVES_KEY: CVEs,
                                                                                        statics.FILTERED_CVES_KEY: filteredCVEs}, expected_number_of_pods = expected_number_of_pods)

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        return self.cleanup()

class RelevantDataIsAppended(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevantDataIsAppended, self).__init__(test_driver=test_driver, test_obj=test_obj,
                                                                    backend=backend,
                                                                    kubernetes_obj=kubernetes_obj)
        
    def start(self):
        # agenda:
        # 1. install helm-chart with relevancy enabled
        # 2. create workload with an sleep as entrypoint
        # 3. check that SBOMp is as expected
        # 4. wait for new file to be open, check that data was appended to SBOMp
        # 5. check backend data against cluster data

        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)
        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()

        # 1.2 install armo helm-chart
        Logger.logger.info('install armo helm-chart')
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        #  1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # 1.4 apply workloads
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)


        # P3 CHECK sbom and sbom'
        Logger.logger.info('Get SBOMs from storage')  
        SBOMs, _ = self.wait_for_report(timeout=1200, report_type=self.get_SBOM_from_storage,
                                        SBOMKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))

        Logger.logger.info('Validate SBOMs was created with expected data')                     
        self.validate_expected_SBOM(SBOMs, self.test_obj["expected_SBOMs"])

        Logger.logger.info('Get SBOMsp from storage')  
        filteredSBOM, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_SBOM_from_storage,
                                               filteredSBOMKeys=self.get_filtered_data_keys(
                                                   pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod',
                                                                                                     namespace=namespace),
                                                   namespace=namespace))

        Logger.logger.info('Validate SBOMsp was created with expected data')
        self.validate_expected_filtered_SBOMs(filteredSBOM, self.test_obj["expected_filtered_SBOMs"], namespace=namespace)

        TestUtil.sleep(1260, "Waiting for new filtered SBOMp to be created")

        Logger.logger.info('Get updated SBOMsp from storage')  
        filteredSBOM, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_SBOM_from_storage,
                                               filteredSBOMKeys=self.get_filtered_data_keys(
                                                   pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod',
                                                                                                     namespace=namespace),
                                                   namespace=namespace))

        Logger.logger.info('Validate updated SBOMsp was created with expected data')
        self.validate_expected_filtered_SBOMs(filteredSBOM, self.test_obj["expected_updated_filtered_SBOMs"], namespace=namespace)

        Logger.logger.info('Get CVEs from storage')  
        CVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_CVEs_from_storage, CVEsKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))

        Logger.logger.info('Validate CVEs was created with expected data')
        self.validate_expected_CVEs(CVEs, self.test_obj["expected_CVEs"])
        
        TestUtil.sleep(300, "Waiting for new filtered CVEs to be created")
        
        Logger.logger.info('Get filtered CVEs from storage')
        filteredCVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_CVEs_from_storage, filteredCVEsKEys=self.get_filtered_data_keys(pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod', namespace=namespace), namespace=namespace))

        Logger.logger.info('Validate filtered CVEs was created with expected data')
        self.validate_expected_filtered_CVEs(filteredCVEs, self.test_obj["expected_filtered_CVEs"],namespace=namespace)

        Logger.logger.info('Get the scan result from Backend')
        be_summary, _ = self.wait_for_report(timeout=560, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=self.get_expected_number_of_pods(
                                                 namespace=namespace))
        
        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        

        return self.cleanup()


class RelevantDataIsAppendedBackendTest(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevantDataIsAppendedBackendTest, self).__init__(test_driver=test_driver, test_obj=test_obj,
                                                                    backend=backend,
                                                                    kubernetes_obj=kubernetes_obj)
        
    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'

        # agenda:
        # 1. install helm-chart with relevancy enabled
        # 2. create workload with an sleep as entrypoint
        # 3. check backend data against cluster data before entrypoint changed
        # 4. wait for new file to be open, check that data was appended to SBOMp
        # 5. check backend data against cluster data after entrypoint changed

        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)
        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()

        # 1.2 install armo helm-chart
        Logger.logger.info('install armo helm-chart')
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        #  1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # 2 apply workloads
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        # 3 check backend data against cluster data before entrypoint changed
        # 3.1 get CVEs
        Logger.logger.info('Get CVEs from storage')  
        CVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_CVEs_from_storage, CVEsKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        
        TestUtil.sleep(300, "Waiting for new filtered CVEs to be created")
        
        # 3.2 get filtered CVEs
        Logger.logger.info('Get filtered CVEs from storage')
        filteredCVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_CVEs_from_storage, filteredCVEsKEys=self.get_filtered_data_keys(pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod', namespace=namespace), namespace=namespace))

        # 3.2 check CVEs exists in the backend
        Logger.logger.info('Get the scan result from Backend')
        be_summary, _ = self.wait_for_report(timeout=560, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=self.get_expected_number_of_pods(
                                                 namespace=namespace))

        # 3.3 check Test no errors in results in the backend
        Logger.logger.info('Test no errors in results')
        self.test_no_errors_in_scan_result(be_summary)

        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)
    
        # 3.4 check expected CVEs exist in the backend
        Logger.logger.info('Test backend CVEs against storage CVEs before entrypoint changed')
        self.test_cve_result(since_time=since_time, containers_scan_id=containers_scan_id,
                                                    be_summary=be_summary, storage_CVEs={statics.ALL_CVES_KEY: CVEs,
                                                                                        statics.FILTERED_CVES_KEY: filteredCVEs}, expected_number_of_pods = self.get_expected_number_of_pods(namespace=namespace))
        # 4 wait for the entrypoint to change
        TestUtil.sleep(1260, "Waiting for new filtered CVEs to be created")

        # 5 check backend data against cluster data after entrypoint changed
        # 5.1 get CVEs
        Logger.logger.info('Get CVEs from storage')  
        CVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_CVEs_from_storage, CVEsKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        
        TestUtil.sleep(300, "Waiting for new filtered CVEs to be created")
        
        # 5.2 get filteredCVEs
        Logger.logger.info('Get filtered CVEs from storage')
        filteredCVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_CVEs_from_storage, filteredCVEsKEys=self.get_filtered_data_keys(pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod', namespace=namespace), namespace=namespace))

        # 5.3 check CVEs exists in the backend
        Logger.logger.info('Get the scan result from Backend')
        be_summary, _ = self.wait_for_report(timeout=560, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=self.get_expected_number_of_pods(
                                                 namespace=namespace))

        # 5.4 check Test no errors in results in the backend
        Logger.logger.info('Test no errors in results')
        self.test_no_errors_in_scan_result(be_summary)

        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)
    
        # 5.5 check expected CVEs exist in the backend
        Logger.logger.info('Test backend CVEs against storage CVEs after entrypoint changed')
        self.test_cve_result(since_time=since_time, containers_scan_id=containers_scan_id,
                                                    be_summary=be_summary, storage_CVEs={statics.ALL_CVES_KEY: CVEs,
                                                                                        statics.FILTERED_CVES_KEY: filteredCVEs}, expected_number_of_pods = self.get_expected_number_of_pods(namespace=namespace))
        
        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        return self.cleanup()

# Tests that sniffer stop sniffing after X time
class RelevancyEnabledStopSniffingAfterTime(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevancyEnabledStopSniffingAfterTime, self).__init__(test_driver=test_driver, test_obj=test_obj,
                                                                    backend=backend,
                                                                    kubernetes_obj=kubernetes_obj)

    def start(self):
        # agenda:
        # 1. install helm-chart with relevancy enabled
        # 2. create workload with an sleep as entrypoint
        # 3. check that files opened after X time are no in SBOMp list and relevant CVEs, by comparing SBOM, SBOMp, CVEs and CVEsp
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()

        # 1.2 install armo helm-chart
        Logger.logger.info('install armo helm-chart')
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # P2 create wl
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        # P3 CHECK sbom and sbom'
        Logger.logger.info('Get SBOMs from storage')  
        SBOMs, _ = self.wait_for_report(timeout=1200, report_type=self.get_SBOM_from_storage,
                                        SBOMKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))

        Logger.logger.info('Validate SBOMs was created with expected data')                     
        self.validate_expected_SBOM(SBOMs, self.test_obj["expected_SBOMs"])

        Logger.logger.info('Get SBOMsp from storage')  
        filteredSBOM, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_SBOM_from_storage,
                                               filteredSBOMKeys=self.get_filtered_data_keys(
                                                   pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod',
                                                                                                     namespace=namespace),
                                                   namespace=namespace))

        Logger.logger.info('Validate SBOMsp was created with expected data')
        self.validate_expected_filtered_SBOMs(filteredSBOM, self.test_obj["expected_filtered_SBOMs"], namespace=namespace)

        Logger.logger.info('Get CVEs from storage')  
        CVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_CVEs_from_storage, CVEsKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))

        Logger.logger.info('Validate CVEs was created with expected data')
        self.validate_expected_CVEs(CVEs, self.test_obj["expected_CVEs"])
        
        Logger.logger.info('Get filtered CVEs from storage')
        filteredCVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_CVEs_from_storage, filteredCVEsKEys=self.get_filtered_data_keys(pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod', namespace=namespace), namespace=namespace))

        Logger.logger.info('Validate filtered CVEs was created with expected data')
        self.validate_expected_filtered_CVEs(filteredCVEs, self.test_obj["expected_filtered_CVEs"],namespace=namespace)

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        return self.cleanup()


# Tests that BE has CVE data when relevancy is disabled
class RelevancyDisabled(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevancyDisabled, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                kubernetes_obj=kubernetes_obj)

    def start(self):
        # agenda:
        # 1. instal helm
        # 2. apply workloads
        # 3. check sbom from storage
        # 4. check CVEs from storage
        # 5. check BE data


        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()


        # 1.2 install armo helm-chart
        Logger.logger.info('install armo helm-chart')
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # P2 apply workloads
        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)
        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        # P3 verify results in storage
        # 3 test SBOM created as expected in the storage
        Logger.logger.info('Test SBOM was created in storage')
        # 3.1 test SBOM created in the storage
        SBOMs, _ = self.wait_for_report(timeout=1200, report_type=self.get_SBOM_from_storage,
                                        SBOMKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        
        # 3.2 test SBOM created as expected result in the storage
        Logger.logger.info('Validate SBOM was created with expected data')
        self.validate_expected_SBOM(SBOMs, self.test_obj["expected_SBOMs"])

        # 3.3 test CVEs created in the storage
        Logger.logger.info('Test CVEs were created in storage')
        CVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_CVEs_from_storage,
                                       CVEsKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        # 3.4 test CVES created as expected result in the storage
        Logger.logger.info('Validate CVEs were created with expected data')
        self.validate_expected_CVEs(CVEs, self.test_obj["expected_CVEs"])

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        return self.cleanup()


# Tests that BE has CVE data when relevancy is disabled
class RelevancyDisabledBackendTest(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevancyDisabledBackendTest, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                kubernetes_obj=kubernetes_obj)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'

        # agenda:
        # 1. instal helm
        # 2. apply workloads
        # 3. get check CVEs in storage
        # 4. check BE data


        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()


        # 1.2 install armo helm-chart
        Logger.logger.info('install armo helm-chart')
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # P2 apply workloads
        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)
        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        # 3.3 get CVEs created in the storage
        Logger.logger.info('Test CVEs were created in storage')
        CVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_CVEs_from_storage,
                                       CVEsKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        
        # # P4 get CVEs results
        # # 4.1 get summary result
        Logger.logger.info('Get the scan result from Backend')
        expected_number_of_pods = self.get_expected_number_of_pods(
            namespace=namespace)
        be_summary, _ = self.wait_for_report(timeout=1200, report_type=self.backend.get_scan_results_sum_summary,
                                            namespace=namespace, since_time=since_time,
                                            expected_results=expected_number_of_pods)
        
        Logger.logger.info('Test no errors in scan result')
        self.test_no_errors_in_scan_result(be_summary)

        # # 4.2 get container scan id
        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)

        # # 4.3 get CVEs for containers
        Logger.logger.info('Test BE CVEs against storage CVEs')
        self.test_cve_result(since_time=since_time, containers_scan_id=containers_scan_id,
                                                    be_summary=be_summary, storage_CVEs={statics.ALL_CVES_KEY: CVEs,
                                                                                        statics.FILTERED_CVES_KEY: []})

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        return self.cleanup()

# Test that when deleting a workload, the relevant resources are deleted from storage
class RelevancyEnabledDeletedImage(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevancyEnabledDeletedImage, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                           kubernetes_obj=kubernetes_obj)

    def start(self):
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()


        # 1.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # P2 apply workloads
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        # P3 verify results in storage
        # 3 test SBOM created as expected in the storage
        Logger.logger.info('Test SBOM was created in storage')
        # 3.1 test SBOM created in the storage
        SBOMs, _ = self.wait_for_report(timeout=1200, report_type=self.get_SBOM_from_storage,
                                        SBOMKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))

        # 3.2 test CVEs created in the storage
        Logger.logger.info('Test CVEs were created in storage')
        CVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_CVEs_from_storage,
                                       CVEsKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))

        Logger.logger.info('Validate SBOMp was created')
        filteredSBOM, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_SBOM_from_storage,
                                               filteredSBOMKeys=self.get_filtered_data_keys(
                                                   pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod',
                                                                                                     namespace=namespace),
                                                   namespace=namespace))

        self.kubernetes_obj.delete_workload(namespace=namespace, application=workload_objs[0])

        TestUtil.sleep(150, "wait for workload CRDs to be deleted")

        SBOM_keys = self.get_imagesIDs_keys(workload_objs, namespace=namespace)
        SBOMS = self.get_SBOM_from_storage(SBOM_keys)
        assert SBOMS == {}, "SBOMs were not deleted"

        Logger.logger.info('Test CVEs were deleted in storage')
        CVE_keys = self.get_imagesIDs_keys(workload_objs, namespace=namespace)
        CVEs = self.get_CVEs_from_storage(CVE_keys)
        assert CVEs == {}, "CVEs were not deleted"

        Logger.logger.info('Test filtered SBOM was deleted in storage')
        filteredSBOM_keys = self.get_filtered_data_keys(
            pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod', namespace=namespace), namespace=namespace)
        filteredSBOMs = self.get_filtered_SBOM_from_storage(filteredSBOM_keys)
        assert filteredSBOMs == {}, "filtered SBOMs were not deleted"

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        

        return self.cleanup()

class RelevancyEnabledLargeImage(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevancyEnabledLargeImage, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                           kubernetes_obj=kubernetes_obj)
        

    def start(self):
        # agenda:
        # 1. install helm-chart with really small maxImageSize in kubevuln
        # 2. apply workload
        # 3. verify that an SBOM was created with an incomplete annotation
        # 4. verify that SBOMp was created with an incomplete annotation
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()


        # 1.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # P2 apply workloads
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        # P3 verify results in storage
        Logger.logger.info('Test SBOM was created in storage')
        SBOMs, _ = self.wait_for_report(timeout=1200, report_type=self.get_SBOM_from_storage,
                                        SBOMKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        

        Logger.logger.info('Validate SBOM was created with expected data')
        self.validate_expected_SBOM(SBOMs, self.test_obj["expected_SBOMs"])

        Logger.logger.info('Get SBOMsp from storage')  
        filteredSBOM, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_SBOM_from_storage,
                                               filteredSBOMKeys=self.get_filtered_data_keys(
                                                   pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod',
                                                                                                     namespace=namespace),
                                                   namespace=namespace))

        Logger.logger.info('Validate SBOMsp was created with expected data')
        self.validate_expected_filtered_SBOMs(filteredSBOM, self.test_obj["expected_filtered_SBOMs"], namespace=namespace)

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")    

        return self.cleanup()
    
class RelevancyEnabledExtraLargeImage(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevancyEnabledExtraLargeImage, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                           kubernetes_obj=kubernetes_obj)
    def start(self):
        # agenda:
        # 1. install helm-chart with really small timeout in kubevuln
        # 2. apply workload
        # 3. verify that an SBOM was created with an incomplete annotation
        # 4. verify that SBOMp was created with an incomplete annotation
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        # Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()


        # 1.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # P2 apply workloads
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        # P3 verify results in storage
        Logger.logger.info('Test SBOM was created in storage')
        SBOMs, _ = self.wait_for_report(timeout=1200, report_type=self.get_SBOM_from_storage,
                                        SBOMKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        

        Logger.logger.info('Validate SBOM was created with expected data')
        self.validate_expected_SBOM(SBOMs, self.test_obj["expected_SBOMs"])


        Logger.logger.info('Get SBOMsp from storage')  
        filteredSBOM, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_SBOM_from_storage,
                                               filteredSBOMKeys=self.get_filtered_data_keys(
                                                   pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod',
                                                                                                     namespace=namespace),
                                                   namespace=namespace))

        Logger.logger.info('Validate SBOMsp was created with expected data')
        self.validate_expected_filtered_SBOMs(filteredSBOM, self.test_obj["expected_filtered_SBOMs"], namespace=namespace)

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        

        return self.cleanup()

class RelevancyStorageDisabled(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevancyStorageDisabled, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                           kubernetes_obj=kubernetes_obj)
        

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        # agenda:
        # 1. install helm-chart with really small timeout in kubevuln
        # 2. apply workload
        # 3. verify that an SBOM was created with an incomplete annotation
        # 4. verify that SBOMp was created with an incomplete annotation
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()


        # 1.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # P2 apply workloads
        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)
        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        Logger.logger.info('Get the scan result from Backend')
        expected_number_of_pods = self.get_expected_number_of_pods(
            namespace=namespace)
        be_summary, _ = self.wait_for_report(timeout=1200, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=expected_number_of_pods)
        # P4 check result
        # 4.1 check results (> from expected result)
        Logger.logger.info('Test no errors in results')
        self.test_no_errors_in_scan_result(be_summary)

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        

        return self.cleanup()
    
class RelevancyFixVuln(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevancyFixVuln, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                           kubernetes_obj=kubernetes_obj)
        

    def start(self):
        # agenda:
        # 1. install helm-chart with really small timeout in kubevuln
        # 2. apply workload
        # 3. verify that an SBOM was created with an incomplete annotation
        # 4. verify that SBOMp was created with an incomplete annotation
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()


        # 1.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # P2 apply workloads
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        # P3 verify results in storage
        # 3 test SBOM and CVEs created as expected in the storage
        Logger.logger.info('Get the scan result from local Storage')
        # 3.1 test SBOM created in the storage
        SBOMs, _ = self.wait_for_report(timeout=1200, report_type=self.get_SBOM_from_storage,
                                        SBOMKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        # 3.2 test SBOM created as expected result in the storage
        self.validate_expected_SBOM(SBOMs, self.test_obj["expected_SBOMs"])
        # 3.3 test CVEs created in the storage
        CVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_CVEs_from_storage,
                                       CVEsKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        # 3.4 test CVES created as expected result in the storage
        self.validate_expected_CVEs(CVEs, self.test_obj["expected_CVEs"])

        # 3.5 test filtered SBOM created in the storage
        filteredSBOM, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_SBOM_from_storage,
                                               filteredSBOMKeys=self.get_filtered_data_keys(
                                                   pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod',
                                                                                                     namespace=namespace),
                                                   namespace=namespace))
        # 3.6 test filtered CVEs created as expected result in the storage
        self.validate_expected_filtered_SBOMs(filteredSBOM, self.test_obj["expected_filtered_SBOMs"], namespace=namespace)
        # 3.7 test filtered SBOM created in the storage

        filteredCVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_CVEs_from_storage, filteredCVEsKEys=self.get_filtered_data_keys(pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod', namespace=namespace), namespace=namespace))
        # 3.8 test filtered CVEs created as expected result in the storage
        self.validate_expected_filtered_CVEs(filteredCVEs, self.test_obj["expected_filtered_CVEs"], namespace=namespace)

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        return self.cleanup()    

class RelevancyFixVulnBackendTest(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RelevancyFixVulnBackendTest, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                           kubernetes_obj=kubernetes_obj)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'

        # agenda:
        # 1. install helm-chart with really small timeout in kubevuln
        # 2. apply workload
        # 3. get CVEs and filtered CVEs from storage
        # 4. check BE data

        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()

        # 1.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        # P2 apply workloads
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=360)

        # P3 get results in storage
        # 3 get CVEs created as expected in the storage
        CVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_CVEs_from_storage,
                                       CVEsKeys=self.get_imagesIDs_keys(workload_objs, namespace=namespace))
        
        filteredCVEs, _ = self.wait_for_report(timeout=1200, report_type=self.get_filtered_CVEs_from_storage, filteredCVEsKEys=self.get_filtered_data_keys(pods=self.kubernetes_obj.get_namespaced_workloads(kind='Pod', namespace=namespace), namespace=namespace))
        
        Logger.logger.info('Get the scan result from Backend')
        expected_number_of_pods = self.get_expected_number_of_pods(
            namespace=namespace)
        be_summary, _ = self.wait_for_report(timeout=1200, report_type=self.backend.get_scan_results_sum_summary,
                                            namespace=namespace, since_time=since_time,
                                            expected_results=expected_number_of_pods)
        # P4 check result
        # 4.1 check results
        Logger.logger.info('Test no errors in results')
        self.test_no_errors_in_scan_result(be_summary)

        # # 4.2 get container scan id
        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)
        # # 4.3 get CVEs for containers
        self.test_cve_result(since_time=since_time, containers_scan_id=containers_scan_id,
                                                    be_summary=be_summary, storage_CVEs={statics.ALL_CVES_KEY: CVEs,
                                                                                        statics.FILTERED_CVES_KEY: filteredCVEs}, expected_number_of_pods = self.get_expected_number_of_pods(namespace=namespace))

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()
        TestUtil.sleep(150, "Waiting for aggregation to end")

        return self.cleanup()
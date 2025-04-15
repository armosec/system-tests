import json
import os
import re
import time
import base64
import kubernetes.client
import requests
import json

from systest_utils import statics, Logger, TestUtil
from datetime import datetime, timezone

from tests_scripts.helm.base_vuln_scan import BaseVulnerabilityScanning
from systest_utils.wlid import Wlid

DEFAULT_BRANCH = "release"


def is_accesstoken_credentials(credentials):
    return 'username' in credentials and 'password' in credentials and credentials['username'] != '' and credentials[
        'password'] != ''


# class VulnerabilityScanningProxy - is a class that is used to test Helm proxy.
# test runs vulnerability scanning on a cluster with proxy and checks that the scan results are updated on backend.

class VulnerabilityScanningProxy(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanningProxy, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                         kubernetes_obj=kubernetes_obj)

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('1. apply cluster resources')

        Logger.logger.info('1.1 apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('1.2 apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)

        Logger.logger.info('1.3 apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)

        Logger.logger.info('2. verify all pods are running')
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        since_time = datetime.now(timezone.utc).astimezone().isoformat()

        Logger.logger.info('3. install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        Logger.logger.info('3.1 verify helm installation')
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        Logger.logger.info('4. Get the scan result from Backend')
        # In order to check proxy it is enough to check that at least one pod is updated on backend.
        expected_number_of_pods = 1
        be_summary, _ = self.wait_for_report(timeout=400, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=expected_number_of_pods)
        self.test_total_is_rce_count(be_summary)
        Logger.logger.info('5. Test no errors in results')
        self.test_no_errors_in_scan_result(be_summary)

        return self.cleanup()


class VulnerabilityScanning(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanning, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                    kubernetes_obj=kubernetes_obj)

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()

        # 1.2 install armo helm-chart
        self.install_armo_helm_chart()

        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        # P2 Install Wikijs
        # 2.1 install Wikijs
        # 2.2 verify installation
        cluster, namespace = self.setup(apply_services=False)

        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)

        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        # P3 run kubescape and Vulnerability scanning
        # 3.1 run kubescape
        # 3.2 get pending statuses with each scan (just over app namespace) (from be) (time-out 10 min)
        Logger.logger.info('Get the scan result from Backend')
        expected_number_of_pods = self.get_expected_number_of_pods(
            namespace=namespace)
        be_summary, _ = self.wait_for_report(timeout=600, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=expected_number_of_pods)
        self.test_total_is_rce_count(be_summary)

        # P4 check result
        # 4.1 check results (> from expected result)
        Logger.logger.info('Test no errors in results')
        self.test_no_errors_in_scan_result(be_summary)

        Logger.logger.info('Get scan result csv')
        self.backend.get_scan_results_sum_summary_CSV(namespace=namespace,
                                                      expected_results=expected_number_of_pods)
        # check CSV with fixable and critical severity filters
        self.backend.get_scan_results_sum_summary_CSV(namespace=namespace,
                                                      expected_results=self.count_containers_with_severity(be_summary,
                                                                                                           "Critical",
                                                                                                           True),
                                                      severity="Critical", fixable=True)

        # P5 get CVEs results
        # 5.1 get container scan id
        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)

        # 5.2 get CVEs for containers
        Logger.logger.info('Test cve result')
        self.test_cve_result(since_time=since_time, containers_scan_id=containers_scan_id, be_summary=be_summary,
                             expected_number_of_pods=self.get_expected_number_of_pods(namespace=namespace))

        Logger.logger.info('Get scan result details csv')
        self.backend.get_scan_results_details_csv(containers_scan_id=containers_scan_id)

        # 4.2 Check logs for error- if there is 1 error- test fail
        Logger.logger.info('Test no errors in armo-system-component logs')
        self.test_no_errors_in_armo_system_logs()

        # 4.3 test cluster info from BE
        Logger.logger.info('Test no errors in cluster api')
        self.test_cluster_info()

        # Logger.logger.info('validate all cluster cve data arrived')
        #  self.test_all_images_vuln_scan_reported(in_cluster_images=in_cluster_images, since_time=since_time)

        return self.cleanup()


class VulnerabilityScanningTriggerScanOnNewImage(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanningTriggerScanOnNewImage, self).__init__(test_driver=test_driver, test_obj=test_obj,
                                                                         backend=backend,
                                                                         kubernetes_obj=kubernetes_obj)

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        # P1 Install Wikijs
        # 1.1 install Wikijs
        # 1.2 verify installation
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_yaml_file(yaml_file=self.test_obj["deployment"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        # P2 install helm-chart (armo)
        # 2.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()

        # 2.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # 2.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        # P3 run kubescape and Vulnerability scanning
        # 3.1 run kubescape
        # 3.2 get pending statuses with each scan (just over app namespace) (from be)
        Logger.logger.info('Get the scan result from Backend')
        be_summary, _ = self.wait_for_report(timeout=900, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=self.get_expected_number_of_pods(
                                                 namespace=namespace))

        # P4 check result
        # 4.1 check results (> from expected result)
        Logger.logger.info('Test no errors in results')
        self.test_no_errors_in_scan_result(be_summary)
        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)
        self.test_cve_result(since_time=since_time, containers_scan_id=containers_scan_id, be_summary=be_summary,
                             expected_number_of_pods=self.get_expected_number_of_pods(namespace=namespace))
        # 4.2 Check logs for error- if there is 1 error- test fail
        Logger.logger.info('Test no errors in armo-system-component logs')
        self.test_no_errors_in_armo_system_logs()
        # 4.3 Check armo components health

        return self.cleanup()


class VulnerabilityScanningCVEExceptions(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None, exceptions_parameters=None):
        super(VulnerabilityScanningCVEExceptions, self).__init__(test_driver=test_driver, test_obj=test_obj,
                                                                 backend=backend,
                                                                 kubernetes_obj=kubernetes_obj)
        self.exceptions_parameters = exceptions_parameters  # Initialize the attribute

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        # P1 Install Wikijs
        # 1.1 install Wikijs
        # 1.2 verify installation
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('apply workload')
        workload_objs: list = self.apply_yaml_file(yaml_file=self.test_obj["deployment"], namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        # P2 install helm-chart (armo)
        # 2.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()

        # 2.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # 2.3 verify installation
        self.verify_running_pods(timeout=360, namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        # P3 run kubescape and Vulnerability scanning
        # 3.1 run kubescape
        # 3.2 get pending statuses with each scan (just over app namespace) (from be) (time-out 10 min)
        Logger.logger.info('Get the scan result from Backend')
        be_summary, _ = self.wait_for_report(timeout=560, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=self.get_expected_number_of_pods(
                                                 namespace=namespace))

        # P4 check result
        # 4.1 check results (> from expected result)
        Logger.logger.info('Test no errors in results')

        self.test_no_errors_in_scan_result(be_summary)
        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)
        self.test_cve_result(since_time=since_time, containers_scan_id=containers_scan_id, be_summary=be_summary,
                             expected_number_of_pods=self.get_expected_number_of_pods(namespace=namespace))
        # 4.2 Check logs for error- if there is 1 error- test fail

        # 5.0 set several cves exceptions
        cve_exception_guid, cves_list = self.set_multiple_cves_exceptions(namespace, wlids)

        # 5.1 rescan
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        self.wait_for_report(timeout=360, report_type=self.backend.scan_image_in_namespace,
                             cluster_name=self.kubernetes_obj.get_cluster_name(), namespace=namespace)

        # 5.2 Get the scan result from Backend
        Logger.logger.info('Get the scan result from Backend')
        self.wait_for_report(timeout=420, report_type=self.test_applied_cve_exceptions,
                             namespace=namespace, since_time=since_time,
                             cve_exception_guid=cve_exception_guid, cves_list=cves_list)

        Logger.logger.info('Test no errors in armo-system-component logs')
        self.test_no_errors_in_armo_system_logs()
        # 4.3 Check armo components health

        return self.cleanup()

    def set_multiple_cves_exceptions(self, namespace, wlids):
        if not self.exceptions_parameters:
            # Use the existing logic
            cves_list = self.get_some_cve_exceptions_list(Wlid.get_name(wlids))
            cve_exception_guid, cve_exception_guid_time = self.wait_for_report(timeout=360,
                                                                               report_type=self.backend.set_cves_exceptions,
                                                                               cves_list=cves_list,
                                                                               cluster_name=self.kubernetes_obj.get_cluster_name(),
                                                                               namespace=namespace,
                                                                               conatiner_name=Wlid.get_name(wlids))
            Logger.logger.info(f'Set CVE exceptions for namespace {namespace} and container {Wlid.get_name(wlids)}')
        else:
            # Use the provided exceptions parameters
            for params in self.exceptions_parameters:
                cluster_name = params.get("cluster_name")
                namespace = params.get("namespace", namespace)
                container_name = params.get("container_name", Wlid.get_name(wlids))

                if not all([cluster_name, namespace, container_name]):
                    # Fallback to the existing logic if any parameter is missing
                    cves_list = self.get_some_cve_exceptions_list(Wlid.get_name(wlids))
                    cve_exception_guid, cve_exception_guid_time = self.wait_for_report(timeout=360,
                                                                                       report_type=self.backend.set_cves_exceptions,
                                                                                       cves_list=cves_list,
                                                                                       cluster_name=self.kubernetes_obj.get_cluster_name(),
                                                                                       namespace=namespace,
                                                                                       conatiner_name=Wlid.get_name(wlids))
                    Logger.logger.info(f'Set CVE exceptions for namespace {namespace} and container {Wlid.get_name(wlids)}')
                else:
                    cves_list = self.get_some_cve_exceptions_list(container_name)
                    cve_exception_guid, cve_exception_guid_time = self.wait_for_report(timeout=360,
                                                                                       report_type=self.backend.set_cves_exceptions,
                                                                                       cves_list=cves_list,
                                                                                       cluster_name=cluster_name,
                                                                                       namespace=namespace,
                                                                                       conatiner_name=container_name)
                    Logger.logger.info(f'Set CVE exceptions for namespace {namespace}, cluster {cluster_name}, and container {container_name}')
        return cve_exception_guid, cves_list



class VulnerabilityScanningTriggeringWithCronJob(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, cacli=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanningTriggeringWithCronJob, self).__init__(test_obj=test_obj, backend=backend,
                                                                         kubernetes_obj=kubernetes_obj,
                                                                         test_driver=test_driver)

    def start(self):
        # test Agenda:
        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)

        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        Logger.logger.info("Installing helm-chart")
        # 2.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 2.2 install armo helm-chart
        self.install_armo_helm_chart()

        # 2.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=240)
        TestUtil.sleep(60, "wait till data will arrive to backend")

        Logger.logger.info("Test create vuln-scan cronjob")
        cj = self.test_create_vuln_scan_cronjob(namespaces_list=[namespace],
                                                schedule_string=self.test_obj.get_arg("schedule_time"))

        Logger.logger.info("Test update vuln-scan cronjob")
        cj = self.test_update_vuln_scan_cronjob(cron_job=cj,
                                                schedule_string=self.test_obj.get_arg("schedule_time"))

        Logger.logger.info("Test delete vuln-scan cronjob")
        self.test_delete_vuln_scan_cronjob(cron_job=cj)

        return self.cleanup()


class VulnerabilityV2Views(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityV2Views, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                         kubernetes_obj=kubernetes_obj)

    def start(self):
        return statics.SUCCESS, ""
        assert self.backend != None
        #use this flag to update expected results (test will fail if flag is not set to prevent accidental overwrite of expected results)
        updateExpected = False
        f'the test {self.test_driver.test_name} must run with backend'

        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('1. apply cluster resources')

        Logger.logger.info('1.1 apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('1.2 apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)

        Logger.logger.info('1.3 verify all pods are running')
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=240)

        Logger.logger.info('1.4 install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart()

        Logger.logger.info('1.5 verify helm installation')
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        Logger.logger.info('2. verify httpd-proxy scan arrived to backend')
        body = {"innerFilters": [
            {
                "cluster": cluster,
                "namespace": namespace,
                "name": "httpd-proxy",
                "riskFactors":"External facing",
            }]}
        wl_list, _ = self.wait_for_report(timeout=600, report_type=self.backend.get_vuln_v2_workloads,
                                              body=body,expected_results=1)

        Logger.logger.info("received httpd-proxy scan {}".format(wl_list))

        Logger.logger.info('2.1 get httpd-proxy workload with filteres and compare with expected')
        body =  {"innerFilters": [{
            "exploitable":"Known Exploited,High Likelihood",
            "riskFactors":"External facing",
            "isRelevant":"Yes",
            "cvssInfo.baseScore":"5|greater",
            "severity":"Medium",
            "cveName":"CVE-2007-0450",
            "labels":"app:httpd-proxy",
            "cluster": cluster,
            "namespace": namespace,
            "name": "httpd-proxy"
            }]}

        res, _ = self.wait_for_report(timeout=300, report_type=self.get_filtered_workload_summary, updateExpected=updateExpected, body=body)

        wl_summary, wl_excluded_paths = res[0], res[1]

        Logger.logger.info('3. get workload details and compare with expected')
        body =  {"innerFilters": [{
            "cluster":wl_summary["cluster"],
            "namespace":wl_summary["namespace"],
            "kind": wl_summary["kind"],
            "name": wl_summary["name"]
            }]}
        wl_summary = self.backend.get_vuln_v2_workload_details(body=body)
        if updateExpected:
            TestUtil.save_expceted_json(wl_summary, "configurations/expected-result/V2_VIEWS/wl_details.json")
        TestUtil.compare_with_expected_file("configurations/expected-result/V2_VIEWS/wl_details.json", wl_summary, wl_excluded_paths)

        Logger.logger.info('4. get workloads components')
        body =  {"innerFilters": [{
            "cluster":wl_summary["cluster"],
            "namespace":wl_summary["namespace"],
            "kind": wl_summary["kind"],
            "workload": wl_summary["name"]
            }]}
        components = self.backend.get_vuln_v2_components(body=body)
        assert len(components) == 41, f'Expected 41 components, but found {len(components)} for httpd-proxy'

        Logger.logger.info('5. get workloads images and compare with expected')
        image = self.backend.get_vuln_v2_images(body=body, expected_results=wl_summary["imagesCount"])
        image = image[0]
        image_excluded_paths = {"root['lastScanTime']", "root['customerGUID']", "root['digest']",
                                "root['repository']", "root['registry']", "root['namespaces']", "root['clusters']",
                                "root['architecture']", "root['os']", "root['size']", "root['baseImage']",
                                "root['clustersCount']", "root['namespacesCount']", "root['workloadsCount']"}
        if updateExpected:
            TestUtil.save_expceted_json(image, "configurations/expected-result/V2_VIEWS/image_details.json")

        TestUtil.save_expceted_json(image, "configurations/expected-result/V2_VIEWS/image_details_temp.json")
        TestUtil.compare_with_expected_file("configurations/expected-result/V2_VIEWS/image_details.json", image, image_excluded_paths)

        Logger.logger.info('6. get workloads CVEs and match with workload summary')
        body['innerFilters'][0]['severity'] = "Critical"
        body['innerFilters'][0]['riskFactors'] = "External facing"
        cves = self.backend.get_vulns_v2(body=body, expected_results=wl_summary["criticalCount"])
        TestUtil.save_expceted_json(image, "configurations/expected-result/V2_VIEWS/cves_temp.json")

        for cve in cves:
            if cve["name"] not in wl_summary["severityStats"]["Critical"]:
                raise Exception(f'cve {cve["name"]} not found in critical cves')

        body['innerFilters'][0]['severity'] = "High"
        cves = self.backend.get_vulns_v2(body=body, expected_results=wl_summary["highCount"])
        TestUtil.save_expceted_json(image, "configurations/expected-result/V2_VIEWS/cves_high_temp.json")

        for cve in cves:
            if cve["name"] not in wl_summary["severityStats"]["High"]:
                raise Exception(f'cve {cve["name"]} not found in high cves')

        body['innerFilters'][0]['severity'] = "Medium"
        cves = self.backend.get_vulns_v2(body=body, expected_results=wl_summary["mediumCount"])
        TestUtil.save_expceted_json(image, "configurations/expected-result/V2_VIEWS/cves_medium_temp.json")

        for cve in cves:
            if cve["name"] not in wl_summary["severityStats"]["Medium"]:
                raise Exception(f'cve {cve["name"]} not found in medium cves')

        body['innerFilters'][0]['severity'] = "Low"
        cves = self.backend.get_vulns_v2(body=body, expected_results=wl_summary["lowCount"])
        TestUtil.save_expceted_json(image, "configurations/expected-result/V2_VIEWS/cves_low_temp.json")

        for cve in cves:
            if cve["name"] not in wl_summary["severityStats"]["Low"]:
                raise Exception(f'cve {cve["name"]} not found in low cves')

        Logger.logger.info('7. get exploitable CVE details and compare with expected')
        body['innerFilters'][0]['severity'] = ""
        body['innerFilters'][0]['exploitable'] = "Known Exploited,High Likelihood"
        cve = self.backend.get_vulns_v2(body=body, expected_results=1)
        TestUtil.save_expceted_json(image, "configurations/expected-result/V2_VIEWS/cves_exploit_temp.json")

        cve = cve[0]
        body['innerFilters'][0]['name'] = cve["name"]
        body['innerFilters'][0]['componentInfo.name'] = cve["componentInfo"]["name"]
        body['innerFilters'][0]['componentInfo.version'] = cve["componentInfo"]["version"]
        cve = self.backend.get_vuln_v2_details(body=body)
        cve_excluded_paths = {"root['links']", "root['epssInfo']","root['cisaKevInfo']",
                              "root['componentInfo']['pathsInfo'][0]['workloadHash']",
                              "root['componentInfo']['pathsInfo'][0]['clusterName']",
                              "root['componentInfo']['pathsInfo'][0]['namespace']",
                              "root['componentInfo']['pathsInfo'][0]['imageHash']",
                              "root['componentInfo']['version']",
                              "root['cvssInfo']['baseScore']"}
        if updateExpected:
            TestUtil.save_expceted_json(cve, "configurations/expected-result/V2_VIEWS/cve_details.json")

        TestUtil.save_expceted_json(cve, "configurations/expected-result/V2_VIEWS/cve_details_details.json")
        TestUtil.compare_with_expected_file("configurations/expected-result/V2_VIEWS/cve_details.json", cve, cve_excluded_paths)

        if updateExpected:
            raise Exception('update expected is set to True')


        return self.cleanup()

    def get_filtered_workload_summary(self, updateExpected, body):
        wl_summary = self.backend.get_vuln_v2_workloads(body)
        if len(wl_summary) == 0:
            raise Exception('no results for httpd-proxy with exploitable filters (check possible exploitability change)')

        wl_excluded_paths = {"root['cluster']", "root['namespace']","root['wlid']","root['resourceHash']", "root['clusterShortName']", "root['customerGUID']", "root['lastScanTime']", "root['missingRuntimeInfoReason']"}
        wl_summary = wl_summary[0]
        if updateExpected:
            TestUtil.save_expceted_json(wl_summary, "configurations/expected-result/V2_VIEWS/wl_filtered.json")
        TestUtil.compare_with_expected_file("configurations/expected-result/V2_VIEWS/wl_filtered.json", wl_summary, wl_excluded_paths)
        return wl_summary,wl_excluded_paths



class VulnerabilityV2ViewsKEV(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityV2ViewsKEV, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                         kubernetes_obj=kubernetes_obj)

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('1. apply cluster resources')

        Logger.logger.info('1.1 apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('1.2 apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)

        Logger.logger.info('2. verify all pods are running')
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=240)

        Logger.logger.info('3. install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(use_offline_db=False)

        Logger.logger.info('3.1 verify helm installation')
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        Logger.logger.info('4. verify mariadb scan arrived to backend')
        body = {"innerFilters": [
            {
                "cluster": cluster,
                "namespace": namespace,
                "kind" : "deployment",
                "name": "mariadb"
            }]}
        self.wait_for_report(timeout=600, report_type=self.backend.get_vuln_v2_workloads,
                                              body=body,expected_results=1)

        Logger.logger.info('4.1 get mariadb knwon exploited cve 2023-44487')
        body =  {"innerFilters": [{
            "name":"CVE-2023-44487",
            "cluster": cluster,
            "namespace":namespace,
            "kind":"deployment",
            "workload":"mariadb",
            "componentInfo.name":"stdlib",
            "componentInfo.version":"go1.16.7"}]}
        kev_vulan = self.backend.get_vuln_v2_details(body)

        Logger.logger.info('4.1 get mariadb knwon exploited cve 2023-44487 using exploitable filter')
        body['innerFilters'][0]['exploitable'] = "Known Exploited"
        kev_vulan = self.backend.get_vuln_v2_details(body)
        if len(kev_vulan["cisaKevInfo"]) == 0:
            raise Exception('vuilnerability CVE-2023-44487 does not include kev info')

        Logger.logger.info('check cve kev info')
        kev_excluded_paths = {"root['knownRansomwareCampaignUse']"}
        TestUtil.compare_with_expected_file("configurations/expected-result/V2_VIEWS/kev_vulan.json", kev_vulan["cisaKevInfo"],kev_excluded_paths)

        return self.cleanup()

import time, requests, os, re, random, yaml, base64, json, hashlib
from systest_utils import statics, Logger, TestUtil
from tests_scripts.helm.base_helm import BaseHelm
from pkg_resources import parse_version
from tests_scripts.kubernetes.base_k8s import BaseK8S

_UNSET_DATE = "0001-01-01T00:00:00Z"


class BaseVulnerabilityScanning(BaseHelm):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(BaseVulnerabilityScanning, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                        kubernetes_obj=kubernetes_obj)
        self.ignore_agent = True
        self.wait_for_agg_to_end = False


    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""

    def test_cluster_deleted(self, since_time: str):
        cluster_result, _ = self.wait_for_report(report_type=self.backend.get_scan_results_sum_summary, namespace='',
                                                 expected_results=0, since_time=since_time, expected_status_code=404,
                                                 cluster_name=self.kubernetes_obj.get_cluster_name(), timeout=600)
        assert cluster_result, 'Failed to verify deleting cluster {x} from backend'. \
            format(x=self.kubernetes_obj.get_cluster_name())

    @staticmethod
    def test_total_is_rce_count(be_summary: dict):
        for container_scan in be_summary:
            rce_fix_count = 0
            for severity in container_scan['severitiesStats']:
                rce_fix_count += severity['rceFixCount']
            assert rce_fix_count == container_scan['rceFixCount']

    @staticmethod
    def count_containers_with_severity(be_summary: dict, severityLvl: str, fixable: bool = False):
        count = 0
        for container_scan in be_summary:
            for severity in container_scan['severitiesStats']:
                if fixable and severity['fixedTotal'] < 1:
                    continue
                if severity['severity'] != severityLvl:
                    continue
                count += 1
        return count

    @staticmethod
    def test_no_errors_in_scan_result(be_summary: dict):
        for scan in be_summary:
            assert scan[statics.SCAN_RESULT_STATUS_FIELD] != 'Error', \
                'container {container_name} received from backend with {num} error: {error_lst}'.format(
                    container_name=scan[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                    num=len(scan[statics.SCAN_RESULT_ERRORS_FIELD]),
                    error_lst=scan[statics.SCAN_RESULT_ERRORS_FIELD]
                )

    def is_storage_enabled(self):
        if "helm_kwargs" in self.test_obj.kwargs and statics.HELM_STORAGE_FEATURE in self.test_obj.kwargs[
            "helm_kwargs"]:
            return self.test_obj["helm_kwargs"][statics.HELM_STORAGE_FEATURE]
        return False

    def test_scan_results_against_expected(self, containers_cve: dict, storage_CVEs=None):
        expected_results = self.create_vulnerabilities_expected_results(
            expected_results=self.test_obj.get_arg('expected_results'))
        failed_paths = []
        for container_name, cve_list in expected_results.items():
            assert container_name in containers_cve.keys(), \
                f"Expect to receive {container_name} in results_details from backend"
            for cve in cve_list:
                if cve not in containers_cve[container_name].keys():
                    failed_paths.append(f"{container_name} -> {cve}")

        assert not failed_paths, 'Expect the data from backend would not fail less CVEs then the expected results.\n' \
                                 f'in the following entries is happened:\nfailed_paths: {failed_paths}\n containers_cve: {containers_cve}'

    # check that all backend CVEs are in storage
    # check that filtered CVEs have relevantLabel set to 'yes'
    # check that non-filtered CVEs have relevantLabel set to 'no'
    # check that we have the same number of CVEs in storage and backend
    def test_scan_result_against_storage(self, containers_cve: dict, storage_CVEs=None):
        failed_CVEs_path = []
        relevancy_enabled = self.is_relevancy_enabled()

        for container_name, cve_list in containers_cve.items():
            assert container_name in containers_cve.keys(), \
                f"Expect to receive {container_name} in results_details from backend"

            if len(cve_list) == 0:
                continue

            image_hash = next(iter(cve_list.items()))[1]['imageHash']
            total_cves = 0
            storage_filtered_CVEs = self.parse_filtered_CVEs_from_storage(storage_CVEs[statics.FILTERED_CVES_KEY],
                                                                          container_name=container_name)
            storage_all_CVEs = self.parse_CVEs_from_storage(storage_CVEs[statics.ALL_CVES_KEY], image_hash=image_hash)

            for cve, cve_details in cve_list.items():
                total_cves += cve_details[statics.SCAN_RESULT_TOTAL_FIELD]
                if cve in storage_filtered_CVEs:
                    assert cve_details[
                               statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_TRUE, \
                        f"Expect to receive {cve} as relevant CVE"
                elif cve in storage_all_CVEs:
                    if relevancy_enabled:
                        assert cve_details[
                                   statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_FALSE, \
                            f"Expect to receive {cve} as not relevant CVE"
                    else:
                        assert cve_details[
                                   statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_UNKNOWN, \
                            f"Expect to receive {cve} as relevant CVE"
                if cve not in storage_filtered_CVEs and cve not in storage_all_CVEs:
                    failed_CVEs_path.append(f"{container_name} -> {cve}")

            assert total_cves == len(storage_all_CVEs), \
                f"Expect to receive {len(storage_all_CVEs)} CVEs in total from backend, but received {total_cves} CVEs"

        assert not failed_CVEs_path, 'Expect the data from backend would be the same as storage CVE results.\n' \
                                     f'in the following entries is happened:\n{failed_CVEs_path}'

    def test_expected_scan_result(self, containers_cve: dict, storage_CVEs=None):
        if self.is_storage_enabled():
            self.test_scan_result_against_storage(containers_cve=containers_cve, storage_CVEs=storage_CVEs)
        else:
            self.test_scan_results_against_expected(containers_cve=containers_cve, storage_CVEs=storage_CVEs)

    def test_applied_cve_exceptions(self, namespace, cve_exception_guid, cves_list, since_time):
        be_summary = self.backend.get_scan_results_sum_summary(
            namespace=namespace, since_time=since_time,
            expected_results=self.get_expected_number_of_pods(
                namespace=namespace))

        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)
        containers_cve = self.get_container_cve_without_filter_response(since_time=since_time,
                                                                        container_scan_id=containers_scan_id)

        # 5.2 test applied cve exceptions in report
        self.test_applied_cve_exceptions_in_report(containers_cve=containers_cve, cve_exception_guid=cve_exception_guid,
                                                   cves_list=cves_list)
        # 5.3 test ignore rules summary in report
        self.test_cve_ignore_rule_summary_in_report(containers_cve=containers_cve,
                                                    cve_exception_guid=cve_exception_guid,
                                                    cves_list=cves_list)

        return None

    @staticmethod
    def test_applied_cve_exceptions_in_report(containers_cve, cve_exception_guid, cves_list):
        result = []
        for cve in cves_list:
            found = False
            for container_name in containers_cve:
                for container_cve in containers_cve[container_name]:
                    if cve == container_cve["name"] and "exceptionApplied" in container_cve:
                        for cve_exception_applied in container_cve["exceptionApplied"]:
                            if cve_exception_applied["guid"] == cve_exception_guid:
                                for inner_cve in cve_exception_applied["vulnerabilities"]:
                                    if inner_cve["name"] == cve:
                                        found = True
                                        break
                if found:
                    break
            if not found:
                result.append(cve)
        assert not result, "test_applied_cve_exceptions failed, not found cvs the applied: {}".format(result)

    @staticmethod
    def test_cve_ignore_rule_summary_in_report(containers_cve, cve_exception_guid, cves_list):
        result = []
        for cve in cves_list:
            found = False
            for container_name in containers_cve:
                for container_cve in containers_cve[container_name]:
                    if cve == container_cve["name"] and "ignoreRulesSummary" in container_cve:
                        ignore_rules_summary = container_cve["ignoreRulesSummary"]
                        if ignore_rules_summary[cve] and cve_exception_guid in ignore_rules_summary[cve][
                            "ignoreRulesIDs"]:
                            found = True
                            break
                if found:
                    break
            if not found:
                result.append(cve)
        assert not result, "test_applied_cve_ignore_rule_summary_in_report failed, not found cvs the ignore rules summary: {}".format(
            result)

    def test_no_errors_in_armo_system_logs(self):
        pass
        # TODO: We cannot simply search the logs for the word "error", we need to find a better solution
        # error_logs = self.get_errors_in_armo_system_logs()
        # assert not error_logs, 'There are errors obtained from the armo-system component logs:/n' + error_logs

    @staticmethod
    def get_error_message_of_compare(header: str, body: str, failed_result: dict):
        result_msg = header
        for k, v in failed_result.items():
            result_msg += body.format(x=v[0], y=v[1], z=k)
        return result_msg

    @staticmethod
    def get_container_scan_id(be_summary: dict):
        return list(map(lambda x: (x[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                                   x[statics.SCAN_RESULT_CONTAINER_SCAN_ID_FIELD],
                                   x[statics.SCAN_RESULT_TOTAL_FIELD]), be_summary))

    @staticmethod
    def get_image_scan_id(be_summary: dict):
        return list(map(lambda x: (x[statics.SCAN_RESULT_IMAGE_TAG_NAME_FIELD],
                                   x[statics.SCAN_RESULT_CONTAINER_SCAN_ID_FIELD],
                                   x[statics.SCAN_RESULT_TOTAL_FIELD]), be_summary))

    @staticmethod
    def get_scan_id(be_summary: dict):
        return be_summary[0][statics.SCAN_RESULT_CONTAINER_SCAN_ID_FIELD]

    def test_cve_result(self, since_time: str, containers_scan_id, be_summary, timeout: int = 1250, storage_CVEs=None,
                        expected_number_of_pods=None):

        start = time.time()
        err = ""
        success = False
        while time.time() - start < timeout:
            Logger.logger.info('wait for detailed CVE aggregation to end in backend')
            try:
                containers_cve = self.get_container_cve(since_time=since_time, container_scan_id=containers_scan_id)
                if self.is_relevancy_enabled():
                    namespace = be_summary[0]['designators']['attributes']['namespace']
                    be_summary, _ = self.wait_for_report(timeout=600,
                                                         report_type=self.backend.get_scan_results_sum_summary,
                                                         namespace=namespace, since_time=since_time,
                                                         expected_results=expected_number_of_pods)
                Logger.logger.info('Test results against expected results')
                self.test_expected_scan_result(containers_cve=containers_cve, storage_CVEs=storage_CVEs)

                Logger.logger.info('Test backend summary')
                is_one_relevant = self.is_at_least_one_cve_relevant(containers_cve=containers_cve)
                self.test_be_summary(be_summary, is_relevant_summary=is_one_relevant, since_time=since_time)

                success = True
                break
            except Exception as e:
                if str(e).find("502 Bad Gateway") > 0:
                    raise e
                err = e
                Logger.logger.warning(
                    "timeout {} since_time {} containers_scan_id {} error: {}".format(timeout // 60, since_time,
                                                                                      containers_scan_id, err))
            time.sleep(30)
        if not success:
            raise Exception(
                f"test_cve_result, timeout: {timeout // 60} minutes, error: {err}. ")

        Logger.logger.info('Test cluster installation data')
        self.test_installation_data()

        Logger.logger.info('Test image scan status')
        self.test_image_scan_status()

        Logger.logger.info('Test backend results_details against results_sum_summary')
        try:
            self.test_results_details_against_results_sum_summary(containers_cve=containers_cve, be_summary=be_summary)
        except Exception as e:
            Logger.logger.warning("test_results_details_against_results_sum_summary failed: {}".format(e))

    def test_image_scan_status(self):
        image_scan_stats = self.get_image_scan_stats()
        assert image_scan_stats['exists'] == True

    def test_installation_data(self):
        cluster = self.get_cluster_name()
        cluster_info = self.get_cluster_info(cluster_name=cluster)

        # for older helm charts, installationData is not available
        if cluster_info is not None:
            assert cluster_info['installationData']['imageVulnerabilitiesScanningEnabled']
            assert cluster_info['installationData']['relevantImageVulnerabilitiesEnabled'] == self.is_relevancy_enabled(), f"installationData.relevantImageVulnerabilitiesEnabled expected: {self.is_relevancy_enabled()}, actual: {cluster_info['installationData']['relevantImageVulnerabilitiesEnabled']}"

    def get_workload_data_from_yaml(self, yaml_file: str, path: str = statics.DEFAULT_DEPLOYMENT_PATH):
        workload = self.load_yaml(yaml_file=yaml_file, path=path)
        workload_obj = {
            "name": workload["metadata"]["name"],
            "kind": workload["kind"],
            "containerName": workload["spec"]["template"]["spec"]["containers"][0]["name"],
            "imageHash": workload["spec"]["template"]["spec"]["containers"][0]["image"],
        }
        return workload_obj

    def get_workload_data_from_deployments(self):
        workload_data = []
        if "deployments" in self.test_obj.kwargs:
            path = self.test_obj["deployments"]
            yaml_files = TestUtil.get_files_in_dir(file_path=path)
            if not yaml_files:
                return None
            for yaml_file in yaml_files:
                workload = self.get_workload_data_from_yaml(yaml_file=yaml_file, path=path)
                workload_data.append(workload)
        elif "deployment" in self.test_obj.kwargs:
            yaml_file = self.test_obj["deployment"]
            workload = self.get_workload_data_from_yaml(yaml_file=yaml_file, path=statics.DEFAULT_DEPLOYMENT_PATH)
            workload_data.append(workload)
        else:
            assert "get_workload_data_from_deployments function support only deployment and deployments as key"

        return workload_data

    @staticmethod
    def is_at_least_one_cve_relevant(containers_cve: dict):
        for container, cves in containers_cve.items():
            for cve, details in cves.items():
                if details[statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_TRUE:
                    return True
        return False

    def get_container_cve(self, since_time: str, container_scan_id):
        """
        params:
            container_scan_id: list of tuples.. [(container-name, container-scan-id), ...]
        return:
            dict of dict: {container-name: dict-of-CVEs, ...}
                dict-of-CVEs contains:{CVE-name: {severity: value, isRce: true/false}}
        """
        expected_results = self.create_vulnerabilities_expected_results(
            expected_results=self.test_obj.get_arg('expected_results'))

        _CONTAINER_NAME = 0
        _CONTAINER_SCAN_ID = 1
        _CONTAINER_TOTAL_CVE = 2
        if isinstance(container_scan_id, tuple):
            container_scan_id = [container_scan_id]
            return self.get_container_cve(since_time=since_time, container_scan_id=container_scan_id)

        result = {}
        for container in container_scan_id:
            container_cve, time = self.wait_for_report(timeout=500, report_type=self.backend.get_scan_results_details,
                                                       containers_scan_id=container[_CONTAINER_SCAN_ID],
                                                       since_time=since_time,
                                                       expected_results=expected_results[container[_CONTAINER_NAME]],
                                                       total_cve=container[_CONTAINER_TOTAL_CVE])

            name = statics.SCAN_RESULT_NAME_FIELD
            imageHash = statics.SCAN_RESULT_IMAGEHASH_FIELD
            severity = statics.SCAN_RESULT_SEVERITY_FIELD
            is_rce = statics.SCAN_RESULT_IS_RCE_FIELD
            categories = statics.SCAN_RESULT_CATEGORIES_FIELD
            is_relevant = statics.SCAN_RESULT_IS_RELEVANT_FIELD
            total_count = statics.SCAN_RESULT_TOTAL_FIELD
            rce_count = statics.SCAN_RESULT_RCETOTAL_FIELD
            is_fixed = statics.SCAN_RESULT_IS_FIXED_FIELD
            container_cve_dict = {}
            for item in container_cve:
                is_rce_cve = item[categories][is_rce]
                if item[name] in container_cve_dict:
                    container_cve_dict[item[name]][total_count] += 1
                    container_cve_dict[item[name]][is_relevant] = item[is_relevant]
                    container_cve_dict[item[name]][imageHash] = item[imageHash]

                    if is_rce_cve:
                        container_cve_dict[item[name]][rce_count] += 1
                else:
                    container_cve_dict[item[name]] = {severity: item[severity], is_rce: item[categories][is_rce],
                                                      total_count: 1, rce_count: 1 if is_rce_cve else 0,
                                                      is_relevant: item[is_relevant], imageHash: item[imageHash],
                                                      is_fixed: item[is_fixed],
                                                      statics.DESIGNATORS_FIELD: item[statics.DESIGNATORS_FIELD],
                                                      statics.SCAN_RESULT_IMAGE_TAG_NAME_FIELD: item[
                                                          statics.SCAN_RESULT_IMAGE_TAG_NAME_FIELD]}

            result[container[_CONTAINER_NAME]] = container_cve_dict

        return result

    def test_all_images_vuln_scan_reported(self, in_cluster_images, since_time):
        for ns in in_cluster_images:
            be_summary, _ = self.wait_for_report(timeout=1250, report_type=self.backend.get_scan_results_sum_summary,
                                                 namespace=ns, since_time=since_time,
                                                 expected_results=len(in_cluster_images[ns]))

    def get_container_cve_without_filter_response(self, since_time: str, container_scan_id):
        expected_results = self.create_vulnerabilities_expected_results(
            expected_results=self.test_obj.get_arg('expected_results'))

        _CONTAINER_NAME = 0
        _CONTAINER_SCAN_ID = 1
        _CONTAINER_TOTAL_CVE = 2
        if isinstance(container_scan_id, tuple):
            container_scan_id = [container_scan_id]
            return self.get_container_cve(since_time=since_time, container_scan_id=container_scan_id)

        result = {}
        for container in container_scan_id:
            container_cve, time = self.wait_for_report(timeout=1250, report_type=self.backend.get_scan_results_details,
                                                       containers_scan_id=container[_CONTAINER_SCAN_ID],
                                                       since_time=since_time,
                                                       expected_results=expected_results[container[_CONTAINER_NAME]],
                                                       total_cve=container[_CONTAINER_TOTAL_CVE])
            result[container[_CONTAINER_NAME]] = container_cve

        return result

    @staticmethod
    def test_results_details_against_results_sum_summary(containers_cve: dict, be_summary: list):

        containers_severity = {}
        for name, cve_dict in containers_cve.items():
            containers_severity[name] = {statics.SCAN_RESULT_RCETOTAL_FIELD: 0, statics.SCAN_RESULT_TOTAL_FIELD: 0,
                                         statics.SCAN_RESULT_FIX_COUNT_FIELD: 0,
                                         statics.SCAN_RESULT_RELEVANT_TOTAL_FIELD: 0,
                                         statics.SCAN_RESULT_RCE_FIX_COUNT: 0,
                                         statics.SCAN_RESULT_RELEVANT_FIX_COUNT: 0}
            for cve, details in cve_dict.items():
                containers_severity[name][statics.SCAN_RESULT_IMAGEHASH_FIELD] = details[
                    statics.SCAN_RESULT_IMAGEHASH_FIELD]
                containers_severity[name][statics.DESIGNATORS_FIELD] = details[statics.DESIGNATORS_FIELD]
                containers_severity[name][statics.SCAN_RESULT_RCETOTAL_FIELD] += details[
                    statics.SCAN_RESULT_RCETOTAL_FIELD]
                containers_severity[name][statics.SCAN_RESULT_TOTAL_FIELD] += details[statics.SCAN_RESULT_TOTAL_FIELD]
                if details[statics.SCAN_RESULT_IS_FIXED_FIELD] == 1:
                    containers_severity[name][statics.SCAN_RESULT_FIX_COUNT_FIELD] += details[
                        statics.SCAN_RESULT_TOTAL_FIELD]
                    if details[statics.SCAN_RESULT_IS_RCE_FIELD] == 1:
                        containers_severity[name][statics.SCAN_RESULT_RCE_FIX_COUNT] += details[
                            statics.SCAN_RESULT_TOTAL_FIELD]
                    if details[statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_TRUE:
                        containers_severity[name][statics.SCAN_RESULT_RELEVANT_FIX_COUNT] += details[
                            statics.SCAN_RESULT_TOTAL_FIELD]
                if details[statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_TRUE:
                    containers_severity[name][statics.SCAN_RESULT_RELEVANT_TOTAL_FIELD] += details[
                        statics.SCAN_RESULT_TOTAL_FIELD]
                if details[statics.SCAN_RESULT_SEVERITY_FIELD] not in containers_severity[name]:
                    containers_severity[name][details[statics.SCAN_RESULT_SEVERITY_FIELD]] = 0
                containers_severity[name][details[statics.SCAN_RESULT_SEVERITY_FIELD]] += details[
                    statics.SCAN_RESULT_TOTAL_FIELD]

        for container in be_summary:
            message = 'It is expected that the data from results_sum_summary and the data from results_details will ' \
                      'be the same, in this case they are different. In container {x}, from results_sum_summary ' \
                      '{x1} = {x2} and from results_details {x1} = {y2}'
            container_severity_key = container[statics.SCAN_RESULT_CONTAINER_NAME_FIELD]
            if container_severity_key == '':
                container_severity_key = container['imageTag']

            if len(containers_cve[container_severity_key]) > 0:
                assert container[statics.SCAN_RESULT_IMAGEHASH_FIELD] == \
                       containers_severity[container_severity_key][statics.SCAN_RESULT_IMAGEHASH_FIELD], \
                    message.format(x=container[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                                   x1=statics.SCAN_RESULT_IMAGEHASH_FIELD,
                                   x2=container[statics.SCAN_RESULT_IMAGEHASH_FIELD],
                                   y2=containers_severity[container_severity_key][statics.SCAN_RESULT_IMAGEHASH_FIELD])

                assert container[statics.DESIGNATORS_FIELD] == \
                       containers_severity[container_severity_key][statics.DESIGNATORS_FIELD], \
                    message.format(x=container[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                                   x1=statics.DESIGNATORS_FIELD,
                                   x2=container[statics.DESIGNATORS_FIELD],
                                   y2=containers_severity[container_severity_key][statics.DESIGNATORS_FIELD])

            assert container[statics.SCAN_RESULT_TOTAL_FIELD] == \
                   containers_severity[container_severity_key][statics.SCAN_RESULT_TOTAL_FIELD], \
                message.format(x=container[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                               x1=statics.SCAN_RESULT_TOTAL_FIELD,
                               x2=container[statics.SCAN_RESULT_TOTAL_FIELD],
                               y2=containers_severity[container_severity_key][
                                   statics.SCAN_RESULT_TOTAL_FIELD])
            assert container[statics.SCAN_RESULT_RCETOTAL_FIELD] == \
                   containers_severity[container_severity_key][
                       statics.SCAN_RESULT_RCETOTAL_FIELD], \
                message.format(x=container[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                               x1=statics.SCAN_RESULT_RCETOTAL_FIELD,
                               x2=container[statics.SCAN_RESULT_RCETOTAL_FIELD],
                               y2=containers_severity[container_severity_key][
                                   statics.SCAN_RESULT_RCETOTAL_FIELD])

            assert container[statics.SCAN_RESULT_FIX_COUNT_FIELD] == \
                   containers_severity[container_severity_key][statics.SCAN_RESULT_FIX_COUNT_FIELD], \
                message.format(x=container[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                               x1=statics.SCAN_RESULT_FIX_COUNT_FIELD,
                               x2=container[statics.SCAN_RESULT_FIX_COUNT_FIELD],
                               y2=containers_severity[container_severity_key][
                                   statics.SCAN_RESULT_FIX_COUNT_FIELD])

            assert container[statics.SCAN_RESULT_RELEVANT_TOTAL_FIELD] == \
                   containers_severity[container_severity_key][statics.SCAN_RESULT_RELEVANT_TOTAL_FIELD], \
                message.format(x=container[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                               x1=statics.SCAN_RESULT_RELEVANT_TOTAL_FIELD,
                               x2=container[statics.SCAN_RESULT_RELEVANT_TOTAL_FIELD],
                               y2=containers_severity[container_severity_key][
                                   statics.SCAN_RESULT_RELEVANT_TOTAL_FIELD])

            assert container[statics.SCAN_RESULT_RCE_FIX_COUNT] == \
                   containers_severity[container_severity_key][statics.SCAN_RESULT_RCE_FIX_COUNT], \
                message.format(x=container[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                               x1=statics.SCAN_RESULT_RCE_FIX_COUNT,
                               x2=container[statics.SCAN_RESULT_RCE_FIX_COUNT],
                               y2=containers_severity[container_severity_key][
                                   statics.SCAN_RESULT_RCE_FIX_COUNT])

            assert container[statics.SCAN_RESULT_RELEVANT_FIX_COUNT] == \
                   containers_severity[container_severity_key][statics.SCAN_RESULT_RELEVANT_FIX_COUNT], \
                message.format(x=container[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                               x1=statics.SCAN_RESULT_RELEVANT_FIX_COUNT,
                               x2=container[statics.SCAN_RESULT_RELEVANT_FIX_COUNT],
                               y2=containers_severity[container_severity_key][
                                   statics.SCAN_RESULT_RELEVANT_FIX_COUNT])

            if container[statics.SCAN_RESULT_SEVERITIES_STATS_FIELD] is not None:
                for severity in container[statics.SCAN_RESULT_SEVERITIES_STATS_FIELD]:
                    assert severity[statics.SCAN_RESULT_TOTAL_FIELD] == \
                           containers_severity[container_severity_key][
                               severity[statics.SCAN_RESULT_SEVERITY_FIELD]], \
                        message.format(x=container[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                                       x1=statics.SCAN_RESULT_SEVERITIES_STATS_FIELD + '->' + severity[
                                           statics.SCAN_RESULT_SEVERITY_FIELD] + '->' + statics.SCAN_RESULT_TOTAL_FIELD,
                                       x2=severity[statics.SCAN_RESULT_TOTAL_FIELD],
                                       y2=containers_severity[container_severity_key][
                                           severity[statics.SCAN_RESULT_SEVERITY_FIELD]])

    def test_cluster_info(self):
        cluster_name = self.kubernetes_obj.get_cluster_name()
        cluster_info = self.get_cluster_with_risk_status(cluster_name=cluster_name)
        Logger.logger.info("cluster_info: %s", cluster_info)
        helm_chart_version = cluster_info['helmChartVersion']
        assert helm_chart_version != ''
        assert cluster_info['installationData']['clusterName'] == cluster_name
        assert cluster_info['installationData']['namespace'] == 'kubescape'
        assert cluster_info['firstConnected'] != _UNSET_DATE
        assert cluster_info['lastReconnected'] != _UNSET_DATE
        assert cluster_info['lastDisconnected'] == _UNSET_DATE
        assert cluster_info['disconnectionCount'] == 0
        assert cluster_info['connectionCount'] >= 1
        assert parse_version(cluster_info['helmChartVersionInfo']['latest']) <= parse_version(
            self.get_latest_helm_version()), f"cluster_info: {cluster_info['helmChartVersionInfo']['latest']}, helm version: {self.get_latest_helm_version()}"
        assert parse_version(helm_chart_version) >= parse_version(cluster_info['helmChartVersionInfo'][
                                                                      'current']), f"cluster_info: {helm_chart_version}, helm version: {cluster_info['helmChartVersionInfo']['current']}"
        assert parse_version(cluster_info['latestHelmChartVersion']) <= parse_version(
            self.get_latest_helm_version()), f"cluster_info: {cluster_info['latestHelmChartVersion']}, helm version: {self.get_latest_helm_version()}"
        assert cluster_info['attributes']['numberOfWorkerNodes'] != 0
        assert cluster_info['attributes']['numberOfWorkerNodes'] <= cluster_info['attributes']['workerNodes']['max']
        assert cluster_info['attributes']['alias'] != ''
        assert cluster_info['attributes']['kind'] == 'k8s', 'The cluster kind is not k8s'
        assert cluster_info['attributes']['description'] == 'created by Kubescape automatically', \
            'The cluster description is not created by Kubescape automatically'
        assert (cluster_info['attributes']['createdBy'] == 'armo-ingesters' or cluster_info['attributes'][
            'createdBy'] == 'armo-aggregator'), \
            f"The cluster created by is not armo-ingesters or armo-aggs. Cluster createdBy: {cluster_info['attributes']['createdBy']}"
        assert 'latest' in cluster_info['kubescapeVersion'], f"invalid cluster_info {cluster_info}"
        assert parse_version(cluster_info['kubescapeVersion']['latest']) <= parse_version(
            self.get_latest_kubescape_version()), f"cluster_info: {cluster_info['kubescapeVersion']['latest']}, kubescape version: {self.get_latest_kubescape_version()}"
        Logger.logger.debug("test_cluster_info passed")

    def get_cluster_with_risk_status(self, cluster_name: str):
        cluster_info, t = self.wait_for_report(report_type=self.backend.get_cluster_with_risk_status,
                                               cluster_name=cluster_name)
        return cluster_info

    def get_cluster_info(self, cluster_name: str):
        cluster_info, t = self.wait_for_report(report_type=self.backend.get_cluster, cluster_name=cluster_name)
        return cluster_info

    def get_image_scan_stats(self):
        image_scan_stats, t = self.wait_for_report(report_type=self.backend.get_image_scan_stats)
        return image_scan_stats

    def get_latest_helm_version(self):
        download_url = 'https://raw.githubusercontent.com/kubescape/helm-charts/gh-pages/index.yaml'
        helm_index = yaml.load(requests.get(download_url).content, Loader=yaml.FullLoader)
        version = "undefined"
        if "entries" in helm_index and "kubescape-operator" in helm_index["entries"]:
            if len(helm_index["entries"]["kubescape-operator"]) > 0:
                version = helm_index["entries"]["kubescape-operator"][0]["version"]

        return version

    def get_latest_kubescape_version(self):
        download_url = 'https://api.github.com/repos/kubescape/kubescape/releases/latest'
        version = self.get_latest_version(download_url)
        return version

    def get_latest_version(self, url):
        res = requests.get(url).json()
        return res['tag_name']

    def get_some_cve_exceptions_list(self, container_name):
        expected_results = self.create_vulnerabilities_expected_results(
            expected_results=self.test_obj.get_arg('expected_results'))
        return expected_results[container_name][:random.randint(1, 5)]

    def test_delete_vuln_scan_cronjob(self, cron_job: dict):
        self.backend.delete_vuln_scan_cronjob(cj=cron_job)
        TestUtil.sleep(30, "wait till delete cronjob will arrive to backend")
        cj, t = self.wait_for_report(report_type=self.backend.get_vuln_scan_cronjob, cj_name=cron_job['name'],
                                     expect_to_results=False)
        assert not cj, f"Failed to verify from backend the cronjob was deleted, cronjob: {cj}"

    def test_update_vuln_scan_cronjob(self, cron_job: dict, schedule_string: str):
        cron_job[statics.CA_VULN_SCAN_CRONJOB_CRONTABSCHEDULE_FILED] = schedule_string
        self.backend.update_vuln_scan_cronjob(cj=cron_job)
        TestUtil.sleep(30, "wait till update cronjob will arrive to backend")

        new_cj, t = self.wait_for_report(report_type=self.backend.get_vuln_scan_cronjob, cj_name=cron_job['name'])
        assert new_cj[statics.CA_VULN_SCAN_CRONJOB_CRONTABSCHEDULE_FILED] == schedule_string, \
            f'Failed to verify that cronjob {cron_job["name"]} with schedule {schedule_string} was updated. ' \
            f'cronjob: {new_cj}'
        assert (new_cj[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED].startswith("kubevuln")), \
            f'cronjob {cron_job["name"]} has wrong label for {statics.CA_VULN_SCAN_CRONJOB_NAME_FILED}. '
        return new_cj

    def test_create_vuln_scan_cronjob(self, namespaces_list: list, schedule_string: str):
        old_expected_cjs = self.kubernetes_obj.get_vuln_scan_cronjob()
        old_actual_cjs, t = self.wait_for_report(report_type=self.backend.get_vuln_scan_cronjob_list,
                                                 expected_cjs=old_expected_cjs,
                                                 cluster_name=self.kubernetes_obj.get_cluster_name())

        self.backend.create_vuln_scan_job_request(cluster_name=self.kubernetes_obj.get_cluster_name(),
                                                  schedule_string=schedule_string, namespaces_list=namespaces_list)
        TestUtil.sleep(30, "wait till cronjob will arrive to backend")
        new_expected_cjs = self.kubernetes_obj.get_vuln_scan_cronjob()
        new_actual_cjs, t = self.wait_for_report(report_type=self.backend.get_vuln_scan_cronjob_list,
                                                 expected_cjs=new_expected_cjs,
                                                 cluster_name=self.kubernetes_obj.get_cluster_name())

        new_cj = self.get_new_cronjob(old_cronjob_list=old_actual_cjs, new_cronjob_list=new_actual_cjs)
        assert new_cj, f"Failed to find the new cronjob, old_cronjob_list: {old_actual_cjs}. " \
                       f"new_cronjob_list: {new_actual_cjs}"

        return new_cj

    @staticmethod
    def get_new_cronjob(old_cronjob_list: list, new_cronjob_list: list):
        old_cj_names = [cj['name'] for cj in old_cronjob_list]
        for cj in new_cronjob_list:
            if cj['name'] not in old_cj_names:
                return cj
        return {}

    @staticmethod
    def test_workload_properties(summary: dict, workload_obj: dict):
        """
        check that the workload properties are as expected in backend summary
        """
        assert workload_obj["kind"].lower() == summary["designators"]['attributes'][
            "kind"].lower(), f"Expect to receive kind {workload_obj['kind'].lower()} but received {summary['designators']['attributes']['kind'].lower()}"

        assert workload_obj["containerName"] == summary['designators']['attributes'][
            'containerName'], f"Expect to receive apiVersion {workload_obj['containerName']} but received {summary['designators']['attributes']['containerName']}"

        assert workload_obj["containerName"] == summary[
            "containerName"], f"Expect to receive containerName {workload_obj['containerName']} but received {summary['containerName']}"

        assert workload_obj["imageHash"] in summary[
            "imageTag"], f"Expect to receive imageHash {workload_obj['imageHash']} but received {summary['imageTag']}"

        assert workload_obj["imageHash"] in summary[
            "imageHash"], f"Expect to receive imageHash {workload_obj['imageHash']} but received {summary['imageHash']}"

    def test_be_summary(self, be_summary: dict, is_relevant_summary: bool, since_time):

        workload_identifiers = []

        customer_guid = self.backend.get_customer_guid()
        cluster = self.get_cluster_name()
        workload_objs = self.get_workload_data_from_deployments()

        for summary in be_summary:
            # check designators
            assert summary['designators']['attributes'][statics.CUSTOMER_GUID_ATTRIBUTE_FIELD] == customer_guid, \
                f"Expect to receive customer guid {customer_guid} but received {summary['designators']['attributes']['customerGUID']}"
            assert summary['designators']['attributes'][statics.CLUSTER_ATTRIBUTE_FIELD] == cluster, \
                f"Expect to receive cluster name {cluster} but received {summary['designators']['attributes']['clusterName']}"

            assert summary[statics.CUSTOMER_GUID_ATTRIBUTE_FIELD] == customer_guid, \
                f"Expect to receive customer guid {customer_guid} but   received {summary[statics.CUSTOMER_GUID_ATTRIBUTE_FIELD]}"
            assert summary[statics.CLUSTER_ATTRIBUTE_FIELD] == cluster, \
                f"Expect to receive cluster name {cluster} but received {summary[statics.CLUSTER_ATTRIBUTE_FIELD]}"

            assert summary[
                       "status"] == "Success", f"Expect to receive status completed, but received {summary['status']}"

            for workload_obj in workload_objs:
                if workload_obj["name"] == summary["designators"]['attributes']["name"]:
                    self.test_workload_properties(summary=summary, workload_obj=workload_obj)
                    break

            # check that each workload is present only once
            workload_identifier = f"{summary['wlid']}/{summary['designators']['attributes']['containerName']}/{summary['registry']}/{summary['imageTag']}"
            assert workload_identifier not in workload_identifiers, f"Expect to receive unique workload identifier, but received {workload_identifier} twice"
            workload_identifiers.append(workload_identifier)

            if is_relevant_summary:
                assert summary[
                           statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_TRUE, f"Expect to receive relevantLabel yes, but received {summary[statics.SCAN_RESULT_IS_RELEVANT_FIELD]}"
            else:
                if self.is_relevancy_enabled():
                    assert summary[
                               statics.SCAN_HAS_RELEVANCY_DATA_FIELD] == True, f"Expect to receive hasRelevancyData true, but received {summary[statics.SCAN_HAS_RELEVANCY_DATA_FIELD]}"
                    assert summary[
                               statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_FALSE, f"Expect to receive relevantLabel False, but received {summary[statics.SCAN_RESULT_IS_RELEVANT_FIELD]}"
                else:
                    assert summary[
                               statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_UNKNOWN, f"Expect to receive relevantLabel None, but received {summary[statics.SCAN_RESULT_IS_RELEVANT_FIELD]}"

            # self.test_inner_filters(customer_guid=customer_guid, since_time=since_time)

    def test_inner_filters(self, since_time, customer_guid: str = None):
        fields_to_check = ['namespace', 'wlid', 'containerName', 'registry', 'imageTag', 'relevantLabel']
        for field in fields_to_check:
            resp = self.backend.get_unique_values_for_field_scan_summary(since_time=since_time, field=field,
                                                                         customer_guid=customer_guid)
            resp = resp.json()
            resp_for_field = resp['fields'][field]
            for value in resp_for_field:
                if value == '':
                    continue
                # first value is always empty (for all values)
                resps = self.backend.get_summary_with_inner_filters(since_time=since_time, filter={field: value},
                                                                    customer_guid=customer_guid)
                objs_with_filter_count = 0
                for obj in resp['fieldsCount'][field]:
                    if obj['key'] == value:
                        objs_with_filter_count = obj['count']
                        break
                objs_with_filter = resps.json()['response']
                assert len(
                    objs_with_filter) == objs_with_filter_count, f"Expect to receive {objs_with_filter_count} objects for {field} filter, but received {len(objs_with_filter)}"
                for obj in objs_with_filter:
                    assert obj[
                               field] == value, f"Expect to receive {value} for {field} filter, but received {obj[field]}"

    def test_cluster_deleted(self, since_time: str):
        cluster_result, _ = self.wait_for_report(report_type=self.backend.get_scan_results_sum_summary, namespace='',
                                                 expected_results=0, since_time=since_time, expected_status_code=404,
                                                 cluster_name=self.kubernetes_obj.get_cluster_name(), timeout=1250)
        assert cluster_result, 'Failed to verify deleting cluster {x} from backend'. \
            format(x=self.kubernetes_obj.get_cluster_name())

    def get_files_from_SBOM(self, SBOM):
        files = set()
        if SBOM['spec']['syft']['artifacts'] is not None:
            for fileData in SBOM['spec']['syft']['artifacts']:
                files.add(fileData['name'])
        return files

    @staticmethod
    def get_annotations_from_crd(obj):
        annotations = {}
        for key, annotation in obj['metadata']['annotations'].items():
            annotations[key] = annotation
        return annotations

    def validate_expected_SBOM(self, SBOMs, expected_SBOM_paths):
        verified_SBOMs = 0
        for expected_SBOM in expected_SBOM_paths:
            for SBOM in SBOMs:
                if TestUtil.get_arg_from_dict(self.test_driver.kwargs, statics.CREATE_TEST_FIRST_TIME_RESULTS, False):
                    self.store_unfilter_data_for_first_time_results(result=SBOM, store_path=expected_SBOM[1] )
                    verified_SBOMs += 1
                    break
                with open(expected_SBOM[1], 'r') as content_file:
                    content = content_file.read()
                expected_SBOM_data = json.loads(content)

                if expected_SBOM_data['metadata']['name'] in SBOM[1]['metadata']['name']:
                    SBOM_annotations = self.get_annotations_from_crd(SBOM[1])
                    expected_SBOM_annotations = self.get_annotations_from_crd(expected_SBOM_data)
                    for key, annotation in expected_SBOM_annotations.items():
                        if key in [statics.RELEVANCY_RESOURCE_SIZE_LABEL, statics.RELEVANCY_SYNC_CHECKSUM_LABEL]:
                            continue
                        assert SBOM_annotations[
                                   key] == annotation, f"annotation {key}:{annotation} != {SBOM_annotations[key]} in the SBOM in the storage is not as expected"

                    expected_SBOM_file_list = self.get_files_from_SBOM(expected_SBOM_data)
                    SBOM_file_list = self.get_files_from_SBOM(SBOM[1])
                    diff = expected_SBOM_file_list.symmetric_difference(SBOM_file_list)
                    assert len(diff) == 0, f"the files in the SBOM in the storage is not as expected, difference: {diff}"
                    verified_SBOMs += 1
                    break
        assert verified_SBOMs == len(expected_SBOM_paths), "not all SBOMs were verified"

    def get_CVEs_from_CVE_manifest(self, CVEManifest):
        cves = set()
        if 'spec' in CVEManifest:
            CVEManifest = CVEManifest['spec']
        if CVEManifest['payload']['matches'] is not None:
            for match in CVEManifest['payload']['matches']:
                vuln = match['vulnerability']
                cves.add(vuln['id'])
        return cves

    def store_filter_data_for_first_time_results(self, result, store_path, namespace):
        with open(store_path, 'r') as content_file:
            content = content_file.read()
        expected_data = json.loads(content)
        result_data = result[1]
        if expected_data['metadata']['labels'][statics.RELEVANCY_NAME_LABEL] == result_data['metadata']['labels'][
            statics.RELEVANCY_NAME_LABEL] \
                and result_data['metadata']['labels'][statics.RELEVANCY_NAMESPACE_LABEL] == namespace:
            del result_data['metadata']['annotations'][statics.RELEVANCY_INSTANCE_ID_LABEL]
            del result_data['metadata']['annotations'][statics.RELEVANCY_WLID_ANNOTATION]
            del result_data['metadata']['labels'][statics.RELEVANCY_NAMESPACE_LABEL]
            del result_data['metadata']['labels'][statics.RELEVANCY_TEMPLATE_HASH_LABEL]
            del result_data['metadata']['labels'][statics.RELEVANCY_RESOURCE_VERSION_LABEL]
            with open(store_path, 'w') as f:
                json.dump(result_data, f)

    def store_unfilter_data_for_first_time_results(self, result, store_path ):
        with open(store_path, 'r') as content_file:
            content = content_file.read()
        expected_data = json.loads(content)
        result_data = result[1]
        if expected_data['metadata']['name'] == result_data['metadata']['name']:
            with open(store_path, 'w') as f:
                json.dump(result_data, f)

    @staticmethod
    def is_mathing_filtered_crd(a, b):

        a_labels = a['metadata']['labels']
        b_labels = b['metadata']['labels']

        a_annotations = BaseVulnerabilityScanning.get_annotations_from_crd(a)
        b_annotations = BaseVulnerabilityScanning.get_annotations_from_crd(b)

        if a_labels[statics.RELEVANCY_NAME_LABEL] != b_labels[statics.RELEVANCY_NAME_LABEL]:
            return False

        if a_annotations[statics.RELEVANCY_IMAGE_ANNOTATIONS] != b_annotations[statics.RELEVANCY_IMAGE_ANNOTATIONS]:
            return False
        if a_annotations[statics.RELEVANCY_CONTAINER_LABEL] != b_annotations[statics.RELEVANCY_CONTAINER_LABEL]:
            return False
        return True

    def validate_expected_filtered_CVEs(self, CVEs, expected_CVEs_path, namespace):
        verified_CVEs = 0
        for expected_CVE in expected_CVEs_path:
            for CVE in CVEs:
                if TestUtil.get_arg_from_dict(self.test_driver.kwargs, statics.CREATE_TEST_FIRST_TIME_RESULTS, False):
                    self.store_filter_data_for_first_time_results(result=CVE, store_path=expected_CVE[1],
                                                                  namespace=namespace)
                    verified_CVEs = len(CVEs)
                    continue
                with open(expected_CVE[1], 'r') as content_file:
                    content = content_file.read()
                expected_CVE_data = json.loads(content)

                if CVE[1]['metadata']['labels'][statics.RELEVANCY_NAMESPACE_LABEL] != namespace:
                    continue
                if not self.is_mathing_filtered_crd(a=expected_CVE_data, b=CVE[1]):
                    continue

                expected_CVE_file_list = self.get_CVEs_from_CVE_manifest(expected_CVE_data)
                CVE_file_list = self.get_CVEs_from_CVE_manifest(CVE[1]['spec'])
                diff = expected_CVE_file_list.symmetric_difference(CVE_file_list)
                assert len(diff) == 0, f"the files in the CVEs in the storage is not as expected, difference: {diff}"
                verified_CVEs += 1
                break
        assert verified_CVEs == len(expected_CVEs_path), "not all CVEs were verified"

    def validate_expected_CVEs(self, CVEs, expected_CVEs_path):
        verified_CVEs = 0
        for expected_CVE in expected_CVEs_path:
            for CVE in CVEs:
                if TestUtil.get_arg_from_dict(self.test_driver.kwargs, statics.CREATE_TEST_FIRST_TIME_RESULTS, False):
                    self.store_unfilter_data_for_first_time_results(result=CVE, store_path=expected_CVE[1])
                    verified_CVEs = len(CVEs)
                    continue
                with open(expected_CVE[1], 'r') as content_file:
                    content = content_file.read()
                expected_CVE_data = json.loads(content)
                Logger.logger.info("CVE[0]: {} =?= expected_CVE_data['metadata']['name']: {}".format(CVE[0],
                                                                                                     expected_CVE_data[
                                                                                                         'metadata'][
                                                                                                         'name']))
                if CVE[0] == expected_CVE_data['metadata']['name']:
                    expected_CVE_file_list = self.get_CVEs_from_CVE_manifest(expected_CVE_data)
                    CVE_file_list = self.get_CVEs_from_CVE_manifest(CVE[1]['spec'])
                    diff = expected_CVE_file_list.symmetric_difference(CVE_file_list)
                    assert len(diff) == 0, f"the files in the CVEs in the storage is not as expected, difference: {diff}"
                    verified_CVEs += 1
                    break
        assert verified_CVEs == len(expected_CVEs_path), "not all CVEs were verified"

    @staticmethod
    def get_kind_from_instance_id(instance_id: str):
        result = re.search('kind-(.*)/name', instance_id)
        return result.group(1)

    @staticmethod
    def get_name_from_instance_id(instance_id: str):
        result = re.search('name-(.*)/containerName', instance_id)
        return result.group(1)

    @staticmethod
    def get_container_from_instance_id(instance_id: str):
        result = re.search('/containerName-(.*)', instance_id)
        return result.group(1)

    @staticmethod
    def sanitize_instance_id(instance_id, slug, container_name):
        instance_id_slug_hash_length = 4
        hashed_id = hashlib.sha256(str(instance_id).encode()).hexdigest()
        leading_digest = hashed_id[:instance_id_slug_hash_length]
        trailing_digest = hashed_id[len(hashed_id) - instance_id_slug_hash_length:]

        if len(slug) > 243:
            slug = slug[:243]
            return "%s-%s-%s" % (slug, leading_digest, trailing_digest)

        if container_name != "":
            return "%s-%s-%s" % (slug, leading_digest, trailing_digest)

        return slug

    def get_filtered_data_key(self, instance_id, namespace):
        container_name = BaseVulnerabilityScanning.get_container_from_instance_id(instance_id)
        slug = "%s-%s" % (BaseVulnerabilityScanning.get_kind_from_instance_id(instance_id),
                          BaseVulnerabilityScanning.get_name_from_instance_id(instance_id))
        if container_name != "":
            slug += "-" + container_name
        return self.sanitize_instance_id(instance_id, slug, container_name).lower()

    def create_instance_ID(self, workload_objs, **kwargs):
        if isinstance(workload_objs, list):
            instance_IDS: list = [self.get_wlid(workload=i, **kwargs) for i in workload_objs]
            return instance_IDS[0] if len(instance_IDS) == 1 else instance_IDS

    def get_workload_image_hash(self, container, **kwargs):
        image_hash_parts = container['image'].split("@sha256:")
        if len(image_hash_parts) != 2:
            raise Exception("image in the workload must be supplied with hash")
        return image_hash_parts[1]

    def get_workload_images_hash(self, workload_obj, **kwargs):
        containers = workload_obj['spec']['template']['spec']['containers']
        images_container_hash: list = [self.get_workload_image_hash(container=i, **kwargs) for i in containers]
        return images_container_hash

    def get_workloads_images_hash(self, workload_objs, **kwargs):
        if isinstance(workload_objs, list):
            images_hash = []
            for i in workload_objs:
                images_hash.extend(self.get_workload_images_hash(workload_obj=i, **kwargs))
            return images_hash[0] if len(images_hash) == 1 else images_hash

    @staticmethod
    def get_container_scan_id(be_summary: dict):
        return list(map(lambda x: (x[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                                   x[statics.SCAN_RESULT_CONTAINER_SCAN_ID_FIELD],
                                   x[statics.SCAN_RESULT_TOTAL_FIELD]), be_summary))

    @staticmethod
    def test_no_errors_in_scan_result(be_summary: dict):
        for scan in be_summary:
            assert scan[statics.SCAN_RESULT_STATUS_FIELD] != 'Error', \
                'container {container_name} received from backend with {num} error: {error_lst}'.format(
                    container_name=scan[statics.SCAN_RESULT_CONTAINER_NAME_FIELD],
                    num=len(scan[statics.SCAN_RESULT_ERRORS_FIELD]),
                    error_lst=scan[statics.SCAN_RESULT_ERRORS_FIELD]
                )

    def parse_filtered_CVEs_from_storage(self, storage_CVEs, container_name):
        cve_list = []
        for storage_cve in storage_CVEs:
            if container_name in storage_cve[0] and storage_cve[1]["spec"]["payload"]["matches"] is not None:
                for cve in storage_cve[1]["spec"]["payload"]["matches"]:
                    cve_list.append(cve["vulnerability"]["id"])
                break
        return cve_list

    def parse_CVEs_from_storage(self, storage_CVEs, image_hash):
        cve_list = []
        for storage_cve in storage_CVEs:
            key = storage_cve[0].split("-")[-2]
            if key in image_hash and storage_cve[1]["spec"]["payload"]["matches"] is not None:
                for cve in storage_cve[1]["spec"]["payload"]["matches"]:
                    cve_list.append(cve["vulnerability"]["id"])
                break
        return cve_list

    def is_relevancy_enabled(self):
        if os.environ.get("DISABLE_RELEVANCY") == "true":
            return False
        if "helm_kwargs" in self.test_obj.kwargs and statics.HELM_RELEVANCY_FEATURE in self.test_obj.kwargs[
            "helm_kwargs"]:
            return self.test_obj["helm_kwargs"][
                       statics.HELM_RELEVANCY_FEATURE] == statics.HELM_RELEVANCY_FEATURE_ENABLED
        return False

    @staticmethod
    def sanitize_image_tag(image_tag):
        sanitized_image_tag = image_tag
        replace_and_subs = [("://", "-"), (":", "-"), ("/", "-"), ("_", "-"), ("@", "-")]
        for rep in replace_and_subs:
            sanitized_image_tag = re.sub(rep[0], rep[1], sanitized_image_tag)
        return sanitized_image_tag

    def get_workloads_images_tags(self, workload_objs, namespace):
        images_container_tags: list = [
            self.get_pod_data(get_data_of_pod_call_back=BaseK8S.get_image_tags, namespace=namespace,
                              subname=i["metadata"]["name"]) for i in workload_objs]
        return images_container_tags

    def get_workloads_images_ids(self, workload_objs, namespace):
        images_container_ids: list = [
            self.get_pod_data(get_data_of_pod_call_back=BaseK8S.get_image_ids, namespace=namespace,
                              subname=i["metadata"]["name"]) for i in workload_objs]
        images_container_ids.extend([
            self.get_pod_data(get_data_of_pod_call_back=BaseK8S.get_image_ids, namespace=namespace,
                              subname=i["metadata"]["name"]) for i in workload_objs])
        return images_container_ids

    @staticmethod
    def parse_container_key(image_tag: str, image_id: str):
        image_id_slug_hash_length = 6
        image_id_stub = image_id[(len(image_id) - image_id_slug_hash_length):]
        sanitized_image_tag = BaseVulnerabilityScanning.sanitize_image_tag(image_tag)
        slug = "%s-%s" % (sanitized_image_tag, image_id_stub)
        slug = slug.lower()
        assert re.match("^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$",
                        slug), 'parse_container_key - not valid SBOM key/slug %s'.format(slug)
        return slug

    def get_filtered_data_keys(self, pods, namespace, **kwargs):
        instance_ids = self.get_instance_IDs(pods=pods, namespace=namespace, kwargs=kwargs)
        filtered_data_keys: list = [self.get_filtered_data_key(instance_id=j, namespace=namespace) for i in instance_ids
                                    for j in i]
        return filtered_data_keys

    def expose_operator(self, cluster):
        running_pods = self.get_ready_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                           name=statics.CA_OPERATOR_DEPLOYMENT_FROM_HELM_NAME)
        try:
            self.port_forward_proc = self.kubernetes_obj.portforward(cluster, statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                                     running_pods[0].metadata.name,
                                                                     {"source": 4002, "exposed": 4002})
            if self.port_forward_proc is None or self.port_forward_proc.stderr is not None:
                raise Exception('port forwarding to operator failed')
            time.sleep(5)
            Logger.logger.info('expose_websocket done')
        except Exception as e:
            print(e)

    def send_vuln_scan_command(self, cluster: str, namespace: str):
        data = {
            "commands": [
                {
                    "CommandName": "scan",
                    "WildWlid": "wlid://cluster-" + cluster + "/namespace-" + namespace
                }
            ]
        }
        resp = requests.post('http://0.0.0.0:4002/v1/triggerAction', json=data)
        print(resp)
        if resp.status_code < 200 or resp.status_code >= 300:
            raise Exception(f'bad response: {resp.text}')

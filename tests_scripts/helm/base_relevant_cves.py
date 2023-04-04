from ensurepip import version
import time
import requests
from systest_utils import statics, Logger, TestUtil
from tests_scripts.helm.base_helm import BaseHelm
import random
import yaml
import base64
from pkg_resources import parse_version
import json
from deepdiff import DeepDiff
import hashlib

_UNSET_DATE = "0001-01-01T00:00:00Z"


class BaseRelevantCves(BaseHelm):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(BaseRelevantCves, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                        kubernetes_obj=kubernetes_obj)
        self.ignore_agent = True
        self.ignore_ca_logs = True

    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""

    def test_cluster_deleted(self, since_time: str):
        cluster_result, _ = self.wait_for_report(report_type=self.backend.get_scan_results_sum_summary, namespace='',
                                                 expected_results=0, since_time=since_time, expected_status_code=404,
                                                 cluster_name=self.kubernetes_obj.get_cluster_name(), timeout=600)
        assert cluster_result, 'Failed to verify deleting cluster {x} from backend'. \
            format(x=self.kubernetes_obj.get_cluster_name())
    
    def get_files_from_SBOM(self, SBOM):
        files = []
        for fileData in SBOM['files']:
            files.append(fileData['fileName'])
        return files
    
    def validate_expected_SBOM(self, SBOMs, expected_SBOM_paths):
        for expected_SBOM in expected_SBOM_paths:
            for SBOM in SBOMs:
                with open(expected_SBOM[1], 'r') as content_file:
                    content = content_file.read()
                expected_SBOM_data = json.loads(content)
                if expected_SBOM[0] in SBOM[0][0]:
                    expected_SBOM_file_list = self.get_files_from_SBOM(expected_SBOM_data)
                    SBOM_file_list = self.get_files_from_SBOM(SBOM[1]['spec']['spdx'])
                    if expected_SBOM_file_list != SBOM_file_list:
                        assert Exception("the files in the SBOM in the storage is not has expected")
                    break

    def get_CVEs_from_CVE_manifest(self, CVEManifest):
        cves = []
        for vuln in CVEManifest['payload']['matches']['vulnerability']:
            cves.append(vuln['id'])
        return cves

    def validate_expected_CVEs(self, CVEs, expected_CVEs_path):
        for expected_CVE in expected_CVEs_path:
            for CVE in CVEs:
                with open(expected_CVE[1], 'r') as content_file:
                    content = content_file.read()
                expected_CVE_data = json.loads(content)
                if CVE[0] in expected_CVE_data[0]:
                    expected_SBOM_file_list = self.get_CVEs_from_CVE_manifest(expected_CVE_data)
                    SBOM_file_list = self.get_CVEs_from_CVE_manifest(CVE[1]['spec'])
                    if expected_SBOM_file_list != SBOM_file_list:
                        assert Exception("the files in the CVEs in the storage is not has expected")
                    break

    def create_instance_ID(self, workload_objs, **kwargs):
        if isinstance(workload_objs, list):
            instance_IDS: list = [self.get_wlid(workload=i, **kwargs) for i in workload_objs]
            return instance_IDS[0] if len(instance_IDS) == 1 else instance_IDS
    
    def get_workload_image_hash(self, container, **kwargs):
        image_hash_parts=container['image'].split("@sha256:")
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
            container_cve, time = self.wait_for_report(timeout=800, report_type=self.backend.get_scan_results_details,
                                                       containers_scan_id=container[_CONTAINER_SCAN_ID],
                                                       since_time=since_time,
                                                       expected_results=expected_results[container[_CONTAINER_NAME]],
                                                       total_cve=container[_CONTAINER_TOTAL_CVE])
            Logger.logger.info(
                "before processing: container {} has CVEs {}".format(container[_CONTAINER_NAME], container_cve))
            name = statics.SCAN_RESULT_NAME_FIELD
            severity = statics.SCAN_RESULT_SEVERITY_FIELD
            is_rce = statics.SCAN_RESULT_IS_RCE_FIELD
            categories = statics.SCAN_RESULT_CATEGORIES_FIELD
            is_relevant = statics.SCAN_RESULT_IS_RELEVANT_FIELD
            container_cve_dict = {i[name]: {severity: i[severity], is_rce: i[categories][is_rce], is_relevant: i[is_relevant]} for i in
                                  container_cve}
            result[container[_CONTAINER_NAME]] = container_cve_dict
            Logger.logger.info(
                "after processing: container {} has CVEs {}".format(container[_CONTAINER_NAME], container_cve_dict))

        return result

    def parse_filtered_CVEs_from_storage(self, storage_CVEs, container_name):
        cve_list = []
        for cve in storage_CVEs["spec"]["payload"]["matches"]:
            cve_list.append(cve["vulnerability"]["id"])
        return cve_list

    def test_expected_scan_result(self, backend_CVEs, storage_CVEs):
        failed_all_CVEs_paths = []
        failed_filtered_CVEs_paths = []
        for container_name, cve_list in backend_CVEs.items():
            assert container_name in backend_CVEs.keys(), \
                f"Expect to receive {container_name} in results_details from backend"
            storage_filtered_CVEs = self.parse_filtered_CVEs_from_storage(storage_CVEs[statics.FILTERED_CVES_KEY], container_name)
            storage_all_CVEs = self.parse_filtered_CVEs_from_storage(storage_CVEs[statics.ALL_CVES_KEY], container_name)
            for cve in cve_list:
                if cve not in storage_all_CVEs:
                    failed_all_CVEs_paths.append(f"{container_name} -> {cve}")
                if cve not in storage_filtered_CVEs:
                    failed_filtered_CVEs_paths.append(f"{container_name} -> {cve}")
                else:
                    if cve[statics.SCAN_RESULT_IS_RELEVANT_FIELD] is not statics.SCAN_RESULT_IS_RELEVANT_FIELD_TRUE:
                        failed_filtered_CVEs_paths.append(f"{container_name} -> {cve}")

        assert not failed_all_CVEs_paths, 'Expect the data from backend would not fail less CVEs then the expected results.\n' \
        f'in the following entries is happened:\n{failed_all_CVEs_paths}'
        assert not failed_filtered_CVEs_paths, f'the following relevant CVEs data is not found as expected\n{failed_filtered_CVEs_paths}'

    @staticmethod
    def test_backend_cve_against_storage_result(self, since_time: str, containers_scan_id, be_summary, storage_CVEs, timeout: int = 600):

        start = time.time()
        err = ""
        success = False
        while time.time() - start < timeout:
            Logger.logger.info('wait for detailed CVE aggregation to end in backend')
            try:
                backend_CVEs = self.get_container_cve(since_time=since_time, container_scan_id=containers_scan_id)
                Logger.logger.info('Test results against expected results')
                self.test_expected_scan_result(backend_CVEs=backend_CVEs, storage_CVEs=storage_CVEs)
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

        Logger.logger.info('Test backend results_details against results_sum_summary')
        self.test_results_details_against_results_sum_summary(containers_cve=containers_cve, be_summary=be_summary)

    def expose_operator(self, cluster):
        running_pods = self.get_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                             name=statics.CA_OPERATOR_DEPLOYMENT_FROM_HELM_NAME)
        try:
            self.port_forward_proc = self.kubernetes_obj.portforward(cluster, statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                                     running_pods[0].metadata.name,
                                                                     {"source": 4002, "exposed": 4002})
            if self.port_forward_proc is None or self.port_forward_proc.stderr is not None:
                raise Exception('port forwarding to operator failed')
            Logger.logger.info('expose_websocket done')
        except Exception as e:
            print(e)

    def send_vuln_scan_command(self, cluster: str, namespace: str):
        data = {
            "commands": [
                {
                    "CommandName": "scan",    
                    "wlid": "wlid://cluster-" + cluster + "/namespace-" + namespace
                }
            ]
        }
        resp = requests.post('http://0.0.0.0:4002/v1/triggerAction', json=data)
        print(resp)
        if resp.status_code < 200 or resp.status_code >= 300:
            raise Exception(f'bad response: {resp.text}')

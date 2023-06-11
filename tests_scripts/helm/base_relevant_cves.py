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
import re
from tests_scripts.kubernetes.base_k8s import BaseK8S

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
        if SBOM['spec']['spdx']['files'] is not None:
            for fileData in SBOM['spec']['spdx']['files']:
                files.append(fileData['fileName'])
        return files
    
    def get_annotations_from_SBOM(self, SBOM):
        annotations = {}
        for key, annotation in SBOM['metadata']['annotations'].items():
            annotations[key] = annotation
        return annotations
    
    def validate_expected_SBOM(self, SBOMs, expected_SBOM_paths):
        verified_SBOMs = 0
        for expected_SBOM in expected_SBOM_paths:
            for SBOM in SBOMs:
                with open(expected_SBOM[1], 'r') as content_file:
                    content = content_file.read()
                expected_SBOM_data = json.loads(content)

                if expected_SBOM_data['metadata']['name'] in SBOM[1]['metadata']['name']:
                    SBOM_annotations = self.get_annotations_from_SBOM(SBOM[1])
                    expected_SBOM_annotations = self.get_annotations_from_SBOM(expected_SBOM_data)
                    for key, annotation in expected_SBOM_annotations.items():
                        assert SBOM_annotations[key] == annotation, f"annotation {key}:{annotation} != {SBOM_annotations[key]} in the SBOM in the storage is not as expected"
                    
                    expected_SBOM_file_list = self.get_files_from_SBOM(expected_SBOM_data)
                    SBOM_file_list = self.get_files_from_SBOM(SBOM[1])
                    assert expected_SBOM_file_list == SBOM_file_list, "the files in the SBOM in the storage is not as expected" 
                    verified_SBOMs += 1
                    break
        assert verified_SBOMs == len(expected_SBOM_paths), "not all SBOMs were verified"

    def get_CVEs_from_CVE_manifest(self, CVEManifest):
        cves = []
        if 'spec' in CVEManifest:
            CVEManifest = CVEManifest['spec']
        if CVEManifest['payload']['matches'] is not None:
            for match in CVEManifest['payload']['matches']:
                vuln = match['vulnerability']
                cves.append(vuln['id'])
        return cves
    
    def validate_expected_filtered_SBOMs(self, SBOMs, expected_SBOM_paths,namespace):
        verified_SBOMs = 0
        for expected_SBOM in expected_SBOM_paths:
            for SBOM in SBOMs:
                with open(expected_SBOM[1], 'r') as content_file:
                    content = content_file.read()
                expected_SBOM_data = json.loads(content)
                instanceID = SBOM[0]
                if self.get_workload_name_from_instance_ID(instanceID) == expected_SBOM_data['metadata']['labels'][statics.RELEVANCY_NAME_LABEL] and self.get_namespace_from_instance_ID(instanceID) == namespace:

                    SBOM_annotations = self.get_annotations_from_SBOM(SBOM[1])
                    expected_SBOM_annotations = self.get_annotations_from_SBOM(expected_SBOM_data)
                    for key, annotation in expected_SBOM_annotations.items():
                        assert SBOM_annotations[key] == annotation, f"annotation {key}:{annotation} in the SBOM in the storage is not as expected"
                    
                    expected_SBOM_file_list = self.get_files_from_SBOM(expected_SBOM_data)
                    SBOM_file_list = self.get_files_from_SBOM(SBOM[1])
                    assert expected_SBOM_file_list == SBOM_file_list, f"the files in the SBOM in the storage is not as expected, expected: {expected_SBOM_file_list}\n storage: {SBOM_file_list}" 
                    verified_SBOMs += 1
                    break
        assert verified_SBOMs == len(expected_SBOM_paths), "not all SBOMs were verified"

    
    def validate_expected_filtered_CVEs(self, CVEs, expected_CVEs_path,namespace):
        verified_CVEs = 0
        for expected_CVE in expected_CVEs_path:
            for CVE in CVEs:
                with open(expected_CVE[1], 'r') as content_file:
                    content = content_file.read()
                expected_CVE_data = json.loads(content)
                instanceID = CVE[0]
                if self.get_workload_name_from_instance_ID(instanceID) == expected_CVE_data['metadata']['labels'][statics.RELEVANCY_NAME_LABEL] and self.get_namespace_from_instance_ID(instanceID) == namespace:
                    expected_SBOM_file_list = self.get_CVEs_from_CVE_manifest(expected_CVE_data)
                    SBOM_file_list = self.get_CVEs_from_CVE_manifest(CVE[1]['spec'])
                    assert expected_SBOM_file_list == SBOM_file_list, "the files in the CVEs in the storage is not has expected"
                    verified_CVEs += 1
                    break
        assert verified_CVEs == len(expected_CVEs_path), "not all CVEs were verified"

    def validate_expected_CVEs(self, CVEs, expected_CVEs_path):
        verified_CVEs = 0
        for expected_CVE in expected_CVEs_path:
            for CVE in CVEs:
                with open(expected_CVE[1], 'r') as content_file:
                    content = content_file.read()
                expected_CVE_data = json.loads(content)
                if CVE[0] == expected_CVE_data['metadata']['name']:
                    expected_SBOM_file_list = self.get_CVEs_from_CVE_manifest(expected_CVE_data)
                    SBOM_file_list = self.get_CVEs_from_CVE_manifest(CVE[1]['spec'])
                    assert expected_SBOM_file_list == SBOM_file_list, "the files in the CVEs in the storage is not has expected"
                    verified_CVEs += 1
                    break
        assert verified_CVEs == len(expected_CVEs_path), "not all CVEs were verified"

    def create_instance_ID(self, workload_objs, **kwargs):
        if isinstance(workload_objs, list):
            instance_IDS: list = [self.get_wlid(workload=i, **kwargs) for i in workload_objs]
            return instance_IDS[0] if len(instance_IDS) == 1 else instance_IDS

    def get_workloads_images_ids(self, workload_objs, namespace):
        images_container_ids: list = [self.get_pod_data(get_data_of_pod_call_back=BaseK8S.get_image_ids, namespace=namespace, subname=i["metadata"]["name"]) for i in workload_objs]
        return images_container_ids

    def get_workloads_images_tags(self, workload_objs, namespace):
        images_container_tags: list = [self.get_pod_data(get_data_of_pod_call_back=BaseK8S.get_image_tags, namespace=namespace, subname=i["metadata"]["name"]) for i in workload_objs]
        return images_container_tags

    @staticmethod
    def sanitize_image_tag(image_tag):
        sanitized_image_tag = image_tag
        replace_and_subs = [("://", "-"), (":", "-"), ("/", "-"), ("_", "-"), ("@", "-")]
        for rep in replace_and_subs:
            sanitized_image_tag = re.sub(rep[0], rep[1], sanitized_image_tag)
        return sanitized_image_tag

    @staticmethod
    def parse_container_key(image_tag: str, image_id: str):
        image_id_slug_hash_length = 6
        image_id_stub = image_id[(len(image_id)-image_id_slug_hash_length):]
        sanitized_image_tag = BaseRelevantCves.sanitize_image_tag(image_tag)
        slug = "%s-%s" % (sanitized_image_tag, image_id_stub)
        slug = slug.lower()
        assert re.match("^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$", slug), 'parse_container_key - not valid SBOM key/slug %s'.format(slug)
        return slug

    def get_imagesIDs_keys(self, workload_objs, namespace):
        container_name_index = 0
        container_image_tag_index = 1
        container_image_id_index = 1
        image_workload_tags = self.get_workloads_images_tags(workload_objs=workload_objs, namespace=namespace)
        image_workload_ids = self.get_workloads_images_ids(workload_objs=workload_objs, namespace=namespace)
        SBOM_keys = []
        for image_tags in image_workload_tags:
            found = False
            for image_tag in image_tags:
                found = False
                for image_ids in image_workload_ids:
                    for image_id in image_ids:
                        if image_tag[container_name_index] == image_id[container_name_index]:
                            SBOM_keys.append(BaseRelevantCves.parse_container_key(image_tag[container_image_tag_index], image_id[container_image_id_index])) 
                            found = True
                            break
                    if found:
                        break
        return SBOM_keys

    @staticmethod
    def get_kind_from_instance_id(instance_id: str):
        result = re.search('kind-(.*)/name', instance_id)
        return result.group(1)

    @staticmethod
    def get_name_from_instance_id(instance_id: str):
        result = re.search('name-(.*)/containerName', instance_id)
        return result.group(1)
    
    @staticmethod
    def sanitize_instance_id(instance_id):
        if len(instance_id) > 243:
            return instance_id[:243]
        return instance_id
        
    def get_filtered_data_key(self, instance_id, namespace):
        instance_id_slug_hash_length = 4
        hashed_id = hashlib.sha256(str(instance_id).encode()).hexdigest()
        leading_digest = hashed_id[:instance_id_slug_hash_length]
        trailing_digest = hashed_id[len(hashed_id)-instance_id_slug_hash_length:]
        hashless_instance_id_slug = "%s-%s-%s" % (namespace, BaseRelevantCves.get_kind_from_instance_id(instance_id), BaseRelevantCves.get_name_from_instance_id(instance_id))
        hashless_instance_id_slug = self.sanitize_instance_id(hashless_instance_id_slug)
        hashless_instance_id_slug = "%s-%s-%s" % (hashless_instance_id_slug, leading_digest, trailing_digest)
        hashless_instance_id_slug = hashless_instance_id_slug.lower()
        return hashless_instance_id_slug


    def get_filtered_data_keys(self, pods, namespace, **kwargs):
        instance_ids = self.get_instance_IDs(pods=pods, namespace=namespace, kwargs=kwargs)
        filtered_data_keys: list = [self.get_filtered_data_key(instance_id=j, namespace=namespace) for i in instance_ids for j in i]
        return filtered_data_keys

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

    @staticmethod
    def test_results_details_against_results_sum_summary(containers_cve: dict, be_summary: list):

        containers_severity = {}
        for name, cve_dict in containers_cve.items():
            containers_severity[name] = {statics.SCAN_RESULT_RCETOTAL_FIELD: 0, statics.SCAN_RESULT_TOTAL_FIELD: 0}
            for cve, details in cve_dict.items():
                containers_severity[name][statics.SCAN_RESULT_RCETOTAL_FIELD] += details[statics.SCAN_RESULT_RCETOTAL_FIELD]
                containers_severity[name][statics.SCAN_RESULT_TOTAL_FIELD] += details[statics.SCAN_RESULT_TOTAL_FIELD]
                if details[statics.SCAN_RESULT_SEVERITY_FIELD] not in containers_severity[name]:
                    containers_severity[name][details[statics.SCAN_RESULT_SEVERITY_FIELD]] = 0
                containers_severity[name][details[statics.SCAN_RESULT_SEVERITY_FIELD]] += details[statics.SCAN_RESULT_TOTAL_FIELD]

        for container in be_summary:
            message = 'It is expected that the data from results_sum_summary and the data from results_details will ' \
                      'be the same, in this case they are different. In container {x}, from results_sum_summary ' \
                      '{x1} = {x2} and from results_details {x1} = {y2}'
            container_severity_key = container[statics.SCAN_RESULT_CONTAINER_NAME_FIELD]
            if container_severity_key == '':
                container_severity_key = container['imageTag']

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
            imageHash = statics.SCAN_RESULT_IMAGEHASH_FIELD
            severity = statics.SCAN_RESULT_SEVERITY_FIELD
            is_rce = statics.SCAN_RESULT_IS_RCE_FIELD
            categories = statics.SCAN_RESULT_CATEGORIES_FIELD
            is_relevant = statics.SCAN_RESULT_IS_RELEVANT_FIELD
            total_count = statics.SCAN_RESULT_TOTAL_FIELD
            rce_count =  statics.SCAN_RESULT_RCETOTAL_FIELD
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
                total_count: 1, rce_count: 1 if is_rce_cve else 0, is_relevant: item[is_relevant], imageHash: item[imageHash]}
            
            result[container[_CONTAINER_NAME]] = container_cve_dict
            Logger.logger.info(
                "after processing: container {} has CVEs {}".format(container[_CONTAINER_NAME], container_cve_dict))

        return result
    
    def parse_filtered_CVEs_from_storage(self, storage_CVEs, container_name):
        cve_list = []
        for storage_cve in storage_CVEs:
            if container_name in  storage_cve[0] and  storage_cve[1]["spec"]["payload"]["matches"] is not None:
                for cve in storage_cve[1]["spec"]["payload"]["matches"]:
                    cve_list.append(cve["vulnerability"]["id"])
                break
        return cve_list

    def parse_CVEs_from_storage(self, storage_CVEs, image_hash):
        cve_list = []
        for storage_cve in storage_CVEs:
            if storage_cve[0] in image_hash and  storage_cve[1]["spec"]["payload"]["matches"] is not None:
                for cve in storage_cve[1]["spec"]["payload"]["matches"]:
                    cve_list.append(cve["vulnerability"]["id"])
                break
        return cve_list
    
    def is_relevancy_enabled(self):
        if self.test_obj.get_arg('relevancy_enabled') is not None:
            return self.test_obj.get_arg('relevancy_enabled')
        else:
            return True


    def test_expected_scan_result(self, backend_CVEs, storage_CVEs):
        # check that all backend CVEs are in storage
        # check that filtered CVEs have relevantLabel set to 'yes'
        # check that non-filtered CVEs have relevantLabel set to 'no'
        # check that we have the same number of CVEs in storage and backend
        failed_CVEs_path = []
        relevancy_enabled = self.is_relevancy_enabled()

        for container_name, cve_list in backend_CVEs.items():
            assert container_name in backend_CVEs.keys(), \
                f"Expect to receive {container_name} in results_details from backend"

            if len(cve_list) == 0: 
                continue

            image_hash = next(iter(cve_list.items()))[1]['imageHash']
            total_cves = 0
            storage_filtered_CVEs = self.parse_filtered_CVEs_from_storage(storage_CVEs[statics.FILTERED_CVES_KEY], container_name=container_name)
            storage_all_CVEs = self.parse_CVEs_from_storage(storage_CVEs[statics.ALL_CVES_KEY], image_hash=image_hash)

            for cve, cve_details in cve_list.items():
                total_cves += cve_details[statics.SCAN_RESULT_TOTAL_FIELD]
                if cve in storage_filtered_CVEs:
                    assert cve_details[statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_TRUE, \
                        f"Expect to receive {cve} as relevant CVE"
                elif cve in storage_all_CVEs:
                    if relevancy_enabled:
                        assert cve_details[statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_FALSE, \
                            f"Expect to receive {cve} as not relevant CVE"
                    else:
                        assert cve_details[statics.SCAN_RESULT_IS_RELEVANT_FIELD] == statics.SCAN_RESULT_IS_RELEVANT_FIELD_UNKNOWN, \
                            f"Expect to receive {cve} as relevant CVE"
                if cve not in storage_filtered_CVEs and cve not in storage_all_CVEs:
                    failed_CVEs_path.append(f"{container_name} -> {cve}")


            assert total_cves == len(storage_all_CVEs), \
                f"Expect to receive {len(storage_all_CVEs)} CVEs in total from backend, but received {total_cves} CVEs"


        assert not failed_CVEs_path, 'Expect the data from backend would be the same as storage CVE results.\n' \
        f'in the following entries is happened:\n{failed_CVEs_path}'

    def test_be_summary(self, be_summary):

        workload_identifiers = []
        customer_guid = be_summary[0]['designators']['attributes']['customerGUID']

        # check that same workload doesn't appear more than once
        for summary in be_summary:
            workload_identifier = f"{summary['wlid']}/{summary['designators']['attributes']['containerName']}/{summary['registry']}/{summary['imageTag']}"
          
            assert workload_identifier not in workload_identifiers , f"Expect to receive unique workload identifier, but received {workload_identifier} twice"

            workload_identifiers.append(workload_identifier)

        # check filters with wlid,  namespace, container, registry, tag, relevantLabel
        fields_to_check = [ 'namespace', 'wlid', 'containerName', 'registry', 'imageTag', 'relevantLabel']
        for field in fields_to_check:
            resp = self.backend.get_unique_values_for_field_scan_summary(field=field, customer_guid=customer_guid)
            resp = resp.json()
            resp_for_field = resp['fields'][field]
            if len(resp_for_field) > 1:
                # first value is always empty (for all values)
                value = resp_for_field[1]
                resps = self.backend.get_summary_with_inner_filters(filter={field:value}, customer_guid=customer_guid)
                objs_with_filter_count = 0
                for obj in resp['fieldsCount'][field]:
                    if obj['key'] == value:
                        objs_with_filter_count = obj['count']
                        break
                objs_with_filter = resps.json()['response']
                assert len(objs_with_filter) == objs_with_filter_count, f"Expect to receive {objs_with_filter_count} objects for {field} filter, but received {len(objs_with_filter)}"
                for obj in objs_with_filter:
                    assert obj[field] == value, f"Expect to receive {value} for {field} filter, but received {obj[field]}"

            

    def test_backend_cve_against_storage_result(self, since_time: str, containers_scan_id, be_summary, storage_CVEs, timeout: int = 900):

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

        # Logger.logger.info('Test backend summary')
        # self.test_be_summary(be_summary)

        # Logger.logger.info('Test backend results_details against results_sum_summary')
        # self.test_results_details_against_results_sum_summary(containers_cve=backend_CVEs, be_summary=be_summary)

    def expose_operator(self, cluster):
        running_pods = self.get_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
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

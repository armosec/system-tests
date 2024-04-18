import time, requests, os, re, random, yaml, base64, json, hashlib
from systest_utils import statics, Logger, TestUtil
from tests_scripts.helm.base_helm import BaseHelm
from pkg_resources import parse_version
from tests_scripts.kubernetes.base_k8s import BaseK8S
import copy


class BaseNetworkPolicy(BaseHelm):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(BaseNetworkPolicy, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                        kubernetes_obj=kubernetes_obj)

    def validate_basic_metadata(self, actual_obj, expected_obj, namespace):
        """
        Validate basic metadata of the object
        param actual_obj: actual object
        param expected_obj: expected object
        param namespace: namespace of the object
        """
        assert actual_obj['apiVersion'] == expected_obj['apiVersion'], f"in validate_basic_metadata: apiVersion is not equal, actual: {actual_obj['apiVersion']}, expected: {expected_obj['apiVersion']}, actual object: {actual_obj}, expected object: {expected_obj}"
        assert actual_obj['kind'] == expected_obj['kind'], f"in validate_basic_metadata: kind is not equal, actual: {actual_obj['kind']}, expected: {expected_obj['kind']}, actual object: {actual_obj}, expected object: {expected_obj}"
        assert actual_obj['metadata']['name'] == expected_obj['metadata']['name'], f"in validate_basic_metadata: name is not equal, actual: {actual_obj['metadata']['name']}, expected: {expected_obj['metadata']['name']}, actual object: {actual_obj}, expected object: {expected_obj}"
        assert actual_obj['metadata']['namespace'] == namespace, f"in validate_basic_metadata: namespace is not equal, actual: {actual_obj['metadata']['namespace']}, expected: {namespace}, actual object: {actual_obj}, expected object: {expected_obj}"


        if 'annotations' in expected_obj['metadata']:
            for key, annotation in expected_obj['metadata']['annotations'].items():
                assert actual_obj['metadata']['annotations'][key] == annotation, f"annotation {key} is not equal, actual: {actual_obj['metadata']['annotations'][key]}, expected: {annotation}, actual object: {actual_obj}, expected object: {expected_obj}"

        for key, label in expected_obj['metadata']['labels'].items():
            assert actual_obj['metadata']['labels'][key] == label, f"label {key} is not equal, actual: {actual_obj['metadata']['labels'][key]}, expected: {label}, actual object: {actual_obj}, expected object: {expected_obj}"
        
    def store_netwrok_for_first_time_results(self, result_data, store_path):
        for file_path in store_path:
            with open(file_path) as f:
                expected_data = json.load(f)
            if expected_data['metadata']['name'] == result_data['metadata']['name']:
                try:
                    # del result_data['metadata']['annotations']["kubescape.io/completion"]
                    # del result_data['metadata']['annotations']["kubescape.io/status"]
                    del result_data['metadata']['annotations'][statics.RELEVANCY_WLID_ANNOTATION]
                    del result_data['metadata']['labels'][statics.RELEVANCY_NAMESPACE_LABEL]
                    del result_data['metadata']['labels'][statics.RELEVANCY_RESOURCE_VERSION_LABEL]
                    del result_data['metadata']['labels'][statics.RELEVANCY_TEMPLATE_HASH_LABEL]
                except:
                    pass
                with open(file_path, 'w') as f:
                    json.dump(result_data, f)

    def validate_expected_network_neighbors_list(self, namespace, expected_network_neighbors_list):
        """
        Validate expected network neighbors list. It pulls the actual network neighbors and validates each one of them
        param namespace: namespace of the object
        param expected_network_neighbors_list: list of expected network neighbors
        """
        for expected_network_neighbors in  expected_network_neighbors_list:
            actual_network_neighbors = self.get_network_neighbors(name=expected_network_neighbors['metadata']['name'] ,namespace=namespace)
            if TestUtil.get_arg_from_dict(self.test_driver.kwargs, statics.CREATE_TEST_FIRST_TIME_RESULTS, False):
                self.store_netwrok_for_first_time_results(result_data=actual_network_neighbors, store_path=self.test_obj["expected_network_neighbors"])
                continue
            self.validate_expected_network_neighbors(actual_network_neighbors=actual_network_neighbors, expected_network_neighbors=expected_network_neighbors, namespace=namespace)
    
    
    def validate_expected_network_neighbors(self, actual_network_neighbors, expected_network_neighbors, namespace: str):
        """
        Validate expected network neighbors. It validates the basic metadata and then validates the network neighbors entries and the match labels
        param actual_network_neighbors: actual network neighbors
        param expected_network_neighbors: expected network neighbors
        param namespace: namespace of the object
        """

        self.validate_basic_metadata(actual_obj=actual_network_neighbors, expected_obj=expected_network_neighbors, namespace=namespace)
        
        for key, label in expected_network_neighbors['spec']['matchLabels'].items():
            assert actual_network_neighbors['spec']['matchLabels'][key] == label, f"label {key} is not equal, actual: {actual_network_neighbors['spec']['matchLabels'][key]}, expected: {label}"


        expected_egress_entries = expected_network_neighbors['spec']['egress']
        actual_egress_entries = actual_network_neighbors['spec']['egress']

        self.validate_network_neighbor_entry(expected_egress_entries, actual_egress_entries)

        expected_ingress_entries = expected_network_neighbors['spec']['ingress']
        actual_ingress_entries = actual_network_neighbors['spec']['ingress']

        self.validate_network_neighbor_entry(expected_entries=expected_ingress_entries, actual_entries=actual_ingress_entries)


    def validate_network_neighbor_entry(self, expected_entries, actual_entries):
        """
        Validate a single network neighbor entry. 
        param expected_entries: expected network neighbor entries
        param actual_entries: actual network neighbor entries        
        """

        # we might have multiple actual entries, but we should have at least the same amount of expected entries
        assert len(expected_entries) <= len(actual_entries), f"expected_entries length is not lower or equal to actual_entries length, actual: {len(actual_entries)}, expected: {len(expected_entries)}"

        # we can't use the identifier for the entry, since IP addresses may change. Instead, we check for all fields that are not IP addresses, and verify that they are equal. If they are all equal, we count this entry as verified.
        for expected_entry in expected_entries:
            # if expected entry contains dns, that means we explicitly expect a DNS entry,
            # we don't care about the IP address
            if expected_entry["dns"] != "": 
                actual_entry = next((actual_entry for actual_entry in actual_entries if expected_entry["dns"] == actual_entry["dns"]), None)
                assert actual_entry, f"expected a network neighbor entry with DNS: {expected_entry['dns']} not found in actual entries {actual_entries}"
                assert expected_entry["type"] == actual_entry["type"], f"expected type: {expected_entry['type']} not found in actual type {actual_entry['type']}"

                # check ports & protocols
                expected_ports = set((port['port'], port['protocol']) for port in expected_entry["ports"])
                actual_ports = set((port['port'], port['protocol']) for port in actual_entry["ports"])
                assert expected_ports == actual_ports, f"expected ports: {expected_ports} not found in actual ports {actual_ports}"
                
            # expected entry does not contain dns, but contains IP address, that means we expect an IP address entry explicitly
            elif expected_entry["ipAddress"] != "":
                actual_entry = next((actual_entry for actual_entry in actual_entries if expected_entry["ipAddress"] == actual_entry["ipAddress"]), None)
                assert actual_entry, f"expected a network neighbor entry with IP Address: {expected_entry['ipAddress']} not found in actual entries {actual_entries}"

                assert expected_entry["type"] == actual_entry["type"], f"expected type: {expected_entry['type']} not found in actual type {actual_entry['type']}"

                # check ports & protocols
                expected_ports = set((port['port'], port['protocol']) for port in expected_entry["ports"])
                actual_ports = set((port['port'], port['protocol']) for port in actual_entry["ports"])
                assert expected_ports == actual_ports, f"expected ports: {expected_ports} not found in actual ports {actual_ports}"

            # third case, expected entry does not contain dns nor IP address, that means we expect a network neighbor entry with matchLabels
            elif expected_entry["namespaceSelector"] is not None or expected_entry["podSelector"] is not None:
                expected_namespace_selector = expected_entry.get("namespaceSelector", {})
                expected_namespace_match_labels = expected_namespace_selector.get("matchLabels", {}) if expected_namespace_selector else {}

                expected_pod_selector = expected_entry.get("podSelector", {})
                expected_pod_selector_match_labels = expected_pod_selector.get("matchLabels", {}) if expected_pod_selector else {}

                # we try to find the actual entry that matches the expected entry match labels
                actual_entry = None
                for entry in actual_entries:
                    if entry is None:
                        continue
                    actual_namespace_selector = entry.get("namespaceSelector", {})
                    actual_pod_selector = entry.get("podSelector", {})
    
                    actual_namespace_match_labels = actual_namespace_selector.get("matchLabels", {}) if actual_namespace_selector else {}
                    actual_pod_selector_match_labels = actual_pod_selector.get("matchLabels", {}) if actual_pod_selector else {}

                    if expected_namespace_match_labels == actual_namespace_match_labels and expected_pod_selector_match_labels == actual_pod_selector_match_labels:
                        actual_entry = entry
                        break
                
                assert actual_entry, f"expected a network neighbor entry with namespaceSelector: {expected_namespace_match_labels} and podSelector: {expected_pod_selector_match_labels} not found in actual entries {actual_entries}"
                assert expected_entry["type"] == actual_entry["type"], f"expected type: {expected_entry['type']} not found in actual type {actual_entry['type']}"

                expected_ports = set((port['port'], port['protocol']) for port in expected_entry["ports"])
                actual_ports = set((port['port'], port['protocol']) for port in actual_entry["ports"])
                assert expected_ports == actual_ports, f"expected ports: {expected_ports} not found in actual ports {actual_ports}"
            else:
                raise ValueError("expected entry is not valid, it should contain either dns, ipAddress or namespaceSelector/podSelector")

    def validate_expected_network_neighbors_and_generated_network_policies_lists(self, namespace, expected_network_neighbors_list, expected_generated_network_policy_list):
        """
        Validate expected network neighbors and generated network policies lists. It validates the expected network neighbors list and the expected generated network policies list
        param namespace: namespace of the object
        param expected_network_neighbors_list: list of expected network neighbors
        param expected_generated_network_policy_list: list of expected generated network policies
        """
        Logger.logger.info("validating expected network neighbors")
        self.validate_expected_network_neighbors_list(namespace=namespace, expected_network_neighbors_list=expected_network_neighbors_list)
        Logger.logger.info("validated expected network neighbors")

        Logger.logger.info("validating expected generated network policies")
        self.validate_expected_generated_network_policy_list(namespace=namespace, expected_generated_network_policy_list=expected_generated_network_policy_list)
        Logger.logger.info("validated expected generated network policies")


    def validate_expected_backend_results(self, cluster, namespace, expected_workloads_list, expected_network_neighbors_list, expected_generated_network_policy_list):
        """
        Validate expected backend results. It validates the expected backend workloads list and the expected backend generated network policies list
        param cluster: cluster name
        param namespace: namespace of the object
        param expected_workloads_list: list of expected workloads
        param expected_network_neighbors_list: list of expected network neighbors
        """
        Logger.logger.info("validating expected backend workloads list")
        self.validate_expected_backend_workloads_list(cluster=cluster, namespace=namespace, expected_workloads_list=expected_workloads_list)
        Logger.logger.info("validated expected backend workloads list")

        Logger.logger.info("validating expected backend generated network policies")
        self.validate_expected_backend_generated_network_policy_list(cluster=cluster, namespace=namespace, expected_network_policy_list=expected_generated_network_policy_list, expected_network_neighbors_list=expected_network_neighbors_list)
        Logger.logger.info("validated expected backend generated network policies")


    def is_workload_deleted_from_backend(self, cluster, workload_name, namespace) -> bool:
        """
        Is workload deleted from backend. It pulls the actual network neighbors and validates that the workload is not in the list
        param cluster: cluster name
        param workload_name: workload name
        param namespace: namespace of the object
        """
        try:
            r, np, graph = self.backend.get_network_policies_generate(cluster_name=cluster, workload_name=workload_name, namespace=namespace)
        except Exception as e:
            return True
        return False
    


    def validate_workload_deleted_from_backend(self, cluster, workload_name, namespace):
        """
        Validate workload deleted from backend. It pulls the actual network neighbors and validates that the workload is not in the list
        param cluster: cluster name
        param workload_name: workload name
        param namespace: namespace of the object
        """

        deleted, t = self.wait_for_report(timeout=100, 
                                        sleep_interval=5,
                                        report_type=self.is_workload_deleted_from_backend, 
                                        cluster=cluster, 
                                        workload_name=workload_name, 
                                        namespace=namespace)


        assert deleted == True, f"workload {workload_name} is not deleted from backend"


    def validate_expected_backend_workloads_list(self, cluster, namespace, expected_workloads_list):
        """
        validate_expected_backend_workloads_list validates the expected backend workloads list. It pulls the actual workloads and validates each one of them
        param cluster: cluster name
        param namespace: namespace of the object
        param expected_workloads_list: list of expected workloads
        """
        res = self.backend.get_network_policies(cluster_name=cluster, namespace=namespace)

        workloads_list = res[1]
        assert len(workloads_list) == len(expected_workloads_list), f"workloads_list length is not equal to expected_workloads_list length, actual: len:{len(workloads_list)}, expected: len:{len(expected_workloads_list)}; actual results: {workloads_list}, expected results: {expected_workloads_list}"


    def validate_expected_backend_generated_network_policy_list(self, cluster, namespace, expected_network_policy_list, expected_network_neighbors_list):
        """
        validate_expected_backend_generated_network_policy_list validates the expected backend generated network policies list. It pulls the actual generated network policies and validates each one of them
        param cluster: cluster name
        param namespace: namespace of the object
        param expected_network_policy_list: list of expected backend generated network policies
        param expected_network_neighbors_list: list of expected network neighbors
        """

        for i in range(0, len(expected_network_policy_list)):
            workload_name = expected_network_policy_list[i]['metadata']['labels']['kubescape.io/workload-name']
            res = self.backend.get_network_policies_generate(cluster_name=cluster, workload_name=workload_name, namespace=namespace)
  
            
            backend_generated_network_policy = res[1]
            graph = res[2]
            
            self.validate_expected_backend_network_policy(expected_network_policy_list[i],backend_generated_network_policy, namespace)

            self.validate_expected_network_neighbors(namespace=namespace, actual_network_neighbors=graph, expected_network_neighbors=expected_network_neighbors_list[i])


    def convert_backend_network_policy_to_generated_network_policy(self, backend_network_policy) -> dict:
        """
        convert_backend_network_policy_to_generated_network_policy converts backend network policy to generated network policy.
        param backend_network_policy: backend network policy
        """

        new_backend_policy = copy.deepcopy(backend_network_policy)
        new_backend_policy["kind"] = "GeneratedNetworkPolicy"
        new_backend_policy["apiVersion"] = "spdx.softwarecomposition.kubescape.io/v1beta1"
        new_backend_policy["spec"]["apiVersion"] = "networking.k8s.io/v1"
        new_backend_policy["spec"]["kind"] = "NetworkPolicy"
        new_backend_policy["spec"]["metadata"] = new_backend_policy["metadata"]
        del(new_backend_policy["spec"]["apiVersion"])
        del(new_backend_policy["spec"]["kind"])

        return new_backend_policy



    def validate_expected_backend_network_policy(self, expected_network_policy, actual_network_policy, namespace: str):
        """
        Validate expected backend network policy. It validates the basic metadata and then validates the policy refs and the network policy
        param expected_network_policy: expected backend network policy
        param actual_network_policy: actual backend network policy
        """

        converted_actual_network_policy = self.convert_backend_network_policy_to_generated_network_policy(actual_network_policy)
        self.validate_basic_metadata( actual_obj=converted_actual_network_policy,expected_obj= expected_network_policy, namespace= namespace)

        if 'policyRef' in converted_actual_network_policy and 'policyRef' in expected_network_policy:
            actual_policies_refs = converted_actual_network_policy['policyRef']
            expected_policies_refs = expected_network_policy['policyRef']
            self.validate_policy_refs(actual_policy_refs=actual_policies_refs, expected_policy_refs=expected_policies_refs)

        actual_policy = converted_actual_network_policy['spec']
        expected_policy = expected_network_policy['spec']['spec']
        self.validate_network_policy_spec(actual_network_policy_spec=actual_policy, expected_network_policy_spec=expected_policy, namespace=namespace)


    def validate_expected_generated_network_policy_list(self, namespace, expected_generated_network_policy_list):
        """
        Validate expected generated network policies list. It pulls the actual generated network policies and validates each one of them
        param namespace: namespace of the object
        param expected_generated_network_policy_list: list of expected generated network policies
        """
        for expected_generated_network_policy in expected_generated_network_policy_list:
            actual_generated_network_policy = self.get_generated_network_policy(namespace=namespace, name=expected_generated_network_policy['metadata']['name'])
            if TestUtil.get_arg_from_dict(self.test_driver.kwargs, statics.CREATE_TEST_FIRST_TIME_RESULTS, False):
                self.store_netwrok_for_first_time_results(result_data=expected_generated_network_policy, store_path=self.test_obj["expected_generated_network_policies"])
                continue
            self.validate_expected_generated_network_policy(actual_network_policy=actual_generated_network_policy,expected_network_policy=expected_generated_network_policy, namespace=namespace)


    def validate_expected_generated_network_policy(self, expected_network_policy, actual_network_policy, namespace: str):
        """
        Validate expected generated network policy. It validates the basic metadata and then validates the policy refs and the network policy
        param expected_network_policy: expected generated network policy
        param actual_network_policy: actual generated network policy
        """

        self.validate_basic_metadata( actual_obj=actual_network_policy,expected_obj= expected_network_policy, namespace= namespace)

        if 'policyRef' in actual_network_policy and 'policyRef' in expected_network_policy:
            actual_policies_refs = actual_network_policy['policyRef']
            expected_policies_refs = expected_network_policy['policyRef']
            self.validate_policy_refs(actual_policy_refs=actual_policies_refs, expected_policy_refs=expected_policies_refs)

        actual_policy = actual_network_policy['spec']
        expected_policy = expected_network_policy['spec']
        self.validate_network_policy(actual_network_policy=actual_policy, expected_network_policy=expected_policy, namespace=namespace)

    
    def validate_network_policy(self, actual_network_policy, expected_network_policy, namespace: str):
        """
        Validate network policy. It validates the basic metadata and then validates the network policy entries
        param actual_network_policy: actual network policy
        param expected_network_policy: expected network policy
        param namespace: namespace of the object
        """

        self.validate_basic_metadata(actual_obj=actual_network_policy, expected_obj=expected_network_policy, namespace=namespace)

        self.validate_network_policy_spec(actual_network_policy_spec=actual_network_policy['spec'], expected_network_policy_spec=expected_network_policy['spec'], namespace=namespace)


    def validate_network_policy_spec(self, actual_network_policy_spec, expected_network_policy_spec, namespace: str):
        """
        Validate network policy. It validates the basic metadata and then validates the network policy entries
        param actual_network_policy: actual network policy
        param expected_network_policy: expected network policy
        param namespace: namespace of the object
        """


        if 'Ingress' in expected_network_policy_spec['policyTypes']:
            expected_network_policy_entries = expected_network_policy_spec['ingress']
            actual_network_policy_entries = actual_network_policy_spec['ingress']
            self.validate_network_policy_entry(expected_network_policy_entries=expected_network_policy_entries, actual_network_policy_entries=actual_network_policy_entries) 

        if 'Egress' in expected_network_policy_spec['policyTypes']:
            expected_network_policy_entries = expected_network_policy_spec['egress']
            actual_network_policy_entries = actual_network_policy_spec['egress']
            self.validate_network_policy_entry(expected_network_policy_entries=expected_network_policy_entries,actual_network_policy_entries=actual_network_policy_entries)

    
    def validate_network_policy_entry(self, expected_network_policy_entries, actual_network_policy_entries):
        """
        Validate network policy entry. It validates the ports and then validates the to and from entries
        param expected_network_policy_entries: expected network policy entries
        param actual_network_policy_entries: actual network policy entries
        """

        verified_entries = 0

        for expected_network_policy_entry in expected_network_policy_entries:
            for actual_network_policy_entry in actual_network_policy_entries:
                verified_ports = 0
                for expected_ports in expected_network_policy_entry['ports']:
                    for actual_ports in actual_network_policy_entry['ports']:
                        if expected_ports['port'] == actual_ports['port']:
                            if expected_ports['protocol'] == actual_ports['protocol']:
                                 verified_ports += 1 
                if verified_ports != len(expected_network_policy_entry['ports']):
                    continue


                if 'to' in expected_network_policy_entry:
                    if self.verify_network_policy_entries(expected_entries=expected_network_policy_entry['to'], actual_entries=actual_network_policy_entry['to']) is False:
                        break

                if 'from'  in expected_network_policy_entry:
                    if self.verify_network_policy_entries(expected_entries=expected_network_policy_entry['from'], actual_entries=actual_network_policy_entry['from']) is False:
                        break

                verified_entries += 1
                break

        assert verified_entries == len(expected_network_policy_entries), f"in validate_network_policy_entry: verified_entries is not equal, actual: {verified_entries}, expected: {len(expected_network_policy_entries)}"


    def verify_network_policy_entries(self, expected_entries, actual_entries):
        """
        Verify entries. It verifies the ipBlock and the match labels
        param expected_entries: expected entries
        param actual_entries: actual entries
        """

        verified_entries = 0
        for expected_to_from in expected_entries:
            for actual_to_from in actual_entries:
                if 'ipBlock' in expected_to_from:
                    if 'ipBlock' in actual_to_from:
                        verified_entries += 1
                        break
                        
                is_labels = True
                if "namespaceSelector" in expected_to_from:
                    is_labels = False
                    if "namespaceSelector" in actual_to_from:
                        for key, label  in expected_to_from["namespaceSelector"]["matchLabels"].items():
                            if actual_to_from["namespaceSelector"]["matchLabels"][key] == label:
                                is_labels = True
                                break
                if not is_labels:
                    continue        

                is_labels = True
                if "podSelector" in expected_to_from:
                    is_labels = False
                    if "podSelector"  in actual_to_from:
                        for key, label  in expected_to_from["podSelector"]["matchLabels"].items():
                            if actual_to_from["podSelector"]["matchLabels"][key] == label:
                                is_labels = True
                                break
                if not is_labels:
                    continue   
                verified_entries += 1
        return verified_entries == len(expected_entries)


    def validate_policy_refs(self, actual_policy_refs, expected_policy_refs):
        """
        Validate policy refs. It validates the name and the dns of each ref
        param actual_policy_refs: actual policy refs
        param expected_policy_refs: expected policy refs
        """

        verified_refs = 0

        for expected_policy_ref in expected_policy_refs:
            for actual_policy_ref in actual_policy_refs:
                if expected_policy_ref['dns'] == actual_policy_ref['dns']:
                    assert expected_policy_ref['name'] == actual_policy_ref['name'], f"in validate_policy_refs: name is not equal, actual: {actual_policy_ref['name']}, expected: {expected_policy_ref['name']}, actual object: {actual_policy_ref}, expected object: {expected_policy_ref}"
                    assert expected_policy_ref['server'] == actual_policy_ref['server'], f"in validate_policy_refs: server is not equal, actual: {actual_policy_ref['server']}, expected: {expected_policy_ref['server']}, actual object: {actual_policy_ref}, expected object: {expected_policy_ref}"
                    verified_refs += 1
                    break

        assert verified_refs == len(expected_policy_refs), f"in validate_policy_refs: verified_refs is not equal, actual: {verified_refs}, expected: {len(expected_policy_refs)}"
    

    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""

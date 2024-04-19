from datetime import datetime,timezone
import os
import time
from tests_scripts.helm.base_helm import BaseHelm
from tests_scripts.kubescape.base_kubescape import BaseKubescape
from systest_utils import Logger, TestUtil, statics
from infrastructure import backend_api
import json
from tests_scripts import base_test


SCENARIOS_TEST_PATH = "./configurations/scenarios-test-env"
SCENARIOS_EXPECTED_VALUES = "./configurations/scenarios_expected_values"

EXPECTED_TRENDS_DAYS_BACK = 31


# maps field name and the expected values file suffix
SECURITY_RISKS_EXPECTED_UNIQUE_VALUES_SUFFIX = {
    "namespace": "_security-risks-uv-namespace.json",
    "severity": "_security-risks-uv-severity.json",
    "category": "_security-risks-uv-category.json",
    "securityRiskName": "_security-risks-uv-securityriskname.json",
}

# maps security risk id and the expected values file prefix
SECURITY_RISKS_RESOURCES_PREFIX = {
    "R_0002": "_security-risks-resources_sidebar_R0002", # control security risk type
    "R_0035": "_security-risks-resources_sidebar_R0035", # attack path security risk type
}

class ScenarioManager(base_test.BaseTest):
    """
    ScenarioManager is a class that manage the in cluster scenarios deployment and validation.
    class have the following methods:
    - apply_scenario: apply the scenario manifests to the cluster
    - apply_fix: apply the fix to the cluster
    - trigger_scan: create a new scan action from the backend
    - verify_scenario: validate the scenario results on the backend - needs to be implemented in the child class
    - verify_fix: validate the fix results on the backend - needs to be implemented in the child class
    """

    def __init__(self, test_obj, backend: backend_api.ControlPanelAPI, cluster, namespace, scenario_path=SCENARIOS_TEST_PATH):
        self.test_scenario = test_obj[("test_scenario", None)]
        self.backend = backend
        self.cluster = cluster
        self.scenario_path = scenario_path
        self.namespace = namespace

    def __del__(self):
        pass


    def apply_scenario(self):
        """
        apply_scenario apply the scenario manifests to the cluster
        """
        Logger.logger.info(f"Applying scenario manifests for {self.test_scenario}")
        deploy_cmd = os.path.join(self.scenario_path, 'deploy_scenario') + ' ' + os.path.join(self.scenario_path , self.test_scenario) + ' --namespace ' + self.namespace
        TestUtil.run_command(command_args=deploy_cmd, display_stdout=True, timeout=300)
        time.sleep(5)

    
    def apply_fix(self, fix_type):
        """
        apply_fix apply the fix to the cluster
        """
        fix_command= os.path.join(self.scenario_path, self.test_scenario, 'fix_' + fix_type) + ' --namespace ' + self.namespace
        TestUtil.run_command(command_args=fix_command, display_stdout=True, timeout=300)
        time.sleep(5)
  

    def trigger_scan(self, trigger_by) -> None:
        """trigger_scan create a new scan action from the backend

        :param trigger_by: the kind of event that trigger the scan ("cronjob", "scan_on_start")
        """
        Logger.logger.info("triggering a new scan")
        if trigger_by == "cronjob":
            self.backend.create_kubescape_job_request(
                cluster_name=self.cluster,
                trigger_by=trigger_by,
                framework_list=["security"],
                with_host_sensor="false"
            )
        else:
            self.backend.trigger_posture_scan(
                cluster_name=self.cluster,
                framework_list=["security"],
                with_host_sensor="false"
                )
            
    def verify_scenario(self):
        raise Exception("Not implemented")
    
    def verify_fix(self):
        raise Exception("Not implemented")
       


class AttackChainsScenarioManager(ScenarioManager):
    """
    AttackChainsScenarioManager is a class that manage
    """

    def __init__(self, test_obj, backend: backend_api.ControlPanelAPI, cluster, namespace):
        super().__init__(test_obj, backend, cluster, namespace, SCENARIOS_TEST_PATH)

    def verify_scenario(self):
        """
        verify_scenario validate the attack chains results on the backend
        """
        current_datetime = datetime.now(timezone.utc)
        Logger.logger.info("wait for response from BE")
        r, t = self.wait_for_report(
            self.backend.get_active_attack_chains, 
            timeout=180,
            current_datetime=current_datetime,
            cluster_name=self.cluster
            )

        Logger.logger.info('loading attack chain scenario to validate it')
        f = open(os.path.join(SCENARIOS_EXPECTED_VALUES, self.test_scenario+'.json'))
        expected = json.load(f) 
        response = json.loads(r.text)

        Logger.logger.info('comparing attack-chains result with expected ones')
        assert self.check_attack_chains_results(response, expected), f"Attack chain response differs from the expected one. Response: {response}, Expected: {expected}"
        return True

    def verify_fix(self):
        """
        verify_fix validate the attack chains fix results on the backend
        """
        Logger.logger.info("wait for response from BE")
        # we set the timeout to 1000s because image scan 
        # cat take more than 15m to get the updated result
        active_attack_chains, t = self.wait_for_report(
            self.backend.has_active_attack_chains, 
            timeout=600, 
            cluster_name=self.cluster
            )

        Logger.logger.info('attack-chain fixed properly')

   
    

    def compare_nodes(self, obj1, obj2) -> bool:
        """Walk 2 dictionary object to compare their values.

        :param obj1: dictionary one to be compared.
        :param obj2: dictionary two to be compared.
        :return: True if all checks passed, False otherwise.
        """
        # check at first if we are managin dictionaries
        if isinstance(obj1, dict) and isinstance(obj2, dict):
            # check if key 'nextNodes' is present in the dictionaries
            if 'nextNodes' in obj1 and 'nextNodes' in obj2:
                # check if length of the items is the same
                if len(obj1['nextNodes']) != len(obj2['nextNodes']):
                    return False
                # loop over the new nextNodes
                for node1, node2 in zip(obj1['nextNodes'], obj2['nextNodes']):
                    if not self.compare_nodes(node1, node2):
                        return False
                return True
            else:
                if 'name' in obj1 and 'name' in obj2:
                    return obj1['name'] == obj2['name']
                return all(self.compare_nodes(obj1[key], obj2[key]) for key in obj1.keys())
        return False

    def check_attack_chains_results(self, result, expected) -> bool:
        """Validate the input content with the expected one.
        
        :param result: content retrieved from backend.
        :return: True if all the controls passed, False otherwise.
        """
        # Some example of assertion needed to recognize attack chain scenarios
        for acid, ac in enumerate(result['response']['attackChains']):
            ac_node_result = result['response']['attackChains'][acid]['attackChainNodes']
            ac_node_expected = expected['response']['attackChains'][acid]['attackChainNodes']
            if ac_node_result['name'] != ac_node_expected['name']:
                return False
            if not self.compare_nodes(ac_node_result, ac_node_expected):
                return False
        return True


class SecurityRisksScenarioManager(ScenarioManager):

    def __init__(self, test_obj, backend: backend_api.ControlPanelAPI, cluster, namespace):
        super().__init__(test_obj, backend, cluster, namespace, SCENARIOS_TEST_PATH)
        
        self.test_security_risk_ids = test_obj["test_job"][0].get("security_risks_ids", [])

    def verify_scenario(self):
        """
        verify_scenario validate the security risks results on the backend
        validations supported:
        - security risks list
        - security risks categories
        - security risks severities
        - security risks unique values
        - security risks resources
        - security risks trends

        """
        Logger.logger.info("validating security risks list")
        res = self.wait_for_report(
        self.verify_security_risks_list, 
        timeout=500,
        sleep_interval=10
        )

        return res[0]



    def verify_fix(self):
        """
        verify_fix validate the security risks fix results on the backend
        """
        Logger.logger.info("wait for response from BE")
        isEmpty, t = self.wait_for_report(
            self.is_security_risk_empty, 
            cluster_name=self.cluster,
            namespace=self.namespace,
            timeout=500,
            sleep_interval=10
            )

        return isEmpty
    
    def apply_fix(self, fix_type):
        """
        apply_fix apply the fix to the cluster
        """
        fix_command= os.path.join(self.scenario_path, self.test_scenario, "delete_deployments") + ' --namespace ' + self.namespace
        TestUtil.run_command(command_args=fix_command, display_stdout=True, timeout=300)
        super().apply_fix(fix_type)


    def check_security_risks_resources_results(self, result, expected):
        """
        check_security_risks_resources_results - Validate the input content with the expected one of security risks resources
        
        :param result: content retrieved from backend.
        """
        ignore_keys = {'relation', 'lastUpdated', 'supportsSmartRemediation', 'namespace', 
                   'cursor', 'k8sResourceHash', 'cluster', 'attackChainID', 'firstSeen', 
                   'clusterShortName', 'lastTimeDetected', 'reportGUID', 'resourceID', 'isNew'}
    
        if 'total' in result and 'total' in expected:
            assert result['total']['value'] == expected['total']['value'], f"'Total' value mismatch: result: {result['total']['value']} != expected: {expected['total']['value']}"


        if 'response' in result and 'response' in expected:
            compare_lists(result['response'], expected['response'], ignore_keys)


    # def check_security_risks_trends(self, result, expected_number_of_events):
    #     """
    #     check_security_risks_trends - Validate the input content with the expected one of security risks trends
        
    #     :param result: content retrieved from backend.
    #     """
    #     ignore_keys = {'date'}

    #     compare_dicts(result, expected, ignore_keys)
        

    def check_security_risks_results(self, result, expected):
        """
        check_security_risks_results - Validate the input content with the expected one of security risks list
        
        :param result: content retrieved from backend.
        """
        ignore_keys = {'relation', 'lastUpdated', 'supportsSmartRemediation', 'namespace',
                   'clusterShortName', 'cursor', 'k8sResourceHash', 'cluster', 'clusterShortName'}
    
        if 'total' in result and 'total' in expected:
            if result['total']['value'] != expected['total']['value']:
                missingSecurityRiskIDs =self.find_missing_security_risks(result, expected)
                raise Exception(f"'Total' value mismatch: result: {result['total']['value']} != expected: {expected['total']['value']}, missing security risks: {missingSecurityRiskIDs}")

        if 'response' in result and 'response' in expected:
            assert result['response']!= None, f"response is None"

            if len(result['response']) != len(expected['response']):
                missingSecurityRiskIDs =self.find_missing_security_risks(result, expected)
                raise Exception(f"Length mismatch: result: {len(result['response'])} != expected: {len(expected['response'])}, missing security risks: {missingSecurityRiskIDs}")
            
            compare_lists(result['response'], expected['response'], ignore_keys)


    def check_security_risks_categories(self, result, expected):
        """
        check_security_risks_categories - Validate the input content with the expected one of security risks categories
        
        :param result: content retrieved from backend.
        """
        assert "total" in result, f"'Total' key not found in the result"
        
        if 'total' in result and 'total' in expected:
            assert result['total']['value'] == expected['total']['value'], f"'Total' value mismatch: result: {result['total']['value']} != expected: {expected['total']['value']}"

       
        assert result['response'] == expected['response'], f"Security risks categories response differs from the expected one. Response: {result['response']}, Expected: {expected['response']}"

    
    def check_security_risks_severities(self, result, expected):
        """
        check_security_risks_severities - Validate the input content with the expected one of security risks severities
        
        :param result: content retrieved from backend.
        """

        assert "total" in result, f"'Total' key not found in the result"
    
        if 'total' in result and 'total' in expected:
            assert result['total']['value'] == expected['total']['value'], f"'Total' value mismatch: result: {result['total']['value']} != expected: {expected['total']['value']}"
        
        assert result['response']['severityResourceCounter'] == expected['response']['severityResourceCounter'], f"Security risks severities resource counter response differs from the expected one. Response: {result['response']['severityResourceCounter']}, Expected: {expected['response']['severityResourceCounter']}"
        assert result['response']['totalResources'] == expected['response']['totalResources'], f"Security risks severities total resources response differs from the expected one. Response: {result['response']['totalResources']}, Expected: {expected['response']['totalResources']}"


    

    def is_security_risk_empty(self, cluster_name, namespace, **kwargs):
        """
        is_security_risk_empty check if the security risks list are empty
        """
        r = self.backend.get_security_risks_list(
            cluster_name=cluster_name,
            namespace=namespace
            )
        
        response = json.loads(r.text)
        assert response['total']['value'] == 0, "Security risks found, expecting no security risks"
        return True
    
    def verify_security_risks_trends(self, expected_n_events_detected, expected_n_events_resolved, expected_current_detected, expected_change_from_beginning_of_period):
        """
        verify_security_risks_trends validate the security risks trends results on the backend
        """
        # current_datetime = datetime.now(timezone.utc)
        Logger.logger.info("wait for response from BE")
        r = self.backend.get_security_risks_trends(self.cluster,self.namespace, self.test_security_risk_ids)

        Logger.logger.info('loading security risks scenario to validate it')
        f = open(os.path.join(SCENARIOS_EXPECTED_VALUES, self.test_scenario+'_security-risks-trends.json'))
        expected = json.load(f) 
        response = json.loads(r.text)

        Logger.logger.info('comparing security risks trends result with expected ones')

        assert len(response['securityIssuesTrends']) == EXPECTED_TRENDS_DAYS_BACK, f"Security risks trends response differs from the expected one. Response: {len(response['securityIssuesTrends'])} != Expected: {EXPECTED_TRENDS_DAYS_BACK}"
        
        assert response["totalDetectedForPeriod"] == expected_n_events_detected, f"Security risks trends total detected for period response differs from the expected one. Response: {response['totalDetectedForPeriod']} != Expected: {expected_n_events_detected}"
        assert response["totalResolvedForPeriod"] == expected_n_events_resolved, f"Security risks trends total resolved for period response differs from the expected one. Response: {response['totalResolvedForPeriod']} != Expected: {expected_n_events_resolved}"
        assert response["currentDetected"] == expected_current_detected, f"Security risks trends current detected response differs from the expected one. Response: {response['currentDetected']} != Expected: {expected_current_detected}"
        assert response["changeFromBeginningOfPeriod"] == expected_change_from_beginning_of_period, f"Security risks trends change from beginning of period response differs from the expected one. Response: {response['changeFromBeginningOfPeriod']} != Expected: {expected_change_from_beginning_of_period}"
 
        

    def verify_security_risks_list_uniquevalues(self, baseFilters):
        """
        verify_security_risks_list_uniquevalues validate the security risks unique values results on the backend
        """

        for fieldName, expectedSuffix in SECURITY_RISKS_EXPECTED_UNIQUE_VALUES_SUFFIX.items():
            newFilters = baseFilters.copy()
            if fieldName != "namespace":
                newFilters[fieldName] = ""
            Logger.logger.info(f"wait for response from BE with filter: {newFilters}")
            r = self.backend.get_security_risks_list_uniquevalues(newFilters, fieldName)


            Logger.logger.info('loading security risks scenario to validate it')
            f = open(os.path.join(SCENARIOS_EXPECTED_VALUES, self.test_scenario+expectedSuffix))
            expected = json.load(f) 
            response = json.loads(r.text)
       
            assert response == expected, f"verify_security_risks_list_uniquevalues - security risks unique values for '{fieldName}' response differs from the expected one. Response: {response}, Expected: {expected}"


    def verify_security_risks_severities(self, list_result):
        """
        verify_security_risks_severities validate the security risks severities results on the backend
        """
        # current_datetime = datetime.now(timezone.utc)
        Logger.logger.info("wait for response from BE")
        r = self.backend.get_security_risks_severities(self.cluster, self.namespace, self.test_security_risk_ids)

        # Logger.logger.info('loading security risks scenario to validate it')
        # f = open(os.path.join(SCENARIOS_EXPECTED_VALUES, self.test_scenario+'_security-risks-severities.json'))
        expected = summarize_severity(list_result)
        response = json.loads(r.text)

        Logger.logger.info('comparing security risks severities result with expected ones')
        self.check_security_risks_severities(response, expected)
    
    def verify_security_risks_categories(self, list_result):
        """
        verify_security_risks_categories validate the security risks categories results on the backend
        """
        # current_datetime = datetime.now(timezone.utc)
        Logger.logger.info("wait for response from BE")
        r = self.backend.get_security_risks_categories(self.cluster, self.namespace, self.test_security_risk_ids)

        # Logger.logger.info('loading security risks scenario to validate it')
        # f = open(os.path.join(SCENARIOS_EXPECTED_VALUES, self.test_scenario+'_security-risks-categories.json'))
        expected = summarize_category(list_result)
        response = json.loads(r.text)

        Logger.logger.info('comparing security risks categories result with expected ones')
        self.check_security_risks_categories(response, expected)


    def verify_security_risks_list(self):
        """
        verify_security_risks_list validate the security risks results on the backend
        """
        # current_datetime = datetime.now(timezone.utc)
        Logger.logger.info("wait for response from BE")
        r = self.backend.get_security_risks_list(self.cluster, self.namespace, self.test_security_risk_ids)

        Logger.logger.info('loading security risks scenario to validate it')
        f = open(os.path.join(SCENARIOS_EXPECTED_VALUES, self.test_scenario+'_security-risks-list.json'))
        expected = json.load(f) 
        response = json.loads(r.text)

        filtered_expected = filter_security_risks_list(expected, self.test_security_risk_ids)

        Logger.logger.info('comparing security risks result with expected ones')
        self.check_security_risks_results(response, filtered_expected)

        return response


    def verify_security_risks_resources(self):
        """
        verify_security_risks_resources_sidebar validate the security risks resources on the backend
        """

        for security_risk_id, expectedPrefix in SECURITY_RISKS_RESOURCES_PREFIX.items():
            if security_risk_id in self.test_security_risk_ids:
                Logger.logger.info(f"wait for response from BE with filter: {security_risk_id}")
                r = self.backend.get_security_risks_resources(self.cluster, self.namespace, security_risk_id)

                Logger.logger.info('loading security risks scenario to validate it')
                f = open(os.path.join(SCENARIOS_EXPECTED_VALUES, self.test_scenario+expectedPrefix+'.json'))
                expected = json.load(f) 
                response = json.loads(r.text)

                Logger.logger.info('comparing security risks result with expected ones')
                self.check_security_risks_resources_results(response, expected)

    def find_missing_security_risks(self, result, expected):
        """
        find_missing_security_risks - Find the missing security risks in the result compared to the expected ones
        """
        missingSecurityRiskIDs = []
        for securityRisk in expected['response']:
            if securityRisk['securityRiskID'] not in [sr['securityRiskID'] for sr in result['response']]:
                missingSecurityRiskIDs.append(securityRisk['securityRiskID'])
        return missingSecurityRiskIDs
        
        
        


def compare_dicts(result, expected, ignore_keys=None):
    """
    Compare two dictionaries deeply, ignoring specific keys.
    """
    if ignore_keys is not None:
        d1_keys = set(result.keys()) - ignore_keys
        d2_keys = set(expected.keys()) - ignore_keys
    else:
        d1_keys = set(result.keys())
        d2_keys = set(expected.keys())

    assert d1_keys == d2_keys, f"Keys mismatch: result: {d1_keys} != expected: {d2_keys}"


    for key in d1_keys:
        if isinstance(result[key], dict) and isinstance(expected[key], dict):
            assert compare_dicts(result[key], expected[key], ignore_keys), f"Difference found at key '{key}': result: {result[key]} != expected: {expected[key]}"

        elif isinstance(result[key], list) and isinstance(expected[key], list):
            compare_lists(result[key], expected[key], ignore_keys)
        else:
            assert result[key] == expected[key], f"Difference found at key '{key}': result: {result[key]} != expected: {expected[key]}"


def compare_lists(result, expected, ignore_keys=None):
    """
    Compare two lists of dictionaries deeply, ignoring specific keys.
    """

    assert len(result) == len(expected), f"List lengths differ: result: {len(result)} != expected: {len(result)}"

    for item1, item2 in zip(result, expected):
        try:
            compare_dicts(item1, item2, ignore_keys)
        except Exception as e:
            raise Exception(f"Error comparing list items: {e}, item1 result: {item1}, item2 expected: {item2}")



def filter_security_risks_list(data, security_risk_ids):
    """
    Filters the security risks based on a list of securityRiskIDs.
    
    :param data: Dict containing the total data and a list of security risks
    :param security_risk_ids: List of securityRiskID strings to filter by; returns all if empty
    :return: A new dictionary with the filtered security risks
    """
    if not security_risk_ids:  # If the list is empty, return all items
        return data

    filtered_response = [risk for risk in data['response'] if risk['securityRiskID'] in security_risk_ids]
    new_data = {
        "total": {
            "value": len(filtered_response),
            "relation": "eq"
        },
        "response": filtered_response,
        "cursor": data['cursor']
    }
    return new_data


def summarize_severity(data):
    """
    Summarizes the security risks by severity and counts total affected resources.
    
    :param data: Dict containing the total data and a list of security risks
    :return: A new dictionary with severity resource counters and total resources count
    """
    severity_counter = {
        "Critical": 0,
        "High": 0,
        "Low": 0,
        "Medium": 0
    }
    total_resources = 0
    
    for item in data['response']:
        severity = item['severity']
        affected_resources = item['affectedResourcesCount']
        
        # Increment the count for the severity level
        if severity in severity_counter:
            severity_counter[severity] += affected_resources
        else:
            # If the severity level is not predefined, we can add it dynamically if necessary
            severity_counter[severity] = affected_resources
        
        # Increment total resources
        total_resources += affected_resources

    # Prepare the final dictionary
    new_data = {
        "total": {
            "value": len(data['response']),
            "relation": "eq"
        },
        "response": {
            "severityResourceCounter": severity_counter,
            "totalResources": total_resources
        },
        "cursor": data['cursor']
    }
    
    return new_data


def summarize_category(data):
    """
    Summarizes the security risks by category and counts total affected resources.
    
    :param data: Dict containing the total data and a list of security risks
    :return: A new dictionary with category resource counters and total resources count
    """
    category_counter = {}
    total_resources = 0

    for item in data['response']:
        category = item['category']
        affected_resources = item['affectedResourcesCount']

        # Increment the count for the category
        if category in category_counter:
            category_counter[category] += affected_resources
        else:
            # If the category is not already in the dictionary, initialize it
            category_counter[category] = affected_resources

        # Increment total resources
        total_resources += affected_resources

    # Prepare the final dictionary
    new_data = {
        "total": {
            "value": len(data['response']),
            "relation": "eq"
        },
        "response": {
            "categoryResourceCounter": category_counter,
            "totalResources": total_resources
        },
        "cursor": data['cursor']
    }

    return new_data

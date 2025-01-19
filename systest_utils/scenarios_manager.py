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
    # "namespace": "_security-risks-uv-namespace.json",
    "severity": "_security-risks-uv-severity.json",
    "category": "_security-risks-uv-category.json",
    "securityRiskName": "_security-risks-uv-securityriskname.json",
}

# maps security risk id and the expected values file prefix
SECURITY_RISKS_RESOURCES_PREFIX = {
    "R_0002": "_security-risks-resources_sidebar_R0002", # control security risk type
    "R_0035": "_security-risks-resources_sidebar_R0035", # attack path security risk type
    "R_0005": "_security-risks-resources_sidebar_R0005", # control security risk type
    "R_0007": "_security-risks-resources_sidebar_R0007", # control security risk type with network policy
    "R_0037": "_security-risks-resources_sidebar_R0037", # vulnerability security risk type

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
        self.scenario_key = self.test_scenario

    def __del__(self):
        pass


    def apply_scenario(self):
        """
        apply_scenario apply the scenario manifests to the cluster
        """
        Logger.logger.info(f"Applying scenario manifests for {self.test_scenario}")
        deploy_cmd = os.path.join(self.scenario_path, 'deploy_scenario') + ' ' + os.path.join(self.scenario_path , self.test_scenario) + ' --namespace ' + self.namespace
        TestUtil.run_command(command_args=deploy_cmd, display_stdout=True, timeout=300)

    
    def apply_fix(self, fix_type):
        """
        apply_fix apply the fix to the cluster
        """
        fix_command= "bash " + os.path.join(self.scenario_path, self.test_scenario, 'fix_' + fix_type) + ' --namespace ' + self.namespace
        TestUtil.run_command(command_args=fix_command, display_stdout=True, timeout=300)
  

    def trigger_scan(self, trigger_by=None,  additional_params={}) -> None:
        """trigger_scan create a new scan action from the backend

        :param trigger_by: the kind of event that trigger the scan ("cronjob", "scan_on_start")
        """
        Logger.logger.info("triggering a new scan")
        if trigger_by == "cronjob":
            self.backend.create_kubescape_job_request(
                cluster_name=self.cluster,
                trigger_by=trigger_by,
                framework_list=["allcontrols"],
                with_host_sensor="false"
            )
        else:
            self.backend.trigger_posture_scan(
                cluster_name=self.cluster,
                 # scanning "allcontrols" framework will trigger a scan for the "security" framework, whereas scanning "security" framework alone is not enough 
                 # since the BE looks at the last scan and scans containing only "security" framework are not returned as last posture scan
                framework_list=["allcontrols"],
                with_host_sensor="false",
                additional_params=additional_params
                )
            
    def verify_scenario(self):
        raise Exception("Not implemented")
    
    def verify_fix(self):
        raise Exception("Not implemented")
    
    def construct_message(self,message):
        return f"{self.scenario_key}: cluster: {self.cluster}, namespace: {self.namespace}, message: {message}"
       


class AttackChainsScenarioManager(ScenarioManager):
    """
    AttackChainsScenarioManager is a class that manage
    """

    def __init__(self, test_obj, backend: backend_api.ControlPanelAPI, cluster, namespace):
        super().__init__(test_obj, backend, cluster, namespace, SCENARIOS_TEST_PATH)
        self.test_scenario = test_obj["test_job"][0].get("test_scenario", "not defined")
        self.attack_track = test_obj["test_job"][0].get("attack_track", "not defined")
        self.fix_object = test_obj["test_job"][0].get("fix_object", "control")
        self.scenario_key = self.test_scenario + " fix: " + self.fix_object
        Logger.logger.info(f"Generated ScenarioManager for {self.test_scenario} scenario on {self.cluster} cluster in {self.namespace} namespace for attack track {self.attack_track}")

    def apply_scenario(self):
        """
        apply_scenario apply the scenario manifests to the cluster
        """
        Logger.logger.info(f"Applying scenario manifests for {self.scenario_key}")
        super().apply_scenario()

    def apply_fix(self):
        """
        apply_fix apply the fix to the cluster
        """
        Logger.logger.info(f"Applying fix for {self.scenario_key}")
        super().apply_fix(self.fix_object)

    def verify_scenario(self, current_datetime=None, timeout=600):
        """
        verify_scenario validate the attack chains results on the backend
        """
        if current_datetime == None:
            current_datetime = datetime.now(timezone.utc)
        Logger.logger.info("wait for response from BE")
        r, t = self.wait_for_report(
            self.backend.get_active_attack_chains, 
            timeout=timeout,
            sleep_interval=15,
            current_datetime=current_datetime,
            cluster_name=self.cluster,
            namespace=self.namespace
            )

        Logger.logger.info('loading attack chain scenario to validate it')
        f = open(os.path.join(SCENARIOS_EXPECTED_VALUES, self.test_scenario+'.json'))
        expected = json.load(f) 
        response = json.loads(r.text)

        Logger.logger.info('comparing attack-chains result with expected ones')
        try:
            self.check_attack_chains_results(response, expected)
        except Exception as e:
            raise Exception(f"Failed to validate attack chains scenario: {e}, response: {response}, expected: {expected}")

    def verify_fix(self, timeout=600):
        """
        verify_fix validate the attack chains fix results on the backend
        """
        Logger.logger.info("wait for response from BE")
        # we set the timeout to 1000s because image scan 
        # cat take more than 15m to get the updated result
        active_attack_chains, t = self.wait_for_report(
            self.backend.has_active_attack_chains, 
            timeout=timeout, 
            sleep_interval=10,
            cluster_name=self.cluster,
            namespace=self.namespace
            )

        Logger.logger.info('attack-chain fixed properly')

   
    

    def compare_nodes(self, obj1, obj2):
        """Walk 2 dictionary object to compare their values.

        :param obj1: dictionary one to be compared.
        :param obj2: dictionary two to be compared.
        :return: True if all checks passed, False otherwise.
        """
        # check at first if we are managin dictionaries
        if isinstance(obj1, dict) and isinstance(obj2, dict):
            if 'relatedResources' in obj1 and 'relatedResources' in obj2 and obj1['relatedResources'] != None and obj2['relatedResources'] != None and obj1['relatedResources'] != "None" and obj2['relatedResources'] != "None":
                assert len(obj1['relatedResources']) == len(obj2['relatedResources']), f"Length mismatch: result: {len(obj1['relatedResources'])} != expected: {len(obj2['relatedResources'])}"
            # check if key 'nextNodes' is present in the dictionaries
            if 'nextNodes' in obj1 and 'nextNodes' in obj2:
                # check if length of the items is the same
                assert len(obj1['nextNodes']) == len(obj2['nextNodes']), f"Length mismatch: result: {len(obj1['nextNodes'])} != expected: {len(obj2['nextNodes'])}"

                # sort the nextNodes by name
                obj1['nextNodes'] = sorted(obj1['nextNodes'], key=lambda x: x['name'])
                obj2['nextNodes'] = sorted(obj2['nextNodes'], key=lambda x: x['name'])

                # loop over the new nextNodes
                for node1, node2 in zip(obj1['nextNodes'], obj2['nextNodes']):
                    self.compare_nodes(node1, node2)

            else:
                if 'name' in obj1 and 'name' in obj2:
                    assert obj1['name'] == obj2['name'], f"Node name mismatch: result: {obj1['name']} != expected: {obj2['name']}"
                return all(self.compare_nodes(obj1[key], obj2[key]) for key in obj1.keys())

    def check_attack_chains_results(self, result, expected):
        """Validate the attack chains results on the backend
        
        :param 
            result: attack chains retrieved from backend.
            expected: expected attack chains.
        :exception Exception: if the content is not as expected.
        """
        assert "response" in result, f"'response' key not found in the result"
        assert len(result['response']['attackChains']) > 0, "No attack chains found, expecting attack chains"
        found = False

        expected_ac = expected['response']['attackChains'][0]
        # Some example of assertion needed to recognize attack chain scenarios
        for acid, ac in enumerate(result['response']['attackChains']):
            if ac['name'] != self.attack_track:
                continue
        
            found = True
            ac_node_result = result['response']['attackChains'][acid]['attackChainNodes']
            ac_node_expected = expected_ac['attackChainNodes']

            # comparing the 'name' (type: attack track) of the attack chain
            assert ac_node_result['name'] == ac_node_expected['name'], f"Attack chain name mismatch: result: {ac_node_result['name']} != expected: {ac_node_expected['name']}"
           
            self.compare_nodes(ac_node_result, ac_node_expected)
            break
        
        assert found, f"Attack chain {self.attack_track} not found, expecting attack chains"
    
    



class SecurityRisksScenarioManager(ScenarioManager):

    def __init__(self, test_obj, backend: backend_api.ControlPanelAPI, cluster, namespace):
        super().__init__(test_obj, backend, cluster, namespace, SCENARIOS_TEST_PATH)
        self.test_scenario = test_obj["test_job"][0].get("test_scenario", "not defined")
        self.fix_object = test_obj["test_job"][0].get("fix_object", "control")
        self.test_security_risk_ids = test_obj["test_job"][0].get("security_risks_ids", [])
        self.scenario_key = self.test_scenario + " fix: " + self.fix_object + " security_risk_ids: " + ','.join(self.test_security_risk_ids)
        self.with_network_policy = test_obj["test_job"][0].get("with_network_policy", False)
        Logger.logger.info(f"Generated ScenarioManager for {self.test_scenario} scenario on {self.cluster} cluster in {self.namespace} namespace")


    def verify_scenario(self, timeout=600):
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
        timeout=timeout,
        sleep_interval=15
        )

        return res[0]


    def verify_fix(self, timeout=600):
        """
        verify_fix validate the security risks fix results on the backend
        """
        Logger.logger.info("wait for response from BE")
        isEmpty, t = self.wait_for_report(
            self.is_security_risk_empty, 
            security_risk_ids=self.test_security_risk_ids,
            timeout=timeout,
            sleep_interval=15
            )

        return isEmpty
    
    def apply_fix(self):
        """
        apply_fix apply the fix to the cluster
        """
        fix_command= "bash " + os.path.join(self.scenario_path, self.test_scenario, "delete_deployments") + ' --namespace ' + self.namespace
        TestUtil.run_command(command_args=fix_command, display_stdout=True, timeout=300)
        # super().apply_fix(self.fix_object)

    def get_exceptions_list(self):
        """
        get_exceptions_list get the list of exceptions from the security risk
        """
        r = self.backend.get_security_risks_exceptions_list(self.cluster)
        response = json.loads(r.text)
        return response

    
    def verify_exception_exists(self, exception_guid=None, timeout=3, sleep_interval=1):
        """
        verify_exception_exists validate the exceptions exists on the backend
        """

        exists, t = self.wait_for_report(
            self.exception_exists, 
            exception_guid=exception_guid,
            timeout=timeout,
            sleep_interval=sleep_interval
            )
        return exists
    
    def verify_exception_not_exists(self, exception_guid=None, timeout=3, sleep_interval=1):
        """
        verify_exception_not_exists validate the exceptions not exists on the backend
        """
        not_exists, t = self.wait_for_report(
            self.exception_not_exists, 
            exception_guid=exception_guid,
            timeout=timeout,
            sleep_interval=sleep_interval
            )
        return True
    
    def exception_exists(self, exception_guid=None):
        """
        exception_exists validate the exceptions exists on the backend
        if exception_guid is None, it will check if there are any exceptions
        if exception_guid is not None, it will check if the exception exists
        """
        if exception_guid == None:
            exceptions_res = self.get_exceptions_list()
            assert exceptions_res["total"]["value"] > 0, "No exceptions found, expecting exceptions"
            return True

        exceptions_res = self.get_exceptions_list()
        exceptions = exceptions_res["response"]

        for exception in exceptions:
            if exception["guid"] == exception_guid:
                return True
        
        raise Exception(f"Exception {exception_guid} not found, expecting exceptions") 

    
    def exception_not_exists(self, exception_guid=None):
        """
        exception_not_exists validate the exceptions not exists on the backend
        if exception_guid is None, it will check if there are no exceptions
        if exception_guid is not None, it will check if the exception not exists
        """
        if exception_guid == None:
            exceptions_res = self.get_exceptions_list()
            assert exceptions_res["total"]["value"] == 0, "Exceptions found, expecting no exceptions"
            return True
        
        exceptions_res = self.get_exceptions_list()
        exceptions = exceptions_res["response"]

        found = False
        if exceptions == None:
            return True
        
        for exception in exceptions:
            if exception["guid"] == exception_guid:
                found = True
                break

        assert not found, f"Exception {exception_guid} found, expecting no exceptions"

    def add_new_exception(self, security_risk_id,exceptions_resources=[], reason=""):
        """
        add_new_exception add a new exception to the security risk
        """

        r = self.backend.add_security_risks_exception(security_risk_id, exceptions_resources, reason)
        new_exception = json.loads(r.text)
        new_exception_guid = new_exception["guid"]

        Logger.logger.info(f"checking if the new exception {new_exception_guid} exists, allowing 3s for the exception to be added")
        assert self.verify_exception_exists(new_exception_guid, timeout=3, sleep_interval=1), f"Failed to add new exception to the security risk, expected exception guid: {new_exception_guid}"

        exceptions_res = self.get_exceptions_list()
        exceptions = exceptions_res["response"]

        found = False
        for exception in exceptions:
            if exception["guid"] == new_exception_guid:
                found = True
                assert exception["reason"] == reason, f"Failed to add exception, expected reason: {reason}, got: {exception['reason']}"
                assert exception["securityRiskID"] == security_risk_id, f"Failed to add exception, expected securityRiskID: {security_risk_id}, got: {exception['securityRiskID']}"
                assert len(exception["resources"]) == len(exceptions_resources), f"Failed to add exception, expected resources: {exceptions_resources}, got: {exception['resources']}"
                
        assert found, f"Failed to add new exception to the security risk, expected security risk: {security_risk_id}, got: {exceptions}"
        return new_exception
    
    def delete_exception(self, exception_guid):
        """
        delete_exception delete an exception from the security risk
        """

        r = self.backend.delete_security_risks_exception(exception_guid)
        response = json.loads(r.text)

        assert response == ["deleted"], f"Failed to delete exception: {response}"

        assert self.verify_exception_not_exists(exception_guid, timeout=3, sleep_interval=1), f"Failed to delete exception {exception_guid}, expecting no exceptions"

    
    def edit_exception(self, exception_guid, security_risk_id, exceptions_resources, reason=""):
        """
        edit_exception edit an exception from the security risk
        """

        r = self.backend.put_security_risks_exception(exception_guid, security_risk_id, exceptions_resources, reason)
        response = json.loads(r.text)

        assert response["guid"] == exception_guid, f"Failed to edit exception, expected guid: {exception_guid}, got: {response['guid']}"
        assert response["reason"] == reason, f"Failed to edit exception, expected reason: {reason}, got: {response['reason']}"
        assert response["securityRiskID"] == security_risk_id, f"Failed to edit exception, expected securityRiskID: {security_risk_id}, got: {response['securityRiskID']}"
        assert len(response["resources"]) == len(exceptions_resources), f"Failed to add exception, expected resources: {exceptions_resources}, got: {response['resources']}"
        return response
    
    def get_security_risks_resources(self, security_risk_id):
        """
        get_security_risks_resources get the security risks resources from the backend
        """
        r = self.backend.get_security_risks_resources(self.cluster, self.namespace, security_risk_id)
        response = json.loads(r.text)
        if "response" not in response or response["response"] ==  None:
            response["response"] = []
        return response
    
    def get_security_risks_list(self, security_risk_ids=[]):
        """
        get_security_risks_list get the security risks list from the backend
        """
        r = self.backend.get_security_risks_list(self.cluster, self.namespace, security_risk_ids)
        response = json.loads(r.text)
        return response
    

    def check_security_risks_resources_results(self, result, expected):
        """
        check_security_risks_resources_results - Validate the input content with the expected one of security risks resources
        
        :param result: content retrieved from backend.
        """
            

        ignore_keys = {'relation', 'lastUpdated', 'supportsSmartRemediation', 'namespace', 
                   'cursor', 'k8sResourceHash', 'cluster', 'attackChainID', 'firstSeen', 
                   'clusterShortName', 'lastTimeDetected', 'reportGUID', 'resourceID', 'isNew', 'exceptionPolicyGUID',
                   'riskFactorsCount', 'riskFactors', 'severityStats', 'criticalCount', 'highCount', 'mediumCount', 'lowCount',# vulnerability specific keys
                   'networkPolicyStatus'
                   }
    
        if 'total' in result and 'total' in expected:
            assert result['total']['value'] == expected['total']['value'], self.construct_message(f"'Total' value mismatch: result: {result['total']['value']} != expected: {expected['total']['value']}")


        if 'response' in result and 'response' in expected:
            compare_lists(result['response'], expected['response'], ignore_keys)


    def check_security_risks_results(self, result, expected):
        """
        check_security_risks_results - Validate the input content with the expected one of security risks list
        
        :param result: content retrieved from backend.
        """
        ignore_keys = {'tickets', 'relation', 'lastUpdated', 'supportsSmartRemediation', 'namespace',
                   'clusterShortName', 'cursor', 'k8sResourceHash', 'cluster', 'clusterShortName'}
    
        if 'total' in result and 'total' in expected:
            if result['total']['value'] != expected['total']['value']:
                missingSecurityRiskIDs =self.find_missing_security_risks(result, expected)
                raise Exception(f"'Total' value mismatch: result: {result['total']['value']} != expected: {expected['total']['value']}, missing security risks: {missingSecurityRiskIDs}")

        if 'response' in result and 'response' in expected:
            assert result['response']!= None, f"response is None"

            if len(result['response']) != len(expected['response']):
                missingSecurityRiskIDs =self.find_missing_security_risks(result, expected)
                raise Exception(self.construct_message(f"Length mismatch: result: {len(result['response'])} != expected: {len(expected['response'])}, missing security risks: {missingSecurityRiskIDs}"))
            
            compare_lists(result['response'], expected['response'], ignore_keys)


    def check_security_risks_categories(self, result, expected):
        """
        check_security_risks_categories - Validate the input content with the expected one of security risks categories
        
        :param result: content retrieved from backend.
        """
        assert "total" in result, f"'Total' key not found in the result"
        
        if 'total' in result and 'total' in expected:
            assert result['total']['value'] == expected['total']['value'], self.construct_message(f"'Total' value mismatch: result: {result['total']['value']} != expected: {expected['total']['value']}")

        assert result['response'] == expected['response'], self.construct_message(f"Security risks categories response differs from the expected one. Response: {result['response']}, Expected: {expected['response']}")

    
    def check_security_risks_severities(self, result, expected):
        """
        check_security_risks_severities - Validate the input content with the expected one of security risks severities
        
        :param result: content retrieved from backend.
        """

        assert "total" in result, f"'Total' key not found in the result"
    
        if 'total' in result and 'total' in expected:
            assert result['total']['value'] == expected['total']['value'], f"'Total' value mismatch: result: {result['total']['value']} != expected: {expected['total']['value']}"
        
        assert result['response']['severityResourceCounter'] == expected['response']['severityResourceCounter'], self.construct_message(f"Security risks severities resource counter response differs from the expected one. Response: {result['response']['severityResourceCounter']}, Expected: {expected['response']['severityResourceCounter']}")
        assert result['response']['totalResources'] == expected['response']['totalResources'], self.construct_message(f"Security risks severities total resources response differs from the expected one. Response: {result['response']['totalResources']}, Expected: {expected['response']['totalResources']}")


    

    def is_security_risk_empty(self, security_risk_ids):
        """
        is_security_risk_empty check if the security risks list are empty
        """
        r = self.backend.get_security_risks_list(
            cluster_name=self.cluster,
            namespace=self.namespace,
            security_risk_ids=security_risk_ids
            )
        
        response = json.loads(r.text)
        assert response['total']['value'] == 0, "Security risks found, expecting no security risks"
        return True
    
    def is_security_risk_resources_empty(self, security_risk_ids):
        """
        is_security_risk_resources_empty check if the security risks resources list are empty
        """
        r = self.backend.get_security_risks_resources(
            cluster_name=self.cluster,
            namespace=self.namespace,
            security_risk_id=security_risk_ids
            )
        
        response = json.loads(r.text)
        assert response['total']['value'] == 0, self.construct_message("Security risks resources found, expecting no security risks resources")
        return True
    
    def verify_security_risks_trends(self, expected_n_events_detected, expected_n_events_resolved, expected_current_detected, expected_change_from_beginning_of_period):
        """
        verify_security_risks_trends validate the security risks trends results on the backend
        """
        # current_datetime = datetime.now(timezone.utc)
        Logger.logger.info("wait for response from BE")
        r = self.backend.get_security_risks_trends(self.cluster,self.namespace, self.test_security_risk_ids)

        response = json.loads(r.text)

        Logger.logger.info('comparing security risks trends result with expected ones')

        assert len(response['securityIssuesTrends']) == EXPECTED_TRENDS_DAYS_BACK, self.construct_message(f"Security risks trends response differs from the expected one. Response: {len(response['securityIssuesTrends'])} != Expected: {EXPECTED_TRENDS_DAYS_BACK}") 

        assert response["totalDetectedForPeriod"] == expected_n_events_detected, self.construct_message(f"Security risks trends total detected for period response differs from the expected one. Response: {response['totalDetectedForPeriod']} != Expected: {expected_n_events_detected}")        
        assert response["totalResolvedForPeriod"] == expected_n_events_resolved, self.construct_message(f"Security risks trends total resolved for period response differs from the expected one. Response: {response['totalResolvedForPeriod']} != Expected: {expected_n_events_resolved}")
        assert response["currentDetected"] == expected_current_detected, self.construct_message(f"Security risks trends current detected response differs from the expected one. Response: {response['currentDetected']} != Expected: {expected_current_detected}")
        assert response["changeFromBeginningOfPeriod"] == expected_change_from_beginning_of_period, self.construct_message(f"Security risks trends change from beginning of period response differs from the expected one. Response: {response['changeFromBeginningOfPeriod']} != Expected: {expected_change_from_beginning_of_period}")
 
    def verify_security_risks_list_uniquevalues(self, list_result):
        """
        verify_security_risks_list_uniquevalues validate the security risks unique values results on the backend
        """

        baseFilters = {"clusterShortName":self.cluster,
                        "namespace":self.namespace,
                        "severity":"",
                        "category":"",
                        "smartRemediation":"",
                        "exceptionApplied":"|empty"}

        if self.with_network_policy:
            baseFilters["label"] = ""
            baseFilters["networkPolicyStatus"] = ""
            

        if self.test_security_risk_ids:
            baseFilters["securityRiskID"] = ','.join(self.test_security_risk_ids)

        for fieldName, _ in SECURITY_RISKS_EXPECTED_UNIQUE_VALUES_SUFFIX.items():
            Logger.logger.info(f"wait for response from BE with filter: {baseFilters} for field: {fieldName}")
            r = self.backend.get_security_risks_list_uniquevalues(baseFilters, fieldName)

            expected = summarize_uniquevalues(list_result, fieldName)
            response = json.loads(r.text)
       
            assert response == expected, self.construct_message(f"security risks unique values for '{fieldName}' response differs from the expected one. Response: {response}, Expected: {expected}")


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
        try:
            self.check_security_risks_severities(response, expected)
        except Exception as e:
            raise Exception(self.construct_message(f"Failed to validate security risks severities: {e}, response: {response}, expected: {expected}"))
    
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
        try:
            self.check_security_risks_categories(response, expected)
        except Exception as e:
            raise Exception(self.construct_message(f"Failed to validate security risks categories: {e}, response: {response}, expected: {expected}"))


    def verify_security_risks_list(self):
        """
        verify_security_risks_list validate the security risks results on the backend
        """
        # current_datetime = datetime.now(timezone.utc)
        Logger.logger.info(f"getting security risks list for {self.test_security_risk_ids}, cluster: {self.cluster}, namespace: {self.namespace}")
        r = self.backend.get_security_risks_list(self.cluster, self.namespace, self.test_security_risk_ids)

        Logger.logger.info(f"loading security risks scenario_key {self.scenario_key} to validate it")
        f = open(os.path.join(SCENARIOS_EXPECTED_VALUES, self.test_scenario+'_security-risks-list.json'))
        expected = json.load(f) 
        response = json.loads(r.text)

        filtered_expected = filter_security_risks_list(expected, self.test_security_risk_ids)

        Logger.logger.info(self.construct_message("comparing security risks result with expected ones"))
        try:
            self.check_security_risks_results(response, filtered_expected)
        except Exception as e:
            raise Exception(self.construct_message(f"Failed to validate security risks list: {e}, response: {response}, expected: {filtered_expected}"))

        return response


    def verify_security_risks_resources(self):
        """
        verify_security_risks_resources_sidebar validate the security risks resources on the backend
        """

        for security_risk_id, expectedPrefix in SECURITY_RISKS_RESOURCES_PREFIX.items():
            if security_risk_id in self.test_security_risk_ids:
                Logger.logger.info(self.construct_message(f"getting security risks resources"))
                r = self.backend.get_security_risks_resources(self.cluster, self.namespace, security_risk_id)

                Logger.logger.info('loading security risks scenario to validate it')
                f = open(os.path.join(SCENARIOS_EXPECTED_VALUES, self.test_scenario+expectedPrefix+'.json'))
                expected = json.load(f) 
                response = json.loads(r.text)

                Logger.logger.info(self.construct_message(f"comparing security risks resources result with expected ones"))
                try:
                    self.check_security_risks_resources_results(response, expected)
                except Exception as e:
                    raise Exception(self.construct_message(f"Failed to validate security risks resources for scenario_key : {self.scenario_key}, security risk id: {security_risk_id}: {e}, response: {response}, expected: {expected}"))
        

    def find_missing_security_risks(self, result, expected):
        """
        find_missing_security_risks - Find the missing security risks in the result compared to the expected ones
        """
        missingSecurityRiskIDs = []
        for securityRisk in expected['response']:
            if securityRisk['securityRiskID'] not in [sr['securityRiskID'] for sr in result['response']]:
                missingSecurityRiskIDs.append(securityRisk['securityRiskID'])
        return missingSecurityRiskIDs
    
    
    def verify_scan_status(self, trigger_time):
        """
        verify_scenario validate the scan status results on the backend
        """

        # self.verify_cluster_lastPostureScanTriggered_time(cluster_name=self.cluster, trigger_time=trigger_time)

        Logger.logger.info("validating scan status of attack chains is processing")
        r, t = self.wait_for_report(
            self.verify_cluster_field_in_scan_status, 
            timeout=60,
            cluster_name=self.cluster,
            sleep_interval=5,
            expected_field='attackChainsProcessingStatus',
            expectedStatus='processing'
            )
        Logger.logger.info("validating scan status of security risks is processing")
        r, t = self.wait_for_report(
            self.verify_cluster_field_in_scan_status, 
            timeout=1,
            cluster_name=self.cluster,
            expected_field='securityRisksProcessingStatus',
            expectedStatus='processing'
            )
        Logger.logger.info("validating scan status of attack chains is done")
        r, t = self.wait_for_report(
            self.verify_cluster_field_in_scan_status, 
            timeout=600,
            cluster_name=self.cluster,
            expected_field='attackChainsProcessingStatus',
            expectedStatus='done'
            )
        Logger.logger.info("validating scan status of security risks is done")
        r, t = self.wait_for_report(
            self.verify_cluster_field_in_scan_status, 
            timeout=180,
            cluster_name=self.cluster,
            expected_field='securityRisksProcessingStatus',
            expectedStatus='done'
            )
        
        Logger.logger.info("validating lastPostureScanTriggered for this cluster was updated")
        r, t = self.wait_for_report(
            self.verify_cluster_lastPostureScanTriggered_time,
            timeout=1,
            cluster_name=self.cluster,
            trigger_time=trigger_time
            )
        
        
    def verify_global_field_in_scan_status(self, expected_field, expectedStatus)-> bool:
        r = self.backend.get_scan_status()
        response = json.loads(r.text)
        assert response[expected_field] == expectedStatus, f"Expected {expected_field} to be {expectedStatus}, got {response[expected_field]}. Response: {response}"
        return True
    
    def verify_cluster_field_in_scan_status(self, cluster_name, expected_field, expectedStatus)-> bool:
        r = self.backend.get_scan_status()
        response = json.loads(r.text)
        for cluster_response in response['clusterScansStatus']:
            if cluster_response['clusterName'] == cluster_name:
                assert cluster_response[expected_field] == expectedStatus, f"Expected {expected_field} to be {expectedStatus}, got {cluster_response[expected_field]}. Response: {response}"
        return True
        
    def verify_cluster_lastPostureScanTriggered_time(self, cluster_name, trigger_time)-> bool:
        r = self.backend.get_scan_status()
        response = json.loads(r.text)
        for cluster_response in response['clusterScansStatus']:
            if cluster_response['clusterName'] == cluster_name:
                assert "lastPostureScanTriggered" in cluster_response, f"Expected 'lastPostureScanTriggered' to be in the response, got {cluster_response}"
                assert cluster_response['lastPostureScanTriggered'] >= trigger_time, f"Expected {'lastPostureScanTriggered'} to be >= than {trigger_time}, got {cluster_response['lastPostureScanTriggered']}"
        return True    
        


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

    assert len(result) == len(expected), f"List lengths differ: result: {len(result)} != expected: {len(expected)}"

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


def summarize_uniquevalues(response, field_name, count=False):
    """
    Transforms a list of dictionaries into a structured output based on the specified field.
    
    :param response: List of dictionaries containing the data.
    :param field_name: The name of the field to base the transformation on (e.g., "category").
    :return: A dictionary structured with unique field values and counts.
    """
    # Initializing a dictionary to count occurrences
    field_counts = {}

    # Count occurrences of each field value
    for item in response:
        if field_name in item:
            value = item[field_name]
            if value in field_counts:
                if count:
                    field_counts[value] += 1
            else:
                if count:
                    field_counts[value] = 1
                else: 
                    field_counts[value] = 0

    # Creating lists of fields and field counts
    fields_list = sorted(field_counts.keys())  # Sorting keys to maintain order
    fields_count_list = [{'key': key, 'count': field_counts[key]} for key in fields_list]

    # Creating the structured output
    structured_response = {
        "fields": {
            field_name: fields_list
        },
        "fieldsCount": {
            field_name: fields_count_list
        }
    }

    return structured_response
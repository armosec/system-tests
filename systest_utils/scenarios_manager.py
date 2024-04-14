from datetime import datetime,timezone
import os
import time
from tests_scripts.helm.base_helm import BaseHelm
from tests_scripts.kubescape.base_kubescape import BaseKubescape
from systest_utils import Logger, TestUtil, statics
from infrastructure import backend_api
import json
from tests_scripts import base_test


ATTACK_CHAINS_SCENARIOS_PATH = "./configurations/attack-chains-test-env"
ATTACK_CHAINS_EXPECTED_VALUES = "./configurations/attack_chains_expected_values"
SECURITY_RISKS_EXPECTED_VALUES = "./configurations/security_risks_expected_values"


class ScenarioManager(base_test.BaseTest):
    """
    ScenarioManager is a class that manage the in cluster scenarios deployment and validation.
    """

    def __init__(self, test_scenario, backend: backend_api.ControlPanelAPI, cluster, scenario_path=ATTACK_CHAINS_SCENARIOS_PATH):
        self.test_scenario = test_scenario
        self.backend = backend
        self.cluster = cluster
        self.scenario_path = scenario_path


    def apply_scenario(self):
        """
        apply_scenario apply the scenario manifests to the cluster
        """
        Logger.logger.info(f"Applying scenario manifests for {self.test_scenario}")
        deploy_cmd = os.path.join(self.scenario_path, 'deploy_scenario') + ' ' + os.path.join(self.scenario_path , self.test_scenario)
        TestUtil.run_command(command_args=deploy_cmd, display_stdout=True, timeout=300)
        time.sleep(5)

    

    def apply_fix(self, fix_type):
        """
        apply_fix apply the fix to the cluster
        """
        fix_command= os.path.join(self.scenario_path, self.test_scenario, 'fix_' + fix_type)
        TestUtil.run_command(command_args=fix_command, display_stdout=True, timeout=300)
        time.sleep(5)


    
    def verify_scenario(self, verify_attack_chains=True, verify_security_risks=False):
        """
        verify_scenario validate the scenario results on the backend

        :param verify_attack_chains: flag to verify the attack chains
        :param verify_security_risks: flag to verify the security risks
        """
        if verify_attack_chains:
            self.verify_attack_chains(ATTACK_CHAINS_EXPECTED_VALUES)
        
        if verify_security_risks:
            self.verify_security_risks(SECURITY_RISKS_EXPECTED_VALUES)

        

    def verify_attack_chains(self, expected_values_path, timeout=600):
        """
        verify_attack_chains validate the attack chains results on the backend
        """
        current_datetime = datetime.now(timezone.utc)
        Logger.logger.info("wait for response from BE")
        r, t = self.wait_for_report(
            self.backend.get_active_attack_chains, 
            timeout=timeout,
            current_datetime=current_datetime,
            cluster_name=self.cluster
            )

        Logger.logger.info('loading attack chain scenario to validate it')
        f = open(os.path.join(expected_values_path, self.test_scenario+'.json'))
        expected = json.load(f) 
        response = json.loads(r.text)

        Logger.logger.info('comparing attack-chains result with expected ones')
        assert self.check_attack_chains_results(response, expected), f"Attack chain response differs from the expected one. Response: {response}, Expected: {expected}"
        

    def verify_security_risks(self, expected_values_path, timeout=600):
        """
        verify_security_risks validate the security risks results on the backend
        """
        pass
    

    def verify_fix(self, verify_atack_chains=True, verify_security_risks=False):
        """
        verify_fix validate the fix results on the backend

        :param verify_attack_chains: flag to verify the attack chains
        :param verify_security_risks: flag to verify the security risks
        """
        if verify_atack_chains:
            self.verify_attack_chains_fix()
        
        if verify_security_risks:
            self.verify_security_risks_fix()


    def verify_attack_chains_fix(self):
        """
        verify_attack_chains_fix validate the attack chains fix results on the backend
        """
        Logger.logger.info("wait for response from BE")
        # we set the timeout to 1000s because image scan 
        # cat take more than 15m to get the updated result
        active_attack_chains, t = self.wait_for_report(
            self.backend.has_active_attack_chains, 
            timeout=1000, 
            cluster_name=self.cluster
            )

        Logger.logger.info('attack-chain fixed properly')


    def verify_security_risks_fix(self):
        """
        verify_security_risks_fix validate the security risks fix results on the backend
        """
        pass


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
                with_host_sensor="true"
            )
        else:
            self.backend.trigger_posture_scan(
                cluster_name=self.cluster,
                framework_list=["security"],
                with_host_sensor="true"
                )

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
    
from datetime import datetime, timezone
import time
import traceback
from tests_scripts.helm.base_helm import BaseHelm
from tests_scripts.kubescape.base_kubescape import BaseKubescape
from systest_utils import Logger, TestUtil, statics
from systest_utils.scenarios_manager import SecurityRisksScenarioManager, AttackChainsScenarioManager

DEFAULT_BRANCH = "release"


class ScanStatusWithKubescapeHelmChart(BaseHelm, BaseKubescape):
    """
    ScanStatusWithKubescapeHelmChart install the kubescape operator and run the scan to check status.
    """

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanStatusWithKubescapeHelmChart, self).__init__(test_obj=test_obj, backend=backend,
                                                               kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        """
        Agenda:
        1. Install kubescape with helm-chart
        2. Install attack-chains scenario manifests in the cluster
        3. Verify scenario on backend
        4. trigger posture scan
        5. verify scan status

        """
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('1. Install attack-chains scenario manifests in the cluster')
        Logger.logger.info(
            f"1.1 construct AttackChainsScenarioManager with test_scenario: {self.test_obj[('test_scenario', None)]} and cluster {cluster}")
        scenarios_manager = SecurityRisksScenarioManager(test_obj=self.test_obj, backend=self.backend, cluster=cluster,
                                                         namespace=namespace)

        Logger.logger.info("1.2 apply attack chains scenario manifests")
        scenarios_manager.apply_scenario()

        Logger.logger.info("2. Install kubescape with helm-chart")
        Logger.logger.info("2.1 Installing kubescape with helm-chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        Logger.logger.info("2.2 verify installation")
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        # TODO: fix the case on which the scan result is logged and triggers security risks before all kubernetes objects are created on backend.
        # meanwhile, sleeping to allow all kubernetes objects to be created on backend and triggering scan.
        time.sleep(20)
        scenarios_manager.trigger_scan(self.test_obj["test_job"][0]["trigger_by"])

        Logger.logger.info("3. Verify scenario on backend")
        scenarios_manager.verify_scenario()

        # wait for status to be updated to done before triggering another scan
        time.sleep(5)
        Logger.logger.info("4. trigger posture scan")
        time_before_scan = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        scenarios_manager.trigger_scan(self.test_obj["test_job"][0]["trigger_by"],
                                       additional_params={"triggeredFrom": "securityRiskPage"})

        Logger.logger.info("5. verify scan status")
        scenarios_manager.verify_scan_status(time_before_scan)

        return self.cleanup()


class ScanSecurityRisksWithKubescapeHelmChartMultiple(BaseHelm, BaseKubescape):
    """
    ScanSecurityRisksExceptionsWithKubescapeHelmChart install the kubescape operator and run the scan to check attack-chains.
    """

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanSecurityRisksWithKubescapeHelmChartMultiple, self).__init__(test_obj=test_obj, backend=backend,
                                                                      kubernetes_obj=kubernetes_obj,
                                                                      test_driver=test_driver)
        # disable node agent capabilities
        self.helm_kwargs = {
            "capabilities.runtimeObservability": "disable",
            # "capabilities.networkPolicyService": "disable", # network policy is enabled in order to check network policy security risks
            "capabilities.relevancy": "disabled",
            "capabilities.malwareDetection": "disable",
            "capabilities.runtimeDetection": "disable",
            "capabilities.seccompProfileService": "disable",
            "capabilities.nodeProfileService": "disable",
            statics.HELM_NODE_SBOM_GENERATION: statics.HELM_NODE_SBOM_GENERATION_DISABLED,

        }

        if self.test_obj.get_arg("helm_kwargs", default={}) != {}:
            self.helm_kwargs.update(self.test_obj.get_arg("helm_kwargs"))
        self.wait_for_agg_to_end = False
        self.scenario_managers: list[SecurityRisksScenarioManager] = []

        self.wait_for_agg_to_end = False

    def start(self):
        """
        Agenda:
        1. construct SecurityRisksScenarioManager objects
        2. apply security risks scenario manifests
        3. Install kubescape with helm-chart
        4. Verify scenarios on backend
        5. Apply security risks fixes
        6. trigger scan after fixes
        7. verify security risks fixes
        8. validate security risks trends

        """
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'


        self.ignore_agent = True
        self.cluster = self.get_cluster_name()

        current_datetime = datetime.now(timezone.utc)

        Logger.logger.info('1. construct SecurityRisksScenarioManager objects')
        self.constuct_scenario_managers()

        Logger.logger.info("2. apply security risks scenario manifests")
        self.apply_scenarios()

        Logger.logger.info("3. Install kubescape with helm-chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        time.sleep(30)

        Logger.logger.info("4. Verify scenarios on backend")
        self.scenario_managers[0].trigger_scan()
        total_events_detected = self.verify_scenarios(current_datetime)

        Logger.logger.info("5. Apply security risks fixes")
        self.apply_fixes()
        
        Logger.logger.info("6. trigger scan after fixes")
        self.scenario_managers[0].trigger_scan()

        Logger.logger.info("7. verify security risks fixes")
        self.verify_fixes()

        Logger.logger.info('7. validate security risks trends')
        self.verify_security_risks_trends(total_events_detected)

        return self.cleanup()

    def constuct_scenario_managers(self):
        for item in self.test_obj["test_job"]:

            # create a new test_obj for each scenario
            # take the first test_obj and update the test_job to be the current item
            tmp_test_obj = self.test_obj
            tmp_test_obj.kwargs["test_job"] = [item]

            namespace =  self.create_namespace()
            scenarios_manager = SecurityRisksScenarioManager(test_obj=tmp_test_obj, backend=self.backend, cluster=self.cluster, namespace=namespace)
            self.scenario_managers.append(scenarios_manager)

    def apply_scenarios(self):
        for scenarios_manager in self.scenario_managers:
            scenarios_manager.apply_scenario()
        time.sleep(30)

    def verify_scenarios(self, current_datetime, timeoutsec=600):
        start_datetime = datetime.now(timezone.utc)
        end_last_run = start_datetime

        verification_report = {}
        succeded = True
        total_events_detected = []
        for scenarios_manager in self.scenario_managers:
            scenario_key = scenarios_manager.scenario_key
            verification_report[scenario_key] = "Scenario not verified yet"

            time_difference_seconds = round((end_last_run - start_datetime).total_seconds())
            timeout = timeoutsec - time_difference_seconds
            if timeout < 0:
                verification_report[scenario_key] = "Timeout reached"
                succeded = False
                break
            Logger.logger.info(f"verify scenario {scenario_key}")
            try:
                result = scenarios_manager.verify_scenario(timeout=timeout)

                events_detected = sum(res['affectedResourcesCount'] for res in result['response'])
                total_events_detected.append(events_detected)

                scenarios_manager.construct_message("validating security risks categories")
                scenarios_manager.verify_security_risks_categories(result)
                
                scenarios_manager.construct_message("validating security risks severities")
                scenarios_manager.verify_security_risks_severities(result)

                # verify unique values - no need to wait.
                scenarios_manager.construct_message("validating security risks unique values")
                scenarios_manager.verify_security_risks_list_uniquevalues(result["response"])

                # verify resources side panel - no need to wait.
                scenarios_manager.construct_message("validating security risks resources")
                scenarios_manager.verify_security_risks_resources()

            except Exception as e:
                error_stack = traceback.format_exc()
                verification_report[scenario_key] = f"Failed to verify scenario on backend, got exception {e}, stack: {error_stack}"
                succeded = False
            else:
                Logger.logger.info(f"scenario verified {scenario_key}")
                verification_report[scenario_key] = "verified"
            end_last_run = datetime.now(timezone.utc)
        
        if not succeded:
            nice_report = "\n".join([f"{key}: {value}" for key, value in verification_report.items()])
            raise Exception(f"Failed to verify all scenarios on backend: \n {nice_report}")
        
        return total_events_detected
    
    def apply_fixes(self):
        for scenarios_manager in self.scenario_managers:
            Logger.logger.info(f"apply fix for scenario {scenarios_manager.scenario_key}")
            scenarios_manager.apply_fix()

    def verify_fixes(self, timeoutsec=600):
        start_datetime = datetime.now(timezone.utc)
        end_last_run = start_datetime

        verification_report = {}
        succeded = True
        for scenarios_manager in self.scenario_managers:
            scenario_key = scenarios_manager.scenario_key
            verification_report[scenario_key] = "Fix not verified yet"

            time_difference_seconds = round((end_last_run - start_datetime).total_seconds())
            timeout = timeoutsec - time_difference_seconds

            # break if timeout is reached
            if timeout < 0:
                verification_report[scenario_key] = "Timeout reached"
                succeded = False
                break
            Logger.logger.info(f"verify fix for scenario {scenarios_manager.scenario_key}")
            try:
                scenarios_manager.verify_fix(timeout=timeout)
            except Exception as e:
                error_stack = traceback.format_exc()
                verification_report[scenario_key] = f"Failed to verify fix, got exception {e} stack: {error_stack}"
                succeded = False
            else:
                Logger.logger.info(f"fix verified for scenario {scenarios_manager.scenario_key}")
                verification_report[scenario_key] = "verified"
            end_last_run = datetime.now(timezone.utc)
            
    
        if not succeded:
            nice_report = "\n".join([f"{key}: {value}" for key, value in verification_report.items()])
            raise Exception(f"Failed to verify all fixes: \n {nice_report}")
        
    def verify_security_risks_trends(self, total_events_detected:list):
        """
        validate security risks trends
        params:
        total_events_detected: list of total events detected for each scenario
        """
        for i in range(len(total_events_detected)):
            self.scenario_managers[i].verify_security_risks_trends(total_events_detected[i], total_events_detected[i], 0, 0)
        Logger.logger.info('attack-chain fixed properly')
        return self.cleanup()
    

class ScanSecurityRisksWithKubescapeHelmChart(BaseHelm, BaseKubescape):
    """
    ScanSecurityRisksExceptionsWithKubescapeHelmChart install the kubescape operator and run the scan to check attack-chains.
    """

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanSecurityRisksWithKubescapeHelmChart, self).__init__(test_obj=test_obj, backend=backend,
                                                                      kubernetes_obj=kubernetes_obj,
                                                                      test_driver=test_driver)
        self.wait_for_agg_to_end = False

    def start(self):
        """
        Agenda:
        1. Install attack-chains scenario manifests in the cluster
        2. Install kubescape with helm-chart
        3. Verify scenario on backend
        4. Verify security risks categories
        5. Verify security risks severities
        6. Verify security risks unique values
        7. Verify security risks resources
        8. Apply attack chain fix
        9. trigger scan after fix
        10. verify fix
        11. validate security risks trends

        """
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        # skip test for production backend
        if self.test_driver.test_name == "sr_r_0037_vulnerability" and self.backend.server == "https://api.armosec.io":
            Logger.logger.info(f"Skipping test '{self.test_driver.test_name}' for production backend")
            return statics.SUCCESS, ""

        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info("1. Install kubescape with helm-chart")
        Logger.logger.info("1.1 Installing kubescape with helm-chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        Logger.logger.info("1.2 verify installation")
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        scenario = self.test_obj[('test_scenario', None)]
        Logger.logger.info(f'2. Install %s scenario manifests in the cluster', scenario)

        Logger.logger.info(
            f"2.1 construct SecurityRisksScenarioManager with test_scenario: {self.test_obj[('test_scenario', None)]} and cluster {cluster}")
        scenarios_manager = SecurityRisksScenarioManager(test_obj=self.test_obj, backend=self.backend, cluster=cluster,
                                                         namespace=namespace)

        Logger.logger.info("2.2 apply scenario manifests")
        scenarios_manager.apply_scenario()
        # TODO: fix the case on which the scan result is logged and triggers security risks before all kubernetes objects are created on backend.
        # meanwhile, sleeping to allow all kubernetes objects to be created on backend and triggering scan.

        if "trigger_by" in self.test_obj["test_job"][0]:
            time.sleep(60)
            scenarios_manager.trigger_scan(self.test_obj["test_job"][0]["trigger_by"])

        Logger.logger.info("3. Verify scenario on backend")
        result = scenarios_manager.verify_scenario()

        total_events_detected = sum(res['affectedResourcesCount'] for res in result['response'])

        Logger.logger.info("4. validating security risks categories")
        scenarios_manager.verify_security_risks_categories(result)

        Logger.logger.info("5. validating security risks severities")
        scenarios_manager.verify_security_risks_severities(result)
        # verify unique values - no need to wait.
        Logger.logger.info("6. validating security risks unique values")
        scenarios_manager.verify_security_risks_list_uniquevalues(result["response"])

        # verify resources side panel - no need to wait.
        Logger.logger.info("7. validating security risks resources")
        scenarios_manager.verify_security_risks_resources()

        Logger.logger.info("8. Apply scenario fix")
        scenarios_manager.apply_fix(self.test_obj[("fix_object", "control")])

        Logger.logger.info("9. trigger scan after fix")
        if "trigger_by" in self.test_obj["test_job"][0]:
            scenarios_manager.trigger_scan(self.test_obj["test_job"][0]["trigger_by"])

        Logger.logger.info("10. verify fix")
        scenarios_manager.verify_fix()

        # after fix is verified, we expect total detected to be equal to total resolved
        total_events_resolved = total_events_detected

        Logger.logger.info('11. validate security risks trends')
        # wait a bit for trends to be updated
        time.sleep(5)
        # after resolve we expect total detected and total resolved to be the same and total new and total remaining to be 0
        scenarios_manager.verify_security_risks_trends(total_events_detected, total_events_resolved, 0, 0)

        Logger.logger.info('attack-chain fixed properly')
        return self.cleanup()


class ScanSecurityRisksExceptionsWithKubescapeHelmChart(BaseHelm, BaseKubescape):
    """
    ScanSecurityRisksExceptionsWithKubescapeHelmChart install the kubescape operator and run the scan to check attack-chains.
    """

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanSecurityRisksExceptionsWithKubescapeHelmChart, self).__init__(test_obj=test_obj, backend=backend,
                                                                                kubernetes_obj=kubernetes_obj,
                                                                                test_driver=test_driver)
        self.wait_for_agg_to_end = False
        self.exceptions_guids = []

    def start(self):
        """
        Agenda:
        1. Install attack-chains scenario manifests in the cluster
        2. Install kubescape with helm-chart
        3. Verify scenario on backend
        4. Add new exception.
        5. Verify resources under exceptions are filtered out from security risks list.
        6. Verify resources under exceptions are filtered out from security risks resources.
        7. edit exception.
        8. delete exception.
        9. Verify resources are back to security risks list.
        10. verify resources are back to security risks resources.


        """
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('1. Install attack-chains scenario manifests in the cluster')
        Logger.logger.info(
            f"1.1 construct AttackChainsScenarioManager with test_scenario: {self.test_obj[('test_scenario', None)]} and cluster {cluster}")
        scenarios_manager = SecurityRisksScenarioManager(test_obj=self.test_obj, backend=self.backend, cluster=cluster,
                                                         namespace=namespace)

        Logger.logger.info("1.2 apply attack chains scenario manifests")
        scenarios_manager.apply_scenario()

        Logger.logger.info("2. Install kubescape with helm-chart")
        Logger.logger.info("2.1 Installing kubescape with helm-chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        Logger.logger.info("2.2 verify installation")
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        # TODO: fix the case on which the scan result is logged and triggers security risks before all kubernetes objects are created on backend.
        # meanwhile, sleeping to allow all kubernetes objects to be created on backend and triggering scan.
        time.sleep(20)
        scenarios_manager.trigger_scan(self.test_obj["test_job"][0]["trigger_by"])

        Logger.logger.info("3. Verify scenario on backend")
        result = scenarios_manager.verify_scenario()

        test_security_risk_id = scenarios_manager.test_security_risk_ids[0]
        resources_list_before_exception = scenarios_manager.get_security_risks_resources(test_security_risk_id)
        security_risks_list_before_exception = scenarios_manager.get_security_risks_list([test_security_risk_id])

        k8s_resources_hash = []
        for resource in resources_list_before_exception["response"]:
            k8s_resources_hash.append(resource["k8sResourceHash"])

        Logger.logger.info("4. Add new exception.")
        Logger.logger.info(
            "4.1 adding new exception for security risk id: {} and resources: {}".format(test_security_risk_id,
                                                                                         k8s_resources_hash))
        exceptions_resources = [
             {
                    "designatorType": "Attribute",
                    "attributes":
                        {
                            "cluster": cluster,
                            "namespace": namespace
                        }
                }
        ]
        new_exception = scenarios_manager.add_new_exception(test_security_risk_id, exceptions_resources, "new exception")
        self.exceptions_guids.append(new_exception["guid"])

        Logger.logger.info("5. Verify resources under exceptions are filtered out from security risks list.")
        resources_list_after_exception = scenarios_manager.get_security_risks_resources(test_security_risk_id)
        assert len(resources_list_after_exception[
                       "response"]) == 0, "resources under exception are not filtered out from security risks list"

        Logger.logger.info("6. Verify resources under exceptions are filtered out from security risks resources.")
        security_risks_list_after_exception = scenarios_manager.get_security_risks_list([test_security_risk_id])
        assert len(security_risks_list_after_exception[
                       "response"]) == 0, "resources under exception are not filtered out from security risks resources"

        Logger.logger.info("7. edit exception.")
        edit_exception = scenarios_manager.edit_exception(new_exception["guid"], test_security_risk_id,
                                                          exceptions_resources, "edit exception")
        resources_list_after_exception_edit = scenarios_manager.get_security_risks_resources(test_security_risk_id)
        security_risks_list_after_exception_edit = scenarios_manager.get_security_risks_list([test_security_risk_id])

        assert len(resources_list_after_exception_edit[
                       "response"]) == 0, "resources under exception are not filtered out from security risks list"
        assert len(security_risks_list_after_exception_edit[
                       "response"]) == 0, "resources under exception are not filtered out from security risks resources"

        Logger.logger.info("8. delete exception.")
        scenarios_manager.delete_exception(edit_exception["guid"])

        Logger.logger.info("9. Verify resources are back to security risks list.")
        resources_list_after_exception_delete = scenarios_manager.get_security_risks_resources(test_security_risk_id)
        assert len(resources_list_after_exception_delete["response"]) == len(resources_list_before_exception[
                                                                                 "response"]), "resources are not back to security risks resources as before exception"

        Logger.logger.info("10. verify resources are back to security risks resources.")
        security_risks_list_after_exception_delete = scenarios_manager.get_security_risks_list([test_security_risk_id])
        assert len(security_risks_list_after_exception_delete["response"]) == len(security_risks_list_before_exception[
                                                                                      "response"]), "resources are not back to security risks list as before exception"
        assert security_risks_list_after_exception_delete["response"][0]["affectedResourcesCount"] == \
               security_risks_list_before_exception["response"][0][
                   "affectedResourcesCount"], "resources are not back to security risks list as before exception"




        return self.cleanup()

    def cleanup(self):
        for exception_guid in self.exceptions_guids:
            self.backend.delete_security_risks_exception(exception_guid)
            Logger.logger.info(f"deleted exception with guid: {exception_guid}")
        return super().cleanup()



class ScanAttackChainsWithKubescapeHelmChartMultiple(BaseHelm, BaseKubescape):
    """
    ScanAttackChainsWithKubescapeHelmChartMultiple install the kubescape operator and run the scan to check attack-chains.
    """

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanAttackChainsWithKubescapeHelmChartMultiple, self).__init__(test_obj=test_obj, backend=backend,
                                                                     kubernetes_obj=kubernetes_obj,
                                                                     test_driver=test_driver)
        
        # disable node agent capabilities
        self.helm_kwargs = {
            "capabilities.runtimeObservability": "disable",
            "capabilities.networkPolicyService": "disable",
            "capabilities.relevancy": "disabled",
            "capabilities.malwareDetection": "disable",
            "capabilities.runtimeDetection": "disable",
            "capabilities.seccompProfileService": "disable",
            "capabilities.nodeProfileService": "disable",
            statics.HELM_NODE_SBOM_GENERATION: statics.HELM_NODE_SBOM_GENERATION_DISABLED,
        }

        if self.test_obj.get_arg("helm_kwargs", default={}) != {}:
            self.helm_kwargs.update(self.test_obj.get_arg("helm_kwargs"))
        self.wait_for_agg_to_end = False
        self.scenario_managers: list[AttackChainsScenarioManager] = []

    def start(self):
        """
        Agenda:
        1. construct AttackChainsScenarioManager objects
        2. apply attack chains scenario manifests
        3. Install kubescape with helm-chart
        4. Verify scenarios on backend
        5. Apply attack chains fix
        6. trigger scan after fixes
        7. verify attack chains fixes

        """
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        self.ignore_agent = True
        self.cluster = self.get_cluster_name()

        current_datetime = datetime.now(timezone.utc)

        Logger.logger.info('1. construct AttackChainsScenarioManager objects')
        self.constuct_scenario_managers()
        
        Logger.logger.info("2. apply attack chains scenario manifests")
        self.apply_scenarios()

        Logger.logger.info("3. Install kubescape with helm-chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=240)


        Logger.logger.info("4. Verify scenarios on backend")
        self.verify_scenarios(current_datetime)
        

        Logger.logger.info("5. Apply attack chains fix")
        self.apply_fixes()

        Logger.logger.info("6. trigger scan after fixes")
        self.scenario_managers[0].trigger_scan()

        Logger.logger.info("7. verify attack chains fixes")
        self.verify_fixes()
        
        Logger.logger.info('all is good')
        return self.cleanup()

    def constuct_scenario_managers(self):
        for item in self.test_obj["test_job"]:

            # create a new test_obj for each scenario
            # take the first test_obj and update the test_job to be the current item
            tmp_test_obj = self.test_obj
            tmp_test_obj.kwargs["test_job"] = [item]

            namespace = "default" if item.get("default_namespace", False) else self.create_namespace()
            scenarios_manager = AttackChainsScenarioManager(test_obj=tmp_test_obj, backend=self.backend, cluster=self.cluster, namespace=namespace)
            self.scenario_managers.append(scenarios_manager)

    def apply_scenarios(self):
        for scenarios_manager in self.scenario_managers:
            scenarios_manager.apply_scenario()
        time.sleep(30)

    def verify_scenarios(self, current_datetime, timeoutsec=600):
        start_datetime = datetime.now(timezone.utc)
        end_last_run = start_datetime

        verification_report = {}
        succeded = True
        for scenarios_manager in self.scenario_managers:
            scenario_key = scenarios_manager.scenario_key
            verification_report[scenario_key] = "Scenario not verified yet"

            time_difference_seconds = round((end_last_run - start_datetime).total_seconds())
            timeout = timeoutsec - time_difference_seconds
            if timeout < 0:
                verification_report[scenario_key] = "Timeout reached"
                succeded = False
                break
            Logger.logger.info(f"verify scenario {scenario_key}")
            try:
                scenarios_manager.verify_scenario(current_datetime, timeout=timeout)
            except Exception as e:
                error_stack = traceback.format_exc()
                verification_report[scenario_key] = f"Failed to verify scenario on backend, got exception {e}, stack: {error_stack}"
                succeded = False
            else:
                Logger.logger.info(f"scenario verified {scenario_key}")
                verification_report[scenario_key] = "verified"
            end_last_run = datetime.now(timezone.utc)
        
        if not succeded:
            nice_report = "\n".join([f"{key}: {value}" for key, value in verification_report.items()])
            raise Exception(f"Failed to verify all scenarios on backend: \n {nice_report}")
    
    def apply_fixes(self):
        for scenarios_manager in self.scenario_managers:
            Logger.logger.info(f"apply fix for scenario {scenarios_manager.scenario_key}")
            scenarios_manager.apply_fix()

    def verify_fixes(self, timeoutsec=600):
        start_datetime = datetime.now(timezone.utc)
        end_last_run = start_datetime

        verification_report = {}
        succeded = True
        for scenarios_manager in self.scenario_managers:
            scenario_key = scenarios_manager.scenario_key
            verification_report[scenario_key] = "Fix not verified yet"

            time_difference_seconds = round((end_last_run - start_datetime).total_seconds())
            timeout = timeoutsec - time_difference_seconds

            # break if timeout is reached
            if timeout < 0:
                verification_report[scenario_key] = "Timeout reached"
                succeded = False
                break
            Logger.logger.info(f"verify fix for scenario {scenarios_manager.scenario_key}")
            try:
                scenarios_manager.verify_fix(timeout=timeout)
            except Exception as e:
                error_stack = traceback.format_exc()
                verification_report[scenario_key] = f"Failed to verify fix, got exception {e} stack: {error_stack}"
                succeded = False
            else:
                Logger.logger.info(f"fix verified for scenario {scenarios_manager.scenario_key}")
                verification_report[scenario_key] = "verified"
            end_last_run = datetime.now(timezone.utc)
            
    
        if not succeded:
            nice_report = "\n".join([f"{key}: {value}" for key, value in verification_report.items()])
            raise Exception(f"Failed to verify all fixes: \n {nice_report}")


class ScanWithKubescapeHelmChart(BaseHelm, BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanWithKubescapeHelmChart, self).__init__(test_obj=test_obj, backend=backend,
                                                         kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'
        # test Agenda:

        # P1 Install Wikijs
        # 1.1 install Wikijs
        # 1.2 verify installation
        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)

        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)

        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        Logger.logger.info("Stage 1.2: Get old report-guid")
        old_report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(), wait_to_result=False)

        Logger.logger.info("Installing kubescape with helm-chart")
        # 2.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 2.2 install armo helm-chart
        self.install_armo_helm_chart()

        # 2.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        Logger.logger.info("Stage 2.2: Get report-guid")
        report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(),
                                           old_report_guid=old_report_guid)

        self.test_helm_chart_results(report_guid=report_guid)

        return self.cleanup()


class ScanWithKubescapeAsServiceTest(BaseHelm, BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanWithKubescapeAsServiceTest, self).__init__(test_obj=test_obj, backend=backend,
                                                             kubernetes_obj=kubernetes_obj, test_driver=test_driver)

        self.helm_kwargs = {
            "capabilities.vulnerabilityScan": "disable",
            "capabilities.relevancy": "disable"
        }

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'
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

        Logger.logger.info("Installing kubescape with helm-chart")
        # 2.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 2.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=240)

        self.test_scan_jobs(port=statics.KS_PORT_FORWARD)

        return self.cleanup()

    def test_scan_jobs(self, port):

        cluster_name = self.kubernetes_obj.get_cluster_name()
        Logger.logger.info("Get old report-guid")
        old_report_guid = self.get_report_guid(cluster_name=cluster_name, wait_to_result=True)
        Logger.logger.info("Port forwarding to kubescape pod")
        pod_name = self.kubernetes_obj.get_kubescape_pod(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        self.port_forward_proc = self.kubernetes_obj.portforward(cluster_name, statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                                 pod_name, 8080)

        Logger.logger.info("Starting tests scenarios")

        for job in self.test_obj["test_job"]:
            job_type = job["trigger_by"]
            if job_type == "scan_on_start":
                self.check_result_in_namespace_creation(job, cluster_name, "", port=port)
            elif job_type == "job":
                self.check_result_with_backend_demand(job, cluster_name, old_report_guid, port=port)
            elif job_type == "cronjob":
                self.check_result_with_backend_cronjob(job, cluster_name, old_report_guid, port=port)

    def check_result_in_namespace_creation(self, job, cluster_name, old_report_guid, port):
        Logger.logger.info('check result in namespace creation')
        report_guid = self.get_report_guid(cluster_name=cluster_name,
                                           old_report_guid=old_report_guid)

        Logger.logger.info('get result from kubescape in cluster')
        kubescape_result = self.get_kubescape_as_server_last_result(cluster_name, port=port, report_guid=report_guid)

        Logger.logger.info('test result against backend results')
        self.test_backend_vs_kubescape_result(report_guid=report_guid, kubescape_result=kubescape_result)

        return report_guid

    def check_result_with_backend_demand(self, job, cluster_name, old_report_guid, port):
        trigger_by = job["trigger_by"]
        framework_list = None
        if "framework" in job.keys():
            framework_list = job["framework"]
        with_host_sensor = "false"
        if "hostsensor" in job.keys():
            if job["hostsensor"]:
                with_host_sensor = "true"

        Logger.logger.info("create scan by backend trigger")

        self.backend.create_kubescape_job_request(cluster_name=cluster_name, trigger_by=trigger_by,
                                                  framework_list=framework_list, with_host_sensor=with_host_sensor)

        if with_host_sensor == "true":
            Logger.logger.info('check hostsensor trigger')
            assert self.is_hostsensor_triggered(), "host sensor has not triggered"

        Logger.logger.info("Get report-guid")
        report_guid = self.get_report_guid(cluster_name=cluster_name,
                                           old_report_guid=old_report_guid,
                                           framework_name=framework_list[0])

        Logger.logger.info('get result from kubescape in cluster')
        kubescape_result = self.get_kubescape_as_server_last_result(cluster_name, port, report_guid)

        Logger.logger.info('test result against backend results')
        self.test_backend_vs_kubescape_result(report_guid=report_guid, kubescape_result=kubescape_result)

    def check_result_with_backend_cronjob(self, job, cluster_name, old_report_guid, port):
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

        if job["operation"] == "update":
            Logger.logger.info("update kubescape cronjob")

            Logger.logger.info("check if kubescape cronjob created")
            assert self.is_ks_cronjob_created(framework_list[0]), "kubescape cronjob failed to create"
            cron_job_schedule = self.kubernetes_obj.get_ks_cronjob_schedule(statics.CA_NAMESPACE_FROM_HELM_NAME)

            Logger.logger.info("update kubescape cronjob created")
            cronjobs_name = self.kubernetes_obj.get_ks_cronjob_name(statics.CA_NAMESPACE_FROM_HELM_NAME)
            self.backend.update_kubescape_job_request(cluster_name=cluster_name, cronjobs_name=cronjobs_name)

            # Schedule update propagation is eventually consistent (backend → cluster).
            # Poll for the schedule to change instead of a fixed sleep to reduce flakes.
            def _schedule_changed():
                new_schedule = self.kubernetes_obj.get_ks_cronjob_schedule(statics.CA_NAMESPACE_FROM_HELM_NAME)
                assert new_schedule is not None, "kubescape cronjob schedule not found yet"
                assert new_schedule != cron_job_schedule, (
                    f"kubescape schedule string is not changed yet (still '{new_schedule}', old '{cron_job_schedule}')"
                )
                return True

            self.wait_for_report(timeout=180, sleep_interval=10, report_type=_schedule_changed)

            Logger.logger.info("check if kubescape update succeeded")
            assert self.is_ks_cronjob_created(framework_list[0]), "kubescape cronjob failed to create"
            new_cron_job_schedule = self.kubernetes_obj.get_ks_cronjob_schedule(statics.CA_NAMESPACE_FROM_HELM_NAME)
            assert cron_job_schedule != new_cron_job_schedule, "kubescape schedule string is not changed new {} old {}".format(
                new_cron_job_schedule, cron_job_schedule)

        if job["operation"] == "delete":
            Logger.logger.info("delete kubescape cronjob")

            Logger.logger.info("check if kubescape cronjob exist")
            assert self.is_ks_cronjob_created(framework_list[0]), "kubescape cronjob is not exist"

            Logger.logger.info("delete kubescape cronjob created")
            cron_job_schedule = self.kubernetes_obj.get_ks_cronjob_schedule(statics.CA_NAMESPACE_FROM_HELM_NAME)
            cronjobs_name = self.kubernetes_obj.get_ks_cronjob_name(statics.CA_NAMESPACE_FROM_HELM_NAME)
            self.backend.delete_kubescape_job_request(cluster_name=cluster_name, schedule=cron_job_schedule,
                                                      cronjobs_name=cronjobs_name)

            Logger.logger.info("check if kubescape cronjob deleted")
            assert self.is_ks_cronjob_deleted(framework_list[0]), "kubescape cronjob failed to deleted"


class ControlClusterFromCLI(BaseHelm, BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ControlClusterFromCLI, self).__init__(test_obj=test_obj, backend=backend,
                                                    kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        # test check in cluster workloads and kubescape CLI
        # assert self.backend == None; f'the test {self.test_driver.test_name} must run without backend'

        # 1 install kubescape in cluster workloads
        Logger.logger.info("Installing kubescape with helm-chart")
        # 1.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 1.2 install armo helm-chart
        self.install_armo_helm_chart()
        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=240)

        # 2 install kubescape CLI
        Logger.logger.info("Installing kubescape CLI")
        # 2.1 Installing kubescape CLI
        self.install(branch=self.ks_branch)

        # 3 trigger in cluster components
        Logger.logger.info("Triggering in cluster components")
        # 3.1 trigger in cluster components
        self.trigger_in_cluster_components(cli_args=self.parse_cli_args(args=self.test_obj["cli_args"]))

        # 4 validate cluster trigger
        Logger.logger.info("Validate triggering in cluster components")
        # 4.1 validate cluster trigger
        self.validate_cluster_trigger_as_expected(cluster_name=self.get_cluster_name(), args=self.test_obj["cli_args"])

        return self.cleanup()




class ScanSBOM(BaseHelm, BaseKubescape):
    """
    ScanSBOM install the kubescape operator and check SBOM.
    """

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanSBOM, self).__init__(test_obj=test_obj, backend=backend,
                                                                     kubernetes_obj=kubernetes_obj,
                                                                     test_driver=test_driver)
        
        # disable node agent capabilities
        self.helm_kwargs = {
            statics.HELM_NODE_SBOM_GENERATION: statics.HELM_NODE_SBOM_GENERATION_DISABLED,
            statics.HELM_SYNC_SBOM: statics.HELM_SYNC_SBOM_ENABLED,
        }

        if self.test_obj.get_arg("helm_kwargs", default={}) != {}:
            self.helm_kwargs.update(self.test_obj.get_arg("helm_kwargs"))
        self.wait_for_agg_to_end = False

    def start(self):
        """
        Agenda:

        1. Install kubescape with helm-chart
        2. Install deployments in the cluster
        3. verify SBOM scan results
        4. verify SBOM scan results unique values
        5. verify SBOM scan results in use
        """
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        self.ignore_agent = True
        self.cluster, self.namespace = self.setup(apply_services=False)





        Logger.logger.info("1. Install kubescape with helm-chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=240)

        Logger.logger.info('2. Install deployments in the cluster')
        current_datetime = datetime.now(timezone.utc)
        workload_objs: list = self.apply_directory(path=self.test_obj[("deployments", None)], namespace=self.namespace)
        self.wait_for_report(self.verify_running_pods, sleep_interval=10, timeout=180, namespace=self.namespace)



        Logger.logger.info("3. verify SBOM scan results")
        filters = {
            "cluster": self.cluster,
            "namespace": self.namespace,
            "workload": "nginx",
            "name": "passwd",
        }
        self.wait_for_report(self.verify_backend_results, sleep_interval=10, timeout=240, filters=filters)


        Logger.logger.info("4. verify SBOM scan results unique values")
        self.verify_backend_results_uniquevalues(filters=filters, field="workload", expected_value="nginx")


        filters = {
            "cluster": self.cluster,
            "namespace": self.namespace,
            "workload": "nginx",
        }

        Logger.logger.info("5. verify SBOM scan results in use")
        self.wait_for_report(self.verify_backend_results_in_use, sleep_interval=10, timeout=240, filters=filters)

        return self.cleanup()
    


    def verify_backend_results(self, filters):
        """
        Verify the results of the scan
        """
        body = {
            "pageSize": 50,
            "pageNum": 1,
            "innerFilters": [
                filters
            ]
        }

        components = self.backend.get_vuln_v2_components(body=body, scope='component', enrich_tickets=False)
        
        # First validate that we got a response
        assert components is not None, "Backend returned None for components"
            
        # Then validate the response structure
        assert isinstance(components, list), f"Expected components to be a list, got {type(components)}"
        assert len(components) == 1, f"Expected 1 component, got {len(components)}"
    
        component = components[0]
        
        # Validate component structure
        assert isinstance(component, dict), f"Expected component to be a dict, got {type(component)}"
            
        # Validate required fields
        assert "name" in component, "Component missing 'name' field"
        assert "licenses" in component, "Component missing 'licenses' field"
        assert "severityStats" in component, "Component missing 'severityStats' field"
            
        # Validate field values
        assert component["name"] == filters["name"], f"Expected component name to be {filters['name']}, got {component['name']}"
            
        assert isinstance(component["licenses"], list), f"Expected licenses to be a list, got {type(component['licenses'])}"
        assert len(component["licenses"]) > 0, "Expected at least one license"
            
        assert isinstance(component["severityStats"], dict), f"Expected severityStats to be a list, got {type(component['severityStats'])}"
        assert len(component["severityStats"]) > 0, "Expected at least one severity stat"

    
    def verify_backend_results_in_use(self, filters):
        """
        Verify the results of the scan
        """

        body = {
            "pageSize":50,
            "pageNum":1,
            "innerFilters":[
              filters
            ]
        }

        filters["isRelevant"] = "Yes"

        components = self.backend.get_vuln_v2_components(body=body, scope='component', enrich_tickets=False)
        assert len(components) > 0, f"expected at least 1 in use component, got {len(components)}"    
       
        filters["isRelevant"] = "No"

        components = self.backend.get_vuln_v2_components(body=body, scope='component', enrich_tickets=False)
        assert len(components) >= 0 , f"expected at least 0 not in use component, got {len(components)}"


    def verify_backend_results_uniquevalues(self, filters, field, expected_value):
        """
        Verify the results of the scan
        """

        uniuqevalues_body = {
            "pageSize":50,
            "pageNum":1,
            "fields":{field:""},
            "innerFilters":[
              filters
            ]
        }

        uniquevalues = self.backend.get_vuln_v2_component_uniquevalues(body=uniuqevalues_body)

        assert "fields" in uniquevalues, "expected fields in uniquevalues, got None"
        assert "workload" in uniquevalues["fields"], "expected workload in uniquevalues, got None"
        assert len(uniquevalues["fields"]["workload"]) == 1, f"expected 1 workload, got {len(uniquevalues['fields']['workload'])}"
        assert uniquevalues["fields"]["workload"][0] == expected_value, f"expected {expected_value}, got {uniquevalues['fields']['workload'][0]}"



        
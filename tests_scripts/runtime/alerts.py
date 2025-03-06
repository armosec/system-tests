

import json
from random import random
import time
from configurations.system.tests_cases.structures import TestConfiguration
from infrastructure.kubectl_wrapper import KubectlWrapper
from systest_utils.systests_utilities import TestUtil
from systest_utils.tests_logger import Logger
from tests_scripts.base_test import BaseTest
from tests_scripts.runtime.incidents import __RELATED_ALERTS_KEY__
from tests_scripts.runtime.policies import POLICY_CREATED_RESPONSE, RuntimePoliciesConfigurations
from tests_scripts.users_notifications.alert_notifications import TEST_NAMESPACE, AlertNotifications, get_env


class IncidentsAlerts(AlertNotifications, RuntimePoliciesConfigurations):
    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(IncidentsAlerts, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

        self.helm_kwargs = {
            "capabilities.configurationScan": "disable",
            "capabilities.continuousScan": "disable",
            "capabilities.nodeScan": "disable",
            "capabilities.vulnerabilityScan": "disable",
            "grypeOfflineDB.enabled": "false",
            # not clear why
            "capabilities.relevancy": "enable",
            # enable application profile, malware and runtime detection
            "capabilities.runtimeObservability": "enable",
            "capabilities.malwareDetection": "enable",
            "capabilities.runtimeDetection": "enable",
            "capabilities.nodeProfileService": "enable",
            "alertCRD.installDefault": True,
            "alertCRD.scopeClustered": True,
            # short learning period
            "nodeAgent.config.maxLearningPeriod": "60s",
            "nodeAgent.config.learningPeriod": "50s",
            "nodeAgent.config.updatePeriod": "30s",
            "nodeAgent.config.nodeProfileInterval": "1m",
            # "nodeAgent.image.repository": "docker.io/amitschendel/node-agent",
            # "nodeAgent.image.tag": "v0.0.5",
        }
        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)

        self.fw_name = None
        self.cluster = None
        self.wait_for_agg_to_end = False
        self.test_policy_guids = []

    def start(self):
        """
        agenda:
        1. get runtime incidents rulesets
        2. enrich the new runtime policy with alert notifications
        3. create new runtime policy
        4. Install kubescape
        5. apply the deployment that will generate the incident
        6. wait for the runtime incidents to be generated
        7. verify messages were sent
        """
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'


        self.cluster, namespace = self.setup(apply_services=False)

        before_test_message_ts = time.time()


        Logger.logger.info("1. get runtime incidents rulesets")
        res = self.backend.get_runtime_incidents_rulesets()
        incident_rulesets = json.loads(res.text)

        incident_rulesets_guids = [rule["guid"] for rule in incident_rulesets["response"] if rule["name"] == "Anomaly"]


        # Update the name field
        new_runtime_policy_body = {
            "name": f"Malware-new-systest-" + self.cluster,
            "description": "Default Malware RuleSet System Test",
            "enabled": True,
            "scope": {},
            "ruleSetType": "Managed",
            "managedRuleSetIDs": incident_rulesets_guids,
            "notifications": [],
            "actions": []
        }


        Logger.logger.info("2. enrich the new runtime policy with alert notifications")
        self.test_obj["enrichAlertChannelFunc"](new_runtime_policy_body)


        Logger.logger.info("3. create new runtime policy")
        new_policy_guid = self.validate_new_policy(new_runtime_policy_body)

        Logger.logger.info(f"New policy created with guid {new_policy_guid}")
        self.test_policy_guids.append(new_policy_guid)


        Logger.logger.info('4. Install kubescape')
        self.install_kubescape(helm_kwargs=self.helm_kwargs)

        Logger.logger.info('5. apply the deployment that will generate the incident')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=240)

        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=self.cluster)
        if isinstance(wlids, str):
            wlids = [wlids]

        Logger.logger.info('6. wait for the runtime incidents to be generated')
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=180, namespace=namespace)

        Logger.logger.info(
            f'workloads are running, waiting for application profile finalizing before exec into pod {wlids}')
        self.wait_for_report(self.verify_application_profiles, wlids=wlids, namespace=namespace)
        time.sleep(30)
        self.exec_pod(wlid=wlids[0], command="cat /etc/hosts")

        Logger.logger.info("Get incidents list")
        incs, _ = self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=5,
                                       cluster=self.cluster, namespace=namespace,
                                       incident_name=["Unexpected process launched","Unexpected Sensitive File Access"])

        inc, _ = self.wait_for_report(self.verify_incident_completed, timeout=5 * 60, sleep_interval=20,
                                      incident_id=incs[0]['guid'])
        Logger.logger.info(f"Got incident {json.dumps(inc)}")
        assert inc.get(__RELATED_ALERTS_KEY__, None) is None or len(
            inc[__RELATED_ALERTS_KEY__]) == 0, f"Expected no related alerts in the incident API {json.dumps(inc)}"


        Logger.logger.info('7. verify messages were sent')
        res = self.wait_for_report(self.assert_all_messages_sent,
                                   timeout=5 * 60,
                                   begin_time=before_test_message_ts, cluster=self.cluster)
        return self.cleanup()

    def verify_incident_completed(self, incident_id):
        response = self.backend.get_incident(incident_id)
        assert response['attributes']['incidentStatus'] == "completed", f"Not completed incident {json.dumps(response)}"

        return response

    def verify_incident_in_backend_list(self, cluster, namespace, incident_name = None):
        Logger.logger.info("Get incidents list")
        filters_dict = {
            "designators.attributes.cluster": cluster,
            "designators.attributes.namespace": namespace,
        }
        if isinstance(incident_name,str):
            filters_dict["name"] = incident_name
        elif isinstance(incident_name, list):
            filters_dict["name"] = ','.join(incident_name)

        response = self.backend.get_incidents(filters=filters_dict)
        incs = response['response']
        assert len(incs) > 0, f"Failed to get incidents list {json.dumps(incs)}"
        return incs

    def cleanup(self):
        for policy_guid in self.test_policy_guids:
            body = {
                "innerFilters": [
                    {
                        "guid": policy_guid,
                    }
                ]
            }
            self.backend.delete_runtime_policies(body)
        return super().cleanup()


    def assert_all_messages_sent(self, begin_time, cluster):
        messages = self.test_obj["getMessagesFunc"](begin_time)
        found = str(messages).count(cluster)
        assert found > 0, f"expected to have at least 1 message, found {found}"
        assert_runtime_incident_message_sent(messages, cluster)



def assert_runtime_incident_message_sent(messages, cluster):
        found = 0
        Logger.logger.info(f"total messages found: {len(messages)}, looking for runtime incident messages")
        if len(messages) > 0:
            Logger.logger.info(f"first message: {messages[0]}")

        for message in messages:
            message_string = str(message)
            if "New threat found" in message_string and cluster in message_string and "redis" in message_string:
                found += 1
        assert found > 0, "expected to have at least one runtime incident message"


def enrich_teams_alert_notifications(data):
    data["notifications"]  =[
        {
            "provider": "teams",
            "teamsWebhookURL" : get_env("CHANNEL_WEBHOOK")
        }
    ]


def enrich_slack_alert_notifications(data):
    data["notifications"] = [
        {
            "provider": "slack",
            "slackChannel": {
                "id": get_env("SLACK_CHANNEL_ID")
            }
        }
    ]

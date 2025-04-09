

import json
import random


from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger, TestUtil, statics
from tests_scripts.runtime.incidents import Incidents
from tests_scripts.users_notifications.alert_notifications import get_env
from tests_scripts.workflows.utils import WEBHOOK_NAME

UPDATE_EXPECTED_RUNTIME_POLICIES = False

EXPECTED_RUNTIME_RULSETS_PATH = "configurations/expected-result/kdr/runtime_rulesets.json"
EXPECTED_RUNTIME_POLICIES_PATH = "configurations/expected-result/kdr/runtime_policies_default.json"
EXPECTED_UNIQUEVALUES_PATH = "configurations/expected-result/kdr/runtime_policies_unique_values.json"

POLICY_CREATED_RESPONSE = "Incident policy created"
POLICY_UPDATED_RESPONSE = "Incident policy updated"
POLICY_DELETED_RESPONSE = "Incident policy deleted"


class RuntimePoliciesConfigurations(Incidents):
    """
        check incidents policy configurations - list, create, update, delete, unique values
    """

    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(RuntimePoliciesConfigurations, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

        self.tested_webhook_guid = []
        self.tested_policy_guid = []
        
    
    def start(self):
        """
        agenda:
        1. validate incident types
        2. validate default rulesets
        3. get runtime policies list
        4. validate unique values
        5. create new runtime policy with webhook
        6. update runtime policy with teams
        7. update runtime policy with slack
        8. delete runtime policy
        9. validate expected errors
        10. create exception
        11. check no incident
        12. delete exception
        13. delete policies

        """
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'
        Logger.logger.info(self.backend.server + statics.ARMO_TEST_WEBHOOK_API)

        cluster, namespace = self.setup()
        Logger.logger.info("1. Install armo helm-chart before application so we will have final AP")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        Logger.logger.info("2. Deploy and wait for report")
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=360,
                             namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        wlids = self.deploy_and_wait(deployments_path=self.test_obj["deployments"], cluster=cluster, namespace=namespace)
        self.create_application_profile(wlids=wlids, namespace=namespace)

        Logger.logger.info("3. validate incident types")
        self.validate_incident_types()

        Logger.logger.info("4. validate default rulesets")
        incident_rulesets = self.validate_default_rulesets()

        Logger.logger.info("5. get runtime policies list")
        res = self.backend.get_runtime_policies_list()
        incident_policies_default = json.loads(res.text)
        policies_guids = [policy["guid"] for policy in incident_policies_default["response"]]

        if UPDATE_EXPECTED_RUNTIME_POLICIES:
            TestUtil.save_expceted_json(incident_policies_default, EXPECTED_RUNTIME_POLICIES_PATH)

        assert len(incident_policies_default["response"]) > 1, f"Runtime policies list is less than 1, got {incident_policies_default['response']}"


        Logger.logger.info("6. validate unique values")
        unique_values_body = {
            "fields": {
                "name": "",
                "ruleSetType": "",
                "scope.designators.cluster": "",
                "scope.designators.namespace": ""
            },
            "innerFilters": [
                {
                "ruleSetType": "Managed"
                }
            ],
            "pageSize": 100,
            "pageNum": 1
            }
        
        res = self.backend.get_runtime_policies_uniquevalues(unique_values_body)
        unique_values = json.loads(res.text)

        if UPDATE_EXPECTED_RUNTIME_POLICIES:
            TestUtil.save_expceted_json(unique_values, EXPECTED_UNIQUEVALUES_PATH)

        expected_unique_values = TestUtil.get_expected_json(EXPECTED_UNIQUEVALUES_PATH) 
        TestUtil.compare_jsons(expected_unique_values, unique_values, [])

        rand = str(random.randint(10000000, 99999999))

        Logger.logger.info("Create webhook")
        self.webhook_name = WEBHOOK_NAME+ "_" + rand
        armo_test_webhook = self.backend.server + statics.ARMO_TEST_WEBHOOK_API + "?customerGUID=" + self.backend.get_customer_guid()
        guid = self.create_webhook(name=self.webhook_name, webhook_url=armo_test_webhook, testWebhook=True)


        notifications_webhook = [
            {
                "provider": "webhook",
                "webhookChannel": {
                    "guid": guid,
                    "name": self.webhook_name,
                    "webhookURL": armo_test_webhook
                }
            }
        ]

        new_runtime_policy_body =  {    
            "name": "Malware-new-systest",    
            "description": "Default Malware RuleSet System Test",
            "enabled": True,
            "scope": {"riskFactors":["Internet facing"],"designators":[{"cluster":"bla"}]},
            "ruleSetType": "Managed",
            "managedRuleSetIDs": [
                incident_rulesets[0]["guid"]
            ],    
            "notifications":notifications_webhook,
            "actions": []
        }


        Logger.logger.info("7. create new runtime policy with webhook")
        new_policy_guid = self.validate_new_policy(new_runtime_policy_body)
        self.validate_notifications(notifications_webhook, new_runtime_policy_body)

        # TODO: check the case of updating empty scope
        update_runtime_policy_body = {    
            "name": "Malware-new-systest - updated",    
            "description": "Default Malware RuleSet System Test  - updated",
            "enabled": True,
            "scope": {"riskFactors":["Internet facing"],"designators":[{"cluster":"bla_update"}]},
            "ruleSetType": "Managed",
            "managedRuleSetIDs": [
                incident_rulesets[0]["guid"]
            ],    
            "notifications": [],
            "actions": []
        }

        notifcations_teams = [
            {
                "provider": "teams",
                "teamsWebhookURL" : get_env("CHANNEL_WEBHOOK")
            }
        ]

        update_runtime_policy_body["notifications"]  = notifcations_teams

        
        Logger.logger.info("8. update runtime policy with teams")
        update_runtime_policy_body_res = self.validate_update_policy_against_backend(new_policy_guid, update_runtime_policy_body)
        self.validate_notifications(notifcations_teams, update_runtime_policy_body_res)


        notifications_slack = [
            {
                "provider": "slack",
                "slackChannel": {
                    "id": get_env("SLACK_CHANNEL_ID")
                }
            }
        ]

        update_runtime_policy_body["notifications"]  = notifications_slack
        Logger.logger.info("9. update runtime policy with slack")
        update_runtime_policy_body_res = self.validate_update_policy_against_backend(new_policy_guid, update_runtime_policy_body)
        self.validate_notifications(notifications_slack, update_runtime_policy_body_res)


        Logger.logger.info("10. delete runtime policy")
        self.validate_delete_policy(new_policy_guid)

        Logger.logger.info("11. validate expected errors")
        self. validate_expected_errors()

        Logger.logger.info("12. Delete webhook")
        self.delete_webhook(guid)

        Logger.logger.info("13. Create exception")
        exception_id = self.backend.create_runtime_exception(policy_ids=["I013"], resources=[{
            "designatorType":"Attribute",
             "attributes":
             {
                "cluster": cluster,
                "namespace": namespace,
                "name":"*/*",
                "kind":"*/*"
             }
            }
        ]).json()["guid"]
        self.ensure_no_incident(wlids=wlids, cluster=cluster, namespace=namespace)

        Logger.logger.info("14. Delete exception")
        self.backend.delete_runtime_exception(exception_id=exception_id)
        self.run_and_wait_for_incident(wlids=wlids, command="cat /etc/hosts", cluster=cluster, namespace=namespace, expected_incident_name="Unexpected process launched")

        Logger.logger.info("15. Delete policies")
        for policy_guid in policies_guids:
            self.validate_delete_policy(policy_guid)

        Logger.logger.info("16. Check no incident")
        self.ensure_no_incident(wlids=wlids, cluster=cluster, namespace=namespace)

        return self.cleanup()
  
    def ensure_no_incident(self, wlids: list, cluster: str, namespace: str):
        exception_occured = False
        try:
            self.run_and_wait_for_incident(wlids=wlids, command="cat /etc/hosts", cluster=cluster, namespace=namespace, expected_incident_name="Unexpected process launched")
        except Exception as e:
            exception_occured = True
        if not exception_occured:
            raise Exception("Exception not created")
        
        
    def cleanup(self, **kwargs):
        for guid in self.tested_webhook_guid:
            self.delete_webhook(guid)

        for guid in self.tested_policy_guid:
            self.validate_delete_policy(guid)
        return super().cleanup(**kwargs)
    
    def get_webhook_name(self, channel_name):
        channels = self.backend.get_webhooks()
        for channel in channels:
            if channel["name"] == channel_name:
                return channel["guid"]
        return "Channel not found"
    
    def delete_webhook(self, channel_guid):
        r = self.backend.delete_webhook(body={"innerFilters": [{"guid": channel_guid}]})
        assert r == "Webhooks channel deleted", f"Expected 'Teams channel deleted', but got {r['response']}"
        channels = self.backend.get_webhooks()
        for channel in channels:
            if channel["guid"] == channel_guid:
                return f"Channel with guid {channel_guid} not deleted"
        self.tested_webhook_guid.remove(channel_guid)
        return "Channel deleted"

    def create_webhook(self, name, webhook_url, testWebhook=True)->str:
        webhook_body = {
            "guid": "",
            "name": name,
            "webhookURL": webhook_url
        }
        try:
            r = self.backend.create_webhook(webhook_body, testWebhook)
        except (Exception, BaseException) as e:
            if "already exists" in str(e):
                Logger.logger.info("Teams channel already exists")
                return
            raise e
        
        assert r == "Webhook channel created", f"Expected 'Teams channel created', but got {r['response']}"

        guid = self.get_webhook_name(self.webhook_name)
        self.tested_webhook_guid.append(guid)
        return guid

    
    def validate_incident_types(self):
        res = self.backend.get_runtime_incident_types()
        incident_type_default = json.loads(res.text)
        assert len(incident_type_default["response"]) > 0, "no incident types found"
        return incident_type_default["response"]


    def validate_default_rulesets(self):
        res = self.backend.get_runtime_incidents_rulesets()
        incident_rulesets = json.loads(res.text)

        if UPDATE_EXPECTED_RUNTIME_POLICIES:
            TestUtil.save_expceted_json(incident_rulesets, EXPECTED_RUNTIME_RULSETS_PATH)
        
        assert len(incident_rulesets["response"]) > 0, "no incident rulesets found"  
        
        return incident_rulesets["response"]


    def validate_new_policy(self, body):
        res = self.backend.new_runtime_policy(body)
        new_runtime_policy_no_scope_res = json.loads(res.text)
        assert new_runtime_policy_no_scope_res == POLICY_CREATED_RESPONSE, f"failed to create new runtime policy, got {new_runtime_policy_no_scope_res}"



        new_generated_runtime_policy_body =  {
            "pageSize": 50,
            "pageNum": 1,
            "innerFilters": [
                {
                    "name": body["name"],
                }
            ]
        }

        res = self.backend.get_runtime_policies_list(new_generated_runtime_policy_body)
        incident_policies = json.loads(res.text)["response"]
        props_to_check = ["name", "scope", "ruleSetType", "managedRuleSetIDs", "actions", "notifications"]
        assert len(incident_policies)  > 0, f"failed to get new runtime policy, expected more than 1 but got {len(incident_policies)}, got result {incident_policies}"

        Logger.logger.info(f"New policy created: {json.dumps(incident_policies[0], indent=4)}")

        for prop in props_to_check:
            if prop == "notifications":
                continue
            assert incident_policies[0][prop] == body[prop], f"failed to get new runtime policy, expected '{prop}' {body[prop]} but got {incident_policies[0][prop]}, got result {incident_policies}"

        
        guid = incident_policies[0]["guid"]
        self.tested_policy_guid.append(guid)
        return guid
    

    def validate_notifications(self, expected_notifications, policy):
        provider_to_data = {
            "webhook": "webhookChannel",
            "slack": "slackChannel",
            "teams": "teamsWebhookURL"
        }

        data_to_fields = {
            "webhookChannel": ["guid", "name", "webhookURL"],
            "slackChannel": ["id"]
        }
        

        for i in range(len(expected_notifications)):
            found_provider = None
            for j in range(len(policy["notifications"])):
                if policy["notifications"][j]["provider"] == expected_notifications[i]["provider"]:
                    found_provider = policy["notifications"][j]["provider"]
                    data = provider_to_data[found_provider]

                    if found_provider == "teams":
                        assert policy["notifications"][j][data] == expected_notifications[i][data], f"failed to get new runtime policy, expected notification '{expected_notifications}' but got {policy['notifications'][j]}, got result {policy}"
                    else:
                        for field in data_to_fields[data]:
                            assert policy["notifications"][j][data][field] == expected_notifications[i][data][field], f"failed to get new runtime policy, expected notification '{expected_notifications}' but got {policy['notifications'][j]}, got result {policy}"
                        break

                assert found_provider, f"failed to get new runtime policy, didnt find provider '{expected_notifications[i]['provider']}' in {policy['notifications']}, got result {policy}"


    

    def validate_update_policy_against_backend(self, guid, body):
        body["guid"] = guid
        res = self.backend.update_runtime_policy(body)
        updated_runtime_policy_no_scope_res = json.loads(res.text)
        assert updated_runtime_policy_no_scope_res == POLICY_UPDATED_RESPONSE, f"failed to update new runtime policy, got {updated_runtime_policy_no_scope_res}"


        new_generated_runtime_policy_body =  {
            "pageSize": 50,
            "pageNum": 1,
            "innerFilters": [
                {
                    "guid": guid,
                }
            ]
        }

        res = self.backend.get_runtime_policies_list(new_generated_runtime_policy_body)
        incident_policies = json.loads(res.text)["response"]
        assert len(incident_policies)  == 1, f"failed to get new runtime policy, expected 1 but got {len(incident_policies)}, got result {incident_policies}"

        props_to_check = ["name", "scope", "ruleSetType", "managedRuleSetIDs", "actions"]
        for prop in props_to_check:
            assert incident_policies[0][prop] == body[prop], f"failed to get new runtime policy, expected '{prop}' {body[prop]} but got {incident_policies[0][prop]}, got result {incident_policies}"

        return incident_policies[0]

    def validate_delete_policy(self, guid):
        body = {
            "innerFilters": [
                {
                    "guid": guid,
                }
            ]
        }
        res = self.backend.delete_runtime_policies(body)
        delete_runtime_policy_no_scope_res = json.loads(res.text)
        assert delete_runtime_policy_no_scope_res == POLICY_DELETED_RESPONSE, f"failed to delete new runtime policy, got {delete_runtime_policy_no_scope_res}"


        new_generated_runtime_policy_body =  {
            "pageSize": 50,
            "pageNum": 1,
            "innerFilters": [
                {
                    "guid": guid,
                }
            ]
        }

        res = self.backend.get_runtime_policies_list(new_generated_runtime_policy_body)
        incident_policies = json.loads(res.text)["response"]
        assert len(incident_policies)  == 0, f"failed to delete new runtime policy, expected 0 but got {len(incident_policies)}, got result {incident_policies}"
        if guid in self.tested_policy_guid:
            self.tested_policy_guid.remove(guid)

    def validate_expected_errors(self):
        test_cases = [
            {  # good case
                "body": {
                    "name": "Malware-new-systest-good",
                    "description": "Default Malware RuleSet System Test",
                    "enabled": True,
                    "scope": {"riskFactors":["Internet facing"],"designators":[{"cluster":"bla"}]},
                    "ruleSetType": "Managed",
                    "managedRuleSetIDs": [
                        "123"
                    ],    
                    "notifications": [],
                    "actions": []
                },
                "expect_error": False
            },
            { # bad case - rule set type is not Managed or Custom
                "body": {
                    "name": "Malware-new-systest-wrong-rule-set-type",    
                    "description": "Default Malware RuleSet System Test",
                    "enabled": True,
                    "scope": {"riskFactors":["Internet facing"],"designators":[{"cluster":"bla"}]},
                    "ruleSetType": "Managed123",
                    "managedRuleSetIDs": [
                        "123"
                    ],    
                    "notifications": [],
                    "actions": []
                },
                "expect_error": True
            },
            { # bad case - rule set is Managed but no rule set id
                "body": {
                    "name": "Malware-new-systest-manage-no-rule-set",    
                    "description": "Default Malware RuleSet System Test",
                    "enabled": True,
                    "scope": {"riskFactors":["Internet facing"],"designators":[{"cluster":"bla"}]},
                    "ruleSetType": "Managed",
                    "managedRuleSetIDs": [
                    ],    
                    "notifications": [],
                    "actions": []
                },
                "expect_error": True
            },
            { # bad case - missing name
                "body": {
                    "description": "Default Malware RuleSet System Test",
                    "enabled": True,
                    "scope": {"riskFactors":["Internet facing"],"designators":[{"cluster":"bla"}]},
                    "ruleSetType": "Managed",
                    "managedRuleSetIDs": [
                        "123"
                    ],    
                    "notifications": [],
                    "actions": []
                },
                "expect_error": True
            }
        ]

        for test_case in test_cases:
            body = test_case["body"]
            expect_error = test_case["expect_error"]
            try:
                self.backend.new_runtime_policy(body)
                if expect_error:
                    raise Exception(f"Expected an error for body: {body}, but no error was raised.")
            except Exception as e:
                if not expect_error:
                    raise Exception(f"Unexpected error for body: {body}: {e}")

        return True  # All cases passed as expected


    def validate_unique_values(self):
        pass


import json
import random
import time
from typing import Any, Dict


from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger, TestUtil, statics
from tests_scripts.runtime.incidents import Incidents
from tests_scripts.users_notifications.alert_notifications import get_env
from tests_scripts.workflows.utils import WEBHOOK_NAME

class Providers:
    WEBHOOK = "webhook"

UPDATE_EXPECTED_RUNTIME_POLICIES = False

EXPECTED_RUNTIME_RULESETS_PATH = "configurations/expected-result/kdr/runtime_rulesets.json"
EXPECTED_RUNTIME_POLICIES_PATH = "configurations/expected-result/kdr/runtime_policies_default.json"
EXPECTED_UNIQUEVALUES_PATH = "configurations/expected-result/kdr/runtime_policies_unique_values.json"
EXPECTED_UNIQUEVALUES_PATH_NO_CDR = "configurations/expected-result/kdr/runtime_policies_no_cdr_unique_values.json"

POLICY_CREATED_RESPONSE = "Incident policy created"
POLICY_UPDATED_RESPONSE = "Incident policy updated"
POLICY_DELETED_RESPONSE = "Incident policy deleted"


class RuntimePoliciesConfigurations(Incidents):
    """
            check incidents policy configurations - list, create, update, delete, unique values
    """

    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None, kubernetes_obj=None):
        super(RuntimePoliciesConfigurations, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver, kubernetes_obj=kubernetes_obj)

        self.tested_webhook_guid = []
        self.tested_policy_guid = []
        self.siem_integration_guids = {}  # {guid: provider}
    
    def start(self):
        """
        agenda:
        1. validate incident types
        2. validate default rulesets
        3. get runtime policies list
        4. create siem integrations
        5. validate unique values
        6. create new runtime policy with webhook
        7. verify siem event sent
        7. update runtime policy with teams
        8. verify siem event sent
        9. update runtime policy with slack
        10. verify siem event sent
        11. delete runtime policy
        12. verify siem event sent
        13. validate expected errors
        14. create exception
        15. verify siem event sent
        16. check no incident
        17. delete exception
        18. verify siem event sent
        20. Create exception with advanced scopes
        21. verify siem event sent
        22. List runtime exceptions
        23. Delete exception
        24. verify siem event sent
        23. delete all siem integrations

        """
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'
        
        # Generate random ID and webhook URLs early
        rand = str(random.randint(10000000, 99999999))
        customer_guid = self.backend.get_customer_guid()
        siem_test_webhook_url = self.backend.server + statics.ARMO_TEST_WEBHOOK_API + "?customerGUID=" + customer_guid
        Logger.logger.info(f"SIEM test webhook URL: {siem_test_webhook_url}")
        
        cluster, namespace = self.setup()
        Logger.logger.info("1. Install armo helm-chart before application so we will have final AP")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        
        
        Logger.logger.info("3. Deploy and wait for report")
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=360,
                             namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        wlids = self.deploy_and_wait(deployments_path=self.test_obj["deployments"], cluster=cluster, namespace=namespace)
        self.create_application_profile(wlids=wlids, namespace=namespace, commands=["more /etc/os-release"])
        
        
        Logger.logger.info("4. Create SIEM webhook integration with events filter (only IncidentCreated and AlertCreated)")
        self.siem_integration_name = "systest-siem-webhook-integration-" + rand
        self.backend.create_siem_integration(
            provider=Providers.WEBHOOK,
            body={
                "name": self.siem_integration_name,
                "configuration": {"webhookURL": siem_test_webhook_url},
                "events": ["IncidentCreated", "AlertCreated"]  # Only these events - policy events will be filtered
            }
        )
        # Get the integration GUID by fetching it back
        integrations = self.backend.get_siem_integrations(provider=Providers.WEBHOOK)
        siem_integration_guid = None
        for integration in integrations:
            if integration.get("name") == self.siem_integration_name:
                siem_integration_guid = integration.get("guid")
                # Verify events field is present and correct
                assert "events" in integration, f"Events field missing in integration response: {integration}"
                assert integration.get("events") == ["IncidentCreated", "AlertCreated"], \
                    f"Expected events ['IncidentCreated', 'AlertCreated'], got {integration.get('events')}"
                break
        assert siem_integration_guid, f"Failed to retrieve GUID for created SIEM integration: {self.siem_integration_name}"
        self.siem_integration_guids[siem_integration_guid] = Providers.WEBHOOK
        Logger.logger.info(f"Created SIEM integration '{self.siem_integration_name}' with GUID: {siem_integration_guid} and events filter: {integrations[0].get('events') if integrations else 'N/A'}")

        Logger.logger.info("5. validate incident types")
        self.validate_incident_types()

        Logger.logger.info("6. validate default rulesets")
        incident_rulesets = self.validate_default_rulesets()

        Logger.logger.info("7. get runtime policies list")
        res = self.backend.get_runtime_policies_list()
        incident_policies_default = json.loads(res.text)
        policies_guids = [policy["guid"] for policy in incident_policies_default["response"]]

        if UPDATE_EXPECTED_RUNTIME_POLICIES:
            TestUtil.save_expected_json(incident_policies_default, EXPECTED_RUNTIME_POLICIES_PATH)

        assert len(incident_policies_default["response"]) > 1, f"Runtime policies list is less than 1, got {incident_policies_default['response']}"


        Logger.logger.info("8. validate unique values")
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
            TestUtil.save_expected_json(unique_values, EXPECTED_UNIQUEVALUES_PATH)

        expected_unique_values = TestUtil.get_expected_json(EXPECTED_UNIQUEVALUES_PATH) 
        TestUtil.compare_jsons(expected_unique_values, unique_values, [])

        Logger.logger.info("9. Create webhook for policy notifications")
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


        Logger.logger.info("10. create new runtime policy with webhook")
        # Get message count before creating policy to verify filtering
        messages_before_create = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_before_create, list):
            messages_before_create = []
        count_before_create = len(messages_before_create)
        
        new_policy_guid = self.validate_new_policy(new_runtime_policy_body)
        self.validate_notifications(notifications_webhook, new_runtime_policy_body)
        
        # Verify RuntimePolicyCreated event is NOT received (filtered out - not in events list)
        time.sleep(15)  # Wait for event to be processed if it would be sent
        messages_after_create = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_after_create, list):
            messages_after_create = []
        new_messages_after_create = messages_after_create[count_before_create:] if len(messages_after_create) > count_before_create else []
        runtime_policy_created_found = any(
            msg.get("event_type") == "RuntimePolicyCreated" 
            for msg in new_messages_after_create 
            if isinstance(msg, dict)
        )
        assert not runtime_policy_created_found, \
            f"RuntimePolicyCreated event was received but should have been filtered out. New messages: {new_messages_after_create}"
        Logger.logger.info("✓ RuntimePolicyCreated event correctly filtered out (not in events list)")
    
        
 
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

        notifications_teams = [
            {
                "provider": "teams",
                "teamsWebhookURL" : get_env("CHANNEL_WEBHOOK")
            }
        ]

        update_runtime_policy_body["notifications"]  = notifications_teams

        
        Logger.logger.info("11. update runtime policy with teams")
        # Get message count before updating policy
        messages_before_update = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_before_update, list):
            messages_before_update = []
        count_before_update = len(messages_before_update)
        
        update_runtime_policy_body_res = self.validate_update_policy_against_backend(new_policy_guid, update_runtime_policy_body)
        self.validate_notifications(notifications_teams, update_runtime_policy_body_res)
        
        # Verify RuntimePolicyUpdated event is NOT received (filtered out - not in events list)
        time.sleep(15)  # Wait for event to be processed if it would be sent
        messages_after_update = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_after_update, list):
            messages_after_update = []
        new_messages_after_update = messages_after_update[count_before_update:] if len(messages_after_update) > count_before_update else []
        runtime_policy_updated_found = any(
            msg.get("event_type") == "RuntimePolicyUpdated" 
            for msg in new_messages_after_update 
            if isinstance(msg, dict)
        )
        assert not runtime_policy_updated_found, \
            f"RuntimePolicyUpdated event was received but should have been filtered out. New messages: {new_messages_after_update}"
        Logger.logger.info("✓ RuntimePolicyUpdated event correctly filtered out (not in events list)")
        

        notifications_slack = [
            {
                "provider": "slack",
                "slackChannel": {
                    "id": get_env("SLACK_CHANNEL_ID")
                }
            }
        ]

        update_runtime_policy_body["notifications"]  = notifications_slack
        Logger.logger.info("12. update runtime policy with slack")
        # Get message count before updating policy
        messages_before_update2 = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_before_update2, list):
            messages_before_update2 = []
        count_before_update2 = len(messages_before_update2)
        
        update_runtime_policy_body_res = self.validate_update_policy_against_backend(new_policy_guid, update_runtime_policy_body)
        self.validate_notifications(notifications_slack, update_runtime_policy_body_res)
        
        # Verify RuntimePolicyUpdated event is NOT received (filtered out - not in events list)
        time.sleep(15)  # Wait for event to be processed if it would be sent
        messages_after_update2 = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_after_update2, list):
            messages_after_update2 = []
        new_messages_after_update2 = messages_after_update2[count_before_update2:] if len(messages_after_update2) > count_before_update2 else []
        runtime_policy_updated_found2 = any(
            msg.get("event_type") == "RuntimePolicyUpdated" 
            for msg in new_messages_after_update2 
            if isinstance(msg, dict)
        )
        assert not runtime_policy_updated_found2, \
            f"RuntimePolicyUpdated event was received but should have been filtered out. New messages: {new_messages_after_update2}"
        Logger.logger.info("✓ RuntimePolicyUpdated event correctly filtered out (not in events list)")


        Logger.logger.info("13. delete runtime policy")
        # Get message count before deleting policy
        messages_before_delete = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_before_delete, list):
            messages_before_delete = []
        count_before_delete = len(messages_before_delete)
        
        self.validate_delete_policy(new_policy_guid)
        
        # Verify RuntimePolicyDeleted event is NOT received (filtered out - not in events list)
        time.sleep(15)  # Wait for event to be processed if it would be sent
        messages_after_delete = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_after_delete, list):
            messages_after_delete = []
        new_messages_after_delete = messages_after_delete[count_before_delete:] if len(messages_after_delete) > count_before_delete else []
        runtime_policy_deleted_found = any(
            msg.get("event_type") == "RuntimePolicyDeleted" 
            for msg in new_messages_after_delete 
            if isinstance(msg, dict)
        )
        assert not runtime_policy_deleted_found, \
            f"RuntimePolicyDeleted event was received but should have been filtered out. New messages: {new_messages_after_delete}"
        Logger.logger.info("✓ RuntimePolicyDeleted event correctly filtered out (not in events list)")
        
        Logger.logger.info("13a. Update SIEM integration to include policy events and verify they are now received")
        # Update integration to include policy events
        current_integrations = self.backend.get_siem_integrations(provider=Providers.WEBHOOK)
        current_integration = None
        for integration in current_integrations:
            if integration.get("guid") == siem_integration_guid:
                current_integration = integration
                break
        assert current_integration, f"Failed to find SIEM integration with GUID: {siem_integration_guid}"
        
        self.backend.update_siem_integration(
            provider=Providers.WEBHOOK,
            body={
                "guid": siem_integration_guid,
                "name": current_integration.get("name"),
                "configuration": current_integration.get("configuration"),
                "isEnabled": current_integration.get("isEnabled", True),
                "events": ["IncidentCreated", "AlertCreated", "RuntimePolicyCreated", "RuntimePolicyUpdated", "RuntimePolicyDeleted", "RiskAcceptanceCreated", "RiskAcceptanceUpdated", "RiskAcceptanceDeleted"]
            }
        )
        Logger.logger.info("✓ Updated SIEM integration to include policy events")
        
        # Create a new policy to verify RuntimePolicyCreated is now received
        test_policy_for_events = {
            "name": "Test-Policy-For-Events-" + rand,
            "description": "Test policy to verify events are received",
            "enabled": True,
            "scope": {"riskFactors": ["Internet facing"], "designators": [{"cluster": "test"}]},
            "ruleSetType": "Managed",
            "managedRuleSetIDs": [incident_rulesets[0]["guid"]],
            "notifications": [],
            "actions": []
        }
        test_policy_guid = self.validate_new_policy(test_policy_for_events)
        # Verify RuntimePolicyCreated event IS now received
        self.wait_for_siem_event("RuntimePolicyCreated", siem_test_webhook_url, timeout=60)
        Logger.logger.info("✓ RuntimePolicyCreated event received as expected (now in events list)")
        
        # Update the policy to verify RuntimePolicyUpdated is now received
        test_policy_for_events["name"] = "Test-Policy-For-Events-Updated-" + rand
        self.validate_update_policy_against_backend(test_policy_guid, test_policy_for_events)
        # Verify RuntimePolicyUpdated event IS now received
        self.wait_for_siem_event("RuntimePolicyUpdated", siem_test_webhook_url, timeout=60)
        Logger.logger.info("✓ RuntimePolicyUpdated event received as expected (now in events list)")
        
        # Delete the policy to verify RuntimePolicyDeleted is now received
        self.validate_delete_policy(test_policy_guid)
        # Verify RuntimePolicyDeleted event IS now received
        self.wait_for_siem_event("RuntimePolicyDeleted", siem_test_webhook_url, timeout=60)
        Logger.logger.info("✓ RuntimePolicyDeleted event received as expected (now in events list)")

        Logger.logger.info("14. validate expected errors")
        self. validate_expected_errors()

        Logger.logger.info("15. Delete webhook")
        self.delete_webhook(guid)

        Logger.logger.info("16. Create incident to validate BE (triggers SIEM IncidentCreated event)")
        self.exec_pod(wlid=wlids[0], command="more /root/malware.o")
        self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=10,
                                cluster=cluster, namespace=namespace,
                                incident_name=["Malware found"])
        
        # Validate SIEM IncidentCreated event
        self.wait_for_siem_event("IncidentCreated", siem_test_webhook_url)

        Logger.logger.info("17. Create exception (triggers SIEM RiskAcceptanceCreated event)")
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
        ])["guid"]
        self.ensure_no_incident(wlid=wlids[0], cluster=cluster, namespace=namespace, expected_incident_name="Unexpected process launched")
        
        # Validate SIEM RiskAcceptanceCreated event
        self.wait_for_siem_event("RiskAcceptanceCreated", siem_test_webhook_url)
        
        Logger.logger.info("18. Delete exception (triggers SIEM RiskAcceptanceDeleted event)")
        self.backend.delete_runtime_exception(exception_id=exception_id)
        
        # Validate SIEM RiskAcceptanceDeleted event
        self.wait_for_siem_event("RiskAcceptanceDeleted", siem_test_webhook_url)
        
        exception_with_advanced_scopes = {
            "resources": [{
                "designatorType": "Attributes",
                "attributes": {
                    "cluster": cluster,
                    "namespace": namespace,
                    "name": "*/*",
                    "kind": "*/*"
                }
            }],
            "advancedScopes": [{
                "entity": "process.commandLine",
                "condition": "contains",
                "values": "/etc/hosts"
            },
            ],
            "policyIDs": ["I013"],
        }
        
        Logger.logger.info("19. Create incident to validate BE")
        self.exec_pod(wlid=wlids[0], command="ls /etc/hosts")
        self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=10,
                                cluster=cluster, namespace=namespace,
                                incident_name=["Unexpected process launched"])
        
        Logger.logger.info("20. Create exception with advanced scopes (triggers SIEM RiskAcceptanceCreated event)")
        exception_id = self.backend.create_runtime_exception(policy_ids=exception_with_advanced_scopes["policyIDs"], 
                                                             resources=exception_with_advanced_scopes["resources"],advanced_scopes=exception_with_advanced_scopes["advancedScopes"])["guid"]
        
        # Validate SIEM RiskAcceptanceCreated event
        self.wait_for_siem_event("RiskAcceptanceCreated", siem_test_webhook_url)

        Logger.logger.info("21. List runtime exceptions")
        exceptions = self.backend.list_runtime_exceptions()["response"][0]
        assert(exceptions.get('advancedScopes') == exception_with_advanced_scopes.get('advancedScopes'))
        
        Logger.logger.info("22. Create alert that matches exception - no incident")       
        self.ensure_no_incident(wlid=wlids[0], cluster=cluster, namespace=namespace, expected_incident_name="Unexpected process launched")
        
        Logger.logger.info("23. Create alert that does not match exception - create incident")
        self.exec_pod(wlid=wlids[0], command="tail /etc/group")
        self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=10,
                                cluster=cluster, namespace=namespace,
                                incident_name=["Unexpected process launched"])
        
        Logger.logger.info("24. Delete exception (triggers SIEM RiskAcceptanceDeleted event)")
        self.backend.delete_runtime_exception(exception_id=exception_id)
        
        # Validate SIEM RiskAcceptanceDeleted event
        self.wait_for_siem_event("RiskAcceptanceDeleted", siem_test_webhook_url)
        
        Logger.logger.info("25. Create incident after delete exception")
        self.exec_pod(wlid=wlids[0], command="head /etc/hosts")
        self.wait_for_specific_incident_count_with_report(cluster=cluster, namespace=namespace,
                                                                      incident_name=["Unexpected process launched"],
                                                                      expected_count=2, timeout=120)


        Logger.logger.info("26. Delete policies (triggers SIEM PolicyDeleted events)")
        for policy_guid in policies_guids:
            self.validate_delete_policy(policy_guid)
        # Validate SIEM PolicyDeleted event for each policy
        self.wait_for_siem_event("RuntimePolicyDeleted", siem_test_webhook_url)
        
        Logger.logger.info("27. Test SIEM Events filtering - Update existing integration with specific events")
        # Get current integration to preserve its configuration
        current_integrations = self.backend.get_siem_integrations(provider=Providers.WEBHOOK)
        current_integration = None
        for integration in current_integrations:
            if integration.get("guid") == siem_integration_guid:
                current_integration = integration
                break
        assert current_integration, f"Failed to find existing SIEM integration with GUID: {siem_integration_guid}"
        
        # Update the existing integration to add events filter (only IncidentCreated and AlertCreated)
        self.backend.update_siem_integration(
            provider=Providers.WEBHOOK,
            body={
                "guid": siem_integration_guid,
                "name": current_integration.get("name"),
                "configuration": current_integration.get("configuration"),
                "isEnabled": current_integration.get("isEnabled", True),
                "events": ["IncidentCreated", "AlertCreated"]
            }
        )
        # Verify the update was successful
        updated_integrations = self.backend.get_siem_integrations(provider=Providers.WEBHOOK)
        updated_integration = None
        for integration in updated_integrations:
            if integration.get("guid") == siem_integration_guid:
                updated_integration = integration
                # Verify events field is present and correct
                assert "events" in integration, f"Events field missing in integration response: {integration}"
                assert integration.get("events") == ["IncidentCreated", "AlertCreated"], \
                    f"Expected events ['IncidentCreated', 'AlertCreated'], got {integration.get('events')}"
                break
        assert updated_integration, f"Failed to retrieve updated SIEM integration with GUID: {siem_integration_guid}"
        Logger.logger.info(f"Updated SIEM integration '{self.siem_integration_name}' with events filter: {updated_integration.get('events')}")
        
        Logger.logger.info("28. Test Events filtering - Verify IncidentCreated event IS received (in filter list)")
        # Get initial message count to track new messages
        initial_messages = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(initial_messages, list):
            initial_messages = []
        initial_count = len(initial_messages)
        # Trigger an incident that should be sent (IncidentCreated is in the filter)
        self.exec_pod(wlid=wlids[0], command="more /root/malware.o")
        self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=10,
                            cluster=cluster, namespace=namespace,
                            incident_name=["Malware found"])
        # Verify IncidentCreated event was received
        self.wait_for_siem_event("IncidentCreated", siem_test_webhook_url, timeout=60)
        Logger.logger.info("✓ IncidentCreated event received as expected (in filter list)")
        
        Logger.logger.info("29. Test Events filtering - Verify RuntimePolicyCreated event is NOT received (not in filter list)")
        # Get message count before creating policy
        messages_before = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_before, list):
            messages_before = []
        count_before = len(messages_before)
        # Create a policy that should trigger RuntimePolicyCreated (but it's NOT in the filter)
        test_policy_body = {
            "name": "Filtered-Test-Policy-" + rand,
            "description": "Test policy for events filtering",
            "enabled": True,
            "scope": {"riskFactors": ["Internet facing"], "designators": [{"cluster": "test"}]},
            "ruleSetType": "Managed",
            "managedRuleSetIDs": [incident_rulesets[0]["guid"]],
            "notifications": [],
            "actions": []
        }
        test_policy_guid = self.validate_new_policy(test_policy_body)
        # Wait to ensure event would have been sent if not filtered
        time.sleep(20)
        # Verify RuntimePolicyCreated was NOT received
        messages_after = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_after, list):
            messages_after = []
        # Check if any new RuntimePolicyCreated messages appeared
        new_messages = messages_after[count_before:] if len(messages_after) > count_before else []
        runtime_policy_created_found = any(
            msg.get("event_type") == "RuntimePolicyCreated" 
            for msg in new_messages 
            if isinstance(msg, dict)
        )
        assert not runtime_policy_created_found, \
            f"RuntimePolicyCreated event was received but should have been filtered out. New messages: {new_messages}"
        Logger.logger.info("✓ RuntimePolicyCreated event correctly filtered out (not in filter list)")
        # Clean up test policy
        self.validate_delete_policy(test_policy_guid)
        
    
        Logger.logger.info("30. Delete SIEM integration")
        self.backend.delete_siem_integration(provider=Providers.WEBHOOK, guid=siem_integration_guid)

        return self.cleanup()
  
    def ensure_no_incident(self, wlid: str, cluster: str, namespace: str, expected_incident_name: str):
        """
        Verify that no incident is created (e.g., when an exception should prevent it).
        If an incident is found, raises an exception indicating the exception/rule is not working as expected.
        """
        exception_occurred = False
        self.exec_pod(wlid=wlid, command="cat /etc/hosts")
        try:
            self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=10,
                                cluster=cluster, namespace=namespace,
                                incident_name=[expected_incident_name])
        except Exception:
            exception_occurred = True
        if not exception_occurred:
            raise Exception(f"Incident '{expected_incident_name}' was created when it should have been prevented (exception/rule may not be working correctly)")
        
    def wait_for_specific_incident_count_with_report(self, cluster: str, namespace: str, incident_name: list, expected_count: int, timeout: int = 120):
        """
        Wait for a specific number of incidents using wait_for_report pattern.
        
        :param cluster: Cluster name
        :param namespace: Namespace name
        :param incident_name: List of incident names to look for
        :param expected_count: Expected number of incidents
        :param timeout: Total timeout in seconds
        :return: List of incidents
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                incidents = self.wait_for_report(self.verify_incident_in_backend_list, timeout=30, sleep_interval=10,
                                                cluster=cluster, namespace=namespace,
                                                incident_name=incident_name)
                if len(incidents[0]) == expected_count:
                    Logger.logger.info(f"Found {expected_count} incidents as expected")
                    return incidents[0]
                else:
                    Logger.logger.info(f"Found {len(incidents[0])} incidents, expecting {expected_count}. Waiting...")
            except Exception as e:
                Logger.logger.warning(f"Error checking incidents: {e}")
            
            time.sleep(10)
        
        raise Exception(f"Timeout waiting for {expected_count} incidents after {timeout} seconds")
        
    def cleanup(self, **kwargs):
        for guid in self.tested_webhook_guid:
            self.delete_webhook(guid)
            
        for guid in self.tested_policy_guid:
            self.validate_delete_policy(guid)
        
        # Clean up SIEM integrations
        for guid, provider in self.siem_integration_guids.items():
            try:
                self.backend.delete_siem_integration(provider=provider, guid=guid)
                Logger.logger.info(f'Successfully deleted {provider} SIEM integration with guid: {guid}')
            except Exception as e:
                Logger.logger.error(f'Failed to delete SIEM integration {guid}: {e}')
        
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
            TestUtil.save_expected_json(incident_rulesets, EXPECTED_RUNTIME_RULESETS_PATH)
        
        assert len(incident_rulesets["response"]) > 0, "no incident rulesets found"  
        
        return incident_rulesets["response"]


    def validate_new_policy(self, body: Dict[str, Any]) -> str:
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
        res = self.backend.delete_runtime_policies(guid)
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

    def wait_for_siem_event(self, expected_event_type: str, url: str, timeout: int = 240, sleep_interval: int = 10) -> dict:
        """
        Wait for a SIEM event of the expected type to be received by the webhook.
        Polls the backend's test webhook endpoint to retrieve received messages.
        """
        Logger.logger.info(f"Waiting for SIEM event of type: {expected_event_type}")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Retrieve webhook messages from the test endpoint
                messages = self.backend.get_test_webhook_messages(url)
                
                # Ensure messages is a list
                if not isinstance(messages, list):
                    messages = []
                
                # Look for the expected event type
                for message in messages:
                    if isinstance(message, dict) and message.get("event_type") == expected_event_type:
                        Logger.logger.info(f"✓ Found SIEM event of type: {expected_event_type}")
                        Logger.logger.info(f"  Event GUID: {message.get('event_guid')}")
                        Logger.logger.info(f"  Customer: {message.get('customer_guid')}")
                        Logger.logger.info(f"  Timestamp: {message.get('timestamp')}")
                        return message
                
                Logger.logger.debug(f"Event {expected_event_type} not found yet, waiting... ({int(time.time() - start_time)}s elapsed)")
            except Exception as e:
                Logger.logger.warning(f"Error retrieving webhook messages: {e}")
            
            time.sleep(sleep_interval)
        
        raise Exception(f"Timeout waiting for SIEM event type '{expected_event_type}' after {timeout} seconds")
    
class RuntimePoliciesConfigurationsNoCDR(Incidents):
    """
            check incidents policy configurations - list, create, update, delete, unique values
    """

    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None, kubernetes_obj=None):
        super(RuntimePoliciesConfigurationsNoCDR, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver, kubernetes_obj=kubernetes_obj)

        self.tested_webhook_guid = []
        self.tested_policy_guid = []
        self.siem_integration_guids = {}  # {guid: provider}
    
    def start(self):
        """
        agenda:
        1. validate incident types
        2. validate default rulesets
        3. get runtime policies list
        4. create siem integrations
        5. validate unique values
        6. create new runtime policy with webhook
        7. verify siem event sent
        7. update runtime policy with teams
        8. verify siem event sent
        9. update runtime policy with slack
        10. verify siem event sent
        11. delete runtime policy
        12. verify siem event sent
        13. validate expected errors
        14. create exception
        15. verify siem event sent
        16. check no incident
        17. delete exception
        18. verify siem event sent
        20. Create exception with advanced scopes
        21. verify siem event sent
        22. List runtime exceptions
        23. Delete exception
        24. verify siem event sent
        23. delete all siem integrations

        """
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'
        
        # Generate random ID and webhook URLs early
        rand = str(random.randint(10000000, 99999999))
        customer_guid = self.backend.get_customer_guid()
        siem_test_webhook_url = self.backend.server + statics.ARMO_TEST_WEBHOOK_API + "?customerGUID=" + customer_guid
        Logger.logger.info(f"SIEM test webhook URL: {siem_test_webhook_url}")
        
        cluster, namespace = self.setup()
        Logger.logger.info("1. Install armo helm-chart before application so we will have final AP")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        
        
        Logger.logger.info("3. Deploy and wait for report")
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=360,
                             namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        wlids = self.deploy_and_wait(deployments_path=self.test_obj["deployments"], cluster=cluster, namespace=namespace)
        self.create_application_profile(wlids=wlids, namespace=namespace, commands=["more /etc/os-release"])
        
        
        Logger.logger.info("4. Create SIEM webhook integration with events filter (only IncidentCreated and AlertCreated)")
        self.siem_integration_name = "systest-siem-webhook-integration-" + rand
        self.backend.create_siem_integration(
            provider=Providers.WEBHOOK,
            body={
                "name": self.siem_integration_name,
                "configuration": {"webhookURL": siem_test_webhook_url},
                "events": ["IncidentCreated", "AlertCreated"]  # Only these events - policy events will be filtered
            }
        )
        # Get the integration GUID by fetching it back
        integrations = self.backend.get_siem_integrations(provider=Providers.WEBHOOK)
        siem_integration_guid = None
        for integration in integrations:
            if integration.get("name") == self.siem_integration_name:
                siem_integration_guid = integration.get("guid")
                # Verify events field is present and correct
                assert "events" in integration, f"Events field missing in integration response: {integration}"
                assert integration.get("events") == ["IncidentCreated", "AlertCreated"], \
                    f"Expected events ['IncidentCreated', 'AlertCreated'], got {integration.get('events')}"
                break
        assert siem_integration_guid, f"Failed to retrieve GUID for created SIEM integration: {self.siem_integration_name}"
        self.siem_integration_guids[siem_integration_guid] = Providers.WEBHOOK
        Logger.logger.info(f"Created SIEM integration '{self.siem_integration_name}' with GUID: {siem_integration_guid} and events filter: {integrations[0].get('events') if integrations else 'N/A'}")

        Logger.logger.info("5. validate incident types")
        self.validate_incident_types()

        Logger.logger.info("6. validate default rulesets")
        incident_rulesets = self.validate_default_rulesets()

        Logger.logger.info("7. get runtime policies list")
        res = self.backend.get_runtime_policies_list()
        incident_policies_default = json.loads(res.text)
        policies_guids = [policy["guid"] for policy in incident_policies_default["response"]]

        if UPDATE_EXPECTED_RUNTIME_POLICIES:
            TestUtil.save_expected_json(incident_policies_default, EXPECTED_RUNTIME_POLICIES_PATH)

        assert len(incident_policies_default["response"]) > 1, f"Runtime policies list is less than 1, got {incident_policies_default['response']}"


        Logger.logger.info("8. validate unique values")
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
            TestUtil.save_expected_json(unique_values, EXPECTED_UNIQUEVALUES_PATH_NO_CDR)

        expected_unique_values = TestUtil.get_expected_json(EXPECTED_UNIQUEVALUES_PATH_NO_CDR) 
        TestUtil.compare_jsons(expected_unique_values, unique_values, [])

        Logger.logger.info("9. Create webhook for policy notifications")
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


        Logger.logger.info("10. create new runtime policy with webhook")
        # Get message count before creating policy to verify filtering
        messages_before_create = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_before_create, list):
            messages_before_create = []
        count_before_create = len(messages_before_create)
        
        new_policy_guid = self.validate_new_policy(new_runtime_policy_body)
        self.validate_notifications(notifications_webhook, new_runtime_policy_body)
        
        # Verify RuntimePolicyCreated event is NOT received (filtered out - not in events list)
        time.sleep(15)  # Wait for event to be processed if it would be sent
        messages_after_create = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_after_create, list):
            messages_after_create = []
        new_messages_after_create = messages_after_create[count_before_create:] if len(messages_after_create) > count_before_create else []
        runtime_policy_created_found = any(
            msg.get("event_type") == "RuntimePolicyCreated" 
            for msg in new_messages_after_create 
            if isinstance(msg, dict)
        )
        assert not runtime_policy_created_found, \
            f"RuntimePolicyCreated event was received but should have been filtered out. New messages: {new_messages_after_create}"
        Logger.logger.info("✓ RuntimePolicyCreated event correctly filtered out (not in events list)")
    
        
 
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

        notifications_teams = [
            {
                "provider": "teams",
                "teamsWebhookURL" : get_env("CHANNEL_WEBHOOK")
            }
        ]

        update_runtime_policy_body["notifications"]  = notifications_teams

        
        Logger.logger.info("11. update runtime policy with teams")
        # Get message count before updating policy
        messages_before_update = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_before_update, list):
            messages_before_update = []
        count_before_update = len(messages_before_update)
        
        update_runtime_policy_body_res = self.validate_update_policy_against_backend(new_policy_guid, update_runtime_policy_body)
        self.validate_notifications(notifications_teams, update_runtime_policy_body_res)
        
        # Verify RuntimePolicyUpdated event is NOT received (filtered out - not in events list)
        time.sleep(15)  # Wait for event to be processed if it would be sent
        messages_after_update = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_after_update, list):
            messages_after_update = []
        new_messages_after_update = messages_after_update[count_before_update:] if len(messages_after_update) > count_before_update else []
        runtime_policy_updated_found = any(
            msg.get("event_type") == "RuntimePolicyUpdated" 
            for msg in new_messages_after_update 
            if isinstance(msg, dict)
        )
        assert not runtime_policy_updated_found, \
            f"RuntimePolicyUpdated event was received but should have been filtered out. New messages: {new_messages_after_update}"
        Logger.logger.info("✓ RuntimePolicyUpdated event correctly filtered out (not in events list)")
        

        notifications_slack = [
            {
                "provider": "slack",
                "slackChannel": {
                    "id": get_env("SLACK_CHANNEL_ID")
                }
            }
        ]

        update_runtime_policy_body["notifications"]  = notifications_slack
        Logger.logger.info("12. update runtime policy with slack")
        # Get message count before updating policy
        messages_before_update2 = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_before_update2, list):
            messages_before_update2 = []
        count_before_update2 = len(messages_before_update2)
        
        update_runtime_policy_body_res = self.validate_update_policy_against_backend(new_policy_guid, update_runtime_policy_body)
        self.validate_notifications(notifications_slack, update_runtime_policy_body_res)
        
        # Verify RuntimePolicyUpdated event is NOT received (filtered out - not in events list)
        time.sleep(15)  # Wait for event to be processed if it would be sent
        messages_after_update2 = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_after_update2, list):
            messages_after_update2 = []
        new_messages_after_update2 = messages_after_update2[count_before_update2:] if len(messages_after_update2) > count_before_update2 else []
        runtime_policy_updated_found2 = any(
            msg.get("event_type") == "RuntimePolicyUpdated" 
            for msg in new_messages_after_update2 
            if isinstance(msg, dict)
        )
        assert not runtime_policy_updated_found2, \
            f"RuntimePolicyUpdated event was received but should have been filtered out. New messages: {new_messages_after_update2}"
        Logger.logger.info("✓ RuntimePolicyUpdated event correctly filtered out (not in events list)")


        Logger.logger.info("13. delete runtime policy")
        # Get message count before deleting policy
        messages_before_delete = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_before_delete, list):
            messages_before_delete = []
        count_before_delete = len(messages_before_delete)
        
        self.validate_delete_policy(new_policy_guid)
        
        # Verify RuntimePolicyDeleted event is NOT received (filtered out - not in events list)
        time.sleep(15)  # Wait for event to be processed if it would be sent
        messages_after_delete = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_after_delete, list):
            messages_after_delete = []
        new_messages_after_delete = messages_after_delete[count_before_delete:] if len(messages_after_delete) > count_before_delete else []
        runtime_policy_deleted_found = any(
            msg.get("event_type") == "RuntimePolicyDeleted" 
            for msg in new_messages_after_delete 
            if isinstance(msg, dict)
        )
        assert not runtime_policy_deleted_found, \
            f"RuntimePolicyDeleted event was received but should have been filtered out. New messages: {new_messages_after_delete}"
        Logger.logger.info("✓ RuntimePolicyDeleted event correctly filtered out (not in events list)")
        
        Logger.logger.info("13a. Update SIEM integration to include policy events and verify they are now received")
        # Update integration to include policy events
        current_integrations = self.backend.get_siem_integrations(provider=Providers.WEBHOOK)
        current_integration = None
        for integration in current_integrations:
            if integration.get("guid") == siem_integration_guid:
                current_integration = integration
                break
        assert current_integration, f"Failed to find SIEM integration with GUID: {siem_integration_guid}"
        
        self.backend.update_siem_integration(
            provider=Providers.WEBHOOK,
            body={
                "guid": siem_integration_guid,
                "name": current_integration.get("name"),
                "configuration": current_integration.get("configuration"),
                "isEnabled": current_integration.get("isEnabled", True),
                "events": ["IncidentCreated", "AlertCreated", "RuntimePolicyCreated", "RuntimePolicyUpdated", "RuntimePolicyDeleted", "RiskAcceptanceCreated", "RiskAcceptanceUpdated", "RiskAcceptanceDeleted"]
            }
        )
        Logger.logger.info("✓ Updated SIEM integration to include policy events")
        
        # Create a new policy to verify RuntimePolicyCreated is now received
        test_policy_for_events = {
            "name": "Test-Policy-For-Events-" + rand,
            "description": "Test policy to verify events are received",
            "enabled": True,
            "scope": {"riskFactors": ["Internet facing"], "designators": [{"cluster": "test"}]},
            "ruleSetType": "Managed",
            "managedRuleSetIDs": [incident_rulesets[0]["guid"]],
            "notifications": [],
            "actions": []
        }
        test_policy_guid = self.validate_new_policy(test_policy_for_events)
        # Verify RuntimePolicyCreated event IS now received
        self.wait_for_siem_event("RuntimePolicyCreated", siem_test_webhook_url, timeout=60)
        Logger.logger.info("✓ RuntimePolicyCreated event received as expected (now in events list)")
        
        # Update the policy to verify RuntimePolicyUpdated is now received
        test_policy_for_events["name"] = "Test-Policy-For-Events-Updated-" + rand
        self.validate_update_policy_against_backend(test_policy_guid, test_policy_for_events)
        # Verify RuntimePolicyUpdated event IS now received
        self.wait_for_siem_event("RuntimePolicyUpdated", siem_test_webhook_url, timeout=60)
        Logger.logger.info("✓ RuntimePolicyUpdated event received as expected (now in events list)")
        
        # Delete the policy to verify RuntimePolicyDeleted is now received
        self.validate_delete_policy(test_policy_guid)
        # Verify RuntimePolicyDeleted event IS now received
        self.wait_for_siem_event("RuntimePolicyDeleted", siem_test_webhook_url, timeout=60)
        Logger.logger.info("✓ RuntimePolicyDeleted event received as expected (now in events list)")

        Logger.logger.info("14. validate expected errors")
        self. validate_expected_errors()

        Logger.logger.info("15. Delete webhook")
        self.delete_webhook(guid)

        Logger.logger.info("16. Create incident to validate BE (triggers SIEM IncidentCreated event)")
        self.exec_pod(wlid=wlids[0], command="more /root/malware.o")
        self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=10,
                                cluster=cluster, namespace=namespace,
                                incident_name=["Malware found"])
        
        # Validate SIEM IncidentCreated event
        self.wait_for_siem_event("IncidentCreated", siem_test_webhook_url)

        Logger.logger.info("17. Create exception (triggers SIEM RiskAcceptanceCreated event)")
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
        ])["guid"]
        self.ensure_no_incident(wlid=wlids[0], cluster=cluster, namespace=namespace, expected_incident_name="Unexpected process launched")
        
        # Validate SIEM RiskAcceptanceCreated event
        self.wait_for_siem_event("RiskAcceptanceCreated", siem_test_webhook_url)
        
        Logger.logger.info("18. Delete exception (triggers SIEM RiskAcceptanceDeleted event)")
        self.backend.delete_runtime_exception(exception_id=exception_id)
        
        # Validate SIEM RiskAcceptanceDeleted event
        self.wait_for_siem_event("RiskAcceptanceDeleted", siem_test_webhook_url)
        
        exception_with_advanced_scopes = {
            "resources": [{
                "designatorType": "Attributes",
                "attributes": {
                    "cluster": cluster,
                    "namespace": namespace,
                    "name": "*/*",
                    "kind": "*/*"
                }
            }],
            "advancedScopes": [{
                "entity": "process.commandLine",
                "condition": "contains",
                "values": "/etc/hosts"
            },
            ],
            "policyIDs": ["I013"],
        }
        
        Logger.logger.info("19. Create incident to validate BE")
        self.exec_pod(wlid=wlids[0], command="ls /etc/hosts")
        self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=10,
                                cluster=cluster, namespace=namespace,
                                incident_name=["Unexpected process launched"])
        
        Logger.logger.info("20. Create exception with advanced scopes (triggers SIEM RiskAcceptanceCreated event)")
        exception_id = self.backend.create_runtime_exception(policy_ids=exception_with_advanced_scopes["policyIDs"], 
                                                             resources=exception_with_advanced_scopes["resources"],advanced_scopes=exception_with_advanced_scopes["advancedScopes"])["guid"]
        
        # Validate SIEM RiskAcceptanceCreated event
        self.wait_for_siem_event("RiskAcceptanceCreated", siem_test_webhook_url)

        Logger.logger.info("21. List runtime exceptions")
        exceptions = self.backend.list_runtime_exceptions()["response"][0]
        assert(exceptions.get('advancedScopes') == exception_with_advanced_scopes.get('advancedScopes'))
        
        Logger.logger.info("22. Create alert that matches exception - no incident")       
        self.ensure_no_incident(wlid=wlids[0], cluster=cluster, namespace=namespace, expected_incident_name="Unexpected process launched")
        
        Logger.logger.info("23. Create alert that does not match exception - create incident")
        self.exec_pod(wlid=wlids[0], command="tail /etc/group")
        self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=10,
                                cluster=cluster, namespace=namespace,
                                incident_name=["Unexpected process launched"])
        
        Logger.logger.info("24. Delete exception (triggers SIEM RiskAcceptanceDeleted event)")
        self.backend.delete_runtime_exception(exception_id=exception_id)
        
        # Validate SIEM RiskAcceptanceDeleted event
        self.wait_for_siem_event("RiskAcceptanceDeleted", siem_test_webhook_url)
        
        Logger.logger.info("25. Create incident after delete exception")
        self.exec_pod(wlid=wlids[0], command="head /etc/hosts")
        self.wait_for_specific_incident_count_with_report(cluster=cluster, namespace=namespace,
                                                                      incident_name=["Unexpected process launched"],
                                                                      expected_count=2, timeout=120)


        Logger.logger.info("26. Delete policies (triggers SIEM PolicyDeleted events)")
        for policy_guid in policies_guids:
            self.validate_delete_policy(policy_guid)
        # Validate SIEM PolicyDeleted event for each policy
        self.wait_for_siem_event("RuntimePolicyDeleted", siem_test_webhook_url)
        
        Logger.logger.info("27. Test SIEM Events filtering - Update existing integration with specific events")
        # Get current integration to preserve its configuration
        current_integrations = self.backend.get_siem_integrations(provider=Providers.WEBHOOK)
        current_integration = None
        for integration in current_integrations:
            if integration.get("guid") == siem_integration_guid:
                current_integration = integration
                break
        assert current_integration, f"Failed to find existing SIEM integration with GUID: {siem_integration_guid}"
        
        # Update the existing integration to add events filter (only IncidentCreated and AlertCreated)
        self.backend.update_siem_integration(
            provider=Providers.WEBHOOK,
            body={
                "guid": siem_integration_guid,
                "name": current_integration.get("name"),
                "configuration": current_integration.get("configuration"),
                "isEnabled": current_integration.get("isEnabled", True),
                "events": ["IncidentCreated", "AlertCreated"]
            }
        )
        # Verify the update was successful
        updated_integrations = self.backend.get_siem_integrations(provider=Providers.WEBHOOK)
        updated_integration = None
        for integration in updated_integrations:
            if integration.get("guid") == siem_integration_guid:
                updated_integration = integration
                # Verify events field is present and correct
                assert "events" in integration, f"Events field missing in integration response: {integration}"
                assert integration.get("events") == ["IncidentCreated", "AlertCreated"], \
                    f"Expected events ['IncidentCreated', 'AlertCreated'], got {integration.get('events')}"
                break
        assert updated_integration, f"Failed to retrieve updated SIEM integration with GUID: {siem_integration_guid}"
        Logger.logger.info(f"Updated SIEM integration '{self.siem_integration_name}' with events filter: {updated_integration.get('events')}")
        
        Logger.logger.info("28. Test Events filtering - Verify IncidentCreated event IS received (in filter list)")
        # Get initial message count to track new messages
        initial_messages = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(initial_messages, list):
            initial_messages = []
        initial_count = len(initial_messages)
        # Trigger an incident that should be sent (IncidentCreated is in the filter)
        self.exec_pod(wlid=wlids[0], command="more /root/malware.o")
        self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=10,
                            cluster=cluster, namespace=namespace,
                            incident_name=["Malware found"])
        # Verify IncidentCreated event was received
        self.wait_for_siem_event("IncidentCreated", siem_test_webhook_url, timeout=60)
        Logger.logger.info("✓ IncidentCreated event received as expected (in filter list)")
        
        Logger.logger.info("29. Test Events filtering - Verify RuntimePolicyCreated event is NOT received (not in filter list)")
        # Get message count before creating policy
        messages_before = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_before, list):
            messages_before = []
        count_before = len(messages_before)
        # Create a policy that should trigger RuntimePolicyCreated (but it's NOT in the filter)
        test_policy_body = {
            "name": "Filtered-Test-Policy-" + rand,
            "description": "Test policy for events filtering",
            "enabled": True,
            "scope": {"riskFactors": ["Internet facing"], "designators": [{"cluster": "test"}]},
            "ruleSetType": "Managed",
            "managedRuleSetIDs": [incident_rulesets[0]["guid"]],
            "notifications": [],
            "actions": []
        }
        test_policy_guid = self.validate_new_policy(test_policy_body)
        # Wait to ensure event would have been sent if not filtered
        time.sleep(20)
        # Verify RuntimePolicyCreated was NOT received
        messages_after = self.backend.get_test_webhook_messages(siem_test_webhook_url)
        if not isinstance(messages_after, list):
            messages_after = []
        # Check if any new RuntimePolicyCreated messages appeared
        new_messages = messages_after[count_before:] if len(messages_after) > count_before else []
        runtime_policy_created_found = any(
            msg.get("event_type") == "RuntimePolicyCreated" 
            for msg in new_messages 
            if isinstance(msg, dict)
        )
        assert not runtime_policy_created_found, \
            f"RuntimePolicyCreated event was received but should have been filtered out. New messages: {new_messages}"
        Logger.logger.info("✓ RuntimePolicyCreated event correctly filtered out (not in filter list)")
        # Clean up test policy
        self.validate_delete_policy(test_policy_guid)
        
    
        Logger.logger.info("30. Delete SIEM integration")
        self.backend.delete_siem_integration(provider=Providers.WEBHOOK, guid=siem_integration_guid)

        return self.cleanup()
  
    def ensure_no_incident(self, wlid: str, cluster: str, namespace: str, expected_incident_name: str):
        """
        Verify that no incident is created (e.g., when an exception should prevent it).
        If an incident is found, raises an exception indicating the exception/rule is not working as expected.
        """
        exception_occurred = False
        self.exec_pod(wlid=wlid, command="cat /etc/hosts")
        try:
            self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=10,
                                cluster=cluster, namespace=namespace,
                                incident_name=[expected_incident_name])
        except Exception:
            exception_occurred = True
        if not exception_occurred:
            raise Exception(f"Incident '{expected_incident_name}' was created when it should have been prevented (exception/rule may not be working correctly)")
        
    def wait_for_specific_incident_count_with_report(self, cluster: str, namespace: str, incident_name: list, expected_count: int, timeout: int = 120):
        """
        Wait for a specific number of incidents using wait_for_report pattern.
        
        :param cluster: Cluster name
        :param namespace: Namespace name
        :param incident_name: List of incident names to look for
        :param expected_count: Expected number of incidents
        :param timeout: Total timeout in seconds
        :return: List of incidents
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                incidents = self.wait_for_report(self.verify_incident_in_backend_list, timeout=30, sleep_interval=10,
                                                cluster=cluster, namespace=namespace,
                                                incident_name=incident_name)
                if len(incidents[0]) == expected_count:
                    Logger.logger.info(f"Found {expected_count} incidents as expected")
                    return incidents[0]
                else:
                    Logger.logger.info(f"Found {len(incidents[0])} incidents, expecting {expected_count}. Waiting...")
            except Exception as e:
                Logger.logger.warning(f"Error checking incidents: {e}")
            
            time.sleep(10)
        
        raise Exception(f"Timeout waiting for {expected_count} incidents after {timeout} seconds")
        
    def cleanup(self, **kwargs):
        for guid in self.tested_webhook_guid:
            self.delete_webhook(guid)
            
        for guid in self.tested_policy_guid:
            self.validate_delete_policy(guid)
        
        # Clean up SIEM integrations
        for guid, provider in self.siem_integration_guids.items():
            try:
                self.backend.delete_siem_integration(provider=provider, guid=guid)
                Logger.logger.info(f'Successfully deleted {provider} SIEM integration with guid: {guid}')
            except Exception as e:
                Logger.logger.error(f'Failed to delete SIEM integration {guid}: {e}')
        
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
            TestUtil.save_expected_json(incident_rulesets, EXPECTED_RUNTIME_RULESETS_PATH)
        
        assert len(incident_rulesets["response"]) > 0, "no incident rulesets found"  
        
        return incident_rulesets["response"]


    def validate_new_policy(self, body: Dict[str, Any]) -> str:
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
        res = self.backend.delete_runtime_policies(guid)
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

    def wait_for_siem_event(self, expected_event_type: str, url: str, timeout: int = 240, sleep_interval: int = 10) -> dict:
        """
        Wait for a SIEM event of the expected type to be received by the webhook.
        Polls the backend's test webhook endpoint to retrieve received messages.
        """
        Logger.logger.info(f"Waiting for SIEM event of type: {expected_event_type}")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Retrieve webhook messages from the test endpoint
                messages = self.backend.get_test_webhook_messages(url)
                
                # Ensure messages is a list
                if not isinstance(messages, list):
                    messages = []
                
                # Look for the expected event type
                for message in messages:
                    if isinstance(message, dict) and message.get("event_type") == expected_event_type:
                        Logger.logger.info(f"✓ Found SIEM event of type: {expected_event_type}")
                        Logger.logger.info(f"  Event GUID: {message.get('event_guid')}")
                        Logger.logger.info(f"  Customer: {message.get('customer_guid')}")
                        Logger.logger.info(f"  Timestamp: {message.get('timestamp')}")
                        return message
                
                Logger.logger.debug(f"Event {expected_event_type} not found yet, waiting... ({int(time.time() - start_time)}s elapsed)")
            except Exception as e:
                Logger.logger.warning(f"Error retrieving webhook messages: {e}")
            
            time.sleep(sleep_interval)
        
        raise Exception(f"Timeout waiting for SIEM event type '{expected_event_type}' after {timeout} seconds")
    
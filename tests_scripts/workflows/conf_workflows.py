from tests_scripts.workflows.utils import(get_env,
WORKFLOW_NAME,
SEVERITIES_CRITICAL,
SLACK_CHANNEL_NAME,
TEAMS_CHANNEL_NAME,
UPDATED_WORKFLOW_NAME,
SEVERITIES_HIGH,
EXPECTED_CREATE_RESPONSE,
EXPECTED_UPDATE_RESPONSE,
WEBHOOK_NAME)
import random

from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger
from tests_scripts.workflows.workflows import Workflows




class WorkflowConfigurations(Workflows):
    """
    Check workflow - list, create, update, delete
    """
    def __init__(self, test_obj=None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)
        self.test_obj: TestConfiguration = test_obj

    def start(self):
        """
        Agenda:
        1. Create webhook
        2. Create slack workflow
        3. Validate slack workflow created successfully
        4. Update slack workflow
        5. Validate slack updated workflow
        6. Delete slack workflow
        7. Create teams workflow
        8. Validate teams workflow created successfully
        9. Update teams workflow
        10. Validate teams updated workflow
        11. Delete teams workflow and teams channel
        """
        assert self.backend is not None, f'The test {self.test_driver.test_name} must run with backend'

        rand = str(random.randint(10000000, 99999999))

        webhook_test_name = WEBHOOK_NAME + "conf_test_" + rand
        webhook_test_name_updated = webhook_test_name + "_updated_" + rand

        workflow_test_name = WORKFLOW_NAME + "conf_test_" + rand
        workflow_test_name_updated = workflow_test_name + "_updated_" + rand

        Logger.logger.info("Stage 1: Create webhook")
        self.create_webhook(name=webhook_test_name)
        channel_guid = self.get_channel_guid_by_name(webhook_test_name)

        Logger.logger.info("stage 2: create slack workflow")
        workflow_creation_body = self.build_slack_workflow_body(workflow_name=workflow_test_name, severities=SEVERITIES_CRITICAL, channel_name=SLACK_CHANNEL_NAME, channel_id=get_env("SLACK_CHANNEL_ID"))
        self.create_and_assert_workflow(workflow_creation_body, EXPECTED_CREATE_RESPONSE)


        Logger.logger.info("stage 3: validate slack workflow created successfully")
        workflow_guid = self.validate_slack_workflow(workflow_test_name, SEVERITIES_CRITICAL, SLACK_CHANNEL_NAME)
        Logger.logger.info(f"slack workflow name {workflow_test_name} guid: {workflow_guid}")
        self.test_workflows_guids.append(workflow_guid)

        Logger.logger.info("stage 4: update slack workflow")
        update_workflow_body = self.build_slack_workflow_body(workflow_name=workflow_test_name_updated, severities=SEVERITIES_HIGH, channel_name=SLACK_CHANNEL_NAME, channel_id=get_env("SLACK_CHANNEL_ID"), guid=workflow_guid)
        self.create_and_assert_workflow(update_workflow_body, EXPECTED_UPDATE_RESPONSE, update=True)
        
        Logger.logger.info("stage 5: validate slack updated workflow")
        workflow_guid = self.validate_slack_workflow(workflow_test_name_updated, SEVERITIES_HIGH, SLACK_CHANNEL_NAME)
        Logger.logger.info("stage 6: delete slack workflow")
        self.delete_and_assert_workflow(workflow_guid=workflow_guid)
        

        Logger.logger.info("stage 7: create teams workflow")
        workflow_creation_body = self.build_teams_workflow_body(workflow_name=workflow_test_name, severities=SEVERITIES_CRITICAL, channel_name=TEAMS_CHANNEL_NAME, channel_id=channel_guid, webhook_url=get_env("CHANNEL_WEBHOOK"))
        self.create_and_assert_workflow(workflow_creation_body, EXPECTED_CREATE_RESPONSE)

        Logger.logger.info("stage 8: validate teams workflow created successfully")
        workflow_guid = self.validate_teams_workflow(workflow_test_name, SEVERITIES_CRITICAL, TEAMS_CHANNEL_NAME)
        Logger.logger.info(f"teams workflow name {workflow_test_name} guid: {workflow_guid}")
        self.test_workflows_guids.append(workflow_guid)

        
        Logger.logger.info("stage 9: update teams workflow")
        workflow_guid = self.return_workflow_guid(workflow_test_name)
        update_workflow_body = self.build_teams_workflow_body(workflow_name=workflow_test_name_updated, severities=SEVERITIES_HIGH, channel_name=TEAMS_CHANNEL_NAME, channel_id=channel_guid, webhook_url=get_env("CHANNEL_WEBHOOK"), guid=workflow_guid)
        self.create_and_assert_workflow(update_workflow_body, EXPECTED_UPDATE_RESPONSE, update=True)

        Logger.logger.info("stage 10: validate teams updated workflow")
        workflow_guid = self.validate_teams_workflow(workflow_test_name_updated, SEVERITIES_HIGH, TEAMS_CHANNEL_NAME)
        self.test_workflows_guids.append(workflow_guid)

        Logger.logger.info("stage 11: delete teams workflow and teams channel")
        self.delete_and_assert_workflow(workflow_guid=workflow_guid)
        self.delete_channel_by_guid(channel_guid)
        return True, "Workflow configurations test passed"
        
    

        
    def create_webhook(self, name):
        webhook_body = {
            "guid": "",
            "name": name,
            "webhookURL": get_env("CHANNEL_WEBHOOK")
        }
        r = self.backend.create_webhook(webhook_body)
        assert r == "Teams channel created", f"Expected 'Teams channel created', but got {r['response']}"
        
    def get_channel_guid_by_name(self, channel_name):
        channels = self.backend.get_webhooks()
        for channel in channels:
            if channel["name"] == channel_name:
                return channel["guid"]
        return "Channel not found"
    
    def delete_channel_by_guid(self, channel_guid):
        r = self.backend.delete_webhook(body={"innerFilters": [{"guid": channel_guid}]})
        assert r == "Teams channel deleted", f"Expected 'Teams channel deleted', but got {r['response']}"
        channels = self.backend.get_webhooks()
        for channel in channels:
            if channel["guid"] == channel_guid:
                return f"Channel with guid {channel_guid} not deleted"
        return "Channel deleted"
            
            
    def build_slack_workflow_body(self, workflow_name, severities, channel_name, channel_id, guid=None):
        return {
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": workflow_name,
            "scope": [
                {
                    "cluster": "some-cluster",
                    "namespace": "some-namespace"
                }
            ],
            "conditions": [
                {
                    "category": "SecurityRisks",
                    "parameters": {
                        "severities": severities
                    }
                }
            ],
            "notifications": [
                {
                    "provider": "slack",
                    "slackChannels": [
                        {
                            "id": channel_id,
                            "name": channel_name
                        }
                    ]
                }
            ]
        }
    
    def build_teams_workflow_body(self, workflow_name, severities, channel_name, channel_id, webhook_url, guid=None):
        return {
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": workflow_name,
             "scope": [
                {
                    "cluster": "some-cluster",
                    "namespace": "some-namespace"
                }
            ],
            "conditions": [
                {
                    "category": "SecurityRisks",
                    "parameters": {
                        "severities": severities
                    }
                }
            ],
            "notifications": [
                {
                    "provider": "teams",
                    "teamsChannels": [
                        {
                            "guid": channel_id,
                            "name": channel_name,
                            "webhookURL": webhook_url
                        }
                    ]
                }
            ]
        }   


    def validate_slack_workflow(self, expected_name, expected_severities, expected_slack_channel):
        json={"pageSize": 1, "pageNum": 1, "orderBy": "", "innerFilters":[{"name":expected_name}]}
        workflows = self.backend.get_workflows(body=json)
        assert workflows["total"]["value"] >= 1, f"Expected total value to be greater or equal to 1, but got {workflows['total']['value']}"

        guid = None
        found = False
        for workflow in workflows["response"]:
            if workflow["name"] == expected_name:
                severities = workflow["conditions"][0]["parameters"]["severities"]
                assert severities == expected_severities, f"Expected severities {expected_severities} but got {severities}"

                slack_channel = workflow["notifications"][0]["slackChannels"][0]["name"]
                assert slack_channel == expected_slack_channel, f"Expected slack channel {expected_slack_channel} but got {slack_channel}"
                guid = workflow["guid"]
                found = True
                break

        assert found, f"Workflow with name {expected_name} not found"
        return guid

    def validate_teams_workflow(self, expected_name, expected_severities, expected_teams_channel):
        workflows = self.backend.get_workflows()
        assert workflows["total"]["value"] >= 1, f"Expected total value to be greater or equal to 1, but got {workflows['total']['value']}"

        guid = None
        found = False
        for workflow in workflows["response"]:
            if workflow["name"] == expected_name:
                severities = workflow["conditions"][0]["parameters"]["severities"]
                assert severities == expected_severities, f"Expected severities {expected_severities} but got {severities}"

                teams_channel = workflow["notifications"][0]["teamsChannels"][0]["name"]
                assert teams_channel == expected_teams_channel, f"Expected teams channel {expected_teams_channel} but got {teams_channel}"

                guid = workflow["guid"]
                found = True
                break

        assert found, f"Workflow with name {expected_name} not found"
        return guid
        
        

    


        
        

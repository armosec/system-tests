from tests_scripts.workflows.utils import(get_env,
WORKFLOW_NAME,
SEVERITIES_CRITICAL,
SLACK_CHANNEL_NAME,
TEAMS_CHANNEL_NAME,
UPDATED_WORKFLOW_NAME,
SEVERITIES_HIGH,
EXPECTED_CREATE_RESPONSE,
EXPECTED_UPDATE_RESPONSE)

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
        1. create workflow
        2. validate workflows
        3. update workflow
        4. validate updated workflow
        5. delete workflow 
        6. cleanup
        """
        assert self.backend is not None, f'The test {self.test_driver.test_name} must run with backend'

        Logger.logger.info("1. create slack workflow")
        workflow_creation_body = self.build_slack_workflow_body(name=WORKFLOW_NAME, severities=SEVERITIES_CRITICAL, channel_name=SLACK_CHANNEL_NAME, channel_id=get_env("SLACK_CHANNEL_ID"))
        self.create_and_assert_workflow(workflow_creation_body, EXPECTED_CREATE_RESPONSE)

        Logger.logger.info("2. validate slack workflow created successfully")
        self.validate_slack_workflow(WORKFLOW_NAME, SEVERITIES_CRITICAL, SLACK_CHANNEL_NAME)

        Logger.logger.info("3. update slack workflow")
        workflow_guid = self.return_workflow_guid(WORKFLOW_NAME)
        update_workflow_body = self.build_slack_workflow_body(name=UPDATED_WORKFLOW_NAME, severities=SEVERITIES_HIGH, channel_name=SLACK_CHANNEL_NAME, channel_id=get_env("SLACK_CHANNEL_ID"), guid=workflow_guid)
        self.create_and_assert_workflow(update_workflow_body, EXPECTED_UPDATE_RESPONSE, update=True)
        
        Logger.logger.info("4. validate slack updated workflow")
        self.validate_slack_workflow(UPDATED_WORKFLOW_NAME, SEVERITIES_HIGH, SLACK_CHANNEL_NAME)

        Logger.logger.info("5. delete slack workflow")
        workflow_guid = self.return_workflow_guid(UPDATED_WORKFLOW_NAME)
        self.delete_and_assert_workflow(workflow_guid=workflow_guid)

        Logger.logger.info("6. create teams workflow")
        workflow_creation_body = self.build_teams_workflow_body(name=WORKFLOW_NAME, severities=SEVERITIES_CRITICAL, channel_name=TEAMS_CHANNEL_NAME, channel_id=get_env("TEAMS_CHANNEL_GUID"), webhook_url=get_env("WEBHOOK_URL"))
        self.create_and_assert_workflow(workflow_creation_body, EXPECTED_CREATE_RESPONSE)

        Logger.logger.info("7. validate teams workflow created successfully")
        self.validate_teams_workflow(WORKFLOW_NAME, SEVERITIES_CRITICAL, TEAMS_CHANNEL_NAME)
        
        Logger.logger.info("8. update teams workflow")
        workflow_guid = self.return_workflow_guid(WORKFLOW_NAME)
        update_workflow_body = self.build_teams_workflow_body(name=UPDATED_WORKFLOW_NAME, severities=SEVERITIES_HIGH, channel_name=TEAMS_CHANNEL_NAME, channel_id=get_env("TEAMS_CHANNEL_GUID"), webhook_url=get_env("WEBHOOK_URL"), guid=workflow_guid)
        self.create_and_assert_workflow(update_workflow_body, EXPECTED_UPDATE_RESPONSE, update=True)

        Logger.logger.info("9. validate teams updated workflow")
        self.validate_teams_workflow(UPDATED_WORKFLOW_NAME, SEVERITIES_HIGH, TEAMS_CHANNEL_NAME)

        Logger.logger.info("10. delete teams workflow")
        workflow_guid = self.return_workflow_guid(UPDATED_WORKFLOW_NAME)
        self.delete_and_assert_workflow(workflow_guid=workflow_guid)

        return True, "Workflow configurations test passed"
        
    

        

            
            
    def build_slack_workflow_body(self, name, severities, channel_name, channel_id, guid=None):
        return {
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": name,
            "scope": [],
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
    
    def build_teams_workflow_body(self, name, severities, channel_name, channel_id, webhook_url, guid=None):
        return {
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": name,
            "scope": [],
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
    
    def create_and_assert_workflow(self, workflow_body, expected_response, update=False):
        if update:
            workflow_res = self.backend.update_workflow(body=workflow_body)
        else:
            workflow_res = self.backend.create_workflow(body=workflow_body)
        
        
        assert workflow_res == expected_response, f"Expected {expected_response}, but got {workflow_res['response']}"
        return workflow_res

    def validate_slack_workflow(self, expected_name, expected_severities, expected_slack_channel):
        workflows = self.backend.get_workflows()
        assert workflows["total"]["value"] >= 1, f"Expected total value to be greater or equal to 1, but got {workflows['total']['value']}"


        found = False
        for workflow in workflows["response"]:
            if workflow["name"] == expected_name:
                severities = workflow["conditions"][0]["parameters"]["severities"]
                assert severities == expected_severities, f"Expected severities {expected_severities} but got {severities}"

                slack_channel = workflow["notifications"][0]["slackChannels"][0]["name"]
                assert slack_channel == expected_slack_channel, f"Expected slack channel {expected_slack_channel} but got {slack_channel}"

                found = True
                break

        assert found, f"Workflow with name {expected_name} not found"

    def validate_teams_workflow(self, expected_name, expected_severities, expected_teams_channel):
        workflows = self.backend.get_workflows()
        assert workflows["total"]["value"] >= 1, f"Expected total value to be greater or equal to 1, but got {workflows['total']['value']}"

        found = False
        for workflow in workflows["response"]:
            if workflow["name"] == expected_name:
                severities = workflow["conditions"][0]["parameters"]["severities"]
                assert severities == expected_severities, f"Expected severities {expected_severities} but got {severities}"

                teams_channel = workflow["notifications"][0]["teamsChannels"][0]["name"]
                assert teams_channel == expected_teams_channel, f"Expected teams channel {expected_teams_channel} but got {teams_channel}"

                found = True
                break

        assert found, f"Workflow with name {expected_name} not found"
        
        

    def delete_and_assert_workflow(self, workflow_guid):
        workflow_delete_res = self.backend.delete_workflow(workflow_guid)
        assert workflow_delete_res == "Workflow deleted", f"Expected 'Workflow deleted', but got {workflow_delete_res['response']}"
        workflows = self.backend.get_workflows()["response"]
        for workflow in workflows:
            assert workflow["guid"] != workflow_guid, f"Expected workflow with guid {workflow_guid} to be deleted, but it still exists"


    def return_workflow_guid(self, workflow_name):
        workflows = self.backend.get_workflows()["response"]
        for workflow in workflows:
            if workflow["name"] == workflow_name:
                return workflow["guid"]
        print(f"Workflow with name {workflow_name} not found")
        return None
        
        

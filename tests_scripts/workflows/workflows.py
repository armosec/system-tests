import json
import time


from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import statics, Logger
from tests_scripts.helm.base_helm import BaseHelm



class Workflows(BaseHelm):
    def __init__(self, test_obj=None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)
        self.test_obj: TestConfiguration = test_obj

    def active_workflow(self):

        # activating workflows feature for the tenant.
        # TODO: remove this activate once feature is live (i.e. no need to activate it)
        res = self.backend.active_workflow(self.test_tenant_id)
        response = json.loads(res.text)

        # verify that the workflows feature is enabled
        assert response["workflowsEnabled"] == True, f"workflowsEnabled is False"
        assert response["workflowsConverted"] == True, f"workflowsConverted is False"
        Logger.logger.info(f"active_workflow response: {response}")


class WorkflowsSlack(Workflows):
    def __init__(self, test_obj=None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)
        self.test_obj: TestConfiguration = test_obj

    def copy_slack_token(self):
        # copy the slack token
        res = self.backend.copy_slack_token(self.test_tenant_id)
        response = json.loads(res.text)
        Logger.logger.info(f"copy_slack_token response: {response}")

    def start(self):
        super().active_workflow()

        # # copy the slack token only if we are under a test tenant
        # if self.test_tenant_id != "":
        #     self.copy_slack_token()

        # ******************** 
        # COMPLETE TEST HERE

        # ********************

        return self.cleanup()
    
    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)
    

class WorkflowsTeams(Workflows):
    def __init__(self, test_obj=None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)
        self.test_obj: TestConfiguration = test_obj

    def start(self):
        super().active_workflow()

        # ******************** 
        # COMPLETE TEST HERE

        # ********************

        return self.cleanup()
    
    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)

class WorkflowConfigurations(Workflows):
    """
    Check slack workflow - list, create, update, delete, unique values
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
        super().active_workflow()
        assert self.backend is not None, f'The test {self.test_driver.test_name} must run with backend'

        Logger.logger.info("1. create workflow")
        workflow_creation_body = self.build_workflow_body(name="test", severities=["Critical"], slack_channel="test_slack_3")
        workflow_creation_res = self.create_and_assert_workflow(workflow_creation_body, "Workflow created")

        Logger.logger.info("2. validate workflow created successfully")
        self.validate_workflow("test", ["Critical"], "test_slack_3")

        Logger.logger.info("3. update workflow")
        update_workflow_body = self.build_workflow_body(name="test_updated", severities=["High"], slack_channel="test_slack_3", guid=workflow_creation_res["response"]["guid"])
        self.create_and_assert_workflow(update_workflow_body, "Workflow updated", update=True)

        Logger.logger.info("4. validate updated workflow")
        self.validate_workflow("test_updated", ["High"], "test_slack_3")

        Logger.logger.info("5. delete workflow")
        self.delete_and_assert_workflow(workflow_creation_res["response"]["guid"])

        self.cleanup()

    def build_workflow_body(self, name, severities, slack_channel, guid=""):
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
                            "id": "C06A5G4V9NE",
                            "name": slack_channel
                        }
                    ]
                }
            ]
        }

    def create_and_assert_workflow(self, workflow_body, expected_response, update=False):
        if update:
            res = self.backend.update_workflow(body=workflow_body)
        else:
            res = self.backend.create_workflow(body=workflow_body)

        workflow_res = json.loads(res.text)
        assert workflow_res["response"] == expected_response, f"Expected {expected_response}, but got {workflow_res['response']}"
        return workflow_res

    def validate_workflow(self, expected_name, expected_severities, expected_slack_channel):
        res = self.backend.get_workflows()
        workflows = json.loads(res.text)
        assert workflows["total"]["value"] > 1, f"Expected total value to be greater than 1, but got {workflows['total']['value']}"

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
        

    def delete_and_assert_workflow(self, workflow_guid):
        delete_body = {
            "guid": workflow_guid
        }
        res = self.backend.delete_workflow(body=delete_body)
        workflow_delete_res = json.loads(res.text)
        assert workflow_delete_res["response"] == "Workflow deleted", f"Expected 'Workflow deleted', but got {workflow_delete_res['response']}"
   

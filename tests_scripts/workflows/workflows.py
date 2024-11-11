import json



from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import statics, Logger
from tests_scripts.helm.base_helm import BaseHelm
from tests_scripts.base_test import BaseTest



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


    def copy_slack_token(self):
        # copy the slack token
        res = self.backend.copy_slack_token(self.test_tenant_id)
        Logger.logger.info(f"copy_slack_token response: {res}")

    

    def start(self):
        """
        Agenda:
        1. Install armo helm-chart
        2. validate the running pods
        3. create slack workflow
        4. validate workflow created successfully
        5. scan the cluster for security risks
        6. validate the alert massage 
        """

        # ******************** 
        # COMPLETE TEST HERE

        # ********************

        # super().active_workflow()
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'
        cluster, namespace = self.setup()

        Logger.logger.info("1. Install armo helm-chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)

        Logger.logger.info("2. validate the running pods")
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=360,
                             namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        
        Logger.logger.info("3. create slack workflow")
        workflow_creation_body = self.build_workflow_body(name="test", severities=["Critical"], slack_channel="test_slack_3", cluster=cluster, namespace=namespace)
        self.create_and_assert_workflow(workflow_creation_body, "Workflow created")

        Logger.logger.info("4. validate workflow created successfully")
        self.validate_workflow("test", ["Critical"], "test_slack_3")

        Logger.logger.info("5. scan the cluster for security risks")
        r = self.backend.create_kubescape_job_request(cluster_name=cluster, framework_list=[""] ,with_host_sensor="false")
        assert r.status_code == 200, f"Expected status code 200, but got {r.status_code}"
        

        

        # # copy the slack token only if we are under a test tenant
        # if self.test_tenant_id != "":
        #     self.copy_slack_token()
            

        return self.cleanup()
    
    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)
    
    
    def create_and_assert_workflow(self, workflow_body, expected_response, update=False):
        if update:
            workflow_res = self.backend.update_workflow(body=workflow_body)
        else:
            workflow_res = self.backend.create_workflow(body=workflow_body)
        
        
        assert workflow_res == expected_response, f"Expected {expected_response}, but got {workflow_res['response']}"
        return workflow_res
    
    def build_workflow_body(self, name, severities, slack_channel, cluster, namespace, guid=None):
        workflow_body = {
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": name,
            "scope": [
                {
                    "cluster": cluster,
                    "namespace": namespace
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
                            "id": "C06A5G4V9NE",
                            "name": slack_channel
                        }
                    ]
                }
            ]
        }
        return workflow_body
    
    def validate_workflow(self, expected_name, expected_severities, expected_slack_channel):
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

class WorkflowConfigurations(BaseTest):
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

        Logger.logger.info("1. create workflow")
        workflow_creation_body = self.build_workflow_body(name="test", severities=["Critical"], slack_channel="test_slack_3")
        self.create_and_assert_workflow(workflow_creation_body, "Workflow created")

        Logger.logger.info("2. validate workflow created successfully")
        self.validate_workflow("test", ["Critical"], "test_slack_3")

        Logger.logger.info("3. update workflow")
        workflow_guid = self.backend.get_workflows()["response"][0]["guid"]
        update_workflow_body = self.build_workflow_body(name="test_updated", severities=["High"], slack_channel="test_slack_3", guid=workflow_guid)
        self.create_and_assert_workflow(update_workflow_body, "Workflow updated", update=True)

        Logger.logger.info("4. validate updated workflow")
        self.validate_workflow("test_updated", ["High"], "test_slack_3")

        Logger.logger.info("5. delete workflow")
        workflow_guid = self.backend.get_workflows()["response"][0]["guid"]
        self.delete_and_assert_workflow(workflow_guid=workflow_guid)

        return self.cleanup()

        

    def build_workflow_body(self, name, severities, slack_channel, guid=None):
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
            workflow_res = self.backend.update_workflow(body=workflow_body)
        else:
            workflow_res = self.backend.create_workflow(body=workflow_body)
        
        
        assert workflow_res == expected_response, f"Expected {expected_response}, but got {workflow_res['response']}"
        return workflow_res

    def validate_workflow(self, expected_name, expected_severities, expected_slack_channel):
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
        
        

    def delete_and_assert_workflow(self, workflow_guid):
        workflow_delete_res = self.backend.delete_workflow(workflow_guid)
        assert workflow_delete_res == "Workflow deleted", f"Expected 'Workflow deleted', but got {workflow_delete_res['response']}"

    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)

    
   

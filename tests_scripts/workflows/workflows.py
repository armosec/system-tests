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

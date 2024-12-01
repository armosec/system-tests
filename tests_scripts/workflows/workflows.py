import json
from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger
from tests_scripts.helm.base_helm import BaseHelm



class Workflows(BaseHelm):
    def __init__(self, test_obj=None, backend=None, test_driver=None, kubernetes_obj=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)
        
    

    def active_workflow(self):

        # activating workflows feature for the tenant.
        # TODO: remove this activate once feature is live (i.e. no need to activate it)
        res = self.backend.active_workflow(self.test_tenant_id)
        response = json.loads(res.text)

        # verify that the workflows feature is enabled
        assert response["workflowsEnabled"] == True, f"workflowsEnabled is False"
        assert response["workflowsConverted"] == True, f"workflowsConverted is False"
        Logger.logger.info(f"active_workflow response: {response}")

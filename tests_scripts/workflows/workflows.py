import json
from systest_utils import Logger, statics
from tests_scripts.helm.base_helm import BaseHelm
from ..kubescape.base_kubescape import BaseKubescape





class Workflows(BaseHelm, BaseKubescape):
    def __init__(self, test_obj=None, backend=None, test_driver=None, kubernetes_obj=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)
        
        self.test_workflows_guids = []
    

    def cleanup(self, **kwargs):
        self.cleanup_workflows()
        return super().cleanup(**kwargs)

    def install_kubescape(self, helm_kwargs: dict = None):
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
    
    def cleanup_workflows(self):
        for guid in self.test_workflows_guids:
            try:
                self.delete_and_assert_workflow(guid)
                Logger.logger.info(f"Deleted workflow with guid {guid}")
            except Exception as e:
                Logger.logger.error(f"Failed to delete workflow with guid {guid}, got exception {e}")
        self.test_workflows_guids = []

    def create_and_assert_workflow(self, workflow_body, expected_response, update=False):
        if update:
            workflow_res = self.backend.update_workflow(body=workflow_body)
        else:
            workflow_res = self.backend.create_workflow(body=workflow_body)
        
        assert workflow_res == expected_response, f"Expected {expected_response}, but got {workflow_res}"
        return workflow_res
    
    def add_workflow_test_guid(self, workflow_guid):
        self.test_workflows_guids.append(workflow_guid)


    def return_workflow_guid(self, workflow_name):
        workflows = self.backend.get_workflows()["response"]
        for workflow in workflows:
            if workflow["name"] == workflow_name:
                return workflow["guid"]
        Logger.logger.info(f"Workflow with name {workflow_name} not found")
        return None

    def delete_and_assert_workflow(self, workflow_guid):
        workflow_delete_res = self.backend.delete_workflow(workflow_guid)
        assert workflow_delete_res == "Workflow deleted", f"Expected 'Workflow deleted', but got {workflow_delete_res['response']}"
        res = self.backend.get_workflows()
        assert "response" in res, f"Expected response in {res}"

        if len(res["response"]) == 0:
            return

        found = False
        for workflow in res["response"]:
            if workflow["guid"] == workflow_guid:
                found = True
                break
        
        assert not found, f"Expected workflow with guid {workflow_guid} to be deleted, but it still exists, got {res['response']} workflows"

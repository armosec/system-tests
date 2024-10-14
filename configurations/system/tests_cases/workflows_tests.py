import inspect
from .structures import TestConfiguration




class WorkflowsTests(object):
    '''
    NOTE: 
    
    '''
    
    @staticmethod
    def slack_alerts_workflows():
        from tests_scripts.workflows.workflows import WorkflowsSlack
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=WorkflowsSlack,
            create_test_tenant = True
        )    
    
    @staticmethod
    def teams_alerts_workflows():
        from tests_scripts.workflows.workflows import WorkflowsSlack
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=WorkflowsSlack,
            create_test_tenant = True
        )    

   
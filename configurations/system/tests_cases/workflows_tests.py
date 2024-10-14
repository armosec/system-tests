import inspect
from tests_scripts.runtime.workflows import WorkflowConfigurations
from .structures import TestConfiguration

class WorkflowsTests(object):
    @staticmethod
    def workflow_configurations():
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=WorkflowConfigurations,
        )
    

    
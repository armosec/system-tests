from tests_scripts import base_test
from  http import client
from systest_utils import Logger

class BaseRuntime(base_test.BaseTest):

    def __init__(self, test_obj=None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)
    
    @staticmethod
    def http_status_ok(http_status: int):
        assert http_status == client.OK
            
    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)
    


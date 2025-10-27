from tests_scripts import base_test
from systest_utils import statics


class BaseIntegrations(base_test.BaseTest):


    def __init__(self, test_obj=None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)

    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)        
        return statics.SUCCESS, ""


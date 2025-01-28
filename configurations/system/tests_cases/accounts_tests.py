import inspect

from .structures import KubescapeConfiguration


class AccountsTests(object):
    
    @staticmethod
    def cspm():
        from tests_scripts.accounts.cspm import CSPM
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CSPM
        )

    @staticmethod
    def clusters():
        from tests_scripts.accounts.clusters import Clusters
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Clusters
        )
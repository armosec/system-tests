import inspect

from .structures import KubescapeConfiguration


class AccountsTests(object):


    @staticmethod
    def clusters():
        from tests_scripts.accounts.clusters import Clusters
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Clusters
        )
    
    @staticmethod
    def cloud_connect():
        from tests_scripts.accounts.connect import CloudConnect
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudConnect
        )
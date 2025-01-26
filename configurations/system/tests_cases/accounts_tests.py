import inspect

from .structures import KubescapeConfiguration


class AccountsTests(object):
    
    @staticmethod
    def cspm():
        from tests_scripts.accounts.cspm import CSPM
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CSPM,
            create_test_tenant=True
        )
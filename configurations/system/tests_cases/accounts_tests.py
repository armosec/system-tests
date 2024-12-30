import inspect

from .structures import KubescapeConfiguration


class AccountsTests(object):
    
    @staticmethod
    def accounts():
        from tests_scripts.accounts.accounts import Accounts
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Accounts,
        )
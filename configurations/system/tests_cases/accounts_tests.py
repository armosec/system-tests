import inspect

from .structures import KubescapeConfiguration
from systest_utils import statics,TestUtil
from os.path import join

class AccountsTests(object):
    @staticmethod
    def clusters():
        from tests_scripts.accounts.clusters import Clusters
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Clusters
        )

    @staticmethod
    def cloud_connect_aws():
        from tests_scripts.accounts.connect import CloudConnect
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudConnect,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )
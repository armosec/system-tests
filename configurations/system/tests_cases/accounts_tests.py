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

    @staticmethod
    def cloud_connect_aws_cspm_single():
        from tests_scripts.accounts.connect_cspm_single import CloudConnectCSPMSingle
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudConnectCSPMSingle,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )

    @staticmethod
    def cloud_connect_aws_cadr_single():
        from tests_scripts.accounts.connect_cadr_single import CloudConnectCADRSingle
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudConnectCADRSingle,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )

    @staticmethod
    def cloud_organization_aws_cspm():
        from tests_scripts.accounts.connect_cspm_org import CloudOrganizationCSPM
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudOrganizationCSPM,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )
    
    @staticmethod
    def cloud_organization_aws_cadr():
        from tests_scripts.accounts.connect_cadr_org import CloudOrganizationCADR
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudOrganizationCADR,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )
    
    @staticmethod
    def cloud_vulnscan_aws():
        from tests_scripts.accounts.vulnscan import CloudVulnScan
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudVulnScan,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )
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
    def cloud_connect_azure_cspm_single():
        from tests_scripts.accounts.cloud_connect_cspm_single_azure import CloudConnectCSPMSingleAzure
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudConnectCSPMSingleAzure,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )
    @staticmethod
    def cloud_connect_gcp_cspm_single():
        from tests_scripts.accounts.cloud_connect_cspm_single_gcp import CloudConnectCSPMSingleGCP
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudConnectCSPMSingleGCP,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )

    @staticmethod
    def cloud_connect_aws_cspm_single():
        from tests_scripts.accounts.cloud_connect_cspm_single_aws import CloudConnectCSPMSingleAWS
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudConnectCSPMSingleAWS,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )

    @staticmethod
    def cloud_connect_aws_cadr_single():
        from tests_scripts.accounts.cloud_connect_cadr_single_aws import CloudConnectCADRSingle
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudConnectCADRSingle,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )

    @staticmethod
    def cloud_organization_aws_cspm():
        from tests_scripts.accounts.cloud_connect_cspm_org_aws import CloudOrganizationCSPM
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudOrganizationCSPM,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )
    
    @staticmethod
    def cloud_organization_aws_cadr():
        from tests_scripts.accounts.cloud_connect_cadr_org_aws import CloudOrganizationCADR
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudOrganizationCADR,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )
    
    @staticmethod
    def cloud_vulnscan_aws():
        from tests_scripts.accounts.cloud_vulnscan_aws import CloudVulnScan
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CloudVulnScan,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )
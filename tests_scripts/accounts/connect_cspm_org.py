import os
import time
from systest_utils import Logger, statics
from tests_scripts.accounts.accounts import COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME
from tests_scripts.accounts.accounts import ExclusionActions, UpdateCloudOrganizationMetadataRequest
from tests_scripts.accounts.accounts import extract_parameters_from_url
from tests_scripts.accounts.accounts import Accounts
import random
from urllib.parse import parse_qs, quote, urlparse
from infrastructure import aws
from typing import List
from tests_scripts.accounts.accounts import CSPM_STATUS_HEALTHY
# static cloudtrail and bucket names that are expected to be existed in the test account
ORGANIZATION_CLOUDTRAIL_SYSTEM_TEST_CONNECT = "trail-system-test-organization-connect-dont-delete"
ORGANIZATION_TRAIL_LOG_LOCATION = "system-test-organization-bucket-armo/AWSLogs/o-63kbjphubt/930002936888"
ACCOUNT_TRAIL_LOG_LOCATION = "system-test-organization-bucket-armo/AWSLogs/930002936888"

REGION_SYSTEM_TEST = "us-east-1"
REGION_SYSTEM_TEST_2 = "us-east-2"



class CloudOrganizationCSPM(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.aws_manager = None
        self.delegated_admin_aws_manager = None
        # Note: Use base tested_stackset_info instead of local compliance_org_stack_set_info
        self.test_global_aws_users = []
        self.test_exclude_account_users = []
        
        self.skip_org_connection_tests = False
    def start(self):
        """
        CSPM/Compliance-only organization test
        """

        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        # generate random number for cloud account name for uniqueness
        self.test_identifier_rand = str(random.randint(10000000, 99999999))

        aws_access_key_id = os.environ.get("ORGANIZATION_AWS_ACCESS_KEY_ID_CLOUD_TESTS")
        aws_secret_access_key = os.environ.get("ORGANIZATION_AWS_SECRET_ACCESS_KEY_CLOUD_TESTS")
        if not aws_access_key_id:
            raise Exception("ORGANIZATION_AWS_ACCESS_KEY_ID_CLOUD_TESTS is not set")
        if not aws_secret_access_key:
            raise Exception("ORGANIZATION_AWS_SECRET_ACCESS_KEY_CLOUD_TESTS is not set")
        

        #compliance tests
        # Initialize AWS manager for compliance tests
        Logger.logger.info('Stage 1: Init AwsManager')
        compliance_test_region = "us-east-1"
        self.aws_manager = aws.AwsManager(compliance_test_region, 
                                                aws_access_key_id=aws_access_key_id,
                                                aws_secret_access_key=aws_secret_access_key)
        Logger.logger.info(f"AwsManager initiated in region {compliance_test_region}")
        Logger.logger.info('Stage 2: Setup AWS managers and validate permissions')
        delegated_admin_account_id = "515497298766"
        single_account_id = "617632154863"
        member_account_id = "897545368193"
        expected_account_ids = [single_account_id, delegated_admin_account_id, member_account_id]
        initial_OU = "ou-fo1t-hbdw5p8g"
        
        single_account_aws_manager = self.aws_manager.assume_role_in_account(single_account_id)
        self.single_account_aws_manager = single_account_aws_manager
        
        
        delegated_admin_aws_manager = self.aws_manager.assume_role_in_account(delegated_admin_account_id)
        self.delegated_admin_aws_manager = delegated_admin_aws_manager
        if not self.delegated_admin_aws_manager.verify_trusted_access_enabled():
            raise Exception("Trusted access is not enabled for StackSets")

        current_account = self.delegated_admin_aws_manager.get_account_id()
        if not self.delegated_admin_aws_manager.verify_delegation_status(current_account):
            raise Exception(f"Account {current_account} is not properly delegated")
        
        Logger.logger.info(f"Account {current_account} is properly delegated")
        
        Logger.logger.info(f"AwsManager initiated in region {compliance_test_region}")

        Logger.logger.info('Stage 3: Create compliance org stack')
        discovery_stack_name = "systest-" + self.test_identifier_rand + "-discovery-org"
        existing_admin_response = self.connect_cspm_new_organization(delegated_admin_aws_manager, discovery_stack_name, compliance_test_region)
        test_org_guid = existing_admin_response.guid
        org = self.get_cloud_org_by_guid(test_org_guid)
        assert org is not None, f"org is not found"
        admin_role_arn = org["orgScanData"]["scanConfig"]["adminRoleArn"]
        admin_external_id = org["orgScanData"]["scanConfig"]["adminRoleExternalID"]
    
        Logger.logger.info('Stage 4: Try connect again to the same CSPM org')
        existing_admin_response = self.connect_existing_cspm_organization(compliance_test_region, admin_role_arn, admin_external_id)
        second_org_guid = existing_admin_response.guid
        assert test_org_guid == second_org_guid, f"new_org_guid {test_org_guid} is not equal to second_org_guid {second_org_guid}"

        Logger.logger.info('Stage 5: Connect compliance to existing organization(without scanning)')
        features = [COMPLIANCE_FEATURE_NAME]
        compliance_stack_set_name = "systest-" + self.test_identifier_rand + "-compliance-org"
        member_role_name, member_role_external_id, stack_set_operation_id = self.connect_cspm_features_to_org(delegated_admin_aws_manager, compliance_stack_set_name, compliance_test_region, features, test_org_guid,organizational_unit_ids=[initial_OU],skip_wait=True)

        self.wait_for_report(self.validate_org_manged_account_list, sleep_interval=30, 
        timeout=300, org_guid=test_org_guid, account_ids=expected_account_ids, 
        feature_name=COMPLIANCE_FEATURE_NAME)

        Logger.logger.info('Stage 6: Connect single account (without scanning) - blocked')
        cspm_stack_name = "systest-" + self.test_identifier_rand + "-cspm-single"
        stack_response = self.get_and_validate_cspm_link_with_external_id(features=[COMPLIANCE_FEATURE_NAME], region=compliance_test_region)
        self.cspm_external_id = stack_response.externalID       
        _, template_url, _, parameters = extract_parameters_from_url(stack_response.stackLink)
        Logger.logger.info(f"Creating stack {cspm_stack_name} with template {template_url} and parameters {parameters}")
        single_compliance_role_arn = self.create_stack_cspm(self.single_account_aws_manager, cspm_stack_name, template_url, parameters)
        account_id = aws.extract_account_id(single_compliance_role_arn)
        Logger.logger.info(f"Created cspm stack {cspm_stack_name} with account id {account_id} and arn {single_compliance_role_arn}")
        is_blocked = self.connect_cspm_single_account_suppose_to_be_blocked(compliance_test_region, single_compliance_role_arn, self.cspm_external_id)
        assert is_blocked, "connect compliance single account blocked successfully"

        Logger.logger.info('Stage 7: Delete compliance feature and validate org and account deleted')
        self.delete_and_validate_org_feature(test_org_guid, COMPLIANCE_FEATURE_NAME)

        Logger.logger.info('Stage 8: Connect single account (without scanning)')
        single_compliance_account_name = "single-compliance-account"
        single_cloud_account_guid = self.connect_cspm_new_account(compliance_test_region, account_id, single_compliance_role_arn, single_compliance_account_name, self.cspm_external_id,skip_scan=True)
        self.validate_account_feature_is_excluded(single_cloud_account_guid, COMPLIANCE_FEATURE_NAME, False)

        Logger.logger.info('Stage 9: Update single account stack add vuln feature')
        self.add_cspm_feature_to_single_account(aws_manager=self.single_account_aws_manager, cloud_account_guid=single_cloud_account_guid, stack_name=cspm_stack_name, feature_name=VULN_SCAN_FEATURE_NAME)

        Logger.logger.info('Stage 10: Connect compliance to existing organization again(without scanning) - validate single is under the new organization and vuln feature no')
        existing_admin_response = self.connect_existing_cspm_organization(compliance_test_region, admin_role_arn, admin_external_id)       
        test_org_guid = existing_admin_response.guid
        self.connect_cspm_features_to_org_existing_stack_set(test_org_guid, member_role_name, member_role_external_id, compliance_test_region, features)
        self.wait_for_report(self.validate_org_manged_account_list, sleep_interval=30, 
        timeout=180, org_guid=test_org_guid, account_ids=expected_account_ids, 
        feature_name=COMPLIANCE_FEATURE_NAME)
        self.validate_account_feature_managed_by_org(single_account_id, VULN_SCAN_FEATURE_NAME, None)
        self.validate_org_status(test_org_guid, CSPM_STATUS_HEALTHY)
        
        Logger.logger.info('Stage 11: Exclude one account, validated it marked as excluded')
        self.org_exclude_accounts_by_feature(test_org_guid, [COMPLIANCE_FEATURE_NAME], ExclusionActions.EXCLUDE, [single_account_id])
        self.validate_account_feature_is_excluded(single_cloud_account_guid, COMPLIANCE_FEATURE_NAME, True)

        Logger.logger.info('Stage 12: Update name and exclude list and validated the changes')
        new_name = f"updated-{test_org_guid}"
        metadata = UpdateCloudOrganizationMetadataRequest(orgGUID=test_org_guid, newName=new_name, featureNames=[COMPLIANCE_FEATURE_NAME], excludeAccounts=["111111111111","222222222222","333333333333"])
        self.update_org_metadata_and_validate(metadata)
        Logger.logger.info(f"Updated org {test_org_guid} name to {new_name} and we updated the exclude list - removing the account {single_account_id} from the list")
        self.validate_account_feature_is_excluded(single_cloud_account_guid, COMPLIANCE_FEATURE_NAME, False)

        Logger.logger.info('Stage 13: Break aws admin role and sync the org - validate the error is shown and the org is not connected')
        self.update_and_validate_admin_external_id(self.delegated_admin_aws_manager, test_org_guid, admin_role_arn)

        Logger.logger.info('Stage 14: Fix aws admin role and sync the org - validate the org is connected')
        member_account_manager = self.aws_manager.assume_role_in_account(member_account_id)
        body = self.build_get_cloud_aws_org_by_accountID_request(member_account_id)
        res = self.backend.get_cloud_accounts(body=body)
        assert len(res["response"]) == 1, f"Expected 1 account, got {len(res['response'])}"
        member_cloud_account_guid = res["response"][0]["guid"]
        self.update_and_validate_member_external_id(member_account_manager, test_org_guid, member_cloud_account_guid ,feature_name=COMPLIANCE_FEATURE_NAME)

        Logger.logger.info('Stage 15: Update the stackset - add vuln connection')
        # Add vulnerability scan feature to the organization
        self.add_cspm_feature_to_organization(
            aws_manager=self.delegated_admin_aws_manager,
            stackset_name=compliance_stack_set_name,
            org_guid=test_org_guid,
            new_feature_name=VULN_SCAN_FEATURE_NAME,
            existing_accounts=expected_account_ids,
            with_wait=False,
        )
        Logger.logger.info('Stage 16: Exclude one account and validate it is excluded in both features')
        self.org_exclude_accounts_by_feature(test_org_guid, [COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME], ExclusionActions.EXCLUDE, [single_account_id])
        self.validate_account_feature_is_excluded(single_cloud_account_guid, COMPLIANCE_FEATURE_NAME, True)
        self.validate_account_feature_is_excluded(single_cloud_account_guid, VULN_SCAN_FEATURE_NAME, True)

        Logger.logger.info('Stage 17: Delete vulnScan and validate feature is deleted')
        self.delete_and_validate_org_feature(test_org_guid, VULN_SCAN_FEATURE_NAME)
        #validate that org accounts have only compliance feature
        self.wait_for_report(self.validate_org_feature_deletion_complete, sleep_interval=5, timeout=30, 
                        org_guid=test_org_guid, deleted_feature=VULN_SCAN_FEATURE_NAME, 
                        expected_features=[COMPLIANCE_FEATURE_NAME], expected_account_ids=expected_account_ids)
        
        Logger.logger.info('Stage 18: Delete compliance feature and validate org and account deleted')
        self.delete_and_validate_org_feature(test_org_guid, COMPLIANCE_FEATURE_NAME)
        
        Logger.logger.info('Stage 19: Validate that no accounts are managed by this org anymore')
        self.wait_for_report(self.validate_no_accounts_managed_by_org, sleep_interval=5, timeout=30, 
                        org_guid=test_org_guid, expected_account_ids=expected_account_ids)
            

        return self.cleanup(feature_name=COMPLIANCE_FEATURE_NAME)

    def cleanup(self, **kwargs):
        # Base Accounts.cleanup handles all stacks, stacksets, accounts, and organizations automatically
        return super().cleanup(**kwargs)



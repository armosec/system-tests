import os
import time
from systest_utils import Logger, statics
from tests_scripts.accounts.accounts import PROVIDER_AWS, CADR_FEATURE_NAME, COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME ,CDR_ALERT_ORG_ID_PATH
from tests_scripts.accounts.accounts import CloudEntityTypes, ExclusionActions, UpdateCloudOrganizationMetadataRequest
from tests_scripts.accounts.accounts import extract_parameters_from_url
from tests_scripts.accounts.accounts import Accounts ,CSPM_SCAN_STATE_COMPLETED ,FEATURE_STATUS_CONNECTED
import random
from urllib.parse import parse_qs, quote, urlparse
from infrastructure import aws
from typing import List
from tests_scripts.accounts.accounts import CSPM_STATUS_HEALTHY ,CSPM_STATUS_DISCONNECTED ,CSPM_STATUS_DEGRADED
# static cloudtrail and bucket names that are expected to be existed in the test account
ORGANIZATION_CLOUDTRAIL_SYSTEM_TEST_CONNECT = "trail-system-test-organization-connect-dont-delete"
ORGANIZATION_BUCKET_NAME_SYSTEM_TEST = "system-test-organization-bucket-armo"
ORGANIZATION_TRAIL_LOG_LOCATION = "system-test-organization-bucket-armo/AWSLogs/o-63kbjphubt/930002936888"
ACCOUNT_TRAIL_LOG_LOCATION = "system-test-organization-bucket-armo/AWSLogs/930002936888"

REGION_SYSTEM_TEST = "us-east-1"
ORG_ID = "o-63kbjphubt"
EXCLUDE_ACCOUNT_ID = "515497298766"



class CloudOrganization(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.aws_manager = None
        self.delegated_admin_aws_manager = None
        self.cspm_org_stack_name = None
        self.cadr_org_stack_name = None
        self.compliance_org_stack_name = []
        self.compliance_org_stack_set_info = []  # List of tuples: (stackset_name, operation_id)
        self.test_global_aws_users = []
        self.test_exclude_account_users = []
        
        self.skip_apis_validation = False
        self.skip_cadr_test_part = True

    def start(self):
        """
        Agenda:
        1. Init AwsManager


        //compliance tests
        12. Create compliance org stack
        13. Connect compliance to existing organization(without scanning,without window)
        14. conenct single account (without scanning) - blocked
        14. delete compliance feature and validate org and account deleted
        15. conenct single account (without scanning)
        16. connect compliance to existing organization again(without scanning) - validate single is under the new organization
        17. exclude one account, valdiated it marked as excluded
        18. update name and exclude list and validated the changes

        //compliance connection error 
        19.break aws admin role and sync the org - validate the error is shown and the org is not connected
        20.fix aws admin role and sync the org - validate the org is connected
        
        //cspm more than 1 feature - combined
        21. connect compliance and vulnScan
        22. delete vulnScan and validate feature is delted(update stack as well)
        23. update stack and add vuln feature and validate it is connected
        24. update stackset and org add vuln feature and validate it is connected - validated all accounts have vuln as well udner the org


        //cadr tests
        25. Connect cadr new organization
        26. Validate cadr status is connected
        27. Validate alert with orgID is created
        27. Exclude one account and validate it is excluded
        28. Include one account and validate it is included
        29. Connect single cadr - validate block
        30. Delete cadr org and validate is deleted
        31. Connect single cadr
        32. Validate cadr status is connected
        11. Connect org cadr - validate merging
        """

        # return statics.SUCCESS, ""
    
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        stack_region = REGION_SYSTEM_TEST

        # generate random number for cloud account name for uniqueness
        self.test_identifier_rand = str(random.randint(10000000, 99999999))

        Logger.logger.info('Stage 1: Init AwsManager')
        aws_access_key_id = os.environ.get("ORGANIZATION_AWS_ACCESS_KEY_ID_CLOUD_TESTS")
        aws_secret_access_key = os.environ.get("ORGANIZATION_AWS_SECRET_ACCESS_KEY_CLOUD_TESTS")
        if not aws_access_key_id:
            raise Exception("ORGANIZATION_AWS_ACCESS_KEY_ID_CLOUD_TESTS is not set")
        if not aws_secret_access_key:
            raise Exception("ORGANIZATION_AWS_SECRET_ACCESS_KEY_CLOUD_TESTS is not set")
        

        self.aws_manager = aws.AwsManager(stack_region, 
                                                aws_access_key_id=aws_access_key_id,
                                                aws_secret_access_key=aws_secret_access_key)
        Logger.logger.info(f"AwsManager initiated in region {stack_region}")

        #compliance tests
        Logger.logger.info('connection Stage 0: Init AwsManager')
        delagted_admin_account_id = "515497298766"
        single_account_id = "617632154863"
        member_account_id = "897545368193"
        expected_account_ids = [single_account_id,delagted_admin_account_id,member_account_id]
        compliance_test_region = "us-east-1"
        initial_OU = "ou-fo1t-hbdw5p8g"
        aws_access_key_id = os.environ.get("ORGANIZATION_AWS_ACCESS_KEY_ID_CLOUD_TESTS")
        aws_secret_access_key = os.environ.get("ORGANIZATION_AWS_SECRET_ACCESS_KEY_CLOUD_TESTS")
        if not aws_access_key_id:
            raise Exception("ORGANIZATION_AWS_ACCESS_KEY_ID_CLOUD_TESTS is not set")
        if not aws_secret_access_key:
            raise Exception("ORGANIZATION_AWS_SECRET_ACCESS_KEY_CLOUD_TESTS is not set")
        

        self.aws_manager = aws.AwsManager(compliance_test_region, 
                                                aws_access_key_id=aws_access_key_id,
                                                aws_secret_access_key=aws_secret_access_key)
        
        single_account_aws_manager = self.aws_manager.assume_role_in_account(single_account_id)
        self.single_account_aws_manager = single_account_aws_manager
        
        
        delegated_admin_aws_manager = self.aws_manager.assume_role_in_account(delagted_admin_account_id)
        self.delegated_admin_aws_manager = delegated_admin_aws_manager
        if not self.delegated_admin_aws_manager.verify_trusted_access_enabled():
            raise Exception("Trusted access is not enabled for StackSets")

        current_account = self.delegated_admin_aws_manager.get_account_id()
        if not self.delegated_admin_aws_manager.verify_delegation_status(current_account):
            raise Exception(f"Account {current_account} is not properly delegated")
        
        Logger.logger.info(f"Account {current_account} is properly delegated")
        
        Logger.logger.info(f"AwsManager initiated in region {compliance_test_region}")

        Logger.logger.info('connection Stage 1: Connect CSPM org')
        discovery_stack_name = "systest-" + self.test_identifier_rand + "-discovery-org"
        self.compliance_org_stack_name.append(discovery_stack_name)
        existing_admin_response = self.connect_cspm_new_organization(delegated_admin_aws_manager, discovery_stack_name, compliance_test_region)
        test_org_guid = existing_admin_response.guid
        self.test_cloud_orgs_guids.append(test_org_guid)
        org = self.get_cloud_org(test_org_guid)
        assert org is not None, f"org is not found"
        admin_role_arn = org["orgScanData"]["scanConfig"]["adminRoleArn"]
        admin_external_id = org["orgScanData"]["scanConfig"]["adminRoleExternalID"]
    
        Logger.logger.info('connection Stage 1.1: try connect again to the same CSPM org')
        existing_admin_response = self.connect_existing_cspm_organization(compliance_test_region, admin_role_arn, admin_external_id)
        second_org_guid = existing_admin_response.guid
        assert test_org_guid == second_org_guid, f"new_org_guid {test_org_guid} is not equal to second_org_guid {second_org_guid}"

        Logger.logger.info('connection Stage 2: Connect compliance to existing organization(without scanning)')
        features = [COMPLIANCE_FEATURE_NAME]
        compliance_stack_set_name = "systest-" + self.test_identifier_rand + "-compliance-org"
        member_role_name, member_role_external_id, stack_set_operation_id = self.connect_cspm_features_to_org(delegated_admin_aws_manager, compliance_stack_set_name, compliance_test_region, features, test_org_guid,organizational_unit_ids=[initial_OU],skip_wait=True)
        self.compliance_org_stack_set_info.append((compliance_stack_set_name, stack_set_operation_id))

        self.wait_for_report(self.validate_org_manged_account_list, sleep_interval=30, 
        timeout=300, org_guid=test_org_guid, account_ids=expected_account_ids, 
        feature_name=COMPLIANCE_FEATURE_NAME)

        Logger.logger.info('connection Stage 4: connect single account (without scanning) - blocked')
        cspm_stack_name = "systest-" + self.test_identifier_rand + "-cspm-single"
        stack_response = self.get_and_validate_cspm_link_with_external_id(features=[COMPLIANCE_FEATURE_NAME], region=stack_region)
        self.cspm_external_id = stack_response.externalID       
        _, template_url, _, parameters = extract_parameters_from_url(stack_response.stackLink)
        Logger.logger.info(f"Creating stack {cspm_stack_name} with template {template_url} and parameters {parameters}")
        single_compliance_role_arn = self.create_stack_cspm(self.single_account_aws_manager, cspm_stack_name, template_url, parameters)
        account_id = aws.extract_account_id(single_compliance_role_arn)
        Logger.logger.info(f"Created cspm stack {cspm_stack_name} with account id {account_id} and arn {single_compliance_role_arn}")
        is_blocked = self.connect_cspm_single_account_suppose_to_be_blocked(stack_region, single_compliance_role_arn, self.cspm_external_id)
        assert is_blocked, "connect compliance single account blocked successfully"

        Logger.logger.info('connection Stage 5: delete compliance feature and validate org and account deleted')
        self.delete_and_validate_org_feature(test_org_guid, COMPLIANCE_FEATURE_NAME)

        Logger.logger.info('connection Stage 6: connect single account (without scanning)')
        single_compliance_account_name = "single-compliance-account"
        single_cloud_account_guid = self.connect_cspm_new_account(stack_region, account_id, single_compliance_role_arn, single_compliance_account_name, self.cspm_external_id,skip_scan=True)
        self.test_cloud_accounts_guids.append(single_cloud_account_guid)
        self.validate_account_feature_is_excluded(single_cloud_account_guid, COMPLIANCE_FEATURE_NAME, False)

        Logger.logger.info('connection Stage 7: update single account stack add vuln feature')
        self.add_cspm_feature_to_single_account(aws_manager=self.single_account_aws_manager, cloud_account_guid=single_cloud_account_guid, stack_name=cspm_stack_name, feature_name=VULN_SCAN_FEATURE_NAME)

        Logger.logger.info('connection Stage 7: connect compliance to existing organization again(without scanning) - validate single is under the new organization and vuln feature no')
        existing_admin_response = self.connect_existing_cspm_organization(compliance_test_region, admin_role_arn, admin_external_id)       
        test_org_guid = existing_admin_response.guid
        self.test_cloud_orgs_guids.append(test_org_guid)
        self.connect_cspm_features_to_org_existing_stack_set(test_org_guid, member_role_name, member_role_external_id, compliance_test_region, features)
        self.wait_for_report(self.validate_org_manged_account_list, sleep_interval=30, 
        timeout=120, org_guid=test_org_guid, account_ids=expected_account_ids, 
        feature_name=COMPLIANCE_FEATURE_NAME)
        self.validate_account_feature_managed_by_org(single_account_id, VULN_SCAN_FEATURE_NAME, None)
        self.validate_org_status(test_org_guid, CSPM_STATUS_HEALTHY)
        
        Logger.logger.info('connection Stage 8: exclude one account, validated it marked as excluded')
        self.org_exclude_accounts_by_feature(test_org_guid, [COMPLIANCE_FEATURE_NAME], ExclusionActions.EXCLUDE, [single_account_id])
        self.validate_account_feature_is_excluded(single_cloud_account_guid, COMPLIANCE_FEATURE_NAME, True)

        Logger.logger.info('connection Stage 9: update name and exclude list and validated the changes')
        new_name = f"updated-{test_org_guid}"
        metadata = UpdateCloudOrganizationMetadataRequest(orgGUID=test_org_guid, newName=new_name, featureNames=[COMPLIANCE_FEATURE_NAME], excludeAccounts=["111111111111","222222222222","333333333333"])
        self.update_org_metadata_and_validate(metadata)
        Logger.logger.info(f"Updated org {test_org_guid} name to {new_name} and we updated the exclude list - removing the account {single_account_id} from the list")
        self.validate_account_feature_is_excluded(single_cloud_account_guid, COMPLIANCE_FEATURE_NAME, False)

        Logger.logger.info('connection Stage 10: update admin connection and validate org status is degraded')
        self.update_and_validate_admin_external_id(self.delegated_admin_aws_manager, test_org_guid, admin_role_arn)

        Logger.logger.info('connection Stage 11: update member connection and validate org status is degraded')
        member_account_manager = self.aws_manager.assume_role_in_account(member_account_id)
        body = self.build_get_cloud_aws_org_by_accountID_request(member_account_id)
        res = self.backend.get_cloud_accounts(body=body)
        assert len(res["response"]) == 1, f"Expected 1 account, got {len(res['response'])}"
        member_cloud_account_guid = res["response"][0]["guid"]
        self.update_and_validate_member_external_id(member_account_manager, test_org_guid, member_cloud_account_guid ,feature_name=COMPLIANCE_FEATURE_NAME)

        Logger.logger.info('connection Stage 12: update the stackset - add vuln connection')

        Logger.logger.info('connection Stage 13: try to connect single account vuln - blocked')

        if not self.skip_cadr_test_part:
            self.cadr_org_stack_name = "systest-" + self.test_identifier_rand + "-cadr-org"
            self.cadr_account_stack_name = "systest-" + self.test_identifier_rand + "-cadr-single"
            self.org_log_location = ORGANIZATION_TRAIL_LOG_LOCATION
            self.account_log_location = ACCOUNT_TRAIL_LOG_LOCATION
            self.runtime_policy_name = "systest-" + self.test_identifier_rand + "-cadr-org"
            self.aws_user = "systest-" + self.test_identifier_rand + "-user-org"

            self.exclude_account_aws_manager = self.aws_manager.assume_role_in_account(EXCLUDE_ACCOUNT_ID)


            Logger.logger.info('Stage 2: Connect cadr new organization')
            org_guid = self.connect_cadr_new_organization(stack_region, self.cadr_org_stack_name, self.org_log_location)
            Logger.logger.info(f"CADR organization created successfully with guid {org_guid}")                                                  
            
            Logger.logger.info('Stage 3: Validate cadr status is connected')
            self.wait_for_report(self.verify_cadr_status, sleep_interval=5, timeout=120, 
                                guid=org_guid, cloud_entity_type=CloudEntityTypes.ORGANIZATION, 
                                expected_status=FEATURE_STATUS_CONNECTED)
            Logger.logger.info(f"CADR organization {org_guid} is connected successfully")
            
            Logger.logger.info('Stage 4: Validate alert with orgID is created')
            self.create_aws_cdr_runtime_policy(self.runtime_policy_name, ["I082"])
            time.sleep(180) # wait for the sensor stack to be active
            self.aws_manager.create_user(self.aws_user)
            self.test_global_aws_users.append(self.aws_user)
            self.wait_for_report(self.get_incidents, sleep_interval=15, timeout=600,
                                filters={CDR_ALERT_ORG_ID_PATH: ORG_ID,
                                        "message": self.aws_user + "|like"},
                                expect_incidents=True)
            
            Logger.logger.info('Stage 5: Exclude one account and validate it is excluded')
            self.update_org_exclude_accounts(org_guid, [CADR_FEATURE_NAME], ExclusionActions.EXCLUDE, [EXCLUDE_ACCOUNT_ID])
            aws_user_excluded = self.aws_user + "-excluded"
            self.exclude_account_aws_manager.create_user(aws_user_excluded)
            self.test_exclude_account_users.append(aws_user_excluded)
            time.sleep(420) # wait to make sure incident were not created
            self.get_incidents(filters={CDR_ALERT_ORG_ID_PATH: ORG_ID,
                                        "message": aws_user_excluded + "|like"},
                                expect_incidents=False)
            Logger.logger.info(f"Account {EXCLUDE_ACCOUNT_ID} is excluded successfully")
            
            Logger.logger.info('Stage 6: Include one account and validate it is included')
            self.update_org_exclude_accounts(org_guid, [CADR_FEATURE_NAME], ExclusionActions.INCLUDE, [EXCLUDE_ACCOUNT_ID])
            aws_user_included = self.aws_user + "-included"
            self.exclude_account_aws_manager.create_user(aws_user_included)
            self.test_exclude_account_users.append(aws_user_included)
            self.wait_for_report(self.get_incidents, sleep_interval=15, timeout=600,
                                filters={CDR_ALERT_ORG_ID_PATH: ORG_ID,
                                        "message": aws_user_included + "|like"},
                                expect_incidents=True)
            Logger.logger.info(f"Account {EXCLUDE_ACCOUNT_ID} is included successfully")
            
            Logger.logger.info('Stage 7: Connect single cadr - validate block')
            self.create_and_validate_cloud_account_with_cadr("test_block", self.account_log_location, PROVIDER_AWS, stack_region, expect_failure=True)
            Logger.logger.info("connect CADR single account blocked successfully")
            
            Logger.logger.info('Stage 8: Delete cadr org and validate is deleted')
            self.delete_and_validate_org_feature(org_guid, CADR_FEATURE_NAME)
            self.aws_manager.delete_stack(self.cadr_org_stack_name)
            self.tested_stacks.remove(self.cadr_org_stack_name)
            Logger.logger.info("Delete cadr successfully")
            
            Logger.logger.info('Stage 9: Connect single cadr')
            account_guid = self.connect_cadr_new_account(stack_region, self.cadr_account_stack_name, "merge-account", self.account_log_location)
            Logger.logger.info(f"CADR account created successfully with guid {account_guid}")
            
            Logger.logger.info('Stage 10: Validate cadr status is connected')
            self.wait_for_report(self.verify_cadr_status, sleep_interval=5, timeout=120, 
                                guid=account_guid, cloud_entity_type=CloudEntityTypes.ACCOUNT, 
                                expected_status=FEATURE_STATUS_CONNECTED)
            Logger.logger.info(f"CADR account {account_guid} is connected successfully")
            
            Logger.logger.info('Stage 11: Connect org cadr - validate merging')
            org_guid = self.connect_cadr_new_organization(stack_region, self.cadr_org_stack_name, self.org_log_location)
            self.validate_feature_deleted_from_entity(account_guid, CADR_FEATURE_NAME, True, CloudEntityTypes.ACCOUNT)
            Logger.logger.info(f"Merged cadr feature of account {account_guid} into the new org {org_guid} successfully")
            

        return self.cleanup()

    def cleanup(self, **kwargs):

        if self.aws_manager:
            for stack_name in self.tested_stacks:
                Logger.logger.info(f"Deleting stack: {stack_name}")
                self.aws_manager.delete_stack(stack_name)

            for stack_name in self.tested_stacks:
                Logger.logger.info(f"Deleting log groups for stack: {stack_name}")
                self.aws_manager.delete_stack_log_groups(stack_name)

        
        if self.delegated_admin_aws_manager:
            for stack_name in self.compliance_org_stack_name:
                Logger.logger.info(f"Deleting stack: {stack_name}")
                self.delegated_admin_aws_manager.delete_stack(stack_name)
            Logger.logger.info(f"Cleaning up stacksets: {[name for name, _ in self.compliance_org_stack_set_info]}")
            self.cleanup_stacksets(self.compliance_org_stack_set_info)

        for cloud_org_guid in self.test_cloud_orgs_guids:
            Logger.logger.info(f"Deleting cloud organization: {cloud_org_guid}")
            self.backend.delete_cloud_organization(cloud_org_guid)
        
        for policy_guid in self.test_runtime_policies:
            Logger.logger.info(f"Deleting runtime policy: {policy_guid}")
            self.backend.delete_runtime_policies(policy_guid)
            
        for aws_user in self.test_global_aws_users:
            Logger.logger.info(f"Deleting aws user: {aws_user}")
            self.aws_manager.delete_user(aws_user)
        
        for aws_user in self.test_exclude_account_users:
            Logger.logger.info(f"Deleting aws user: {aws_user}")
            self.exclude_account_aws_manager.delete_user(aws_user)


        return super().cleanup(**kwargs)
    
    def cleanup_stacksets(self, stackset_info: List[tuple]):
        """
        Enhanced cleanup method to replace your current delete_stackset calls.
        Waits for any in-progress operations to complete before deleting.
        
        Args:
            stackset_info: List of tuples (stackset_name, operation_id)
        """
        Logger.logger.info(f"🧹 Starting cleanup of {len(stackset_info)} StackSets")
        aws_manager = self.delegated_admin_aws_manager
        
        # Add organizations client if not already present
        if not hasattr(self, 'organizations'):
            self.organizations = aws_manager.organizations
        
        # Wait for any in-progress operations to complete
        Logger.logger.info(f"⏳ Checking for {len(stackset_info)} in-progress operations")
        for stackset_name, operation_id in stackset_info:
            if operation_id is not None:
                Logger.logger.info(f"Waiting for operation {operation_id} on StackSet {stackset_name} to complete...")
                final_status = aws_manager.wait_for_stackset_operation(stackset_name, operation_id)
                
                if final_status == 'SUCCEEDED':
                    Logger.logger.info(f"Operation {operation_id} completed successfully")
                elif final_status in ['FAILED', 'STOPPED']:
                    Logger.logger.warning(f"Operation {operation_id} finished with status: {final_status}")
                elif final_status == 'TIMED_OUT':
                    Logger.logger.warning(f"Operation {operation_id} timed out, proceeding with cleanup")
                else:
                    Logger.logger.warning(f"peration {operation_id} status: {final_status}, proceeding with cleanup")
            else:
                Logger.logger.info(f"No operation ID for StackSet {stackset_name}, proceeding with cleanup")
        
        # Extract stackset names for deletion
        stackset_names = [name for name, _ in stackset_info]
        
        # Now proceed with deletion
        success = aws_manager.delete_stacksets_by_names(stackset_names)
        
        if success:
            Logger.logger.info("✅ All StackSets cleaned up successfully")
        else:
            Logger.logger.error("❌ Some StackSets failed to clean up")
        
        return success


 # Helper functions for testing StackSet functionality
def create_armo_vulnscan_stackset(aws_manager: aws.AwsManager, stackset_name: str, external_id: str, 
                                    organizational_unit_ids: List[str] = None, 
                                    account_ids: List[str] = None,
                                    regions: List[str] = None):
    """
    Create a StackSet for Armo VulnScan capabilities
    
    Args:
        stackset_name: Name for the StackSet
        external_id: External ID for secure cross-account role assumption
        organizational_unit_ids: List of OU IDs to deploy to
        account_ids: List of account IDs to deploy to
        regions: List of regions to deploy to
    
    Returns:
        StackSet ID if successful, None otherwise
    """
    # Template URL for Armo VulnScan template
    template_url = "https://s3.amazonaws.com/armo-templates/armo-vulnscan-role.yaml"
    
    parameters = [
        {
            'ParameterKey': 'ExternalID',
            'ParameterValue': external_id
        }
    ]
    
    return aws_manager.create_stackset(
        template_url=template_url,
        parameters=parameters,
        stackset_name=stackset_name,
        organizational_unit_ids=organizational_unit_ids,
        account_ids=account_ids,
        regions=regions
    )

def create_armo_combined_stackset(aws_manager: aws.AwsManager, stackset_name: str, external_id: str,
                                    organizational_unit_ids: List[str] = None,
                                    account_ids: List[str] = None,
                                    regions: List[str] = None):
    """
    Create a StackSet for Armo Combined Compliance and VulnScan capabilities
    
    Args:
        stackset_name: Name for the StackSet
        external_id: External ID for secure cross-account role assumption
        organizational_unit_ids: List of OU IDs to deploy to
        account_ids: List of account IDs to deploy to
        regions: List of regions to deploy to
    
    Returns:
        StackSet ID if successful, None otherwise
    """
    # Template URL for Armo Combined template
    template_url = "https://s3.amazonaws.com/armo-templates/armo-combined-role.yaml"
    
    parameters = [
        {
            'ParameterKey': 'ExternalID',
            'ParameterValue': external_id
        }
    ]
    
    return aws_manager.create_stackset(
        template_url=template_url,
        parameters=parameters,
        stackset_name=stackset_name,
        organizational_unit_ids=organizational_unit_ids,
        account_ids=account_ids,
        regions=regions
    )

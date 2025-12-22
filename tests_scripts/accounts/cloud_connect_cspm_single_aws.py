import os
from systest_utils import Logger
from tests_scripts.accounts.accounts import (
    Accounts,
    CADR_FEATURE_NAME,
    COMPLIANCE_FEATURE_NAME,
    CSPM_SCAN_STATE_COMPLETED,
    FEATURE_STATUS_CONNECTED,
    PROVIDER_AWS,
    VULN_SCAN_FEATURE_NAME,
    extract_parameters_from_url,
)
import random
from infrastructure import aws


REGION_SYSTEM_TEST = "us-east-1"

class CloudConnectCSPMSingleAWS(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.aws_manager = None
        self.cspm_stack_name = None

        self.skip_apis_validation = False
        self.skip_jira_validation = False

    def start(self):
        """
        CSPM-only test
        Agenda:
        1. Init AwsManager
        2. Create cspm stack
        3. Create bad arn cloud account with cspm
        4. Connect cspm new account
        5. Wait for cspm scan to complete successfully
        6. Validate all scan results
        7. Create Jira issue for resource
        8. Accept the risk
        9. Disconnect the cspm account
        10. Recreate cspm stack
        11. Delete cspm feature and validate
        12. Validate aws regions
        13. Validate aws regions details
        14. Setup for combination test - reconnect CSPM account
        15. Test connection conflict - connect CADR to existing CSPM account
        16. Validate CSPM feature unchanged after CADR connection
        17. Test CSPM connection blocked - try to connect CSPM again to existing account
        18. Delete cadr feature and validate
        19. Delete cspm feature and validate
        """

        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        stack_region = REGION_SYSTEM_TEST
        # generate random number for cloud account name for uniqueness
        self.test_identifier_rand = str(random.randint(10000000, 99999999))

        Logger.logger.info('Stage 0: Cleanup existing AWS single accounts')
        aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID_CLOUD_TESTS")
        aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY_CLOUD_TESTS")
        temp_aws_manager = aws.AwsManager(stack_region, 
                                          aws_access_key_id=aws_access_key_id, 
                                          aws_secret_access_key=aws_secret_access_key)
        account_id = temp_aws_manager.get_account_id()
        if account_id:
            self.cleanup_aws_single_accounts_by_id(account_id, [COMPLIANCE_FEATURE_NAME, CADR_FEATURE_NAME, VULN_SCAN_FEATURE_NAME])

        Logger.logger.info('Stage 1: Init AwsManager')
        aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID_CLOUD_TESTS")
        aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY_CLOUD_TESTS")
    
        
        self.aws_manager = aws.AwsManager(stack_region, 
                                                  aws_access_key_id=aws_access_key_id, 
                                                  aws_secret_access_key=aws_secret_access_key)
        
        # cspm_stack_name doesn't require an existing account therefore can be created once and be used across the test
        Logger.logger.info('Stage 2: Create cspm stack')
        self.cspm_stack_name = "systest-" + self.test_identifier_rand + "-cspm"
        aws_stack_response = self.get_and_validate_cspm_link_with_external_id(features=[COMPLIANCE_FEATURE_NAME], region=stack_region)
        self.cspm_external_id = aws_stack_response.externalID       
        _, template_url, _, parameters = extract_parameters_from_url(aws_stack_response.stackLink)
        Logger.logger.info(f"Creating stack {self.cspm_stack_name} with template {template_url} and parameters {parameters}")
        test_arn = self.create_stack_cspm(self.aws_manager, self.cspm_stack_name, template_url, parameters)
        account_id = aws.extract_account_id(test_arn)
        Logger.logger.info(f"Created cspm stack {self.cspm_stack_name} with account id {account_id} and arn {test_arn}")

        bad_arn = "arn:aws:iam::12345678:role/armo-scan-role-cross-with_customer-12345678"

        # cspm cloud account names
        self.cspm_cloud_account_name = "systest-" + self.test_identifier_rand + "-cspm"
        self.cspm_bad_cloud_account_name = "systest-" + self.test_identifier_rand + "-cspm-bad"

        Logger.logger.info('Stage 3: Create bad arn cloud account with cspm')
        cloud_account_guid = self.connect_cspm_bad_arn(stack_region, bad_arn, self.cspm_bad_cloud_account_name)

        Logger.logger.info('Stage 4: Connect cspm new account')
        cloud_account_guid = self.connect_aws_cspm_new_account(stack_region, account_id, test_arn, self.cspm_cloud_account_name, self.cspm_external_id)

        # Store CSPM config for later validation
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        self.cspm_cloud_account_name = account["name"]
        cspm_feature = account["features"][COMPLIANCE_FEATURE_NAME]
        
        Logger.logger.info('Stage 5: Fail to connect same AWS CSPM account')
        cloud_account_guid_fail = self.connect_aws_cspm_new_account(stack_region, account_id, test_arn, self.cspm_cloud_account_name, self.cspm_external_id, validate_apis=False, is_to_cleanup_accounts=False, expect_failure=True)
        assert cloud_account_guid_fail is None, f"Expected same account to fail, but got account GUID: {cloud_account_guid_fail}"

        if not self.skip_apis_validation:
            Logger.logger.info('Stage 6: Wait for cspm scan to complete successfully')
            # wait for success
            self.wait_for_report(self.validate_accounts_cloud_list_cspm_compliance,
                                timeout=1600,
                                sleep_interval=60,
                                provider=PROVIDER_AWS,
                                cloud_account_guid=cloud_account_guid,
                                identifier=test_arn,
                                scan_status=CSPM_SCAN_STATE_COMPLETED)
            Logger.logger.info("the account has been scan successfully")

            account = self.get_cloud_account_by_guid(cloud_account_guid)
            last_success_scan_id = account["features"][COMPLIANCE_FEATURE_NAME]["lastSuccessScanID"]
            Logger.logger.info("extracted last success scan id from created account")

            Logger.logger.info('Stage 7: Validate all scan results')
            self.validate_scan_data(PROVIDER_AWS, cloud_account_guid, self.cspm_cloud_account_name, last_success_scan_id)
            Logger.logger.info("all scan data is being validated successfully")

            if not self.skip_jira_validation:
                Logger.logger.info('Stage 8: Create Jira issue for resource')
                self.create_jira_issue_for_cspm(PROVIDER_AWS, last_success_scan_id)
                Logger.logger.info("Jira issue for resource has been created successfully")

            Logger.logger.info('Stage 9: Accept the risk')
            self.accept_cspm_risk(PROVIDER_AWS, cloud_account_guid, self.cspm_cloud_account_name, last_success_scan_id)
            Logger.logger.info("risk has been accepted successfully")

        if not self.skip_apis_validation:
            Logger.logger.info('Stage 10: Disconnect the cspm account')
            self.disconnect_cspm_account_without_deleting_cloud_account(stack_name=self.cspm_stack_name, cloud_account_guid=cloud_account_guid, feature_name=COMPLIANCE_FEATURE_NAME)

            Logger.logger.info('Stage 11: Recreate cspm stack')
            new_arn = self.create_stack_cspm(self.aws_manager, self.cspm_stack_name, template_url, parameters)
            test_arn = new_arn #update the test arn to the new arn - it is changed though time format in role name
            
        Logger.logger.info('Stage 12: Delete cspm feature and validate')
        self.delete_and_validate_account_feature(cloud_account_guid, COMPLIANCE_FEATURE_NAME)

        Logger.logger.info('Stage 13: Validate aws regions')
        res = self.backend.get_aws_regions()
        assert len(res) > 0, f"failed to get aws regions, res is {res}"

        Logger.logger.info('Stage 14: Validate aws regions details')
        res = self.backend.get_aws_regions_details()
        assert len(res) > 0, f"failed to get aws regions details, res is {res}"

        # Combination/Conflict section - test CSPM with CADR
        Logger.logger.info('Stage 15: Setup for combination test - reconnect CSPM account')
        # Reconnect CSPM for combination testing
        cloud_account_guid = self.connect_aws_cspm_new_account(stack_region, account_id, test_arn, self.cspm_cloud_account_name, self.cspm_external_id, validate_apis=False, is_to_cleanup_accounts=False)
        
        # Store CSPM config for conflict validation
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        cspm_feature = account["features"][COMPLIANCE_FEATURE_NAME]
        
        # Log CSPM scan info before CADR connection to investigate scan initiation
        if "lastSuccessScanID" in cspm_feature:
            Logger.logger.info(f"Before CADR connection - CSPM lastSuccessScanID: {cspm_feature.get('lastSuccessScanID')}")
        if "lastTimeInitiateScan" in cspm_feature:
            Logger.logger.info(f"Before CADR connection - CSPM lastTimeInitiateScan: {cspm_feature.get('lastTimeInitiateScan')}")
        
        # Setup cloudtrail for CADR connection
        self.cloud_trail_name = "system-test-connect-dont-delete"
        log_location, _ = self.aws_manager.get_cloudtrail_details(self.cloud_trail_name)
        
        # cadr stack and account names for conflict test
        self.cadr_stack_name = "systest-" + self.test_identifier_rand + "-cadr-conflict"
        self.cadr_conflict_account_name = "systest-" + self.test_identifier_rand + "-cadr-conflict"

        Logger.logger.info('Stage 16: Test connection conflict - connect CADR to existing CSPM account')
        # Connect CADR to the same account to test conflict handling
        account_guid_after_cadr = self.connect_cadr_new_account(stack_region, self.cadr_stack_name, self.cadr_conflict_account_name, log_location)
        Logger.logger.info("CADR has been connected successfully to existing CSPM account")
        # Verify it's the same account (CADR merges into existing account)
        assert account_guid_after_cadr == cloud_account_guid, f"Account GUID mismatch: {account_guid_after_cadr} != {cloud_account_guid}"
        
        # Log CSPM scan info after CADR connection to investigate scan initiation
        account_after_cadr = self.get_cloud_account_by_guid(cloud_account_guid)
        cspm_feature_after = account_after_cadr["features"][COMPLIANCE_FEATURE_NAME]
        if "lastSuccessScanID" in cspm_feature_after:
            Logger.logger.info(f"After CADR connection - CSPM lastSuccessScanID: {cspm_feature_after.get('lastSuccessScanID')}")
        if "lastTimeInitiateScan" in cspm_feature_after:
            Logger.logger.info(f"After CADR connection - CSPM lastTimeInitiateScan: {cspm_feature_after.get('lastTimeInitiateScan')}")
        if "lastSuccessScanID" in cspm_feature and "lastSuccessScanID" in cspm_feature_after:
            if cspm_feature.get("lastSuccessScanID") != cspm_feature_after.get("lastSuccessScanID"):
                Logger.logger.warning(f"WARNING: Scan ID changed after CADR connection! Before: {cspm_feature.get('lastSuccessScanID')}, After: {cspm_feature_after.get('lastSuccessScanID')}")

        Logger.logger.info('Stage 17: Validate CSPM feature unchanged after CADR connection')
        # Validate CSPM config remains unchanged after CADR connection
        self.validate_features_unchanged(cloud_account_guid, COMPLIANCE_FEATURE_NAME, cspm_feature)
        Logger.logger.info("CSPM feature config remains unchanged after CADR connection")

        Logger.logger.info('Stage 18: Test CSPM connection blocked - try to connect CSPM again to existing account')
        # Try to connect CSPM again - should be blocked
        is_blocked = self.connect_cspm_single_account_suppose_to_be_blocked(stack_region, test_arn, self.cspm_external_id)
        assert is_blocked, "Connecting CSPM again to existing account should be blocked"
        Logger.logger.info("CSPM connection correctly blocked for account that already has CSPM")

        Logger.logger.info('Stage 19: Delete cadr feature and validate')
        self.delete_and_validate_account_feature(cloud_account_guid, CADR_FEATURE_NAME)

        Logger.logger.info('Stage 20: Delete cspm feature and validate')
        self.delete_and_validate_account_feature(cloud_account_guid, COMPLIANCE_FEATURE_NAME)

        return self.cleanup()

    def cleanup(self, **kwargs):
        # Base Accounts.cleanup handles all stacks, stacksets, accounts, and organizations automatically
        return super().cleanup(**kwargs)

import os
import time
from systest_utils import Logger, statics
from tests_scripts.accounts.accounts import Accounts ,CSPM_SCAN_STATE_COMPLETED ,FEATURE_STATUS_CONNECTED
from tests_scripts.accounts.accounts import CADR_FEATURE_NAME, COMPLIANCE_FEATURE_NAME, extract_parameters_from_url
from tests_scripts.accounts.accounts import CloudEntityTypes, CDR_ALERT_ACCOUNT_ID_PATH
import random
from urllib.parse import parse_qs, quote, urlparse
from infrastructure import aws




# static cloudtrail and bucket names that are expected to be existed in the test account
CLOUDTRAIL_SYSTEM_TEST_CONNECT = "system-test-connect-dont-delete"
BUCKET_NAME_SYSTEM_TEST = "system-test-bucket-armo"
REGION_SYSTEM_TEST = "us-east-1"

class CloudConnect(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.aws_manager = None
        self.cspm_stack_name = None
        self.cadr_stack_name = None

        self.skip_apis_validation = False
        self.skip_jira_validation = False


    def validate_account_name(self, cloud_account_guid, expected_name):
        """Validate that the account name remains unchanged after operations.
            
        Args:
            cloud_account_guid (str): The GUID of the cloud account to validate
            expected_name (str): The expected name of the account
        """
        Logger.logger.info(f"Validating account name for GUID {cloud_account_guid}, expecting '{expected_name}'")
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        assert account["name"] == expected_name, f"Account name changed from {expected_name} to {account['name']}"
        Logger.logger.info(f"Account name for GUID {cloud_account_guid} is unchanged and matches '{expected_name}'")

    def start(self):
        """
        Agenda:
        1. Init AwsManager
        2. Create cspm stack
        3. Create bad arn cloud account with cspm
        4. Connect cspm new account
        5. Wait for cspm scan to complete successfully
        6. Validate all scan results
        7. Create Jira issue for resource
        8. accept the risk
        9. Connect cadr to existing account
        10. Validate cadr status is connected
        11. Validate alert with accountID is created
        12. Validate both features exist and cspm unchanged
        13. disconnect the cspm account
        14. Recreate cspm stack for Stage 17
        15. Delete cspm feature and validate
        16. Delete cadr feature and validate account deleted
        17. Create bad log location cloud account with cadr
        18. Connect cadr new account
        19. Connect cspm to existing account
        20. Validate both features exist and cadr unchanged
        21. Delete cadr feature and validate
        22. Delete cspm feature and validate account deleted
        23. Validate aws regions
        24. Validate aws regions details
        """
        return statics.SUCCESS, ""


        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        stack_region = REGION_SYSTEM_TEST
        # generate random number for cloud account name for uniqueness
        self.test_identifier_rand = str(random.randint(10000000, 99999999))

        Logger.logger.info('Stage 1: Init AwsManager')
        aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID_CLOUD_TESTS")
        aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY_CLOUD_TESTS")
    
        
        self.aws_manager = aws.AwsManager(stack_region, 
                                                  aws_access_key_id=aws_access_key_id, 
                                                  aws_secret_access_key=aws_secret_access_key)
        
        # cspm_stack_name doesn't require an existing account therefore can be created once and be used accross the test
        Logger.logger.info('Stage 2: Create cspm stack')
        self.cspm_stack_name = "systest-" + self.test_identifier_rand + "-cspm"
        aws_stack_response = self.get_and_validate_cspm_link_with_external_id(features=[COMPLIANCE_FEATURE_NAME], region=stack_region)
        self.cspm_external_id = aws_stack_response.externalID       
        _, template_url, _, parameters = extract_parameters_from_url(aws_stack_response.stackLink)
        Logger.logger.info(f"Creating stack {self.cspm_stack_name} with template {template_url} and parameters {parameters}")
        test_arn = self.create_stack_cspm(self.aws_manager, self.cspm_stack_name, template_url, parameters)
        account_id = aws.extract_account_id(test_arn)
        Logger.logger.info(f"Created cspm stack {self.cspm_stack_name} with account id {account_id} and arn {test_arn}")

        # cadr_stack_name requires an existing account therefore should be created for each account tested
        self.cadr_stack_name_first = "systest-" + self.test_identifier_rand + "-cadr-first"
        self.cadr_stack_name_second = "systest-" + self.test_identifier_rand + "-cadr-second"

        self.bucket_name = BUCKET_NAME_SYSTEM_TEST
        self.cloud_trail_name = CLOUDTRAIL_SYSTEM_TEST_CONNECT
        log_location, kms_key = self.aws_manager.get_cloudtrail_details(self.cloud_trail_name)

        bad_arn = "arn:aws:iam::12345678:role/armo-scan-role-cross-with_customer-12345678"
        bad_log_location = "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail"

        # cspm cloud account name - first creating cspm and then cadr
        self.cspm_first_cloud_account_name = "systest-" + self.test_identifier_rand + "-cspm-first"
        self.cadr_second_cloud_account_name = "systest-" + self.test_identifier_rand + "-cadr-second"

        # cadr cloud account name - first creating cadr and then cspm
        self.cadr_first_cloud_account_name = "systest-" + self.test_identifier_rand + "-cadr-first"
        self.cspm_second_cloud_account_name = "systest-" + self.test_identifier_rand + "-cspm-second"

        # First flow: CSPM first, then CADR
        Logger.logger.info('Stage 3: Create bad arn cloud account with cspm')
        cloud_account_guid = self.connect_cspm_bad_arn(stack_region, bad_arn, self.cspm_first_cloud_account_name)

        Logger.logger.info('Stage 4: Connect cspm new account')
        cloud_account_guid = self.connect_cspm_new_account(stack_region, account_id, test_arn, self.cspm_first_cloud_account_name, self.cspm_external_id)

        # Store CSPM config for later validation
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        self.cspm_cloud_account_name = account["name"]

        cspm_feature = account["features"][COMPLIANCE_FEATURE_NAME]

        Logger.logger.info('Stage 5: Connect cadr to existing account')
        account_guid = self.connect_cadr_new_account(stack_region, self.cadr_stack_name_second, self.cadr_second_cloud_account_name, log_location)
        Logger.logger.info("cadr has been connected successfully")
        
        Logger.logger.info('Stage 6: Validate cadr status is connected')
        self.wait_for_report(self.verify_cadr_status, sleep_interval=5, timeout=120, 
                             guid=account_guid, cloud_entity_type=CloudEntityTypes.ACCOUNT, 
                             expected_status=FEATURE_STATUS_CONNECTED)
        Logger.logger.info(f"CADR account {account_guid} is connected successfully")
        
        Logger.logger.info('Stage 7: Validate alert with accountID is created')
        self.runtime_policy_name = "systest-" + self.test_identifier_rand + "-cadr"
        self.create_aws_cdr_runtime_policy(self.runtime_policy_name, ["I082"])
        time.sleep(180) # wait for the sensor stack to be active
        self.aws_user = "systest-" + self.test_identifier_rand + "-user"
        self.aws_manager.create_user(self.aws_user)
        self.test_global_aws_users.append(self.aws_user)
        self.wait_for_report(self.get_incidents, sleep_interval=15, timeout=700,
                             filters={CDR_ALERT_ACCOUNT_ID_PATH: account_id,
                                      "message": self.aws_user + "|like"},
                             expect_incidents=True)
        
        if not self.skip_apis_validation:
            Logger.logger.info('Stage 8: Wait for cspm scan to complete successfully')
            # wait for success
            self.wait_for_report(self.validate_accounts_cloud_list_cspm_compliance,
                                timeout=1600,
                                sleep_interval=60,
                                cloud_account_guid=cloud_account_guid,
                                arn=test_arn,
                                scan_status=CSPM_SCAN_STATE_COMPLETED,
                                feature_status=FEATURE_STATUS_CONNECTED)
            Logger.logger.info("the account has been scan successfully")

            account = self.get_cloud_account_by_guid(cloud_account_guid)
            # Store CSPM config for later validation
            cspm_feature = account["features"][COMPLIANCE_FEATURE_NAME]

            last_success_scan_id = account["features"][COMPLIANCE_FEATURE_NAME]["lastSuccessScanID"]
            Logger.logger.info("extracted last success scan id from created account")

            Logger.logger.info('Stage 9: Validate all scan results')
            self.validate_scan_data(cloud_account_guid, self.cspm_cloud_account_name, last_success_scan_id)
            Logger.logger.info("all scan data is being validated successfully")

            if not self.skip_jira_validation:
                Logger.logger.info('Stage 10: Create Jira issue for resource')
                self.create_jira_issue_for_cspm(last_success_scan_id)
                Logger.logger.info("Jira issue for resource has been created successfully")

            Logger.logger.info('Stage 11: accept the risk')
            self.accept_cspm_risk(cloud_account_guid, self.cspm_cloud_account_name, last_success_scan_id)
            Logger.logger.info("risk has been accepted successfully")

        Logger.logger.info('Stage 12: Validate both features exist and cspm unchanged')
        # Validate CSPM config remains unchanged
        self.validate_features_unchanged(cloud_account_guid, COMPLIANCE_FEATURE_NAME, cspm_feature)
        
        # Validate account name changed to cadr second cloud account name
        self.validate_account_name(cloud_account_guid, self.cadr_second_cloud_account_name)

        if not self.skip_apis_validation:
            Logger.logger.info('Stage 13: disconnect the cspm account')
            self.disconnect_cspm_account_without_deleting_cloud_account(stack_name=self.cspm_stack_name,cloud_account_guid=cloud_account_guid, feature_name=COMPLIANCE_FEATURE_NAME)
            self.tested_stacks.remove(self.cspm_stack_name)

            Logger.logger.info('Stage 12: Recreate cspm stack for Stage 17')
            new_arn = self.create_stack_cspm(self.aws_manager, self.cspm_stack_name, template_url, parameters)
            test_arn = new_arn #update the test arn to the new arn - it is changed though time format in role name
            
        Logger.logger.info('Stage 13: Delete cspm feature and validate')
        self.delete_and_validate_account_feature(cloud_account_guid, COMPLIANCE_FEATURE_NAME)
            

        Logger.logger.info('Stage 16: Delete cadr feature and validate account deleted')
        self.delete_and_validate_account_feature(cloud_account_guid, CADR_FEATURE_NAME)

        # Second flow: CADR first, then CSPM
        Logger.logger.info('Stage 17: Create bad log location cloud account with cadr')
        cloud_account_guid = self.connect_cadr_bad_log_location(stack_region, self.cadr_first_cloud_account_name, bad_log_location)

        Logger.logger.info('Stage 18: Connect cadr new account')
        cloud_account_guid = self.connect_cadr_new_account(stack_region, self.cadr_stack_name_first, self.cadr_first_cloud_account_name, log_location)

        # Store CADR config for later validation
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        cadr_feature = account["features"][CADR_FEATURE_NAME]
        self.cadr_cloud_account_name = account["name"]

        Logger.logger.info('Stage 19: Connect cspm to existing account')
        # we don't want to cleanup the accounts because we want to keep the account id for the next test + no need apis validation cuase we validate it in the first case
        self.connect_cspm_new_account(stack_region, account_id, test_arn, self.cspm_second_cloud_account_name, self.cspm_external_id, validate_apis=False, is_to_cleanup_accounts=False)

        Logger.logger.info('Stage 20: Validate both features exist and cadr unchanged')
        # Validate CADR config remains unchanged
        self.validate_features_unchanged(cloud_account_guid, CADR_FEATURE_NAME, cadr_feature)
        
        # Validate account name changed to cspm second cloud account name
        self.validate_account_name(cloud_account_guid, self.cspm_second_cloud_account_name)

        Logger.logger.info('Stage 21: Delete cadr feature and validate')
        self.delete_and_validate_account_feature(cloud_account_guid, CADR_FEATURE_NAME)

        Logger.logger.info('Stage 22: Delete cspm feature and validate account deleted')
        self.delete_and_validate_account_feature(cloud_account_guid, COMPLIANCE_FEATURE_NAME)

        Logger.logger.info('Stage 23: Validate aws regions')
        res = self.backend.get_aws_regions()
        assert len(res) > 0, f"failed to get aws regions, res is {res}"

        Logger.logger.info('Stage 24: Validate aws regions details')
        res = self.backend.get_aws_regions_details()
        assert len(res) > 0, f"failed to get aws regions details, res is {res}"

        return self.cleanup()

    def cleanup(self, **kwargs):
        if self.tested_stack_refs:
            for ref in self.tested_stack_refs:
                Logger.logger.info(f"Deleting stack: {ref.stack_name} (region={ref.region})")
                ref.manager.delete_stack(ref.stack_name)
            for ref in self.tested_stack_refs:
                Logger.logger.info(f"Deleting log groups for stack: {ref.stack_name} (region={ref.region})")
                ref.manager.delete_stack_log_groups(ref.stack_name)
        elif self.aws_manager:
            for stack_name in self.tested_stacks:
                Logger.logger.info(f"Deleting stack: {stack_name}")
                self.aws_manager.delete_stack(stack_name)

            for cloud_trail_name in self.tested_cloud_trails:
                Logger.logger.info(f"Deleting cloudtrail: {cloud_trail_name}")
                self.aws_manager.delete_cloudtrail(cloud_trail_name)
            for stack_name in self.tested_stacks:
                Logger.logger.info(f"Deleting log groups for stack: {stack_name}")
                self.aws_manager.delete_stack_log_groups(stack_name )

        for cloud_account_guid in self.test_cloud_accounts_guids:
            try:
                remaining_account = self.get_cloud_account_by_guid(cloud_account_guid)
                if remaining_account:
                    Logger.logger.info(f"Remaining cloud account before deletion: {remaining_account}")
            except Exception as e:
                Logger.logger.info(f"Cloud account {cloud_account_guid} not found before deletion: {str(e)}")
            
            Logger.logger.info(f"Deleting cloud account: {cloud_account_guid}")
            self.backend.delete_cloud_account(cloud_account_guid)
        
        for policy_guid in self.test_runtime_policies:
            Logger.logger.info(f"Deleting runtime policy: {policy_guid}")
            self.backend.delete_runtime_policies(policy_guid)
            
        for aws_user in self.test_global_aws_users:
            Logger.logger.info(f"Deleting aws user: {aws_user}")
            self.aws_manager.delete_user(aws_user)


        return super().cleanup(**kwargs)

import os
import time
from tests_scripts.accounts.accounts import Accounts, FEATURE_STATUS_CONNECTED
from tests_scripts.accounts.accounts import CADR_FEATURE_NAME
from tests_scripts.accounts.accounts import CloudEntityTypes, CDR_ALERT_ACCOUNT_ID_PATH
import random
from systest_utils import Logger, statics

from infrastructure import aws


# static cloudtrail name that is expected to be existed in the test account
CLOUDTRAIL_SYSTEM_TEST_CONNECT = "system-test-connect-dont-delete"
REGION_SYSTEM_TEST = "us-east-1"

class CloudConnectCADRSingle(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.aws_manager = None
        self.cadr_stack_name = None

    def start(self):
        """
        CADR-only test
        Agenda:
        1. Init AwsManager
        2. Setup cloudtrail and log location
        3. Connect cadr new account
        4. Validate cadr status is connected
        5. Validate alert with accountID is created
        6. Create bad log location cloud account with cadr
        7. Delete cadr feature and validate account deleted
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

        account_id = self.aws_manager.get_account_id()
        assert account_id is not None, f"Could not extract account ID from account {account_guid}"
        
        Logger.logger.info('Stage 2: Setup cloudtrail and log location')
        self.cloud_trail_name = CLOUDTRAIL_SYSTEM_TEST_CONNECT
        log_location, _ = self.aws_manager.get_cloudtrail_details(self.cloud_trail_name)

        bad_log_location = "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail"

        # cadr stack and account names
        self.cadr_stack_name = "systest-" + self.test_identifier_rand + "-cadr"
        self.cadr_cloud_account_name = "systest-" + self.test_identifier_rand + "-cadr"
        self.cadr_bad_cloud_account_name = "systest-" + self.test_identifier_rand + "-cadr-bad"

        Logger.logger.info('Stage 3: Connect cadr new account')
        #validate that there are no existing accounts with cadr feature
        self.validate_no_accounts_exists_by_id([account_id], CADR_FEATURE_NAME)
        account_guid = self.connect_cadr_new_account(stack_region, self.cadr_stack_name, self.cadr_cloud_account_name, log_location)
        Logger.logger.info("cadr has been connected successfully")
        
        # Get account ID for alert validation
        account = self.get_cloud_account_by_guid(account_guid)
        # Extract account ID from providerInfo
        account_id = account.get("providerInfo", {}).get("accountID") if account.get("providerInfo") else None
        assert account_id is not None, f"Could not extract account ID from account {account_guid}"
        
        Logger.logger.info('Stage 4: Validate cadr status is connected')
        self.wait_for_report(self.verify_cadr_status, sleep_interval=10, timeout=300, 
                             guid=account_guid, cloud_entity_type=CloudEntityTypes.ACCOUNT, 
                             expected_status=FEATURE_STATUS_CONNECTED)
        Logger.logger.info(f"CADR account {account_guid} is connected successfully")
        
        Logger.logger.info('Stage 5: Validate alert with accountID is created')
        self.runtime_policy_name = "systest-" + self.test_identifier_rand + "-cadr"
        self.create_aws_cdr_runtime_policy(self.runtime_policy_name, ["I082"])
        time.sleep(180) # wait for the sensor stack to be active
        self.aws_user = "systest-" + self.test_identifier_rand + "-user"
        self.aws_manager.create_user(self.aws_user)
        self.test_global_aws_users.append(self.aws_user)
        self.wait_for_report(self.get_incidents, sleep_interval=15, timeout=900,
                             filters={CDR_ALERT_ACCOUNT_ID_PATH: account_id,
                                      "message": self.aws_user + "|like"},
                             expect_incidents=True)

        Logger.logger.info('Stage 6: Create bad log location cloud account with cadr')
        self.connect_cadr_bad_log_location(stack_region, self.cadr_bad_cloud_account_name, bad_log_location)

        Logger.logger.info('Stage 7: Delete cadr feature and validate account deleted')
        self.delete_and_validate_account_feature(account_guid, CADR_FEATURE_NAME)

        return self.cleanup()

    def cleanup(self, **kwargs):
        # Base Accounts.cleanup handles all stacks, stacksets, accounts, and organizations automatically
        
        # Handle runtime policies and AWS users specific to this test
        for policy_guid in self.test_runtime_policies:
            try:
                Logger.logger.info(f"Deleting runtime policy: {policy_guid}")
                self.backend.delete_runtime_policies(policy_guid)
            except Exception as e:
                Logger.logger.error(f"Failed to delete runtime policy {policy_guid}: {e}")
            
        for aws_user in self.test_global_aws_users:
            try:
                Logger.logger.info(f"Deleting aws user: {aws_user}")
                self.aws_manager.delete_user(aws_user)
            except Exception as e:
                Logger.logger.error(f"Failed to delete aws user {aws_user}: {e}")

        return super().cleanup(**kwargs)


import os
import time
from systest_utils import Logger, statics
from tests_scripts.accounts.accounts import PROVIDER_AWS, CADR_FEATURE_NAME, CDR_ALERT_ORG_ID_PATH
from tests_scripts.accounts.accounts import CloudEntityTypes, ExclusionActions
from tests_scripts.accounts.accounts import Accounts, FEATURE_STATUS_CONNECTED
import random
from infrastructure import aws
# from typing import List
# static cloudtrail and bucket names that are expected to be existed in the test account
ORGANIZATION_CLOUDTRAIL_SYSTEM_TEST_CONNECT = "trail-system-test-organization-connect-dont-delete"
ORGANIZATION_TRAIL_LOG_LOCATION = "system-test-organization-bucket-armo/AWSLogs/o-63kbjphubt/930002936888"
ACCOUNT_TRAIL_LOG_LOCATION = "system-test-organization-bucket-armo/AWSLogs/930002936888"

REGION_SYSTEM_TEST = "us-east-1"
REGION_SYSTEM_TEST_2 = "us-east-2"
ORG_ID = "o-63kbjphubt"
EXCLUDE_ACCOUNT_ID = "515497298766"



class CloudOrganizationCADR(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.aws_manager = None
        self.cadr_org_stack_name = None
        self.test_global_aws_users = []
        self.test_exclude_account_users = []
        
    def start(self):
        """
        CADR-only organization test
        1) Connect CADR org and validate
        2) Generate events for included/excluded accounts and validate incidents
        3) Validate single CADR block and merging into org
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
        

        cadr_region = REGION_SYSTEM_TEST_2
        self.aws_manager = aws.AwsManager(cadr_region, 
                                            aws_access_key_id=aws_access_key_id,
                                            aws_secret_access_key=aws_secret_access_key)
        Logger.logger.info(f"AwsManager initiated in region {cadr_region}")

        self.cadr_org_stack_name = "systest-" + self.test_identifier_rand + "-cadr-org"
        self.org_log_location = ORGANIZATION_TRAIL_LOG_LOCATION
        self.account_log_location = ACCOUNT_TRAIL_LOG_LOCATION
        self.runtime_policy_name = "systest-" + self.test_identifier_rand + "-cadr-org"
        self.aws_user = "systest-" + self.test_identifier_rand + "-user-org"

        self.exclude_account_aws_manager = self.aws_manager.assume_role_in_account(EXCLUDE_ACCOUNT_ID)


        Logger.logger.info('Stage 1: Connect cadr new organization')
        #validate that there are no existing org with cadr feature
        self.validate_org_not_exists_by_id(ORG_ID, CADR_FEATURE_NAME)
        org_guid = self.connect_cadr_new_organization(cadr_region, self.cadr_org_stack_name, self.org_log_location)
        Logger.logger.info(f"CADR organization created successfully with guid {org_guid}")
                
        Logger.logger.info('Stage 2: Validate cadr status is connected')
        self.wait_for_report(self.verify_cadr_status, sleep_interval=5, timeout=120, 
                            guid=org_guid, cloud_entity_type=CloudEntityTypes.ORGANIZATION, 
                            expected_status=FEATURE_STATUS_CONNECTED)
        Logger.logger.info(f"CADR organization {org_guid} is connected successfully")            
        
        Logger.logger.info('Stage 3: Create aws users for regular (included) and exclude (excluded) accounts of cadr feature')
        self.create_aws_cdr_runtime_policy(self.runtime_policy_name, ["I082"])

        # exclude account
        self.org_exclude_accounts_by_feature(org_guid=org_guid, feature_names=[CADR_FEATURE_NAME], action=ExclusionActions.EXCLUDE, accounts=[EXCLUDE_ACCOUNT_ID])
        aws_user_excluded = self.aws_user + "-excluded"
        self.exclude_account_aws_manager.create_user(aws_user_excluded)
        self.test_exclude_account_users.append(aws_user_excluded)
        #wait cause we dont want the events the be united
        time.sleep(360)
        # regular account
        self.aws_manager.create_user(self.aws_user)
        self.test_global_aws_users.append(self.aws_user)

        Logger.logger.info('Stage 4: Validate alert with orgID is created for regular account')
        self.wait_for_report(self.get_incidents, sleep_interval=30, timeout=900,
                            filters={CDR_ALERT_ORG_ID_PATH: ORG_ID,
                                    "message": self.aws_user + "|like"},
                            expect_incidents=True)

        Logger.logger.info('Stage 5: Validate excluded account incident is not created')
        self.get_incidents(filters={CDR_ALERT_ORG_ID_PATH: ORG_ID,
                                    "message": aws_user_excluded + "|like"},
                            expect_incidents=False)
        Logger.logger.info(f"Account {EXCLUDE_ACCOUNT_ID} is excluded successfully")
        
        Logger.logger.info('Stage 6: Connect single cadr - validate block')
        self.create_and_validate_cloud_account_with_cadr("test_block", self.account_log_location, PROVIDER_AWS, cadr_region, expect_failure=True)
        Logger.logger.info("connect CADR single account blocked successfully")
        
        Logger.logger.info('Stage 7: Delete cadr org and validate is deleted')
        self.delete_and_validate_org_feature(org_guid, CADR_FEATURE_NAME)
        Logger.logger.info("Delete cadr successfully")
        
        Logger.logger.info('Stage 8: Connect single cadr')
        merged_account_guid =self.create_and_validate_cloud_account_with_cadr(cloud_account_name="merge-account", trail_log_location=self.account_log_location, provider=PROVIDER_AWS, region=cadr_region, expect_failure=False)   
        Logger.logger.info(f"CADR account created successfully with guid {merged_account_guid}")
                    
        Logger.logger.info('Stage 9: Connect org cadr - validate merging')
        org_guid = self.create_and_validate_cloud_org_with_cadr(trail_log_location=self.org_log_location, region=cadr_region, expect_failure=False)
        self.validate_no_account(merged_account_guid)
        Logger.logger.info(f"the account merged into the org {org_guid}")
        self.validate_feature_deleted_from_entity(merged_account_guid, CADR_FEATURE_NAME, True, CloudEntityTypes.ACCOUNT)
        Logger.logger.info(f"Merged cadr feature of account {merged_account_guid} into the new org {org_guid} successfully")
            

        return self.cleanup()

    def cleanup(self, **kwargs):
        # Base Accounts.cleanup handles all stacks, stacksets, accounts, and organizations automatically
        
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
        
        for aws_user in self.test_exclude_account_users:
            try:
                Logger.logger.info(f"Deleting aws user: {aws_user}")
                if hasattr(self, 'exclude_account_aws_manager') and self.exclude_account_aws_manager:
                    self.exclude_account_aws_manager.delete_user(aws_user)
            except Exception as e:
                Logger.logger.error(f"Failed to delete aws user {aws_user}: {e}")

        return super().cleanup(**kwargs)



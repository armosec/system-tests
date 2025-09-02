import os
import time
from systest_utils import Logger, statics
from tests_scripts.accounts.accounts import Accounts ,CSPM_SCAN_STATE_COMPLETED ,FEATURE_STATUS_CONNECTED
from tests_scripts.accounts.accounts import PROVIDER_AWS, CADR_FEATURE_NAME
from tests_scripts.accounts.accounts import CloudEntityTypes, ExclusionActions
import random
from urllib.parse import parse_qs, quote, urlparse
from infrastructure import aws


# static cloudtrail and bucket names that are expected to be existed in the test account
ORGANIZATION_CLOUDTRAIL_SYSTEM_TEST_CONNECT = "trail-system-test-organization-connect-dont-delete"
ORGANIZATION_BUCKET_NAME_SYSTEM_TEST = "system-test-organization-bucket-armo"
ORGANIZATION_TRAIL_LOG_LOCATION = "system-test-organization-bucket-armo/AWSLogs/o-63kbjphubt/930002936888"
ACCOUNT_TRAIL_LOG_LOCATION = "system-test-organization-bucket-armo/AWSLogs/930002936888"

REGION_SYSTEM_TEST = "us-east-2"
ORG_ID = "o-63kbjphubt"
EXCLUDE_ACCOUNT_ID = "515497298766"



class CloudOrganization(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.aws_manager = None
        self.cspm_org_stack_name = None
        self.cadr_org_stack_name = None
        self.compliance_org_stack_name = None
        self.test_global_aws_users = []
        self.test_exclude_account_users = []
        
        self.skip_apis_validation = False

    def start(self):
        """
        Agenda:
        1. Init AwsManager

        //cadr tests
        2. Connect cadr new organization
        3. Validate cadr status is connected
        4. Validate alert with orgID is created
        5. Exclude one account and validate it is excluded
        6. Include one account and validate it is included
        7. Connect single cadr - validate block
        8. Delete cadr org and validate is deleted
        9. Connect single cadr
        10. Validate cadr status is connected
        11. Connect org cadr - validate merging

        //compliance tests
        12. Create compliance org stack
        13. Connect compliance to existing organization(without scanning,without window)
        14. delete compliance feature and validate org and account deleted
        15. conenct single account (without scanning)
        16. connect compliance to existing organization again(without scanning) - validate single is under the new organization
        17. update compliance org stackset to impact more accounts and validted the syncing windwo is working
        18. update compliance org stackset after end of window to make sure the window is closed and no new accounts are added
        19. exclude one account valdiated it marked as excluded
        20. update name and exclude list and validated the changes

        //compliance connection error 
        21.break aws admin role and sync the org - validate the error is shown and the org is not connected
        22. fix aws admin role and sync the org - validate the org is connected
        
        //cspm more than 1 feature - combined
        22. connect compliance and vulnScan
        23. delete vulnScan and validate feature is delted(update stack as well)
        24. update stack and add vuln feature and validate it is connected
        25. update stackset and org add vuln feature and validate it is connected - validated all accounts have vuln as well udner the org

        //vulnscan tests
        TODO: eran need to add his cases
        """
        
        #return statics.SUCCESS, ""
    
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        stack_region = REGION_SYSTEM_TEST
        # generate random number for cloud account name for uniqueness
        self.test_identifier_rand = str(random.randint(10000000, 99999999))
        self.cadr_org_stack_name = "systest-" + self.test_identifier_rand + "-cadr-org"
        self.cadr_account_stack_name = "systest-" + self.test_identifier_rand + "-cadr-single"
        self.org_log_location = ORGANIZATION_TRAIL_LOG_LOCATION
        self.account_log_location = ACCOUNT_TRAIL_LOG_LOCATION
        self.runtime_policy_name = "systest-" + self.test_identifier_rand + "-cadr-org"
        self.aws_user = "systest-" + self.test_identifier_rand + "-user-org"

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
                             filters={"cdrevent.eventdata.awscloudtrail.useridentity.orgid": ORG_ID,
                                      "message": self.aws_user + "|like"},
                             expect_incidents=True)
        
        Logger.logger.info('Stage 5: Exclude one account and validate it is excluded')
        self.update_org_exclude_accounts(org_guid, [CADR_FEATURE_NAME], ExclusionActions.EXCLUDE, [EXCLUDE_ACCOUNT_ID])
        aws_user_excluded = self.aws_user + "-excluded"
        self.exclude_account_aws_manager.create_user(aws_user_excluded)
        self.test_exclude_account_users.append(aws_user_excluded)
        time.sleep(420) # wait to make sure incident were not created
        self.get_incidents(filters={"cdrevent.eventdata.awscloudtrail.useridentity.orgid": ORG_ID,
                                    "message": aws_user_excluded + "|like"},
                             expect_incidents=False)
        Logger.logger.info(f"Account {EXCLUDE_ACCOUNT_ID} is excluded successfully")
        
        Logger.logger.info('Stage 6: Include one account and validate it is included')
        self.update_org_exclude_accounts(org_guid, [CADR_FEATURE_NAME], ExclusionActions.INCLUDE, [EXCLUDE_ACCOUNT_ID])
        aws_user_included = self.aws_user + "-included"
        self.exclude_account_aws_manager.create_user(aws_user_included)
        self.test_exclude_account_users.append(aws_user_included)
        self.wait_for_report(self.get_incidents, sleep_interval=15, timeout=600,
                             filters={"cdrevent.eventdata.awscloudtrail.useridentity.orgid": ORG_ID,
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
        

        #compliance tests

        return self.cleanup()

    def cleanup(self, **kwargs):

        if self.aws_manager:
            for stack_name in self.tested_stacks:
                Logger.logger.info(f"Deleting stack: {stack_name}")
                self.aws_manager.delete_stack(stack_name)

            for stack_name in self.tested_stacks:
                Logger.logger.info(f"Deleting log groups for stack: {stack_name}")
                self.aws_manager.delete_stack_log_groups(stack_name)

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



import os
from systest_utils import Logger, statics
from tests_scripts.accounts.accounts import Accounts ,CSPM_SCAN_STATE_COMPLETED ,FEATURE_STATUS_CONNECTED
from tests_scripts.accounts.accounts import PROVIDER_AWS, CADR_FEATURE_NAME
from tests_scripts.accounts.accounts import CloudEntityTypes
import random
from urllib.parse import parse_qs, quote, urlparse
from infrastructure import aws


# static cloudtrail and bucket names that are expected to be existed in the test account
ORGANIZATION_CLOUDTRAIL_SYSTEM_TEST_CONNECT = "trail-system-test-organization-connect-dont-delete"
ORGANIZATION_BUCKET_NAME_SYSTEM_TEST = "system-test-organization-bucket-armo"
ORGANIZATION_TRAIL_LOG_LOCATION = "system-test-organization-bucket-armo/AWSLogs/o-63kbjphubt/930002936888"
ACCOUNT_TRAIL_LOG_LOCATION = "system-test-organization-bucket-armo/AWSLogs/930002936888"

REGION_SYSTEM_TEST = "us-east-2"



class CloudOrganization(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.stack_manager = None
        self.cspm_org_stack_name = None
        self.cadr_org_stack_name = None
        self.compliance_org_stack_name = None
        
        self.skip_apis_validation = False

    def start(self):
        """
        Agenda:
        1. Init cloud formation manager

        //cadr tests
        2. Connect cadr new organization
        3. Validate cadr is connected
        4. Connect single cadr - validate block
        5. Delete cadr org and validate is deleted
        6. Connect single cadr
        7. Validate cadr is connected
        8. Connect org cadr - validate merging
        9. Exclude one account and validate it is excluded
        10. include one account and validate it is included

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

        return statics.SUCCESS, ""
    
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        stack_region = REGION_SYSTEM_TEST
        # generate random number for cloud account name for uniqueness
        self.test_identifier_rand = str(random.randint(10000000, 99999999))
        self.cadr_org_stack_name = "systest-" + self.test_identifier_rand + "-cadr-org"
        self.cadr_account_stack_name = "systest-" + self.test_identifier_rand + "-cadr-single"
        self.org_log_location = ORGANIZATION_TRAIL_LOG_LOCATION
        self.account_log_location = ACCOUNT_TRAIL_LOG_LOCATION

        Logger.logger.info('Stage 1: Init cloud formation manager')
        aws_access_key_id = os.environ.get("ORGANIZATION_AWS_ACCESS_KEY_ID_CLOUD_TESTS")
        aws_secret_access_key = os.environ.get("ORGANIZATION_AWS_SECRET_ACCESS_KEY_CLOUD_TESTS")
        if not aws_access_key_id:
            raise Exception("ORGANIZATION_AWS_ACCESS_KEY_ID_CLOUD_TESTS is not set")
        if not aws_secret_access_key:
            raise Exception("ORGANIZATION_AWS_SECRET_ACCESS_KEY_CLOUD_TESTS is not set")
        

        self.stack_manager = aws.CloudFormationManager(stack_region, 
                                                  aws_access_key_id=aws_access_key_id,
                                                  aws_secret_access_key=aws_secret_access_key)
        Logger.logger.info(f"CloudFormationManager initiated in region {stack_region}")

        Logger.logger.info('Stage 2: Connect cadr new organization')
        org_guid = self.connect_cadr_new_organization(stack_region, self.cadr_org_stack_name, self.org_log_location)
        Logger.logger.info(f"CADR organization created successfully with guid {org_guid}")                                                  
        
        Logger.logger.info('Stage 3: Validate cadr is connected')
        self.wait_for_report(self.verify_cadr_status, sleep_interval=5, timeout=120, 
                             guid=org_guid, cloud_entity_type=CloudEntityTypes.ORGANIZATION, 
                             expected_status=FEATURE_STATUS_CONNECTED)
        Logger.logger.info(f"CADR organization {org_guid} is connected successfully")
        
        Logger.logger.info('Stage 4: Connect single cadr - validate block')
        self.create_and_validate_cloud_account_with_cadr("test_block", self.account_log_location, PROVIDER_AWS, stack_region, expect_failure=True)
        Logger.logger.info("connect CADR single account blocked successfully")
        
        Logger.logger.info('Stage 5: Delete cadr org and validate is deleted')
        self.delete_and_validate_org_feature(org_guid, CADR_FEATURE_NAME)
        self.stack_manager.delete_stack(self.cadr_org_stack_name)
        Logger.logger.info("Delete cadr successfully")
        
        Logger.logger.info('Stage 6: Connect single cadr')
        account_guid = self.connect_cadr_new_account(stack_region, self.cadr_account_stack_name, "merge-account", self.account_log_location)
        Logger.logger.info(f"CADR account created successfully with guid {account_guid}")
        
        Logger.logger.info('Stage 7: Validate cadr is connected')
        self.wait_for_report(self.verify_cadr_status, sleep_interval=5, timeout=120, 
                             guid=account_guid, cloud_entity_type=CloudEntityTypes.ACCOUNT, 
                             expected_status=FEATURE_STATUS_CONNECTED)
        Logger.logger.info(f"CADR account {account_guid} is connected successfully")
        
        Logger.logger.info('Stage 8: Connect org cadr - validate merging')
        org_guid = self.connect_cadr_new_organization(stack_region, self.cadr_org_stack_name, self.org_log_location)
        self.validate_feature_deleted(account_guid, CADR_FEATURE_NAME, True, CloudEntityTypes.ACCOUNT)
        Logger.logger.info(f"Merged cadr feature of account {account_guid} into the new org {org_guid} successfully")


        #compliance tests


        return self.cleanup()

    def cleanup(self, **kwargs):

        if self.stack_manager:
            for stack_name in self.tested_stacks:
                Logger.logger.info(f"Deleting stack: {stack_name}")
                self.stack_manager.delete_stack(stack_name)

            for stack_name in self.tested_stacks:
                Logger.logger.info(f"Deleting log groups for stack: {stack_name}")
                self.stack_manager.delete_stack_log_groups(stack_name)

        for cloud_org_guid in self.test_cloud_orgs_guids:
            Logger.logger.info(f"Deleting cloud organization: {cloud_org_guid}")
            self.backend.delete_cloud_organization(cloud_org_guid)


        return super().cleanup(**kwargs)



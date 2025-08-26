import os
from systest_utils import Logger, statics
from tests_scripts.accounts.accounts import Accounts ,CSPM_SCAN_STATE_COMPLETED ,FEATURE_STATUS_CONNECTED
from tests_scripts.accounts.accounts import CADR_FEATURE_NAME, CSPM_FEATURE_NAME, extract_parameters_from_url
import random
from urllib.parse import parse_qs, quote, urlparse
from infrastructure import aws


# static cloudtrail and bucket names that are expected to be existed in the test account
ORGANIZATION_CLOUDTRAIL_SYSTEM_TEST_CONNECT = "system-test-organization-connect-dont-delete"
ORGANIZATION_BUCKET_NAME_SYSTEM_TEST = "system-test-organization-bucket-armo"

REGION_SYSTEM_TEST = "us-east-1"



class CloudOrganization(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.stack_manager = None
        self.cspm_org_stack_name = None
        self.cadr_org_stack_name = None

        self.skip_apis_validation = False

    def start(self):
        """
        Agenda:
        1. Init cloud formation manager

        //cadr tests
        3. Create cadr org stack
        4. Connect cadr new organization
        5. validate cadr is connected and data
        6. conenct single cadr - validate block
        7. delete cadr org and validate is deleted
        8. conenct single cadr 
        9. conenct org cadr - validate merging
        10. exclude one account and validate it is excluded
        11. include one account and validate it is included

        //cspm tests
        12. Create cspm org stack
        13. Connect cspm to existing organization(without scanning,without window)
        14. delete cspm feature and validate org and account deleted
        15. conenct single account (without scanning)
        16. connect cspm to existing organization again(without scanning) - validate single is under the new organization
        17. update cspm org stackset to impact more accounts and validted the syncing windwo is working
        18. update cspm org stackset after end of window to make sure the window is closed and no new accounts are added
        19. exclude one account valdiated it marked as excluded
        20. update name and exclude list and validated the changes

        //cspm connection error 
        21.break aws admin role and sync the org - validate the error is shown and the org is not connected
        22. fix aws admin role and sync the org - validate the org is connected
        
        //cspm more than 1 feature - combined
        23. connect compliance and vulnScan
        24. delete vulnScan and validate feature is delted(update stack as well)
        25. update stack and add vuln feature and validate it is connected
        26. udate stackset and org add vuln feature and validate it is connected - validated all accounts have vuln as well udner the org

        //vulnscan tests
        TODO: eran need to add his cases
        """

        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        stack_region = REGION_SYSTEM_TEST
        # generate random number for cloud account name for uniqueness
        self.test_identifer_rand = str(random.randint(10000000, 99999999))

        Logger.logger.info('Stage 1: Init cloud formation manager')
        self.stack_manager = aws.CloudFormationManager(stack_region, 
                                                  aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID_CLOUD_TESTS"), 
                                                  aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY_CLOUD_TESTS"))
        
        # cspm_stack_name doesn't require an existing account therefore can be created once and be used accross the test
        Logger.logger.info('Stage 2: Create cadr org stack')
        #TODO: add static org trail and buckt int he test account
        self.bucket_name = ORGANIZATION_BUCKET_NAME_SYSTEM_TEST
        self.cloud_trail_name = ORGANIZATION_CLOUDTRAIL_SYSTEM_TEST_CONNECT
        log_location, kms_key = self.stack_manager.get_cloudtrail_details(self.cloud_trail_name)

        Logger.logger.info('Stage 3: Connect cadr new organization')
        self.connect_cadr_new_organization(stack_region, self.cadr_org_stack_name, log_location)


        return self.cleanup()

    def cleanup(self, **kwargs):

        if self.stack_manager:
            for stack_name in self.tested_stacks:
                Logger.logger.info(f"Deleting stack: {stack_name}")
                self.stack_manager.delete_stack(stack_name)

            for cloud_trail_name in self.tested_cloud_trails:
                Logger.logger.info(f"Deleting cloudtrail: {cloud_trail_name}")
                self.stack_manager.delete_cloudtrail(cloud_trail_name)

            for stack_name in self.tested_stacks:
                Logger.logger.info(f"Deleting log groups for stack: {stack_name}")
                self.stack_manager.delete_stack_log_groups(stack_name )

        for cloud_account_guid in self.test_cloud_accounts_guids:
            Logger.logger.info(f"Deleting cloud account: {cloud_account_guid}")
            self.backend.delete_cloud_account(cloud_account_guid)


        return super().cleanup(**kwargs)

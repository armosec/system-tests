

import os
from systest_utils import Logger, statics
from tests_scripts.accounts.accounts import Accounts
from tests_scripts.accounts.accounts import CADR_FEATURE_NAME, CSPM_FEATURE_NAME, extract_parameters_from_url
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

        self.stack_manager = None
        self.cspm_stack_name = None
        self.cadr_stack_name = None




    def start(self):
        """
        Agenda:
        1. Init cloud formation manager
        2. Create cspm stack
        3. Create bad arn cloud account with cspm
        4. Connect cspm new account
        5. Connect cadr existing account
        6. Delete and validate feature cspm when cspm is first
        7. Delete and validate feature cadr when cspm is first
        8. Delete and validate cloud account where cspm is first
        9. Create bad log location cloud account with cadr
        10. Connect cadr new account
        11. Connect cspm existing account
        12. Delete and validate feature cadr when cadr is first
        13. Delete and validate feature cspm when cadr is first
        14. Delete and validate cloud account where cadr is first
        15. Validate aws regions
        16. Validate aws regions details
       


        """

        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        return statics.SUCCESS, ""

        stack_region = REGION_SYSTEM_TEST
        # generate random number for cloud account name for uniqueness
        self.test_identifer_rand = str(random.randint(10000000, 99999999))


        Logger.logger.info('Stage 1: Init cloud formation manager')
        self.stack_manager = aws.CloudFormationManager(stack_region, 
                                                  aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID_CLOUD_TESTS"), 
                                                  aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY_CLOUD_TESTS"))
        
        # cspm_stack_name doesn't require an existing account therefore can be created once and be used accross the test
        Logger.logger.info('Stage 2: Create cspm stack')
        self.cspm_stack_name = "systest-" + self.test_identifer_rand + "-cspm"
        stack_link = self.get_and_validate_cspm_link(stack_region)
        _, template_url, _, parameters = extract_parameters_from_url(stack_link)
        Logger.logger.info(f"Creating stack {self.cspm_stack_name} with template {template_url} and parameters {parameters}")
        test_arn =  self.create_stack_cspm(self.cspm_stack_name, template_url, parameters)
        account_id = aws.extract_account_id(test_arn)
        Logger.logger.info(f"Created cspm stack {self.cspm_stack_name} with account id {account_id} and arn {test_arn}")

        # cadr_stack_name requires an existing account therefore should be created for each account tested
        self.cadr_stack_name_first = "systest-" + self.test_identifer_rand + "-cadr-first"
        self.cadr_stack_name_second = "systest-" + self.test_identifer_rand + "-cadr-second"

        self.bucket_name = BUCKET_NAME_SYSTEM_TEST
        self.cloud_trail_name = CLOUDTRAIL_SYSTEM_TEST_CONNECT
        log_location, kms_key = self.stack_manager.get_cloudtrail_details(self.cloud_trail_name)

        bad_arn = "arn:aws:iam::12345678:role/armo-scan-role-cross-with_customer-12345678"
        bad_log_location = "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail"

        # cloud account names
    
        # cspm cloud account name - first creating cspm and then cadr
        self.cspm_first_cloud_account_name = "systest-" + self.test_identifer_rand + "-cspm-first"

        # cadr cloud account name - first creating cadr and then cspm
        self.cadr_first_cloud_account_name = "systest-" + self.test_identifer_rand + "-cadr-first"

        
        Logger.logger.info('Stage 3: Create bad arn cloud account with cspm')
        cloud_account_guid = self.connect_cspm_bad_arn(stack_region, bad_arn, self.cspm_first_cloud_account_name)

        Logger.logger.info('Stage 4: Connect cspm new account')
        cloud_account_guid = self.connect_cspm_new_account(stack_region, account_id, test_arn, self.cspm_first_cloud_account_name)

        Logger.logger.info('Stage 5: Connect cadr existing account')
        self.connect_cadr_existing_account(stack_region, self.cadr_stack_name_second, cloud_account_guid, log_location)

        Logger.logger.info('Stage 6: Delete and validate feature cspm when cspm is first')
        self.delete_and_validate_feature(cloud_account_guid, CSPM_FEATURE_NAME)

        Logger.logger.info('Stage 7: Delete and validate feature cadr when cspm is first')
        self.delete_and_validate_feature(cloud_account_guid, CADR_FEATURE_NAME)

        Logger.logger.info('Stage 8: Delete and validate cloud account where cspm is first')
        self.delete_and_validate_cloud_account(cloud_account_guid)

        Logger.logger.info('Stage 9: Create bad log location cloud account with cadr')
        cloud_account_guid = self.connect_cadr_bad_log_location(stack_region, self.cadr_first_cloud_account_name, bad_log_location)

        Logger.logger.info('Stage 10: Connect cadr new account')
        cloud_account_guid = self.connect_cadr_new_account(stack_region, self.cadr_stack_name_first, self.cadr_first_cloud_account_name, self.bucket_name, log_location)

        Logger.logger.info('Stage 11: Connect cspm existing account')
        self.connect_cspm_existing_account(cloud_account_guid, stack_region, test_arn)

        Logger.logger.info('Stage 12: Delete and validate feature cadr when cadr is first')
        self.delete_and_validate_feature(cloud_account_guid, CADR_FEATURE_NAME)

        Logger.logger.info('Stage 13: Delete and validate feature cspm when cadr is first')
        self.delete_and_validate_feature(cloud_account_guid, CSPM_FEATURE_NAME)

        Logger.logger.info('Stage 14: Delete and validate cloud account where cadr is first')
        self.delete_and_validate_cloud_account(cloud_account_guid)

        Logger.logger.info('Stage 15: Validate aws regions')
        res = self.backend.get_aws_regions()
        assert len(res) > 0, f"failed to get aws regions, res is {res}"

        Logger.logger.info('Stage 16: Validate aws regions details')
        res = self.backend.get_aws_regions_details()
        assert len(res) > 0, f"failed to get aws regions details, res is {res}"

        return self.cleanup()
    
    def cleanup(self, **kwargs):

        if self.stack_manager:
            for stack_name in self.tested_stacks:
                self.stack_manager.delete_stack(stack_name)

            for cloud_trail_name in self.tested_cloud_trails:
                self.stack_manager.delete_cloudtrail(cloud_trail_name)

        for cloud_account_guid in self.test_cloud_accounts_guids:
            self.backend.delete_cloud_account(cloud_account_guid)


        return super().cleanup(**kwargs)

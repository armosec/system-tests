

import os
from systest_utils import Logger, statics
from tests_scripts.accounts.accounts import Accounts
import random
from urllib.parse import quote
from infrastructure import aws




PROVIDER_AWS = "aws"
PROVIDER_AZURE = "azure"
PROVIDER_GCP = "gcp"

# a generated good arn from Eran aws dev account - consider moving to an env var?
GOOD_ARN = "arn:aws:iam::015253967648:role/armo-scan-role-015253967648"

# # cspm template url - consider moving to an env var?
# CSPM_TEMPLATE_URL = "https://armo-scan-user-stack.s3.us-east-1.amazonaws.com/cspm-template-dev.yaml"

# system test trail name : system-test-dev




class CSPM(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.stack_manager = None




    def start(self):
        """
        Agenda:
        1. Get and validate cspm link.
        2. Create stack for cspm and get arn.
        3. Create bad arn cloud account with cspm.
        4. Create new arn cloud account with cspm.
        5. Validate accounts cloud with cspm list.
        6. Validate accounts cloud with cspm uniquevalues.
        7. Edit name and validate cloud account with cspm.
        8. Delete and validate feature.
        9. Delete and validate cloud account with cspm.
        10. Validate cspm results apis.
        11. Validate aws regions.


        Install kubescape with helm-chart
        Validate accounts kubernetes list.
        Validate accounts kubernetes uniquevalues.

        """

        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        stack_region = "us-east-1"
        # generate random number for cloud account name for uniqueness
        rand = str(random.randint(10000000, 99999999))

        Logger.logger.info('Stage 1: Get and validate cspm link')
        stack_link = self.get_and_validate_cspm_link(stack_region)

        self.stack_manager = aws.CloudFormationManager(stack_link, 
                                                  aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID_CLOUD_TESTS"), 
                                                  aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY_CLOUD_TESTS"))
        
        test_stack_name = "systest-" + rand + "-cspm"
        
        Logger.logger.info('Stage 2: Create stack for cspm and get arn')
        stack_id =  self.stack_manager.create_stack(stack_name=test_stack_name)
        assert stack_id, f"failed to create stack for cspm, stack name is {test_stack_name}"
        Logger.logger.info(f"Stack creation initiated for: {test_stack_name}, stack id is {stack_id}")

        self.stack_manager.wait_for_stack_creation()
        test_arn =  self.stack_manager.get_stack_output_role_arn()
        assert test_arn, f"failed to get stack output arn for cspm, stack name is {test_stack_name}"
        Logger.logger.info(f"Got stack output arn for cspm, arn is {test_arn}")

        bad_arn = "arn:aws:iam::12345678:role/armo-scan-role-cross-with_customer-12345678"
        cloud_account_name = test_stack_name

        Logger.logger.info('Stage 3: Create bad arn cloud account with cspm')
        self.create_and_validate_cloud_account_with_cspm(cloud_account_name, bad_arn, PROVIDER_AWS, region=stack_region, expect_failure=True)

        account_id = aws.extract_account_id(test_arn)
        self.cleanup_existing_aws_cloud_accounts(account_id)


        Logger.logger.info('Stage 4: Create new arn cloud account with cspm')
        self.create_and_validate_cloud_account_with_cspm(cloud_account_name, test_arn, PROVIDER_AWS, region=stack_region, expect_failure=False)

        Logger.logger.info('Stage 5: Validate accounts cloud with cspm list')
        guid = self.validate_accounts_cloud_list_cspm(cloud_account_name, test_arn)
        self.test_cloud_accounts_guids.append(guid)

        Logger.logger.info('Stage 6: Validate accounts cloud with cspm uniquevalues')
        self.validate_accounts_cloud_uniquevalues(cloud_account_name)
  
        Logger.logger.info('Stage 7: Edit name and validate cloud account with cspm')
        self.update_and_validate_cloud_account(guid, cloud_account_name + " updated", test_arn)

        Logger.logger.info('Stage 8: Delete and validate feature')
        self.delete_and_validate_feature(guid, "cspm")

        Logger.logger.info('Stage 9: Delete and validate cloud account with cspm')
        self.delete_and_validate_cloud_account(guid)
        self.test_cloud_accounts_guids.remove(guid)

        Logger.logger.info('Stage 10: Validate cspm results apis - TODO')
        ### TODO ###
        #
        #
        ####################


        Logger.logger.info('Stage 11: Validate aws regions')
        res = self.backend.get_aws_regions()
        assert len(res) > 0, f"failed to get aws regions, res is {res}"

        return self.cleanup()


 

    def cleanup(self, **kwargs):
        if self.stack_manager:
            self.stack_manager.delete_stack()
        return super().cleanup(**kwargs)

    

    def cleanup_existing_aws_cloud_accounts(self, account_id):
        """
        Cleanup existing aws cloud accounts.
        """

        if not account_id:
            raise Exception("account_id is required")

        body = {
            "pageSize": 100,
            "pageNum": 0,
            "innerFilters": [
                {
                    "provider": PROVIDER_AWS,
                    "providerInfo.accountID":account_id
                }
            ]
        }
        res = self.backend.get_cloud_accounts(body=body)

        if "response" in res:
            if len(res["response"]) == 0:
                Logger.logger.info(f"No existing aws cloud accounts to cleanup for account_id {account_id}")
                return
            for account in res["response"]:
                guid = account["guid"]
                self.backend.delete_cloud_account(guid)
                Logger.logger.info(f"Deleted cloud account with guid {guid} for account_id {account_id}")

        return res

    def get_and_validate_cspm_link(self, region) -> str:
        """
        Get and validate cspm link.
        """
        tenant = self.backend.get_selected_tenant()
        expected_template_url = os.environ.get("CSPM_TEMPLATE_URL")
        parsed_cspm_template = quote(expected_template_url, safe='')
        stack_link = self.backend.get_cspm_link(region=region)
        expected_link = f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/quickcreate?param_AccountID={tenant}\u0026stackName=create-armo-scan-user\u0026templateUrl={parsed_cspm_template}"
        assert stack_link == expected_link,  f"failed to get cspm link, link is {stack_link}, expected link is {expected_link}"
        return stack_link


    def create_and_validate_cloud_account_with_cspm(self, cloud_account_name:str, arn:str, provider:str, region:str, expect_failure:bool=False):
        """
        Create and validate cloud account.
        """

        body = {
                "name": cloud_account_name,
                "cspmConfig": {
                    "crossAccountsRoleARN": arn,
                    "stackRegion": region
                },
            }
        
        failed = False
        try:
            res = self.backend.create_cloud_account(body=body, provider=provider)
        except Exception as e:
            if not expect_failure:
                Logger.logger.error(f"failed to create cloud account, body used: {body}, error is {e}")
            failed = True
        
        assert failed == expect_failure, f"expected_failure is {expect_failure}, but failed is {failed}, body used: {body}"

        if not expect_failure:
            assert "guid" in res, f"guid not in {res}"
            
    
    def validate_accounts_cloud_list_cspm(self, cloud_account_name:str, arn:str):
        """
        Validate accounts cloud list.
        """

        body = {
                "pageSize": 100,
                "pageNum": 0,
                "innerFilters": [
                    {
                        "name": cloud_account_name
                    }
                ],
            }

        res = self.backend.get_cloud_accounts(body=body)
        assert "response" in res, f"response not in {res}"
        assert len(res["response"]) > 0, f"response is empty"
        assert res["response"][0]["name"] == cloud_account_name, f"name is not {cloud_account_name}"
        assert "features" in res["response"][0], f"features not in {res['response'][0]}"
        assert "cspm" in res["response"][0]["features"], f"cspm not in {res['response'][0]['features']}"
        assert "config" in res["response"][0]["features"]["cspm"], f"config not in {res['response'][0]['features']['cspm']}"
        assert "crossAccountsRoleARN" in res["response"][0]["features"]["cspm"]["config"], f"crossAccountsRoleARN not in {res['response'][0]['features']['cspm']['config']}"
        assert res["response"][0]["features"]["cspm"]["config"]["crossAccountsRoleARN"] == arn, f"crossAccountsRoleARN is not {arn}"

        guid = res["response"][0]["guid"]
        return guid
    
    
    def validate_accounts_kubernetes_list(self, cluster:str):
        """
        Validate accounts kubernetes list.
        """

        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [{
                "cluster": cluster
            }]
        }

        res = self.backend.get_kubernetes_accounts(body=body)

     

        assert "response" in res, f"response not in {res}"
        assert len(res["response"]) > 0, f"response is empty"
        assert res["response"][0]["cluster"] == cluster, f"cluster is not {cluster}"

    def validate_accounts_kubernetes_uniquevalues(self, cluster:str):
        """
        Validate accounts kubernetes uniquevalues.
        """

        unique_values_body = {
            "fields": {
                "cluster": cluster,
            },
            "innerFilters": [
                {
                "cluster": cluster
                }
            ],
            "pageSize": 100,
            "pageNum": 1
            }
        
        res = self.backend.get_kubernetes_accounts_uniquevalues(body=unique_values_body)
        assert "fields" in res, f"failed to get fields for kubernetes accounts unique values, body used: {unique_values_body}, res is {res}"
        assert len(res["fields"]) > 0, f"response is empty"
        assert len(res["fields"]["cluster"]) == 1, f"response is empty"
        assert res["fields"]["cluster"][0] == cluster, f"cluster is not {cluster}"
    

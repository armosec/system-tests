

from systest_utils import Logger
from tests_scripts.accounts.accounts import Accounts
import random
from urllib.parse import quote




PROVIDER_AWS = "aws"
PROVIDER_AZURE = "azure"
PROVIDER_GCP = "gcp"

# a generated good arn from Eran aws dev account - consider moving to an env var?
GOOD_ARN = "arn:aws:iam::015253967648:role/armo-scan-role-015253967648"

# cspm template url - consider moving to an env var?
CSPM_TEMPLATE_URL = "https://armo-scan-user-stack.s3.us-east-1.amazonaws.com/cspm-template-dev.yaml"

# system test trail name : system-test-dev




class CSPM(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)


        self.helm_kwargs = {
            "capabilities.runtimeObservability": "disable",
            "capabilities.networkPolicyService": "disable",
            "capabilities.seccompProfileService": "disable",
            "capabilities.nodeProfileService": "disable",
            "capabilities.vulnerabilityScan": "disable",
            "grypeOfflineDB.enabled": "false",
            "capabilities.relevancy": "disabled",
            "capabilities.malwareDetection": "disable",
            "capabilities.runtimeDetection": "disable",
            "alertCRD.installDefault": False,
            "alertCRD.scopeClustered": False,
        }
        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)

        self.test_cloud_accounts_guids = []
        self.cluster = None
        self.wait_for_agg_to_end = False


    def start(self):
        """
        Agenda:
        1. Create bad arn cloud account with cspm.
        2. Get and validate cspm link
        3. Create good arn cloud account with cspm.
        4. Validate accounts cloud with cspm list.
        5. Validate accounts cloud with cspm uniquevalues.
        6. Edit and validate cloud account with cspm.
        7. Delete and validate featur
        8. Delete and validate cloud account with cspm.
        9. Validate cspm results apis - TODO
        10. Validate aws regions


        Install kubescape with helm-chart
        Validate accounts kubernetes list.
        Validate accounts kubernetes uniquevalues.

        """

        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        # generate random number for cloud account name for uniqueness
        rand = str(random.randint(10000000, 99999999))

        bad_arn = "arn:aws:iam::12345678:role/armo-scan-role-cross-with_customer-12345678"
        cloud_account_name = "AWS System Test Account " + rand



        Logger.logger.info('Stage 1: Create bad arn cloud account with cspm')
        self.create_and_validate_cloud_account_with_cspm(cloud_account_name, bad_arn, PROVIDER_AWS, expect_failure=True)

        Logger.logger.info('Stage 2: Get and validate cspm link')
        self.get_and_validate_cspm_link("us-east-1")


        Logger.logger.info('Stage 3: Create good arn cloud account with cspm')
        self.create_and_validate_cloud_account_with_cspm(cloud_account_name, GOOD_ARN, PROVIDER_AWS, expect_failure=False)

        Logger.logger.info('Stage 4: Validate accounts cloud with cspm list')
        guid = self.validate_accounts_cloud_list_cspm(cloud_account_name, GOOD_ARN)
        self.test_cloud_accounts_guids.append(guid)

        Logger.logger.info('Stage 5: Validate accounts cloud with cspm uniquevalues')
        self.validate_accounts_cloud_uniquevalues(cloud_account_name)
        
  
        Logger.logger.info('Stage 6: Edit and validate cloud account with cspm')
        self.update_and_validate_cloud_account(guid, cloud_account_name + " updated", GOOD_ARN)

        Logger.logger.info('Stage 7: Delete and validate feature')
        self.delete_and_validate_feature(guid, "cspm")

        Logger.logger.info('Stage 8: Delete and validate cloud account with cspm')
        self.delete_and_validate_cloud_account(guid)
        self.test_cloud_accounts_guids.remove(guid)

        Logger.logger.info('Stage 9: Validate cspm results apis - TODO')
        ### TODO ###
        #
        #
        ####################


        Logger.logger.info('Stage 10: Validate aws regions')
        res = self.backend.get_aws_regions()
        assert len(res) > 0, f"failed to get aws regions, res is {res}"



        ## TODO: consider moving to a separate test that checks posture results
        self.cluster, self.namespace = self.setup(apply_services=False)

        
        Logger.logger.info('Install kubescape with helm-chart')
        self.install_kubescape(helm_kwargs=self.helm_kwargs)

        Logger.logger.info('Validate accounts kubernetes list')

        r, t = self.wait_for_report(
            self.validate_accounts_kubernetes_list, 
            timeout=180,
            cluster=self.cluster
        )

        Logger.logger.info('Validate accounts kubernetes uniquevalues')
        self.validate_accounts_kubernetes_uniquevalues(cluster=self.cluster)


        return super().cleanup()
 



    

    def get_and_validate_cspm_link(self, region): 
        """
        Get and validate cspm link.
        """
        tenant = self.backend.get_selected_tenant()
        parsed_cspm_template = quote(CSPM_TEMPLATE_URL, safe='')
        res = self.backend.get_cspm_link(region=region)
        expected_link = f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/quickcreate?param_AccountID={tenant}\u0026stackName=create-armo-scan-user\u0026templateUrl={parsed_cspm_template}"
        assert res == expected_link,  f"failed to get cspm link, link is {res}, expected link is {expected_link}"


    def create_and_validate_cloud_account_with_cspm(self, cloud_account_name:str, arn:str, provider:str, expect_failure:bool=False):
        """
        Create and validate cloud account.
        """

        body = {
                "name": cloud_account_name,
                "cspmConfig": {
                    "crossAccountsRoleARN": arn,
                    "stackRegion": "us-east-1"
                },
            }
        
        failed = False
        try:
            res = self.backend.create_cloud_account(body=body, provider=provider)
        except Exception as e:
            failed = True
        
        assert failed == expect_failure, f"expected to fail bad ARN for cspm, body used: {body}"

        if not expect_failure:
            assert "Cloud account created" in res, f"Cloud account was not created, body used: {body}"
            
    
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
    

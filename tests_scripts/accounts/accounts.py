
from systest_utils import Logger, statics
from tests_scripts.helm.base_helm import BaseHelm
import random



PROVIDER_AWS = "aws"
PROVIDER_AZURE = "azure"
PROVIDER_GCP = "gcp"

# a generated good arn from Eran aws dev account - consider moving to an env var?
GOOD_ARN = "arn:aws:iam::015253967648:role/armo-scan-role-cross-with_customer-015253967648"


class Accounts(BaseHelm):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)


        self.helm_kwargs = {
            "capabilities.vulnerabilityScan": "disable",
            "grypeOfflineDB.enabled": "false",
            "capabilities.relevancy": "disabled",
            # "capabilities.runtimeObservability": "disable",
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
        2. Create good arn cloud account with cspm.
        3. Validate accounts cloud with cspm list.
        4. Validate accounts cloud with cspm uniquevalues.
        5. Edit and validate cloud account with cspm.
        6. Delete and validate cloud account with cspm.
        7. Validate cspm results apis - TODO
        8. Validate aws regions
        9. Install kubescape with helm-chart
        10. Validate accounts kubernetes list.
        11. Validate accounts kubernetes uniquevalues.

        """

        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        # generate random number for cloud account name for uniqueness
        rand = str(random.randint(10000000, 99999999))

        bad_arn = "arn:aws:iam::12345678:role/armo-scan-role-cross-with_customer-12345678"
        cloud_account_name = "AWS System Test Account " + rand

        Logger.logger.info('Stage 1: Create bad arn cloud account with cspm')
        self.create_and_validate_cloud_account(cloud_account_name, bad_arn, PROVIDER_AWS, expect_failure=True)

        Logger.logger.info('Stage 2: Create good arn cloud account with cspm')
        self.create_and_validate_cloud_account(cloud_account_name, GOOD_ARN, PROVIDER_AWS, expect_failure=False)

        Logger.logger.info('Stage 3: Validate accounts cloud with cspm list')
        guid = self.validate_accounts_cloud_list(cloud_account_name, GOOD_ARN)
        self.test_cloud_accounts_guids.append(guid)

        Logger.logger.info('Stage 4: Validate accounts cloud with cspm uniquevalues')
        self.validate_accounts_cloud_uniquevalues(cloud_account_name)
        
  
        Logger.logger.info('Stage 5: Edit and validate cloud account with cspm')
        self.update_and_validate_cloud_account(guid, cloud_account_name + " updated", GOOD_ARN)

        Logger.logger.info('Stage 6: Delete and validate cloud account with cspm')
        self.delete_and_validate_cloud_account(guid)
        self.test_cloud_accounts_guids.remove(guid)

        Logger.logger.info('Stage 7: Validate cspm results apis - TODO')
        ### TODO ###
        #
        #
        ####################


        Logger.logger.info('Stage 8: Validate aws regions')
        res = self.backend.get_aws_regions()
        assert len(res) > 0, f"failed to get aws regions, res is {res}"


        self.cluster, self.namespace = self.setup(apply_services=False)


        ## TODO: consider moving to a separate test that checks posture results
        Logger.logger.info('Stage 9: Install kubescape with helm-chart')
        self.install_kubescape(helm_kwargs=self.helm_kwargs)

        Logger.logger.info('Stage 10: Validate accounts kubernetes list')

        r, t = self.wait_for_report(
            self.validate_accounts_kubernetes_list, 
            timeout=180,
            cluster=self.cluster
        )

        Logger.logger.info('Stage 11: Validate accounts kubernetes uniquevalues')
        self.validate_accounts_kubernetes_uniquevalues(cluster=self.cluster)


        return self.cleanup()
 
    

    def cleanup(self, **kwargs):
        for guid in self.test_cloud_accounts_guids:
            self.backend.delete_cloud_account(guid=guid)
            Logger.logger.info(f"Deleted cloud account with guid {guid}")
        return super().cleanup(**kwargs)
    

    def install_kubescape(self, helm_kwargs: dict = None):
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)


    def create_and_validate_cloud_account(self, cloud_account_name:str, arn:str, provider:str, expect_failure:bool=False):
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
            
    
    def validate_accounts_cloud_list(self, cloud_account_name:str, arn:str):
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
    
    def validate_accounts_cloud_uniquevalues(self, cloud_account_name:str):
        """
        Validate accounts cloud uniquevalues.
        """

        unique_values_body = {
            "fields": {
                "name": "",
            },
            "innerFilters": [
                {
                "name": cloud_account_name
                }
            ],
            "pageSize": 100,
            "pageNum": 1
            }
        
        res = self.backend.get_cloud_accounts_uniquevalues(body=unique_values_body)
        assert "fields" in res, f"failed to get fields for cloud accounts unique values, body used: {unique_values_body}, res is {res}"
        assert len(res["fields"]) > 0, f"response is empty"
        assert len(res["fields"]["name"]) == 1, f"response is empty"
        assert res["fields"]["name"][0] == cloud_account_name, f"name is not {cloud_account_name}"

    def update_and_validate_cloud_account(self, guid:str, cloud_account_name:str, arn:str):
        """
        Update and validate cloud account.
        """

        body = {
        "guid": guid,
        "name": cloud_account_name,
        "cspmConfig": {
            "crossAccountsRoleARN": arn,
            "stackRegion": "us-east-1"
        }
        }

        res = self.backend.update_cloud_account(body=body, provider=PROVIDER_AWS)
        assert "Cloud account updated" in res, f"Cloud account with guid {guid} was not updated"

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
        assert "response" in res, f"failed to get cloud accounts, body used: {body}, res is {res}"
        assert len(res["response"]) > 0, f"response is empty"
        assert res["response"][0]["name"] == cloud_account_name, f"failed to update cloud account, name is not {cloud_account_name}"

    def delete_and_validate_cloud_account(self, guid:str):
        """
        Delete and validate cloud account.
        """

        res = self.backend.delete_cloud_account(guid=guid)
        assert "Cloud account deleted" in res, f"Cloud account with guid {guid} was not deleted"

        body = {
                        "pageSize": 100,
                        "pageNum": 0,
                        "innerFilters": [
                            {
                                "guid": guid
                            }
                        ],
                    }

        res = self.backend.get_cloud_accounts(body=body)
        assert "response" in res, f"response not in {res}"
        assert len(res["response"]) == 0, f"response is not empty"
    
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
    


from systest_utils import Logger, statics
from urllib.parse import quote
from tests_scripts import base_test





PROVIDER_AWS = "aws"
PROVIDER_AZURE = "azure"
PROVIDER_GCP = "gcp"



class Accounts(base_test.BaseTest):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)
        self.test_cloud_accounts_guids = []

    def cleanup(self, **kwargs):
        for guid in self.test_cloud_accounts_guids:
            self.backend.delete_cloud_account(guid=guid)
            Logger.logger.info(f"Deleted cloud account with guid {guid}")
        return super().cleanup(**kwargs)
    
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
    
    def delete_and_validate_feature(self, guid:str, feature_name:str):
        """
        Delete and validate feature.
        """

        res = self.backend.delete_accounts_feature(account_guid=guid, feature_name=feature_name)
        assert "Feature deleted" in res, f"Feature {feature_name} for cloud account with guid {guid} was not deleted"

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
        assert len(res["response"]) > 0, f"response is empty"
        assert feature_name not in res["response"][0]["features"], f"'{feature_name}' feature was not deleted and is in {res['response']['features']}"

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
    
    
    

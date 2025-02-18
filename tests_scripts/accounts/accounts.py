
import os
from infrastructure import aws
from systest_utils import Logger, statics
from urllib.parse import parse_qs, quote, urlparse
from tests_scripts import base_test




PROVIDER_AWS = "aws"
PROVIDER_AZURE = "azure"
PROVIDER_GCP = "gcp"

CADR_FEATURE_NAME = "cadr"
CSPM_FEATURE_NAME = "cspm"

ACCOUNT_STATUS_CONNECTED = "Connected"
ACCOUNT_STATUS_PARTIALLY_CONNECTED = "Partially connected"
CSPM_SCAN_STATE_IN_PROGRESS = "In Progress"
CSPM_SCAN_STATE_COMPLETED = "Completed"
CSPM_SCAN_STATE_FAILED = "Failed"


class Accounts(base_test.BaseTest):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)
        self.test_cloud_accounts_guids = []
        self.tested_stacks = []
        self.tested_cloud_trails = []
        self.stack_manager: aws.CloudFormationManager



    def cleanup(self, **kwargs):
        for guid in self.test_cloud_accounts_guids:
            self.backend.delete_cloud_account(guid=guid)
            Logger.logger.info(f"Deleted cloud account with guid {guid}")
        return super().cleanup(**kwargs)
    


    def create_stack_cspm(self, stack_name, template_url, parameters)->str:
        self.create_stack(stack_name, template_url, parameters)
        test_arn =  self.stack_manager.get_stack_output_role_arn(stack_name)
        return test_arn
    
    def connect_cspm_new_account(self, region, account_id, arn, cloud_account_name, validate_apis=True)->str:
        self.cleanup_existing_aws_cloud_accounts(account_id)
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm(cloud_account_name, arn, PROVIDER_AWS, region=region, expect_failure=False)
        Logger.logger.info('Validate accounts cloud with cspm list')
        account = self.validate_accounts_cloud_list_cspm(cloud_account_name, arn ,CSPM_SCAN_STATE_IN_PROGRESS)
        guid = account["guid"]
        self.test_cloud_accounts_guids.append(guid)

        if validate_apis:
            Logger.logger.info('Validate accounts cloud with cspm uniquevalues')
            self.validate_accounts_cloud_uniquevalues(cloud_account_name)
    
            Logger.logger.info('Edit name and validate cloud account with cspm')
            self.update_and_validate_cloud_account(guid, cloud_account_name + " updated", arn)
            return cloud_account_guid
    

    def connect_cspm_existing_account(self, cloud_account_guid, region, arn, validate_apis=True)->str:
        body = {
                "guid": cloud_account_guid,
                "cspmConfig": {
                    "crossAccountsRoleARN": arn,
                    "stackRegion": region
                },
            }
        res = self.backend.update_cloud_account(body=body, provider=PROVIDER_AWS)
        assert "Cloud account updated" in res, f"Cloud account was not updated"

        body = {
                "pageSize": 1,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "guid": cloud_account_guid
                    }
                ],
            }
        
        res = self.backend.get_cloud_accounts(body=body)

        assert "response" in res, f"failed to get cloud accounts, body used: {body}, res is {res}"
        assert len(res["response"]) > 0, f"response is empty"
        assert res["response"][0]["guid"] == cloud_account_guid, f"guid is not {cloud_account_guid}"


        return cloud_account_guid
    

    def connect_cspm_bad_arn(self, region, arn, cloud_account_name)->str:
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm(cloud_account_name, arn, PROVIDER_AWS, region=region, expect_failure=True)
        return cloud_account_guid



    def create_stack(self, stack_name, template_url, parameters):
        stack_id =  self.stack_manager.create_stack(template_url, parameters, stack_name)
        assert stack_id, f"failed to create stack {stack_name}"
        Logger.logger.info(f"Stack creation initiated for: {stack_name}, stack id is {stack_id}")
        try:
            self.stack_manager.wait_for_stack_creation(stack_name)
        except Exception as e:
            Logger.logger.error(f"An error occurred while waiting for stack creation: {e}")
            failuer_reason = self.stack_manager.get_stack_failure_reason(stack_name)
            Logger.logger.error(f"Stack failure reason: {failuer_reason}")
            raise Exception(f"failed to create stack {stack_name}, failuer_reason is {failuer_reason}, exception is {e}")
        self.tested_stacks.append(stack_name)


    
    def connect_cadr_bad_log_location(self, region, cloud_account_name, trail_log_location)->str:
        cloud_account_guid = self.create_and_validate_cloud_account_with_cadr(cloud_account_name, trail_log_location, PROVIDER_AWS, region=region, expect_failure=True)
        return cloud_account_guid
    

    def connect_cadr_new_account(self, region, stack_name, cloud_account_name, bucket_name, log_location, validate_apis=True)->str:
        Logger.logger.info('Connect cadr new account')
        cloud_account_guid = self.create_and_validate_cloud_account_with_cadr(cloud_account_name, log_location, PROVIDER_AWS, region=region, expect_failure=False)

        self.create_stack_cadr(region, stack_name, cloud_account_guid)
        self.test_cloud_accounts_guids.append(cloud_account_guid)

        return cloud_account_guid


    def create_stack_cadr(self, region, stack_name, cloud_account_guid)->str:
        Logger.logger.info('Get and validate cadr link')
        stack_link = self.get_and_validate_cadr_link(region, cloud_account_guid)

        _, template_url, region, parameters = extract_parameters_from_url(stack_link)

        Logger.logger.info(f"Creating stack with name: {stack_name}, template_url: {template_url}, parameters: {parameters}")
        _ =  self.create_stack(stack_name, template_url, parameters)
    

    def connect_cadr_existing_account(self, region, stack_name, cloud_account_guid, trail_log_location, validate_apis=True)->str:
        
        body = {
                "guid": cloud_account_guid,
                "cadrConfig": {
                    "trailLogLocation": trail_log_location,
                    "stackRegion": region
                },
            }
        res = self.backend.update_cloud_account(body=body, provider=PROVIDER_AWS)
        assert "Cloud account updated" in res, f"Cloud account was not updated"

        self.create_stack_cadr(region, stack_name, cloud_account_guid)

        body = {
                "pageSize": 1,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "guid": cloud_account_guid
                    }
                ],
            }
        
        res = self.backend.get_cloud_accounts(body=body)

        assert "response" in res, f"failed to get cloud accounts, body used: {body}, res is {res}"
        assert len(res["response"]) > 0, f"response is empty"
        assert res["response"][0]["guid"] == cloud_account_guid, f"guid is not {cloud_account_guid}"
        assert "features" in res["response"][0], f"features not in {res['response'][0]}"
        assert CADR_FEATURE_NAME in res["response"][0]["features"], f"cadr not in {res['response'][0]['features']}"


        Logger.logger.info('Verify cadr is connected - happens when "StackReady" message is received')
        self.wait_for_report(self.verify_cadr_status, 
                                timeout=180,
                                sleep_interval=10,
                                 cloud_account_guid=cloud_account_guid,
                                 expected_status=ACCOUNT_STATUS_CONNECTED)
        
    
        Logger.logger.info('Verify cadr is disconnected - happens when "StackReady" message is expired, for system test is after 15 seconds')
        self.wait_for_report(self.verify_cadr_status,
                                timeout=180,
                                sleep_interval=10,
                                 cloud_account_guid=cloud_account_guid,
                                 expected_status=ACCOUNT_STATUS_PARTIALLY_CONNECTED)


        return cloud_account_guid
    
    def verify_cadr_status(self, cloud_account_guid, expected_status):
        body = {
                "pageSize": 1,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "guid": cloud_account_guid
                    }
                ],
            }
        
        expected_feature_connected = False

        if expected_status == ACCOUNT_STATUS_CONNECTED:
            expected_feature_connected = True
        
        res = self.backend.get_cloud_accounts(body=body)

        assert "response" in res, f"failed to get cloud accounts, body used: {body}, res is {res}"
        assert len(res["response"]) > 0, f"response is empty"
        assert res["response"][0]["accountStatus"] == expected_status, f"accountStatus is not {expected_status} but {res['response'][0]['accountStatus']}"
        assert res["response"][0]["features"][CADR_FEATURE_NAME]["isConnected"] == expected_feature_connected, f"isConnected is not {expected_feature_connected} but {res['response'][0]['features'][CADR_FEATURE_NAME]['isConnected']}"
        return True
    


    def create_cloudtrail(self, trail_name, bucket_name, kms_key_id=None):

        # have to clean up since there is a limit of 5 trails per region
        self.stack_manager.delete_all_cloudtrails("systest-cloud-trail")

        trail_arn = self.stack_manager.create_cloudtrail(trail_name, bucket_name)
        Logger.logger.info(f"Created CloudTrail with ARN: {trail_arn}, cloud_trail_name is {trail_name}, bucket_name is {bucket_name}")
       

        log_location, kms_key = self.stack_manager.get_cloudtrail_details(trail_name)
        Logger.logger.info(f"CloudTrail details retrieved: Log Location: {log_location}, KMS Key: {kms_key}")

        self.tested_cloud_trails.append(trail_arn)
        return log_location, kms_key


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
        expected_link = f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/quickcreate?param_AccountID={tenant}\u0026stackName=armo-security-readonly\u0026templateUrl={parsed_cspm_template}"
        assert stack_link == expected_link,  f"failed to get cspm link, link is {stack_link}, expected link is {expected_link}"
        return stack_link

    def get_and_validate_cadr_link(self, region, cloud_account_guid) -> str:
        """
        Get and validate cspm link.
        """

        stack_link = self.backend.get_cadr_link(region=region, cloud_account_guid=cloud_account_guid)
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
        
        return self.create_and_validate_cloud_account(body=body, provider=provider, expect_failure=expect_failure)

            
    def create_and_validate_cloud_account_with_cadr(self, cloud_account_name:str, trail_log_location:str, provider:str, region:str, expect_failure:bool=False):
        """
        Create and validate cloud account.
        """

        body = {
                "name": cloud_account_name,
                "cadrConfig": {
                    "trailLogLocation": trail_log_location,
                    "stackRegion": region
                },
            }
        
        return self.create_and_validate_cloud_account(body=body, provider=provider, expect_failure=expect_failure)
    
    def create_and_validate_cloud_account(self, body, provider, expect_failure:bool=False)->str:
        """
        Create and validate cloud account.
        """

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
            return res["guid"]
        
        return None

    def validate_accounts_cloud_list_cspm(self, cloud_account_name:str, arn:str ,scan_status: str):
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
        assert res["response"][0]["accountStatus"] == ACCOUNT_STATUS_CONNECTED, f"accountStatus is not {ACCOUNT_STATUS_CONNECTED}"
        assert "features" in res["response"][0], f"features not in {res['response'][0]}"
        assert CSPM_FEATURE_NAME in res["response"][0]["features"], f"cspm not in {res['response'][0]['features']}"
        assert res["response"][0]["features"][CSPM_FEATURE_NAME]["scanState"] == scan_status, f"scanState is not {scan_status}"
        assert "config" in res["response"][0]["features"][CSPM_FEATURE_NAME], f"config not in {res['response'][0]['features']['cspm']}"
        assert "crossAccountsRoleARN" in res["response"][0]["features"][CSPM_FEATURE_NAME]["config"], f"crossAccountsRoleARN not in {res['response'][0]['features']['cspm']['config']}"
        assert res["response"][0]["features"][CSPM_FEATURE_NAME]["config"]["crossAccountsRoleARN"] == arn, f"crossAccountsRoleARN is not {arn}"
        assert res["response"][0]["features"][CSPM_FEATURE_NAME]["nextScanTime"] != "", f"nextScanTime is empty"

        if scan_status== CSPM_SCAN_STATE_COMPLETED:
            assert res["response"][0]["features"][CSPM_FEATURE_NAME]["lastTimeScanSuccess"] != "", f"lastTimeScanSuccess is empty"
            assert res["response"][0]["features"][CSPM_FEATURE_NAME]["lastSuccessScanID"] != "", f"lastSuccessScanID is empty"
        elif scan_status==CSPM_SCAN_STATE_FAILED:
            assert res["response"][0]["features"][CSPM_FEATURE_NAME]["lastTimeScanFailed"] != "", f"lastTimeScanFailed is empty"

        return res["response"][0]


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

        self.test_cloud_accounts_guids.remove(guid)

    def validate_compliance_accounts_api(self,cloud_account_name:str ,last_success_scan_id:str):
        severity_counts_res =self.backend.get_cloud_severity_count()
        body = {
            "pageSize": 1,
            "pageNum": 1,
            "innerFilters": [
                {
                    "guid": cloud_account_name
                }
            ],
        }

        total_critical_severity_count = severity_counts_res["response"][0]["Critical"]
        total_high_severity_count = severity_counts_res["response"][0]["High"]
        total_medium_severity_count = severity_counts_res["response"][0]["Medium"]
        total_low_severity_count = severity_counts_res["response"][0]["Low"]

        accounts_data_res=self.backend.get_cloud_compliance_account(body=body)["response"]
        assert len(accounts_data_res) == 1

        assert accounts_data_res[0]["accountName"] == cloud_account_name
        assert accounts_data_res[0]["reportGUID"] == last_success_scan_id

        assert accounts_data_res[0]["criticalSeverityResources"] == total_critical_severity_count
        assert accounts_data_res[0]["highSeverityResources"] == total_high_severity_count
        assert accounts_data_res[0]["mediumSeverityResources"] == total_medium_severity_count
        assert accounts_data_res[0]["lowSeverityResources"] == total_low_severity_count


    def validate_scan_data(self,cloud_account_name:str ,last_success_scan_id:str):
        self.validate_compliance_accounts_api(cloud_account_name =cloud_account_name,last_success_scan_id=last_success_scan_id)
        Logger.logger.info("compliance account API data is valid")


def extract_parameters_from_url(url):
    parsed_url = urlparse(url)

    # Parse query parameters from the query and fragment (after #)
    query_params = parse_qs(parsed_url.query)
    fragment_params = parse_qs(parsed_url.fragment.split("?")[-1])

    # Merge query and fragment parameters
    query_params.update(fragment_params)

    stack_name = query_params.get("stackName", [None])[0]
    template_url = query_params.get("templateUrl", [None])[0]
    region = query_params.get("region", [None])[0]

    # Extract parameters starting with 'param_'
    parameters = [
        {"ParameterKey": key.replace("param_", ""), "ParameterValue": value[0]}
        for key, value in query_params.items()
        if key.startswith("param_")
    ]

    if not stack_name or not template_url or not region:
        raise ValueError("The URL does not contain the required parameters 'stackName', 'templateUrl', or 'region'.")

    return stack_name, template_url, region, parameters
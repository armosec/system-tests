import os
import datetime
from dateutil import parser
from typing import List, Tuple

from infrastructure import aws
from systest_utils import Logger, statics
from urllib.parse import parse_qs, quote, urlparse
from tests_scripts import base_test
from tests_scripts.helm.jira_integration import setup_jira_config, DEFAULT_JIRA_SITE_NAME
from .cspm_test_models import (
    SeverityCount,
    ComplianceAccountResponse,
    ComplianceFramework,
    ComplianceFrameworkOverTime,
    ComplianceControl,
    ComplianceRuleSummary,
    ComplianceResourceToCheck,
    ComplianceResourceSummaries,
    ComplianceControlWithChecks,
    FRAMEWORKS_CONFIG,
    DEFAULT_TEST_CONFIG,
    get_expected_control_response,
    get_expected_rules_response,
    get_expected_resources_under_check_response,
    get_expected_resource_summaries_response,
    get_expected_only_check_under_control_response
)



SCAN_TIME_WINDOW = 2000

PROVIDER_AWS = "aws"
PROVIDER_AZURE = "azure"
PROVIDER_GCP = "gcp"

CADR_FEATURE_NAME = "cadr"
CSPM_FEATURE_NAME = "cspm"

FEATURE_STATUS_CONNECTED = "Connected"
FEATURE_STATUS_DISCONNECTED = "Disconnected"
FEATURE_STATUS_PENDING = "Pending"
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

    def setup_jira_config(self, site_name=DEFAULT_JIRA_SITE_NAME):
        """Setup Jira configuration using the standalone function."""
        self.site, self.project, self.issueType, self.jiraCollaborationGUID = setup_jira_config(self.backend, site_name)

    def get_cloud_account(self, cloud_account_guid):
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
        return res["response"][0]

    def create_stack_cspm(self, stack_name, template_url, parameters)->str:
        self.create_stack(stack_name, template_url, parameters)
        test_arn =  self.stack_manager.get_stack_output_role_arn(stack_name)
        return test_arn

    def connect_cspm_new_account(self, region, account_id, arn, cloud_account_name,external_id, validate_apis=True, is_to_cleanup_accounts=True)->str:
        if is_to_cleanup_accounts:   
            self.cleanup_existing_aws_cloud_accounts(account_id)
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm(cloud_account_name, arn, PROVIDER_AWS, region=region, external_id=external_id, expect_failure=False)
        Logger.logger.info('Validate accounts cloud with cspm list')
        account = self.validate_accounts_cloud_list_cspm(cloud_account_guid, arn ,CSPM_SCAN_STATE_IN_PROGRESS , FEATURE_STATUS_CONNECTED)
        self.test_cloud_accounts_guids.append(cloud_account_guid)

        if validate_apis:
            Logger.logger.info('Validate accounts cloud with cspm uniquevalues')
            self.validate_accounts_cloud_uniquevalues(cloud_account_name)

            Logger.logger.info('Edit name and validate cloud account with cspm')
            self.update_and_validate_cloud_account(cloud_account_guid, cloud_account_name + " updated", arn)
            return cloud_account_guid

    def connect_cspm_bad_arn(self, region, arn, cloud_account_name)->str:
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm(cloud_account_name, arn, PROVIDER_AWS, region=region,external_id="", expect_failure=True)
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
        
        Logger.logger.info('Validate feature status Pending')
        account = self.get_cloud_account(cloud_account_guid)
        assert account["features"][CADR_FEATURE_NAME]["featureStatus"] == FEATURE_STATUS_PENDING, f"featureStatus is not {FEATURE_STATUS_PENDING} but {account['features'][CADR_FEATURE_NAME]['featureStatus']}"
        
        self.create_stack_cadr(region, stack_name, cloud_account_guid)
        self.test_cloud_accounts_guids.append(cloud_account_guid)

        return cloud_account_guid


    def create_stack_cadr(self, region, stack_name, cloud_account_guid)->str:
        Logger.logger.info('Get and validate cadr link')
        stack_link = self.get_and_validate_cadr_link(region, cloud_account_guid)

        _, template_url, region, parameters = extract_parameters_from_url(stack_link)

        Logger.logger.info(f"Creating stack with name: {stack_name}, template_url: {template_url}, parameters: {parameters}")
        _ =  self.create_stack(stack_name, template_url, parameters)
    
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

        if expected_status == FEATURE_STATUS_CONNECTED:
            expected_feature_connected = True

        res = self.backend.get_cloud_accounts(body=body)
        assert "response" in res, f"failed to get cloud accounts, body used: {body}, res is {res}"
        assert len(res["response"]) > 0, f"response is empty"
        assert res["response"][0]["features"][CADR_FEATURE_NAME]["featureStatus"] == expected_status, f"featureStatus is not {expected_status} but {res['response'][0]['features'][CADR_FEATURE_NAME]['featureStatus']}"
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
    
    def get_and_validate_cspm_link_with_external_id(self, region) -> Tuple[str, str]:
        """
        Get and validate cspm link.
        Returns tuple of (stack_link, external_id) strings.
        """
        tenant = self.backend.get_selected_tenant()
        expected_template_url = os.environ.get("CSPM_TEMPLATE_URL_EXTERNAL_ID")
        parsed_cspm_template = quote(expected_template_url, safe='')
        response = self.backend.get_cspm_link(region=region, external_id=True)

        # Since we're requesting with external_id=True, we expect the external ID to be included
        external_id = response["externalID"]
        assert external_id != "", f"failed to get cspm external id, external id is {external_id}"

        # Build expected link including the external ID parameter
        expected_link = f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/quickcreate?param_AccountID={tenant}&param_ExternalID={external_id}&stackName=armo-security-readonly&templateUrl={parsed_cspm_template}"

        assert response["stackLink"] == expected_link, f"failed to get cspm link, link is {response['stackLink']}, expected link is {expected_link}"

        return response["stackLink"], response["externalID"]

    def get_and_validate_cadr_link(self, region, cloud_account_guid) -> str:
        """
        Get and validate cspm link.
        """

        stack_link = self.backend.get_cadr_link(region=region, cloud_account_guid=cloud_account_guid)
        return stack_link
    
    def create_and_validate_cloud_account_with_cspm(self, cloud_account_name:str, arn:str, provider:str, region:str, external_id:str ="", expect_failure:bool=False):
        """
        Create and validate cloud account.
        """

        if external_id:
            body = {
                    "name": cloud_account_name,
                    "cspmConfig": {
                        "crossAccountsRoleARN": arn,
                        "stackRegion": region,
                        "externalID" :external_id  
                    },
                }
        else:
            body = {
                    "name": cloud_account_name,
                    "cspmConfig": {
                        "crossAccountsRoleARN": arn,
                        "stackRegion": region,
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

    def validate_accounts_cloud_list_cspm(self, cloud_account_guid:str, arn:str ,scan_status: str ,feature_status :str):
        """
        Validate accounts cloud list.
        """
        body = {
                "pageSize": 100,
                "pageNum": 0,
                "innerFilters": [
                    {
                        "guid": cloud_account_guid
                    }
                ],
            }
        acount_list = self.backend.get_cloud_accounts(body=body)
        assert "response" in acount_list, f"response not in {acount_list}"
        assert len(acount_list["response"]) > 0, f"response is empty"
        account = acount_list["response"][0]
        assert "features" in account, f"features not in {account}"
        assert CSPM_FEATURE_NAME in account["features"], f"cspm not in {account['features']}"
        assert account["features"][CSPM_FEATURE_NAME]["scanState"] == scan_status, f"scanState is not {scan_status}"
        assert account["features"][CSPM_FEATURE_NAME]["featureStatus"] == feature_status, f"featureStatus is not {feature_status}"
        assert "config" in account["features"][CSPM_FEATURE_NAME], f"config not in {account['features']['cspm']}"
        assert "crossAccountsRoleARN" in account["features"][CSPM_FEATURE_NAME]["config"], f"crossAccountsRoleARN not in {account['features']['cspm']['config']}"
        assert account["features"][CSPM_FEATURE_NAME]["config"]["crossAccountsRoleARN"] == arn, f"crossAccountsRoleARN is not {arn}"
        assert account["features"][CSPM_FEATURE_NAME]["nextScanTime"] != "", f"nextScanTime is empty"
        if scan_status==CSPM_SCAN_STATE_COMPLETED:
            assert account["features"][CSPM_FEATURE_NAME]["lastTimeScanSuccess"] != "", f"lastTimeScanSuccess is empty"
            assert account["features"][CSPM_FEATURE_NAME]["lastSuccessScanID"] != "", f"lastSuccessScanID is empty"
        elif scan_status==CSPM_SCAN_STATE_FAILED:
            assert account["features"][CSPM_FEATURE_NAME]["lastTimeScanFailed"] != "", f"lastTimeScanFailed is empty"
        return account


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

    def validate_scan_data(self, cloud_account_guid: str, cloud_account_name: str, last_success_scan_id: str, with_accepted_resources: bool = False, with_jira: bool = False):
        """
        Validate CSPM scan data across all relevant APIs.

        Args:
            cloud_account_guid (str): The GUID of the cloud account
            cloud_account_name (str): The name of the cloud account
            last_success_scan_id (str): The ID of the last successful scan
            with_accepted_resources (bool): Whether to validate with accepted resources
            with_jira (bool): Whether to validate with Jira tickets
        """
        Logger.logger.info(f"Validating account {cloud_account_guid}|{cloud_account_name} and its last scan ID {last_success_scan_id}")

        # self.validate_compliance_accounts(cloud_account_name, last_success_scan_id)
        self.validate_compliance_frameworks(cloud_account_guid, last_success_scan_id)
        control_hash = self.validate_compliance_controls(last_success_scan_id, with_accepted_resources, with_jira)
        rule_hash = self.validate_compliance_rules(last_success_scan_id, control_hash, with_accepted_resources, with_jira)
        resource_hash ,resource_name = self.validate_compliance_resources_under_rule(last_success_scan_id,rule_hash,with_accepted_resources,with_jira)
        self.validate_resource_summaries_response(last_success_scan_id,resource_name,with_accepted_resources,with_jira)
        self.validate_control_and_checks_under_resource(last_success_scan_id,resource_hash,with_accepted_resources,with_jira)

        Logger.logger.info("Compliance account API data validation completed successfully")

    def validate_compliance_accounts(self, cloud_account_name: str, last_success_scan_id: str):
        """Validate compliance accounts data."""
        # Get and validate severity counts
        severity_counts_res = self.backend.get_cloud_severity_count()
        severity_counts = SeverityCount(**severity_counts_res["response"])

        # Get and validate account data
        body = {
            "pageSize": 1,
            "pageNum": 1,
            "innerFilters": [{"accountName": cloud_account_name}],
        }

        accounts_data_res = self.backend.get_cloud_compliance_account(body=body)
        account_data = ComplianceAccountResponse(**accounts_data_res["response"][0])

        # Validate severity counts match
        assert account_data.criticalSeverityResources == severity_counts.Critical
        assert account_data.highSeverityResources == severity_counts.High
        assert account_data.mediumSeverityResources == severity_counts.Medium
        assert account_data.lowSeverityResources == severity_counts.Low
        assert account_data.reportGUID == last_success_scan_id

    def validate_compliance_frameworks(self, cloud_account_guid: str, last_success_scan_id: str):
        """Validate compliance frameworks data."""
        # Validate frameworks API
        body = {
            "innerFilters": [{"cloudAccountGUID": cloud_account_guid}],
        }

        frameworks_res = self.backend.get_cloud_compliance_framework(body=body)
        frameworks = [ComplianceFramework(**f) for f in frameworks_res["response"]]

        self._validate_frameworks(frameworks, last_success_scan_id)

        # Validate frameworks over time
        body = {
            "pageSize": 10000,
            "pageNum": 1,
            "innerFilters": [{"cloudAccountGUID": cloud_account_guid}],
        }

        framework_over_time_resp = self.backend.get_cloud_compliance_framework_over_time(body=body)
        framework_over_time = ComplianceFrameworkOverTime(**framework_over_time_resp["response"][0])

        self._validate_framework_over_time(framework_over_time, cloud_account_guid, last_success_scan_id)

    def _validate_frameworks(self, frameworks: List[ComplianceFramework], last_success_scan_id: str):
        """Validate framework data against expected values."""
        Logger.logger.info(f"frameworks: {frameworks}")
        assert len(frameworks) == len(FRAMEWORKS_CONFIG), f"Expected {len(FRAMEWORKS_CONFIG)} frameworks, got {len(frameworks)}"

        now = datetime.datetime.now(datetime.timezone.utc)
        scan_time_window = now - datetime.timedelta(minutes=SCAN_TIME_WINDOW)

        framework_names = set()
        for framework in frameworks:
            framework_names.add(framework.name)
            assert framework.name in FRAMEWORKS_CONFIG, f"Unexpected framework name: {framework.name}"
            assert framework.reportGUID == last_success_scan_id
            assert framework.failedControls > 0
            assert framework.complianceScorev1 > 0

            timestamp = parser.parse(str(framework.timestamp))
            assert scan_time_window <= timestamp <= now, f"Timestamp {framework.timestamp} is not within the last {SCAN_TIME_WINDOW} minutes"

        missing_frameworks = set(FRAMEWORKS_CONFIG.keys()) - framework_names
        assert not missing_frameworks, f"Missing frameworks: {missing_frameworks}"

    def _validate_framework_over_time(self, framework_over_time: ComplianceFrameworkOverTime,
                                    cloud_account_guid: str, last_success_scan_id: str):
        """Validate framework over time data."""
        assert framework_over_time.cloudAccountGUID == cloud_account_guid
        assert framework_over_time.provider == "aws"

        framework_names = set()
        for framework in framework_over_time.frameworks:
            framework_names.add(framework.frameworkName)
            assert framework.frameworkName in FRAMEWORKS_CONFIG
            assert framework.complianceScore > 0
            # assert len(framework.cords) == 1

            cord = framework.cords[0]
            assert cord.reportGUID == last_success_scan_id
            assert cord.complianceScore > 0

            timestamp = parser.parse(str(cord.timestamp))
            now = datetime.datetime.now(datetime.timezone.utc)
            scan_time_window = now - datetime.timedelta(minutes=SCAN_TIME_WINDOW)
            assert scan_time_window <= timestamp <= now

        missing_frameworks = set(FRAMEWORKS_CONFIG.keys()) - framework_names
        assert not missing_frameworks, f"Missing frameworks: {missing_frameworks}"


    def validate_compliance_controls(self, last_success_scan_id: str, with_accepted_resources: bool, with_jira: bool = False) -> str:
        """Validate compliance controls data and return control hash."""
        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [
                {
                    "reportGUID": last_success_scan_id,
                    "frameworkName": DEFAULT_TEST_CONFIG["framework"],
                    "cloudControlName": DEFAULT_TEST_CONFIG["control_name"],
                    "status": DEFAULT_TEST_CONFIG["status"]
                }
            ],
        }

        if with_accepted_resources:
            body["innerFilters"][0]["status"] = "ACCEPT"

        if with_jira:
            body["innerFilters"][0]["tickets"] = "|exists"

        control_resp = self.backend.get_cloud_compliance_controls(body=body, with_rules=False)
        control = ComplianceControl(**control_resp["response"][0])

        assert control.reportGUID == last_success_scan_id , f"Expected reportGUID: {last_success_scan_id}, got: {control.reportGUID}"
        expected_response = get_expected_control_response(with_accepted_resources)
        for key, value in expected_response.items():
            if value != "":  # Skip empty string values as they're placeholders
                assert getattr(control, key) == value, f"Expected {key}: {value}, got: {getattr(control, key)}"
            elif key == "section":
                assert getattr(control, key) != "", f"Expected non-empty section, got empty string"

        if with_jira:
            assert control.tickets is not None and len(control.tickets) > 0, "Expected tickets to be present"

        return control.cloudControlHash

    def validate_compliance_rules(self, last_success_scan_id: str, control_hash: str,
                                 with_accepted_resources: bool = False, with_jira: bool = False) ->str:
        """Validate compliance checks data."""
        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [
                {
                    "reportGUID": last_success_scan_id,
                    "controlHash": control_hash,
                    "frameworkName": DEFAULT_TEST_CONFIG["framework"]
                }
            ],
        }


        check_resp = self.backend.get_cloud_compliance_rules(body=body)
        rule = ComplianceRuleSummary(**check_resp["response"][0])

        expected_response = get_expected_rules_response(with_accepted_resources)
        for key, value in expected_response.items():
            assert getattr(rule, key) == value, f"Expected {key}: {value}, got: {getattr(rule, key)}"

        assert len(rule.affectedControls) > 0

        if with_jira:
            assert rule.tickets is not None and len(rule.tickets) > 0, "Expected tickets to be present"

        return rule.cloudCheckHash
    def validate_compliance_resources_under_rule(self, last_success_scan_id: str, rule_hash: str,
                                              with_accepted_resources: bool, with_jira: bool) -> Tuple[str, str]:
        """Validate compliance resources under rule and return resource hash and name."""
        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [
                {
                    "reportGUID": last_success_scan_id,
                    "frameworkName": DEFAULT_TEST_CONFIG["framework"],
                    "exceptionApplied": "|empty"
                }
            ],
        }
        if with_accepted_resources:
            body["innerFilters"][0]["exceptionApplied"] = "true,|empty"

        resources_resp = self.backend.get_cloud_compliance_resources(rule_hash=rule_hash, body=body)
        resources = [ComplianceResourceToCheck(**r) for r in resources_resp["response"]]
        assert len(resources) == 1, f"Expected 1 resource, got: {len(resources)}"

        resource = resources[0]
        expected_response = get_expected_resources_under_check_response(with_accepted_resources)
        for key, value in expected_response.items():
            if value != "":  # Skip empty string values as they're placeholders
                assert getattr(resource, key) == value, f"Expected {key}: {value}, got: {getattr(resource, key)}"

        if with_jira:
            assert resource.tickets is not None and len(resource.tickets) > 0, "Expected tickets to be present"

        return resource.cloudResourceHash, resource.cloudResourceName

    def validate_resource_summaries_response(self,last_success_scan_id:str,resource_name:str,with_accepted_resources:bool,with_jira:bool):
        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [
                {
                    "frameworkName": DEFAULT_TEST_CONFIG["framework"],
                    "cloudResourceName": resource_name,
                    "reportGUID": last_success_scan_id
                }
            ]
        }

        if with_jira:
            body["innerFilters"][0]["tickets"] = "|exists"

        resources_resp = self.backend.get_cloud_compliance_resources(rule_hash=None,body=body)
        resources = [ComplianceResourceSummaries(**r) for r in resources_resp["response"]]
        assert len(resources) == 1, f"Expected resources, got: {resources}"
        resource = resources[0]
        expected_response = get_expected_resource_summaries_response(with_accepted_resources)
        for key, value in expected_response.items():
              if value != "":  # Skip empty string values as they're placeholders
                assert getattr(resource, key) == value, f"Expected {key}: {value}, got: {getattr(resource, key)}"

        if with_jira:
            assert resource.tickets is not None and len(resource.tickets) > 0, "Expected tickets to be present"

    def validate_control_and_checks_under_resource(self,last_success_scan_id:str,resource_hash:str,with_accepted_resources:bool ,with_jira:bool):
        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [
                {
                    "exceptionApplied" :"|empty",
                    "reportGUID": last_success_scan_id,
                    "frameworkName": DEFAULT_TEST_CONFIG["framework"],
                    "cloudResourceHash": resource_hash,
                    "status": DEFAULT_TEST_CONFIG["status"],
                }
            ]
        }
        if with_accepted_resources:
            body["innerFilters"][0]["exceptionApplied"] = "true,|empty"
            body["innerFilters"][0]["status"] =f"{DEFAULT_TEST_CONFIG['status']},ACCEPT"
            

        control_with_checks_resp = self.backend.get_cloud_compliance_controls(with_rules=True,body=body)
        control_with_checks = ComplianceControlWithChecks(**control_with_checks_resp["response"][0])
        assert control_with_checks.reportGUID == last_success_scan_id, f"Expected reportGUID: {last_success_scan_id}, got: {control_with_checks.ComplianceControl.reportGUID}"
        assert control_with_checks.cloudControlName == DEFAULT_TEST_CONFIG["control_name"], f"Expected control name: {DEFAULT_TEST_CONFIG['control_name']}, got: {control_with_checks.ComplianceControl.name}"
        assert len(control_with_checks.rules) == 1, f"Expected 1 rule, got: {len(control_with_checks.rules)}"

        rule = control_with_checks.rules[0]
        expected_response = get_expected_only_check_under_control_response(with_accepted_resources)
        for key, value in expected_response.items():
            if value != "":
                assert getattr(rule, key) == value, f"Expected {key}: {value}, got: {getattr(rule, key)}"

        if with_jira:
            assert control_with_checks.tickets is not None and len(control_with_checks.tickets) > 0, "Expected tickets to be present in control"
            assert rule.tickets is not None and len(rule.tickets) > 0, "Expected tickets to be present in rule"

    def create_jira_issue_for_cspm(self, last_success_scan_id: str, site_name: str = DEFAULT_JIRA_SITE_NAME):
        """Create and validate a Jira issue for CSPM resource.
        Args:
            last_success_scan_id (str): The ID of the last successful scan
            site_name (str): The Jira site name (default: cyberarmor-io)
        """
        # Setup Jira configuration if not already done
        if not hasattr(self, 'site') or not hasattr(self, 'project') or not hasattr(self, 'issueType'):
            self.setup_jira_config(site_name)

        # Get control data first to use in the ticket
        control_hash = self.validate_compliance_controls(last_success_scan_id, False, False)
        rule_hash = self.validate_compliance_rules(last_success_scan_id, control_hash, False, False)
        resource_hash, resource_name = self.validate_compliance_resources_under_rule(last_success_scan_id, rule_hash, False, False)

        # Create Jira issue
        Logger.logger.info(f"Create Jira issue for resource {resource_name} and rule {rule_hash}")
        issue = self.test_obj["issueTemplate"].copy()
        issue["collaborationGUID"] = self.jiraCollaborationGUID
        issue["issueType"] = "cloudRule"
        issue["siteId"] = self.site["id"]
        issue["projectId"] = self.project["id"]
        issue["issueTypeId"] = self.issueType["id"]
        issue["owner"] = {
            "resourceHash": resource_hash
        }
        issue["subjects"] = [{
            "ruleHash": rule_hash
        }]
        issue["fields"]["summary"] = f"{resource_name} ({DEFAULT_TEST_CONFIG['resource_type']}) - {DEFAULT_TEST_CONFIG['rule_name']}"
        issue["fields"]["description"] = f"""CSPM System Test Issue
            Resource Name: {resource_name}
            Resource Hash: {resource_hash}
            Framework: {DEFAULT_TEST_CONFIG['framework']}
            Control: {DEFAULT_TEST_CONFIG['control_name']}
            Status: {DEFAULT_TEST_CONFIG['status']}
            Severity: {DEFAULT_TEST_CONFIG['severity']}
            """

        ticket = self.backend.create_jira_issue(issue)
        assert ticket['owner']['resourceHash'] == resource_hash, "Resource hash mismatch"
        assert ticket['subjects'][0]['ruleHash'] == rule_hash, "Rule hash mismatch"

        # Validate ticket presence using existing validation functions with with_jira=True
        Logger.logger.info("Validating ticket presence in all APIs")
        self.validate_compliance_controls(last_success_scan_id, False, True)
        self.validate_compliance_rules(last_success_scan_id, control_hash, False, True)
        self.validate_compliance_resources_under_rule(last_success_scan_id, rule_hash, False, True)
        self.validate_resource_summaries_response(last_success_scan_id, resource_name, False, True)
        self.validate_control_and_checks_under_resource(last_success_scan_id, resource_hash, False, True)

        Logger.logger.info(f"Unlink Jira issue")
        self.backend.unlink_issue(ticket['guid'])

        return ticket
    
    def accept_cspm_risk(self, cloud_account_guid: str, cloud_account_name: str, last_success_scan_id: str):
        """
        Accept CSPM risk with different scopes and validate after each change.
        
        Flow:
        1. Accept risk for specific resource and rule
        2. Validate scan data with accepted=True
        3. Update to all resources in account
        4. Validate scan data
        5. Update to all accounts and resources
        6. Validate scan data
        7. Delete exception
        8. Validate scan data with accepted=False
        """
        # Get initial control and rule data
        control_hash = self.validate_compliance_controls(last_success_scan_id, False)
        rule_hash = self.validate_compliance_rules(last_success_scan_id, control_hash, False)
        resource_hash, _ = self.validate_compliance_resources_under_rule(last_success_scan_id, rule_hash, False, False)

        # 1. Create exception for specific resource
        Logger.logger.info("Creating exception for specific resource")
        response = self.backend.create_cspm_exception(
            rule_hashes=[rule_hash],
            accounts=[cloud_account_guid],
            resource_hashes=[resource_hash]
        )
        exception_guid = response.json()["guid"]

        # Wait and validate scan data with accepted=True
        Logger.logger.info("Validating scan data after specific resource exception")
        self.wait_for_report(
            self.validate_scan_data,
            timeout=60,
            sleep_interval=5,
            cloud_account_guid=cloud_account_guid,
            cloud_account_name=cloud_account_name,
            last_success_scan_id=last_success_scan_id,
            with_accepted_resources=True
        )

        # 2. Update to all resources in account
        Logger.logger.info("Updating exception to all resources in account")
        self.backend.update_cspm_exception_resources(
            exception_guid=exception_guid,
            rule_hash=rule_hash,
            accounts=[cloud_account_guid]  # No resource_hashes means all resources
        )

        # Wait and validate scan data
        Logger.logger.info("Validating scan data after all resources exception")
        self.wait_for_report(
            self.validate_scan_data,
            timeout=60,
            sleep_interval=5,
            cloud_account_guid=cloud_account_guid,
            cloud_account_name=cloud_account_name,
            last_success_scan_id=last_success_scan_id,
            with_accepted_resources=True
        )

        # 3. Delete exception
        Logger.logger.info("Deleting exception")
        self.backend.delete_cspm_exception(exception_guid)

        # Wait and validate scan data with accepted=False
        Logger.logger.info("Validating scan data after exception deletion")
        self.wait_for_report(
            self.validate_scan_data,
            timeout=60,
            sleep_interval=5,
            cloud_account_guid=cloud_account_guid,
            cloud_account_name=cloud_account_name,
            last_success_scan_id=last_success_scan_id,
            with_accepted_resources=False
        )

    def disconnect_cspm_account_without_deleting_cloud_account(self, stack_name: str ,cloud_account_guid: str , test_arn: str):
        self.stack_manager.delete_stack(stack_name)
        Logger.logger.info("Disconnecting CSPM account without deleting cloud account")
        self.backend.cspm_scan_now(cloud_account_guid)
        Logger.logger.info("Waiting for scan to complete with failed status")
        self.wait_for_report(self.validate_accounts_cloud_list_cspm,
                             timeout=120,
                             sleep_interval=10,
                             cloud_account_guid=cloud_account_guid,
                             arn=test_arn,
                             scan_status=CSPM_SCAN_STATE_FAILED,
                             feature_status = FEATURE_STATUS_DISCONNECTED)
        Logger.logger.info("Scan failed, disconnecting account")

        body = {
            "pageSize": 150,
            "pageNum": 1,
            "innerFilters": [
                {
                    "guid": cloud_account_guid
                }
            ]
        }
        res = self.backend.get_cloud_accounts(body=body)
        assert len(res["response"]) == 1, f"Expected 1 cloud account, got: {len(res['response'])}"
        account= res["response"][0]
        assert account["features"][CSPM_FEATURE_NAME]["lastTimeScanFailed"] is not None, f"Expected lastTimeScanFail to be set, got: {account['features'][CSPM_FEATURE_NAME]['lastTimeScanFail']}"
        assert account["features"][CSPM_FEATURE_NAME]["scanFailureReason"] is not None, f"Expected scanFailureReason to be set, got: {account['features'][CSPM_FEATURE_NAME]['scanFailureReason']}"
        assert account["features"][CSPM_FEATURE_NAME]["scanState"] is not None, f"Expected scanState to be set, got: {account['features'][CSPM_FEATURE_NAME]['scanState']}"

        Logger.logger.info("the account has been successfully disconnected")

    def validate_features_unchanged(self, cloud_account_guid: str, feature_name: str, expected_feature: dict):
        """
        Validate that a feature's structure remains unchanged when adding a new feature.
        
        Args:
            cloud_account_guid (str): The GUID of the cloud account
            feature_name (str): The name of the feature to validate (CSPM_FEATURE_NAME or CADR_FEATURE_NAME)
            expected_feature (dict): The expected feature structure
        """
        body = {
            "pageSize": 1,
            "pageNum": 1,
            "innerFilters": [
                {
                    "guid": cloud_account_guid
                }
            ]
        }

        res = self.backend.get_cloud_accounts(body=body)
        assert "response" in res, f"failed to get cloud accounts, body used: {body}, res is {res}"
        assert len(res["response"]) > 0, f"response is empty"
        account = res["response"][0]
        
        # Validate feature exists and has correct structure
        assert feature_name in account["features"], f"{feature_name} not in {account['features']}"
        feature = account["features"][feature_name]
        assert "config" in feature, f"config not in {feature}"  # This is the new field
        
        # Compare each config field
        for key, value in expected_feature.items():
            assert key in feature, f"{key} not in {feature}"
            assert feature[key] == value, f"Expected {key}: {value}, got: {feature[key]}"

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
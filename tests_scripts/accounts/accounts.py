import datetime
import json
from dateutil import parser
from enum import Enum
from typing import List, Tuple, Any, Dict

from infrastructure import aws
from systest_utils import Logger
from .accounts_aws import AwsAccountsMixin
from .accounts_azure import AzureAccountsMixin
from .accounts_gcp import GcpAccountsMixin
from urllib.parse import parse_qs, urlparse
from tests_scripts import base_test
from tests_scripts.helm.jira_integration import setup_jira_config, DEFAULT_JIRA_SITE_NAME
from tests_scripts.runtime.policies import POLICY_CREATED_RESPONSE
from .cspm_test_models import (
    PROVIDER_AWS,
    PROVIDER_AZURE,
    PROVIDER_GCP,
    FRAMEWORKS_CONFIG_PROVIDER_MAP,
    TEST_CONFIG_PROVIDER_MAP,
    SeverityCount,
    ComplianceAccountResponse,
    ComplianceFramework,
    ComplianceFrameworkOverTime,
    ComplianceControl,
    ComplianceRuleSummary,
    ComplianceResourceToCheck,
    ComplianceResourceSummaries,
    ComplianceControlWithChecks,
    get_expected_control_response,
    get_expected_rules_response,
    get_expected_resources_under_check_response,
    get_expected_resource_summaries_response,
    get_expected_only_check_under_control_response,
    UpdateCloudOrganizationMetadataRequest,
)


SCAN_TIME_WINDOW = 2000

CADR_FEATURE_NAME = "cadr"
COMPLIANCE_FEATURE_NAME = "cspm"
VULN_SCAN_FEATURE_NAME = "vulnScan"

PROVIDER_IDENTIFIER_FIELD_MAP = {
    PROVIDER_AWS: "accountID",
    PROVIDER_AZURE: "subscriptionID",
    PROVIDER_GCP: "projectID",
}

FEATURE_STATUS_CONNECTED = "Connected"
FEATURE_STATUS_DISCONNECTED = "Disconnected"
FEATURE_STATUS_PENDING = "Pending"
FEATURE_STATUS_PARTIALLY_CONNECTED = "Partially connected"

CSPM_STATUS_HEALTHY = "healthy"
CSPM_STATUS_DEGRADED = "degraded"
CSPM_STATUS_DISCONNECTED = "disconnected"

CSPM_SCAN_STATE_IN_PROGRESS = "In Progress"
CSPM_SCAN_STATE_COMPLETED = "Completed"
CSPM_SCAN_STATE_FAILED = "Failed"

class CloudEntityTypes(Enum):
    ACCOUNT = "account"
    ORGANIZATION = "organization"

class ExclusionActions(Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"
    OVERRIDE = "override"

CDR_ALERT_USER_IDENTITY_PATH = "cdrevent.eventdata.awscloudtrail.useridentity"
CDR_ALERT_ACCOUNT_ID_PATH = CDR_ALERT_USER_IDENTITY_PATH + ".accountid"
CDR_ALERT_ORG_ID_PATH = CDR_ALERT_USER_IDENTITY_PATH + ".orgid"

from dataclasses import dataclass

@dataclass
class StackRef:
    manager: aws.AwsManager
    stack_name: str
    region: str

@dataclass
class StackSetRef:
    aws_manager: aws.AwsManager
    stackset_name: str
    operation_id: str = None

class Accounts(base_test.BaseTest, AwsAccountsMixin, AzureAccountsMixin, GcpAccountsMixin):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)
        self.test_cloud_accounts_guids = []
        self.test_cloud_orgs_guids = []
        self.test_runtime_policies = []
        self.test_global_aws_users = []
        self.tested_stack_refs: List[StackRef] = []
        self.tested_stackset_refs: List[StackSetRef] = []

    def generate_timestamped_role_name(self, role_prefix: str) -> str:
        """
        Generate a timestamped role name with milliseconds precision.
        
        Args:
            prefix: The prefix for the role name
            
        Returns:
            A string in format: {prefix}-{YYYYMMDDHHMMSS}{mmm}
            where {mmm} is 3-digit milliseconds
        """
        now = datetime.datetime.now()
        timestamp = now.strftime("%Y%m%d%H%M%S")
        milliseconds = str(now.microsecond // 1000).zfill(3)
        return f"{role_prefix}-{timestamp}{milliseconds}"

    def cleanup(self, **kwargs):
        # Delete all tracked stacks with error handling
        if self.tested_stack_refs:
            for ref in self.tested_stack_refs:
                try:
                    Logger.logger.info(f"Deleting stack: {ref.stack_name} (region={ref.region})")
                    ref.manager.delete_stack(ref.stack_name)
                    Logger.logger.info(f"Successfully deleted stack: {ref.stack_name}")
                except Exception as e:
                    Logger.logger.error(f"Failed to delete stack {ref.stack_name} in region {ref.region}: {e}")
            
            # Delete log groups for all stacks
            for ref in self.tested_stack_refs:
                try:
                    Logger.logger.info(f"Deleting log groups for stack: {ref.stack_name} (region={ref.region})")
                    ref.manager.delete_stack_log_groups(ref.stack_name)
                    Logger.logger.info(f"Successfully deleted log groups for stack: {ref.stack_name}")
                except Exception as e:
                    Logger.logger.error(f"Failed to delete log groups for stack {ref.stack_name} in region {ref.region}: {e}")
        
        # Delete all tracked StackSets with error handling
        if self.tested_stackset_refs:
            Logger.logger.info(f"Cleaning up {len(self.tested_stackset_refs)} StackSets")
            self._cleanup_stacksets(self.tested_stackset_refs)
        
        # Delete all tracked cloud accounts with error handling
        for guid in self.test_cloud_accounts_guids:
            try:
                Logger.logger.info(f"Deleting cloud account with guid {guid}")
                self.backend.delete_cloud_account(guid=guid)
                Logger.logger.info(f"Successfully deleted cloud account with guid {guid}")
            except Exception as e:
                Logger.logger.error(f"Failed to delete cloud account with guid {guid}: {e}")
        
        # Delete all tracked cloud organizations with error handling
        for guid in self.test_cloud_orgs_guids:
            try:
                Logger.logger.info(f"Deleting cloud organization with guid {guid}")
                self.backend.delete_cloud_organization(guid=guid)
                Logger.logger.info(f"Successfully deleted cloud organization with guid {guid}")
            except Exception as e:
                Logger.logger.error(f"Failed to delete cloud organization with guid {guid}: {e}")
        
        # Azure-specific cleanup (restore Reader role if it was removed)
        # Method checks internally if credentials exist, so safe to call for all tests
        self.cleanup_azure_reader_role()
        
        return super().cleanup(**kwargs)
    
    def build_get_cloud_entity_by_guid_request(self, guid: str) -> Dict:
        body = {
                "pageSize": 1,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "guid": guid
                    }
                ],
            }
            
        return body

    def setup_jira_config(self, site_name=DEFAULT_JIRA_SITE_NAME):
        """Setup Jira configuration using the standalone function."""
        self.site, self.project, self.issueType, self.jiraCollaborationGUID = setup_jira_config(self.backend, site_name)

    def get_cloud_account_by_guid(self, cloud_account_guid):
        body = self.build_get_cloud_entity_by_guid_request(cloud_account_guid)
        res = self.backend.get_cloud_accounts(body=body)
        assert "response" in res, f"failed to get cloud accounts, body used: {body}, res is {res}"
        assert len(res["response"]) > 0, f"response is empty"
        return res["response"][0]
    
    def get_cloud_org_by_guid(self, cloud_org_guid: str):
        body = self.build_get_cloud_entity_by_guid_request(cloud_org_guid)
        res = self.backend.get_cloud_orgs(body=body)
        assert "response" in res, f"failed to get cloud orgs, body used: {body}, res is {res}"
        assert len(res["response"]) > 0, f"response is empty"
        return res["response"][0]

    def cleanup_existing_cloud_accounts(self, provider: str, identifier: str):
        """
        Cleanup existing cloud accounts by provider and identifier.
        
        Args:
            provider: Cloud provider (PROVIDER_AWS, PROVIDER_AZURE, etc.)
            identifier: The account identifier (account_id for AWS, subscription_id for Azure)
        """
        identifier_field = PROVIDER_IDENTIFIER_FIELD_MAP.get(provider)
        if not identifier_field:
            Logger.logger.error(f"Unknown provider {provider}, supported providers: {list(PROVIDER_IDENTIFIER_FIELD_MAP.keys())}")
            raise Exception(f"Unknown provider {provider}")
        
        Logger.logger.info(f"Cleaning up existing {provider} cloud accounts for {identifier_field}: {identifier}")      
        if not identifier:
            Logger.logger.error(f"{identifier_field} is required for cleanup_existing_cloud_accounts")
            raise Exception(f"{identifier_field} is required")
        
        body = {
            "pageSize": 100,
            "pageNum": 0,
            "innerFilters": [
                {
                    "provider": provider,
                    f"providerInfo.{identifier_field}": identifier
                }
            ]
        }
        res = self.backend.get_cloud_accounts(body=body)

        if "response" in res:
            if len(res["response"]) == 0:
                Logger.logger.info(f"No existing {provider} cloud accounts to cleanup for {identifier_field} {identifier}")
                return
            for account in res["response"]:
                guid = account["guid"]
                self.backend.delete_cloud_account(guid)
                Logger.logger.info(f"Deleted {provider} cloud account with guid {guid} for {identifier_field} {identifier}")

        return res

    def create_and_validate_cloud_account_with_feature(self, cloud_account_name: str, provider: str, feature_config: dict, skip_scan: bool = False, expect_failure: bool = False) -> str:
        """
        Create and validate cloud account with specified feature configuration.
        
        Args:
            cloud_account_name: Name of the cloud account
            provider: Cloud provider (e.g., PROVIDER_AWS)
            feature_config: Dictionary containing feature configuration
            skip_scan: Whether to skip initial scan (for CSPM features)
            expect_failure: Whether to expect the creation to fail
            
        Returns:
            Cloud account GUID if successful, None if failed
        """
        body = {
            "name": cloud_account_name,
            **feature_config
        }
        
        if skip_scan and any(key in feature_config for key in ["cspmConfig", "vulnerabilityScanConfig"]):
            body["skipScan"] = skip_scan

        return self.create_and_validate_cloud_account(body=body, provider=provider, expect_failure=expect_failure)

    def create_and_validate_cloud_account(self, body: dict, provider: str, expect_failure: bool = False) -> str:
        failed = False
        account_guid = None
        
        try:
            res = self.backend.create_cloud_account(body=body, provider=provider)
            if "guid" in res:
                account_guid = res["guid"]
                # If we got a GUID, track it for cleanup regardless of expect_failure
                if account_guid not in self.test_cloud_accounts_guids:
                    self.test_cloud_accounts_guids.append(account_guid)
        except Exception as e:
            if not expect_failure:
                Logger.logger.error(f"failed to create cloud account, body used: {body}, error is {e}")
            failed = True
        
        assert failed == expect_failure, f"expected_failure is {expect_failure}, but failed is {failed}, body used: {body}"

        if not expect_failure:
            assert account_guid is not None, f"guid not found in response, body used: {body}"
            return account_guid
        
        return account_guid  # Returns None if failed, or GUID if it was created despite failure

    def validate_accounts_cloud_list_cspm_compliance(self, provider: str, cloud_account_guid: str, identifier: str, scan_status: str = None, feature_status: str = FEATURE_STATUS_CONNECTED, skipped_scan: bool = False):
        body = self.build_get_cloud_entity_by_guid_request(cloud_account_guid)
        account_list = self.backend.get_cloud_accounts(body=body)
        assert "response" in account_list, f"response not in {account_list}"
        assert len(account_list["response"]) > 0, "response is empty"
        account = account_list["response"][0]

        assert account["provider"] == provider, f"provider mismatch, expected {provider}, got {account['provider']}: {account}"
        assert "features" in account, f"features not in {account}"
        assert COMPLIANCE_FEATURE_NAME in account["features"], f"cspm not in {account['features']}"
        feature = account["features"][COMPLIANCE_FEATURE_NAME]
        assert feature["featureStatus"] == feature_status, f"featureStatus is not {feature_status} it is {feature['featureStatus']}"
        assert "config" in feature, f"config not in {feature}"
        config = feature["config"]

        provider_info = account["providerInfo"]
        if provider == PROVIDER_AWS:
            # AWS: identifier is role ARN
            assert "crossAccountsRoleARN" in config, f"crossAccountsRoleARN not in config {config}"
            assert config["crossAccountsRoleARN"] == identifier, f"crossAccountsRoleARN is not {identifier} it is {config['crossAccountsRoleARN']}"
            assert provider_info["accountID"], f"providerInfo.accountID missing: {provider_info}"
        elif provider == PROVIDER_AZURE:
            # Azure: identifier is subscription ID
            assert config["subscriptionID"] == identifier, f"subscriptionID mismatch: {config}"
            assert config["tenantID"], f"tenantID missing in config: {config}"
            assert config["clientID"], f"clientID missing in config: {config}"
            # TODO: clientSecret should not be returned back; ensure it is not exposed
            assert config["clientSecret"], f"clientSecret missing in config: {config}"
            assert provider_info, f"providerInfo missing in account: {account}"
            assert provider_info["subscriptionID"] == identifier, f"providerInfo subscriptionID mismatch: {provider_info}"
            assert provider_info["tenantID"], f"providerInfo tenantID missing: {provider_info}"
        elif provider == PROVIDER_GCP:
            # GCP: identifier is project ID
            assert config["projectID"] == identifier, f"projectID mismatch: {config}"
            assert config["serviceAccountKey"], f"serviceAccountKey missing in config: {config}"
            assert provider_info, f"providerInfo missing in account: {account}"
            assert provider_info["projectID"] == identifier, f"providerInfo projectID mismatch: {provider_info}"
        else:
            raise AssertionError(f"Unsupported provider for CSPM validation: {provider}")

        if not skipped_scan:
            assert scan_status is not None, "scan_status must be provided when skipped_scan is False"
            assert feature["scanState"] == scan_status, f"scanState is not {scan_status} it is {feature['scanState']}"
            assert "nextScanTime" in feature, f"nextScanTime key is missing from account features. Available keys: {list(feature.keys())}"
            assert feature["nextScanTime"] != "", "nextScanTime is empty"
            if scan_status == CSPM_SCAN_STATE_COMPLETED:
                assert feature["lastTimeScanSuccess"], "lastTimeScanSuccess is empty"
                assert feature["lastSuccessScanID"], "lastSuccessScanID is empty"
            elif scan_status == CSPM_SCAN_STATE_FAILED:
                assert feature["lastTimeScanFailed"], "lastTimeScanFailed is empty"
        Logger.logger.info(f"validated {provider} cspm list for {cloud_account_guid} successfully")
        return account

    def validate_accounts_cloud_uniquevalues(self, cloud_account_name:str):
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
        assert len(res["fields"]) > 0, f"response is empty for name {cloud_account_name}, and request {unique_values_body}, res is {res}"
        assert len(res["fields"]["name"]) == 1, f"response is empty for name {cloud_account_name}, and request {unique_values_body}, res is {res}"
        assert res["fields"]["name"][0] == cloud_account_name, f"name is not {cloud_account_name}, request: {unique_values_body}, res: {res}"

    def update_and_validate_cloud_account(self, provider: str, guid: str, cloud_account_name: str):
        Logger.logger.info(f"Updating cloud account {guid} to new name '{cloud_account_name}'")
        body = {
        "guid": guid,
        "name": cloud_account_name,
        }

        res = self.backend.update_cloud_account(body=body, provider=provider)
        assert "Cloud account updated" in res, f"Cloud account with guid {guid} was not updated"
        Logger.logger.info(f"Cloud account {guid} updated, validating update...")
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
        Logger.logger.info(f"Cloud account {guid} name successfully updated to '{cloud_account_name}'")

    def delete_and_validate_account_feature(self, guid:str, feature_name:str):
        account = self.get_cloud_account_by_guid(guid)
        assert account is not None, f"Cloud account with guid {guid} was not found"
        assert feature_name in account["features"], f"'{feature_name}' feature was not found in {account['features']}"
        
        accountNeedToBeDeleted = False
        #check if it is last feature - features is a dict
        if len(list(account["features"].keys())) == 1:
            accountNeedToBeDeleted = True

        self.backend.delete_accounts_feature(account_guid=guid, feature_name=feature_name)
        self.validate_feature_deleted_from_entity(guid, feature_name, accountNeedToBeDeleted, CloudEntityTypes.ACCOUNT)
        
    def delete_and_validate_org_feature(self, guid: str, feature_name: str):
        org = self.get_cloud_org_by_guid(guid)
        assert org is not None, f"Cloud org with guid {guid} was not found"
        assert feature_name in org["features"], f"'{feature_name}' feature was not found in {org['features']}"
        
        orgNeedToBeDeleted = False
        #check if it is last feature - features is a dict
        if len(list(org["features"].keys())) == 1:
            orgNeedToBeDeleted = True

        self.backend.delete_org_feature(org_guid=guid, feature_name=feature_name)
        self.validate_feature_deleted_from_entity(guid, feature_name, orgNeedToBeDeleted, CloudEntityTypes.ORGANIZATION)

    def cleanup_single_accounts_by_id(self, provider: str, identifier: str, features_to_cleanup: List[str]):
        """
        Generic cleanup method for single accounts by provider and identifier, deleting specified features.
        Prints the GUIDs of entities deleted.
        
        Args:
            provider: Cloud provider (PROVIDER_AWS, PROVIDER_AZURE, PROVIDER_GCP)
            identifier: The account identifier (account_id for AWS, subscription_id for Azure, project_id for GCP)
            features_to_cleanup: List of feature names to delete (e.g., [COMPLIANCE_FEATURE_NAME, CADR_FEATURE_NAME, VULN_SCAN_FEATURE_NAME])
        """
        identifier_field = PROVIDER_IDENTIFIER_FIELD_MAP.get(provider)
        if not identifier_field:
            Logger.logger.error(f"Unknown provider {provider}, supported providers: {list(PROVIDER_IDENTIFIER_FIELD_MAP.keys())}")
            raise Exception(f"Unknown provider {provider}")
        
        Logger.logger.info(f"Cleaning up {provider} single accounts for {identifier_field}: {identifier}, features: {features_to_cleanup}")
        
        body = {
            "pageSize": 100,
            "pageNum": 0,
            "innerFilters": [
                {
                    "provider": provider,
                    f"providerInfo.{identifier_field}": identifier
                }
            ]
        }
        res = self.backend.get_cloud_accounts(body=body)
        
        if "response" not in res or len(res["response"]) == 0:
            Logger.logger.info(f"No {provider} single accounts found for {identifier_field}: {identifier}")
            return
        
        deleted_guids = []
        for account in res["response"]:
            account_guid = account.get("guid")
            if not account_guid:
                continue
            
            features = account.get("features") or {}
            
            # Delete each feature that exists
            for feature_name in features_to_cleanup:
                if feature_name in features:
                    try:
                        self.delete_and_validate_account_feature(account_guid, feature_name)
                        deleted_guids.append(account_guid)
                        Logger.logger.info(f"Deleted feature '{feature_name}' from account GUID: {account_guid}")
                    except Exception as e:
                        Logger.logger.error(f"Failed to delete feature '{feature_name}' from account {account_guid}: {e}")
        
        if deleted_guids:
            Logger.logger.info(f"Cleanup completed. Deleted account GUIDs: {', '.join(set(deleted_guids))}")
        else:
            Logger.logger.info("No accounts were deleted during cleanup")

    def validate_feature_deleted_from_entity(self, guid: str, feature_name: str, NeedsToBeDeleted: bool, cloud_entity_type: CloudEntityTypes):
        body = self.build_get_cloud_entity_by_guid_request(guid)

        if cloud_entity_type == CloudEntityTypes.ACCOUNT:
            res = self.backend.get_cloud_accounts(body=body)
        else:  
            res = self.backend.get_cloud_orgs(body=body)
            
        assert "response" in res, f"response not in {res}, request: {body}"
        if NeedsToBeDeleted:
            assert len(res["response"]) == 0, f"response is not empty, request: {body}"
            if guid in self.test_cloud_accounts_guids: self.test_cloud_accounts_guids.remove(guid)
            if guid in self.test_cloud_orgs_guids: self.test_cloud_orgs_guids.remove(guid)
        else:
            assert len(res["response"]) > 0, f"response is empty, request: {body}"
            assert feature_name not in res["response"][0]["features"], f"'{feature_name}' feature was not deleted and is in {res['response']['features']}, request: {body}"


    def validate_scan_data(self, provider: str, cloud_account_guid: str, cloud_account_name: str, last_success_scan_id: str, with_accepted_resources: bool = False, with_jira: bool = False):
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
        self.validate_compliance_frameworks(provider, cloud_account_guid, last_success_scan_id)
        control_hash = self.validate_compliance_controls(provider, last_success_scan_id, with_accepted_resources, with_jira)
        rule_hash = self.validate_compliance_rules(provider, last_success_scan_id, control_hash, with_accepted_resources, with_jira)
        resource_hash ,resource_name = self.validate_compliance_resources_under_rule(provider, last_success_scan_id, rule_hash, with_accepted_resources, with_jira)
        self.validate_resource_summaries_response(provider, last_success_scan_id, resource_name, with_accepted_resources, with_jira)
        self.validate_control_and_checks_under_resource(provider, last_success_scan_id, resource_hash, with_accepted_resources, with_jira)

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

    def validate_compliance_frameworks(self, provider: str, cloud_account_guid: str, last_success_scan_id: str):
        """Validate compliance frameworks data."""
        # Validate frameworks API
        body = {
            "innerFilters": [{"cloudAccountGUID": cloud_account_guid}],
        }

        frameworks_res = self.backend.get_cloud_compliance_framework(body=body)
        frameworks = [ComplianceFramework(**f) for f in frameworks_res["response"]]

        self._validate_frameworks(provider, frameworks, last_success_scan_id)

        # Validate frameworks over time
        body = {
            "pageSize": 10000,
            "pageNum": 1,
            "innerFilters": [{"cloudAccountGUID": cloud_account_guid}],
        }

        framework_over_time_resp = self.backend.get_cloud_compliance_framework_over_time(body=body)
        assert len(framework_over_time_resp["response"]) > 0, f"framework_over_time response is empty. This may indicate the backend hasn't fully processed the scan data yet. Response: {framework_over_time_resp}"
        framework_over_time = ComplianceFrameworkOverTime(**framework_over_time_resp["response"][0])

        self._validate_framework_over_time(provider, framework_over_time, cloud_account_guid, last_success_scan_id)

    def _validate_frameworks(self, provider: str, frameworks: List[ComplianceFramework], last_success_scan_id: str):
        """Validate framework data against expected values."""
        Logger.logger.info(f"frameworks: {frameworks}")
        assert len(frameworks) == len(FRAMEWORKS_CONFIG_PROVIDER_MAP[provider]), f"Expected {len(FRAMEWORKS_CONFIG_PROVIDER_MAP[provider])} frameworks, got {len(frameworks)}"

        now = datetime.datetime.now(datetime.timezone.utc)
        scan_time_window = now - datetime.timedelta(minutes=SCAN_TIME_WINDOW)

        framework_names = set()
        for framework in frameworks:
            framework_names.add(framework.name)
            assert framework.name in FRAMEWORKS_CONFIG_PROVIDER_MAP[provider], f"Unexpected framework name: {framework.name}"
            assert framework.reportGUID == last_success_scan_id
            assert framework.failedControls > 0
            assert framework.complianceScorev1 > 0

            timestamp = parser.parse(str(framework.timestamp))
            assert scan_time_window <= timestamp <= now, f"Timestamp {framework.timestamp} is not within the last {SCAN_TIME_WINDOW} minutes"

        missing_frameworks = set(FRAMEWORKS_CONFIG_PROVIDER_MAP[provider].keys()) - framework_names
        assert not missing_frameworks, f"Missing frameworks: {missing_frameworks}"

    def _validate_framework_over_time(self, provider: str, framework_over_time: ComplianceFrameworkOverTime, cloud_account_guid: str, last_success_scan_id: str):
        """Validate framework over time data."""
        assert framework_over_time.cloudAccountGUID == cloud_account_guid
        assert provider in FRAMEWORKS_CONFIG_PROVIDER_MAP.keys(), f"Unexpected provider: {provider}"

        framework_names = set()
        for framework in framework_over_time.frameworks:
            framework_names.add(framework.frameworkName)
            assert framework.frameworkName in FRAMEWORKS_CONFIG_PROVIDER_MAP[provider].keys(), f"Unexpected framework name: {framework.frameworkName}"
            assert framework.complianceScore > 0
            assert len(framework.cords) > 0, f"framework.cords is empty for framework {framework.frameworkName}. This may indicate the backend hasn't fully processed the scan data yet."

            cord = framework.cords[0]
            assert cord.reportGUID == last_success_scan_id
            assert cord.complianceScore > 0

            timestamp = parser.parse(str(cord.timestamp))
            now = datetime.datetime.now(datetime.timezone.utc)
            scan_time_window = now - datetime.timedelta(minutes=SCAN_TIME_WINDOW)
            assert scan_time_window <= timestamp <= now

        missing_frameworks = set(FRAMEWORKS_CONFIG_PROVIDER_MAP[provider].keys()) - framework_names
        assert not missing_frameworks, f"Missing frameworks: {missing_frameworks}"


    def validate_compliance_controls(self, provider: str, last_success_scan_id: str, with_accepted_resources: bool, with_jira: bool = False) -> str:
        """Validate compliance controls data and return control hash."""
        default_test_config = TEST_CONFIG_PROVIDER_MAP[provider]
        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [
                {
                    "reportGUID": last_success_scan_id,
                    "frameworkName": default_test_config["framework"],
                    "cloudControlName": default_test_config["control_name"],
                    "status": default_test_config["status"],
                }
            ],
        }

        if with_accepted_resources:
            body["innerFilters"][0]["status"] = "ACCEPT"

        if with_jira:
            body["innerFilters"][0]["tickets"] = "|exists"

        control_resp = self.backend.get_cloud_compliance_controls(body=body, with_rules=False)
        assert len(control_resp["response"]) > 0, f"control response is empty. This may indicate the backend hasn't fully processed the scan data yet. Response: {control_resp}"
        control = ComplianceControl(**control_resp["response"][0])

        assert control.reportGUID == last_success_scan_id , f"Expected reportGUID: {last_success_scan_id}, got: {control.reportGUID}"

        expected_response = get_expected_control_response(provider, with_accepted_resources)
        for key, value in expected_response.items():
            if value != "":  # Skip empty string values as they're placeholders
                assert getattr(control, key) == value, f"Expected {key}: {value}, got: {getattr(control, key)}"
            elif key == "section":
                assert getattr(control, key) != "", f"Expected non-empty section, got empty string"

        if with_jira:
            assert control.tickets is not None and len(control.tickets) > 0, "Expected tickets to be present"

        return control.cloudControlHash

    def validate_compliance_rules(self, provider: str, last_success_scan_id: str, control_hash: str, with_accepted_resources: bool = False, with_jira: bool = False) ->str:
        """Validate compliance checks data."""
        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [
                {
                    "reportGUID": last_success_scan_id,
                    "controlHash": control_hash,
                    "frameworkName": TEST_CONFIG_PROVIDER_MAP[provider]["framework"],
                }
            ],
        }


        check_resp = self.backend.get_cloud_compliance_rules(body=body)
        assert len(check_resp["response"]) > 0, f"rules response is empty. This may indicate the backend hasn't fully processed the scan data yet. Response: {check_resp}"
        rule = ComplianceRuleSummary(**check_resp["response"][0])

        expected_response = get_expected_rules_response(provider, with_accepted_resources)
        for key, value in expected_response.items():
            assert getattr(rule, key) == value, f"Expected {key}: {value}, got: {getattr(rule, key)}"

        assert len(rule.affectedControls) > 0

        if with_jira:
            assert rule.tickets is not None and len(rule.tickets) > 0, "Expected tickets to be present"

        return rule.cloudCheckHash
    def validate_compliance_resources_under_rule(self, provider: str, last_success_scan_id: str, rule_hash: str, with_accepted_resources: bool, with_jira: bool) -> Tuple[str, str]:
        """Validate compliance resources under rule and return resource hash and name."""
        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [
                {
                    "reportGUID": last_success_scan_id,
                    "frameworkName": TEST_CONFIG_PROVIDER_MAP[provider]["framework"],
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

        expected_response = get_expected_resources_under_check_response(provider, with_accepted_resources)
        for key, value in expected_response.items():
            if value != "":  # Skip empty string values as they're placeholders
                assert getattr(resource, key) == value, f"Expected {key}: {value}, got: {getattr(resource, key)}"

        if with_jira:
            assert resource.tickets is not None and len(resource.tickets) > 0, "Expected tickets to be present"

        return resource.cloudResourceHash, resource.cloudResourceName

    def validate_resource_summaries_response(self, provider: str, last_success_scan_id : str, resource_name : str, with_accepted_resources : bool, with_jira : bool):
        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [
                {
                    "frameworkName": TEST_CONFIG_PROVIDER_MAP[provider]["framework"],
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

        expected_response = get_expected_resource_summaries_response(provider, with_accepted_resources)
        Logger.logger.info(f"resource: {resource}\n expected_response: {expected_response}")
        for key, value in expected_response.items():
            if value != "":  # Skip empty string values as they're placeholders
                assert getattr(resource, key) == value, f"Expected {key}: {value}, got: {getattr(resource, key)}"

        if with_jira:
            assert resource.tickets is not None and len(resource.tickets) > 0, "Expected tickets to be present"

    def validate_control_and_checks_under_resource(self, provider: str, last_success_scan_id : str, resource_hash : str, with_accepted_resources : bool, with_jira : bool):
        default_test_config = TEST_CONFIG_PROVIDER_MAP[provider]
        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [
                {
                    "exceptionApplied": "|empty",
                    "reportGUID": last_success_scan_id,
                    "frameworkName": default_test_config["framework"],
                    "cloudResourceHash": resource_hash,
                    "status": default_test_config["status"],
                }
            ]
        }
        if with_accepted_resources:
            body["innerFilters"][0]["exceptionApplied"] = "true,|empty"
            body["innerFilters"][0]["status"] = f"{default_test_config['status']},ACCEPT"
            

        control_with_checks_resp = self.backend.get_cloud_compliance_controls(with_rules=True,body=body)
        assert len(control_with_checks_resp["response"]) > 0, f"control_with_checks response is empty. This may indicate the backend hasn't fully processed the scan data yet. Response: {control_with_checks_resp}"
        for control in control_with_checks_resp["response"]:
            if control["cloudControlName"] == default_test_config["control_name"]:
                control_with_checks = ComplianceControlWithChecks(**control)
                break
        assert control_with_checks is not None, f"Control with name {default_test_config['control_name']} not found in response"
        assert control_with_checks.reportGUID == last_success_scan_id, f"Expected reportGUID: {last_success_scan_id}, got: {control_with_checks.ComplianceControl.reportGUID}"
        assert control_with_checks.cloudControlName == default_test_config["control_name"], f"Expected control name: {default_test_config['control_name']}, got: {control_with_checks.ComplianceControl.name}"

        assert len(control_with_checks.rules) == 1, f"Expected 1 rule, got: {len(control_with_checks.rules)}"
        rule = control_with_checks.rules[0]

        expected_response = get_expected_only_check_under_control_response(provider, with_accepted_resources)
        for key, value in expected_response.items():
            if value != "":
                assert getattr(rule, key) == value, f"Expected {key}: {value}, got: {getattr(rule, key)}"

        if with_jira:
            assert control_with_checks.tickets is not None and len(control_with_checks.tickets) > 0, "Expected tickets to be present in control"
            assert rule.tickets is not None and len(rule.tickets) > 0, "Expected tickets to be present in rule"

    def create_jira_issue_for_cspm(self, provider: str, last_success_scan_id: str, site_name: str = DEFAULT_JIRA_SITE_NAME):
        """Create and validate a Jira issue for CSPM resource.
        Args:
            last_success_scan_id (str): The ID of the last successful scan
            site_name (str): The Jira site name (default: cyberarmor-io)
        """
        # Setup Jira configuration if not already done
        if not hasattr(self, 'site') or not hasattr(self, 'project') or not hasattr(self, 'issueType'):
            self.setup_jira_config(site_name)

        # Get control data first to use in the ticket
        control_hash = self.validate_compliance_controls(provider, last_success_scan_id, False, False)
        rule_hash = self.validate_compliance_rules(provider, last_success_scan_id, control_hash, False, False)
        resource_hash, resource_name = self.validate_compliance_resources_under_rule(provider, last_success_scan_id, rule_hash, False, False)

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
        default_test_config = TEST_CONFIG_PROVIDER_MAP[provider]
        issue["fields"]['summary'] = f"{resource_name} ({default_test_config['resource_type']}) - {default_test_config['rule_name']}"
        issue["fields"]["description"] = f"""CSPM System Test Issue
            Resource Name: {resource_name}
            Resource Hash: {resource_hash}
            Framework: {default_test_config['framework']}
            Control: {default_test_config['control_name']}
            Status: {default_test_config['status']}
            Severity: {default_test_config['severity']}
            """

        ticket = self.backend.create_jira_issue(issue)
        assert ticket['owner']['resourceHash'] == resource_hash, "Resource hash mismatch"
        assert ticket['subjects'][0]['ruleHash'] == rule_hash, "Rule hash mismatch"

        # Validate ticket presence using existing validation functions with with_jira=True
        Logger.logger.info("Validating ticket presence in all APIs")
        self.validate_compliance_controls(provider, last_success_scan_id, False, True)
        self.validate_compliance_rules(provider, last_success_scan_id, control_hash, False, True)
        self.validate_compliance_resources_under_rule(provider, last_success_scan_id, rule_hash, False, True)
        self.validate_resource_summaries_response(provider, last_success_scan_id, resource_name, False, True)
        self.validate_control_and_checks_under_resource(provider, last_success_scan_id, resource_hash, False, True)

        Logger.logger.info(f"Unlink Jira issue")
        self.backend.unlink_issue(ticket['guid'])

        return ticket
    
    def accept_cspm_risk(self, provider: str, cloud_account_guid: str, cloud_account_name: str, last_success_scan_id: str):
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
        control_hash = self.validate_compliance_controls(provider, last_success_scan_id, False, False)
        rule_hash = self.validate_compliance_rules(provider, last_success_scan_id, control_hash, False, False)
        resource_hash, _ = self.validate_compliance_resources_under_rule(provider, last_success_scan_id, rule_hash, False, False)

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
            provider=provider,
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
            provider=provider,
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
            timeout=180,
            sleep_interval=15,
            provider=provider,
            cloud_account_guid=cloud_account_guid,
            cloud_account_name=cloud_account_name,
            last_success_scan_id=last_success_scan_id,
            with_accepted_resources=False
        )


    def validate_features_unchanged(self, cloud_account_guid: str, feature_name: str, expected_feature: dict):
        """
        Validate that a feature's structure remains unchanged when adding a new feature.
        
        Args:
            cloud_account_guid (str): The GUID of the cloud account
            feature_name (str): The name of the feature to validate (CSPM_FEATURE_NAME or CADR_FEATURE_NAME)
            expected_feature (dict): The expected feature structure
        """
        body = self.build_get_cloud_entity_by_guid_request(cloud_account_guid)

        res = self.backend.get_cloud_accounts(body=body)
        assert "response" in res, f"failed to get cloud accounts, body used: {body}, res is {res}"
        assert len(res["response"]) > 0, f"response is empty"
        account = res["response"][0]
        
        # Validate feature exists and has correct structure
        assert feature_name in account["features"], f"{feature_name} not in {account['features']}"
        feature = account["features"][feature_name]
        assert "config" in feature, f"config not in {feature}"  # This is the new field
        
        # Check if a new scan was initiated by comparing lastSuccessScanID
        expected_scan_id = expected_feature.get("lastSuccessScanID")
        current_scan_id = feature.get("lastSuccessScanID")
        expected_initiate_time = expected_feature.get("lastTimeInitiateScan")
        current_initiate_time = feature.get("lastTimeInitiateScan")
        skip_last_time_initiate_scan = False
        
        # Log scan information for debugging
        Logger.logger.info(f"Scan validation check - lastSuccessScanID: Expected={expected_scan_id}, Current={current_scan_id}, "
                          f"lastTimeInitiateScan: Expected={expected_initiate_time}, Current={current_initiate_time}")
        
        # Case 1: Both scan IDs exist and don't match → new scan initiated (OK, skip timestamp validation)
        if expected_scan_id and current_scan_id and expected_scan_id != current_scan_id:
            Logger.logger.warning(f"Scan ID mismatch detected - Expected lastSuccessScanID: {expected_scan_id}, got: {current_scan_id}. "
                                f"This indicates a new scan was initiated. Skipping lastTimeInitiateScan validation.")
            skip_last_time_initiate_scan = True
        # Case 2: Both scan IDs exist and match, but timestamps differ → ERROR (should fail)
        elif expected_scan_id and current_scan_id and expected_scan_id == current_scan_id:
            if expected_initiate_time and current_initiate_time and expected_initiate_time != current_initiate_time:
                Logger.logger.error(f"ERROR: Scan IDs match ({expected_scan_id}) but lastTimeInitiateScan changed - "
                                  f"Expected: {expected_initiate_time}, got: {current_initiate_time}. "
                                  f"This should not happen - same scan cannot have different initiation times.")
                # Don't skip validation - let it fail to catch this issue
                skip_last_time_initiate_scan = False
        # Case 3: Scan IDs don't exist (or one is missing) but timestamps differ → likely new scan initiated (OK, skip timestamp validation)
        elif not (expected_scan_id and current_scan_id):
            if expected_initiate_time and current_initiate_time and expected_initiate_time != current_initiate_time:
                Logger.logger.warning(f"lastTimeInitiateScan changed (Expected: {expected_initiate_time}, got: {current_initiate_time}) "
                                    f"but scan IDs not available (Expected: {expected_scan_id}, Current: {current_scan_id}). "
                                    f"Assuming new scan was initiated. Skipping lastTimeInitiateScan validation.")
                skip_last_time_initiate_scan = True
        
        # Compare each config field
        for key, value in expected_feature.items():
            assert key in feature, f"{key} not in {feature}"
            
            # Skip lastTimeInitiateScan validation if scan IDs don't match (new scan was initiated)
            if key == "lastTimeInitiateScan" and skip_last_time_initiate_scan:
                Logger.logger.info(f"Skipping validation of {key} due to scan ID mismatch (new scan was initiated)")
                continue
            
            assert feature[key] == value, f"Expected {key}: {value}, got: {feature[key]}"
    
    def validate_new_policy(self, body: Dict[str, Any]) -> str:
        res = self.backend.new_runtime_policy(body)
        new_runtime_policy_no_scope_res = json.loads(res.text)
        assert new_runtime_policy_no_scope_res == POLICY_CREATED_RESPONSE, f"failed to create new runtime policy, got {new_runtime_policy_no_scope_res}"

        new_generated_runtime_policy_body =  {
            "pageSize": 50,
            "pageNum": 1,
            "innerFilters": [
                {
                    "name": body["name"],
                }
            ]
        }

        res = self.backend.get_runtime_policies_list(new_generated_runtime_policy_body)
        incident_policies = json.loads(res.text)["response"]
        props_to_check = ["name", "enabled", "scope", "ruleSetType", "incidentTypeIDs"]
        assert len(incident_policies)  > 0, f"failed to get new runtime policy, expected more than 1 but got {len(incident_policies)}, got result {incident_policies}"

        Logger.logger.info(f"New policy created: {json.dumps(incident_policies[0], indent=4)}")

        for prop in props_to_check:
            assert incident_policies[0][prop] == body[prop], f"failed to get new runtime policy, expected '{prop}' {body[prop]} but got {incident_policies[0][prop]}, got result {incident_policies}"
        
        guid = incident_policies[0]["guid"]
        return guid

    
    def get_incidents(self, filters: Dict[str, Any], expect_incidents: bool = True):
        incidents = self.backend.get_incidents(filters)
        if expect_incidents:
            assert len(incidents["response"]) > 0, f"failed to get incidents"
            return incidents["response"]
        assert len(incidents["response"]) == 0, f"expected no incidents but got {len(incidents['response'])}"
        return None

    def validate_entity_status(self, entity_guid: str, status_path: str, expected_status: str, entity_type: CloudEntityTypes):
        """
        Generic function to validate status of accounts or organizations.
        
        Args:
            entity_guid: GUID of the account or organization
            status_path: JSON path to the status field (e.g., "cspmSpecificData.cspmStatus")
            expected_status: Expected status value
            entity_type: Type of entity (CloudEntityTypes.ACCOUNT or CloudEntityTypes.ORGANIZATION)
        """
        if entity_type == CloudEntityTypes.ACCOUNT:
            entity = self.get_cloud_account_by_guid(entity_guid)
        elif entity_type == CloudEntityTypes.ORGANIZATION:
            entity = self.get_cloud_org_by_guid(entity_guid)
        
        # Navigate through the status path on the json
        current = entity
        for key in status_path.split('.'):
            current = current[key]
        
        assert current == expected_status, f"Expected status: {expected_status}, got: {current}"

    def validate_account_feature_status(self, cloud_account_guid: str, feature_name: str, expected_status: str):
        """Validate account feature status."""
        self.validate_entity_status(cloud_account_guid, f"features.{feature_name}.featureStatus", expected_status, CloudEntityTypes.ACCOUNT)

    def validate_account_status(self, cloud_account_guid: str, expected_status: str):
        """Validate account CSPM status."""
        self.validate_entity_status(cloud_account_guid, "cspmSpecificData.cspmStatus", expected_status, CloudEntityTypes.ACCOUNT)
   
    def validate_org_status(self, org_guid: str, expected_status: str):
        """Validate organization CSPM status."""
        self.validate_entity_status(org_guid, "cspmSpecificData.cspmStatus", expected_status, CloudEntityTypes.ORGANIZATION)

    def validate_org_feature_status(self, org_guid: str, feature_name: str, expected_status: str):
        """Validate organization feature status."""
        self.validate_entity_status(org_guid, f"features.{feature_name}.featureStatus", expected_status, CloudEntityTypes.ORGANIZATION)

    def validate_admin_status(self, org_guid: str, expected_status: str):
        """Validate organization admin status."""
        self.validate_entity_status(org_guid, "orgScanData.featureStatus", expected_status, CloudEntityTypes.ORGANIZATION)

    def validate_account_feature_is_excluded(self, cloud_account_guid: str, feature_name: str, is_excluded: bool):
        body = self.build_get_cloud_entity_by_guid_request(cloud_account_guid)
        res = self.backend.get_cloud_accounts(body=body)
        assert len(res["response"]) == 1, f"Expected 1 cloud account, got: {len(res['response'])}"
        account= res["response"][0]
        
        # Handle case where feature doesn't exist or is false
        feature_data = account["features"][feature_name]
        actual_excluded = feature_data.get("excluded", False)
        
        assert actual_excluded == is_excluded, f"Expected isExcluded: {is_excluded}, got: {actual_excluded}"
        return 
    
    def validate_account_feature_is_managed(self, cloud_account_guid: str, feature_name: str, is_managed: str = None):
        body = self.build_get_cloud_entity_by_guid_request(cloud_account_guid)
        res = self.backend.get_cloud_accounts(body=body)
        assert len(res["response"]) == 1, f"Expected 1 cloud account, got: {len(res['response'])}"
        account= res["response"][0]
          
        if is_managed is not None:
            # Check if feature exists and has isManaged field
            if feature_name not in account["features"]:
                assert False, f"Feature {feature_name} does not exist"
            feature_data = account["features"][feature_name]
            actual_is_managed = feature_data.get("managedByOrg")
            assert actual_is_managed == is_managed, f"Expected managedByOrg: {is_managed}, got: {actual_is_managed}"
        else:
            feature_data = account["features"][feature_name]
            assert "managedByOrg" not in feature_data, f"Expected managedByOrg field to not exist, but it exists with value: {feature_data.get('isManaged')}"
    
    def org_exclude_accounts_by_feature(self, org_guid: str, feature_names: List[str], action: ExclusionActions, accounts: List[str]):
        body = {
            "orgGUID": org_guid,
            "featureNames": feature_names,
            "action": action.value,
            "accounts": accounts
        }
        self.backend.update_org_exclude_accounts(body)
    
    def validate_no_account(self,cloud_account_guid: str):
        body = self.build_get_cloud_entity_by_guid_request(cloud_account_guid)
        res = self.backend.get_cloud_accounts(body=body)
        assert "response" in res, f"failed to get cloud accounts, body used: {body}, res is {res}"
        assert len(res["response"]) == 0, f"response is not empty"

    def update_org_metadata_and_validate(self, metadata: UpdateCloudOrganizationMetadataRequest):
        """Update cloud organization metadata using the proper request model."""
        body = metadata.model_dump()
        self.backend.update_org_metadata(body)
        org = self.get_cloud_org_by_guid(metadata.orgGUID)
        if metadata.newName is not None:
            assert org["name"] == metadata.newName, f"Expected name: {metadata.newName}, got: {org['name']}"
        if metadata.excludeAccounts is not None:
               for feature_name in metadata.featureNames:
                   org["features"][feature_name]["accountExcludeList"]["excludeAccountIDs"] = metadata.excludeAccounts

            

def extract_parameters_from_url(url: str) -> Tuple[str, str, str, List[Dict[str, str]]]:
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
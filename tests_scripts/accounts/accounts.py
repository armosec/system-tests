import datetime
import json
import time
import uuid
from dateutil import parser
from enum import Enum
from typing import List, Tuple, Any, Dict, Union

from infrastructure import aws
from systest_utils import Logger
from urllib.parse import parse_qs, urlparse
from tests_scripts import base_test
from tests_scripts.helm.jira_integration import setup_jira_config, DEFAULT_JIRA_SITE_NAME
from tests_scripts.runtime.policies import POLICY_CREATED_RESPONSE
from .cspm_test_models import (
    PROVIDER_AWS,
    PROVIDER_AZURE,
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
    AwsStackResponse,
    AwsMembersStackResponse,
    AWSOrgCreateCloudOrganizationAdminRequest,
    CreateOrUpdateCloudOrganizationResponse,
    ConnectCloudOrganizationMembersRequest,
    UpdateCloudOrganizationMetadataRequest,
    SyncCloudOrganizationRequest
)


SCAN_TIME_WINDOW = 2000

CADR_FEATURE_NAME = "cadr"
COMPLIANCE_FEATURE_NAME = "cspm"
VULN_SCAN_FEATURE_NAME = "vulnScan"

PROVIDER_IDENTIFIER_FIELD_MAP = {
    PROVIDER_AWS: "accountID",
    PROVIDER_AZURE: "subscriptionID",
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
from typing import List, Dict, Any, Union

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

class Accounts(base_test.BaseTest):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)
        self.test_cloud_accounts_guids = []
        self.test_cloud_orgs_guids = []
        self.test_runtime_policies = []
        self.test_global_aws_users = []
        self.tested_stack_refs: List[StackRef] = []
        self.tested_stackset_refs: List[StackSetRef] = []
        self.aws_manager: aws.AwsManager
        self.delegated_admin_aws_manager: aws.AwsManager

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
        
        return super().cleanup(**kwargs)
    
    def _cleanup_stacksets(self, stackset_refs: List[StackSetRef]):
        """
        Enhanced cleanup method for StackSets.
        Waits for any in-progress operations to complete before deleting.
        
        Args:
            stackset_refs: List of StackSetRef objects
        """
        if not stackset_refs:
            Logger.logger.info("No StackSets to clean up")
            return
        
        Logger.logger.info(f"🧹 Starting cleanup of {len(stackset_refs)} StackSets")
        
        # Wait for any in-progress operations to complete with error handling
        Logger.logger.info(f"⏳ Checking for {len(stackset_refs)} in-progress operations")
        for ref in stackset_refs:
            try:
                aws_manager = ref.aws_manager
                if not aws_manager:
                    Logger.logger.warning(f"No AWS manager for StackSet {ref.stackset_name}, skipping")
                    continue
                
                if ref.operation_id is not None:
                    Logger.logger.info(f"Waiting for operation {ref.operation_id} on StackSet {ref.stackset_name} to complete...")
                    final_status = aws_manager.wait_for_stackset_operation(ref.stackset_name, ref.operation_id)
                    
                    if final_status == 'SUCCEEDED':
                        Logger.logger.info(f"Operation {ref.operation_id} completed successfully")
                    elif final_status in ['FAILED', 'STOPPED']:
                        Logger.logger.warning(f"Operation {ref.operation_id} finished with status: {final_status}")
                    elif final_status == 'TIMED_OUT':
                        Logger.logger.warning(f"Operation {ref.operation_id} timed out, proceeding with cleanup")
                    else:
                        Logger.logger.warning(f"Operation {ref.operation_id} status: {final_status}, proceeding with cleanup")
                else:
                    Logger.logger.info(f"No operation ID for StackSet {ref.stackset_name}, checking for any running operations...")
                    # Check if there are any running operations we missed
                    try:
                        operations = aws_manager.get_stackset_operations(ref.stackset_name)
                        running_ops = [op for op in operations if op.get('Status') == 'RUNNING']
                        if running_ops:
                            Logger.logger.warning(f"Found {len(running_ops)} running operations for {ref.stackset_name}")
                            for op in running_ops:
                                op_id = op.get('OperationId')
                                Logger.logger.info(f"Stopping running operation {op_id}")
                                try:
                                    aws_manager.stop_stack_set_operation(ref.stackset_name, op_id)
                                    # Wait a bit for the stop to take effect
                                    import time
                                    time.sleep(5)
                                except Exception as e:
                                    Logger.logger.error(f"Failed to stop operation {op_id} for StackSet {ref.stackset_name}: {e}")
                    except Exception as e:
                        Logger.logger.warning(f"Failed to check operations for StackSet {ref.stackset_name}: {e}, proceeding with cleanup")
            except Exception as e:
                Logger.logger.error(f"Error while waiting for StackSet {ref.stackset_name} operation {ref.operation_id}: {e}, proceeding with cleanup")
        
        # Extract stackset names for deletion, grouped by AWS manager
        stacksets_by_manager = {}
        for ref in stackset_refs:
            if ref.aws_manager:
                manager_key = id(ref.aws_manager)  # Use object ID as key
                if manager_key not in stacksets_by_manager:
                    stacksets_by_manager[manager_key] = (ref.aws_manager, [])
                stacksets_by_manager[manager_key][1].append(ref.stackset_name)
        
        # Now proceed with deletion with error handling
        all_success = True
        for aws_manager, stackset_names in stacksets_by_manager.values():
            try:
                Logger.logger.info(f"Deleting {len(stackset_names)} StackSets")
                success = aws_manager.delete_stacksets_by_names(stackset_names)
                
                if success:
                    Logger.logger.info(f"✅ Successfully deleted {len(stackset_names)} StackSets")
                else:
                    Logger.logger.error(f"❌ Some StackSets failed to clean up: {stackset_names}")
                    all_success = False
            except Exception as e:
                Logger.logger.error(f"❌ Exception during StackSet cleanup: {e}")
                all_success = False
        
        if all_success:
            Logger.logger.info("✅ All StackSets cleaned up successfully")
    
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
    
    def build_get_cloud_aws_org_by_accountID_request(self, accountID: str) -> Dict:
        body = {
            "pageSize": 1,
            "pageNum": 1,
            "innerFilters": [
                {
                    "providerInfo.accountID": accountID
                }
            ]
        }
        return body
    
    def build_get_cloud_aws_org_by_orgID_request(self, orgID: str) -> Dict:
        body = {
            "pageSize": 1,
            "pageNum": 1,
            "innerFilters": [
                {
                    "providerData.providerEntityData.organizationID": orgID
                }
            ]
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

    def create_stack_cspm(self, aws_manager: aws.AwsManager, stack_name: str, template_url: str, parameters: List[Dict[str, Any]]) -> str :
        generated_role_name = self.generate_timestamped_role_name(role_prefix="armo-scan-role")
        parameters.append({"ParameterKey": "RoleName", "ParameterValue": generated_role_name})
        self.create_stack(aws_manager, stack_name, template_url, parameters)
        test_arn =  aws_manager.get_stack_output_role_arn(stack_name)
        return test_arn


    def connect_cspm_vulnscan_new_account(self, region, account_id, arn, cloud_account_name,external_id, validate_apis=True, is_to_cleanup_accounts=True)->str: 
        if is_to_cleanup_accounts:
            Logger.logger.info(f"Cleaning up existing AWS cloud accounts for account_id {account_id}")
            self.cleanup_existing_cloud_accounts(PROVIDER_AWS, account_id)
        Logger.logger.info(f"Creating and validating CSPM cloud account: {cloud_account_name}, ARN: {arn}, region: {region}, external_id: {external_id}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm_vulnscan(cloud_account_name, arn, PROVIDER_AWS, region=region, external_id=external_id, expect_failure=False)
        Logger.logger.info(f"connected cspm to new account {cloud_account_name}, cloud_account_guid is {cloud_account_guid}")
        Logger.logger.info('Validate accounts cloud with cspm list')
        Logger.logger.info(f"validated cspm list for {cloud_account_guid} successfully")
        return cloud_account_guid

    def connect_aws_cspm_new_account(self, region, account_id, arn, cloud_account_name,external_id, skip_scan: bool = False, validate_apis=True, is_to_cleanup_accounts=True)->str:
        if is_to_cleanup_accounts:   
            Logger.logger.info(f"Cleaning up existing AWS cloud accounts for account_id {account_id}")
            self.cleanup_existing_cloud_accounts(PROVIDER_AWS, account_id)
        Logger.logger.info(f"Creating and validating CSPM cloud account: {cloud_account_name}, ARN: {arn}, region: {region}, external_id: {external_id}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm_aws(cloud_account_name, arn, region=region, external_id=external_id, skip_scan=skip_scan, expect_failure=False)
        Logger.logger.info(f"connected cspm to new account {cloud_account_name}, cloud_account_guid is {cloud_account_guid}")
        Logger.logger.info('Validate accounts cloud with cspm list')
        self.validate_accounts_cloud_list_cspm_compliance_aws(cloud_account_guid, arn ,CSPM_SCAN_STATE_IN_PROGRESS , FEATURE_STATUS_CONNECTED, skipped_scan=skip_scan)
        Logger.logger.info(f"validated cspm list for {cloud_account_guid} successfully")
        if validate_apis:
            Logger.logger.info('Validate accounts cloud with cspm unique values')
            self.validate_accounts_cloud_uniquevalues(cloud_account_name)
            Logger.logger.info('Edit name and validate cloud account with cspm')
            self.update_and_validate_cloud_account(cloud_account_guid, cloud_account_name + "-updated", provider=PROVIDER_AWS)
        return cloud_account_guid

    def connect_azure_cspm_new_account(
        self,
        subscription_id: str,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        cloud_account_name: str,
        services: List[str] = None,
        skip_scan: bool = False,
        validate_apis: bool = True,
        is_to_cleanup_accounts: bool = True,
    ) -> str:
        """
        Connect Azure CSPM account (called subscription in Azure) via Service Principal.
        """
        if is_to_cleanup_accounts:
            Logger.logger.info(f"Cleaning up existing Azure cloud accounts for subscription {subscription_id}")
            self.cleanup_existing_cloud_accounts(PROVIDER_AZURE, subscription_id)

        Logger.logger.info(f"Creating and validating Azure CSPM cloud account: {cloud_account_name}, subscription: {subscription_id}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm_azure(
            cloud_account_name=cloud_account_name,
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            services=services,
            skip_scan=skip_scan,
            expect_failure=False,
        )
        Logger.logger.info(f"connected azure cspm to new account {cloud_account_name}, cloud_account_guid is {cloud_account_guid}")
        Logger.logger.info("Validate accounts cloud with azure cspm list")
        self.validate_accounts_cloud_list_cspm_compliance_azure(cloud_account_guid, subscription_id, CSPM_SCAN_STATE_IN_PROGRESS, FEATURE_STATUS_CONNECTED, skipped_scan=skip_scan)
        Logger.logger.info(f"validated azure cspm list for {cloud_account_guid} successfully")

        if validate_apis:
            Logger.logger.info("Validate accounts cloud with cspm unique values")
            self.validate_accounts_cloud_uniquevalues(cloud_account_name)
            Logger.logger.info("Edit name and validate cloud account with cspm")
            self.update_and_validate_cloud_account(cloud_account_guid, cloud_account_name + "-updated", provider=PROVIDER_AZURE)
        return cloud_account_guid
    
    def add_cspm_feature_to_organization(self, aws_manager: aws.AwsManager, stackset_name: str,
                                        org_guid: str, new_feature_name: str ,with_wait: bool = True ,existing_accounts: List[str] = None) -> str:
        """
        Add a CSPM feature to an organization by updating the existing StackSet with a new template
        that supports both CSPM and VulnScan features, then connecting the feature to the organization.
        
        Args:
            aws_manager: AWS manager instance
            stackset_name: Name of the existing StackSet to update
            org_guid: GUID of the organization
            new_feature_name: Name of the feature to add (COMPLIANCE_FEATURE_NAME or VULN_SCAN_FEATURE_NAME)
            with_wait: Whether to wait for the update to complete
            existing_accounts: List of existing accounts to validate
        Returns:
            The organization GUID
        """
        Logger.logger.info(f"Adding {new_feature_name} feature to organization {org_guid}")
        
        # Step 1: Get existing organization details and StackSet configuration
        existing_org = self.get_cloud_org_by_guid(org_guid)
        
        # Extract existing configuration from whichever feature already exists
        existing_cspm_config = None
        existing_region = None
        existing_member_role_arn = None
        existing_member_external_id = None
        existing_feature_name = None
        
        features = [COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME]


        # Find the first existing feature to get configuration from
        existing_features = existing_org.get("features", {})
        for feature_name in features:
            if feature_name in existing_features:
                existing_cspm_config = existing_features[feature_name]["config"]
                existing_region = existing_cspm_config["stackRegion"]
                existing_member_role_arn = existing_cspm_config["memberAccountRoleName"]
                existing_member_external_id = existing_cspm_config["memberAccountExternalID"]
                existing_feature_name = feature_name
                break
        
        if not existing_cspm_config:
            raise Exception(f"No existing CSPM features found in organization {org_guid}. Expected one of: {[COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME]}")
        
        Logger.logger.info(f"Using configuration from existing feature: {existing_feature_name}")
        Logger.logger.info(f"Existing Region: {existing_region}")
        Logger.logger.info(f"Existing Member Role ARN: {existing_member_role_arn}")
        Logger.logger.info(f"Existing Member External ID: {existing_member_external_id}")
        
        # Step 2: Get StackSet configuration (regions, parameters, OUs, etc.)
        stackset_info = aws_manager._get_stackset_deployment_info(stackset_name)
        if not stackset_info:
            raise Exception(f"Could not get StackSet deployment info for {stackset_name}")
        
        existing_regions = stackset_info.get('regions', [existing_region])
        existing_ous = stackset_info.get('organizational_unit_ids', [])
        existing_accounts = stackset_info.get('accounts', [])
        
        # Get existing parameters from the StackSet
        existing_parameters = aws_manager.get_stackset_parameters(stackset_name)
        if not existing_parameters:
            raise Exception(f"Could not get existing parameters from StackSet {stackset_name}")
        
        Logger.logger.info(f"StackSet Regions: {existing_regions}")
        Logger.logger.info(f"StackSet OUs: {existing_ous}")
        Logger.logger.info(f"StackSet Accounts: {existing_accounts}")
        Logger.logger.info(f"StackSet Existing Parameters: {existing_parameters}")
        
        # Step 3: Get template link with both CSPM and VulnScan features
        Logger.logger.info("Getting template link with both CSPM and VulnScan features for organization")
        aws_response = self.get_org_members_stack_link(region=existing_region, stack_name=stackset_name, features=features)
        
        # Extract template URL
        template_url = aws_response.s3TemplatePath
        
        Logger.logger.info(f"Updating StackSet {stackset_name} with new template {template_url}")
        Logger.logger.info(f"Template supports features: {features}")
        
        # Step 4: Update the existing StackSet using the new template
        # According to AWS docs, we need to specify regions and deployment targets
        try:
            # Prepare update parameters based on existing StackSet configuration
            update_params = {
                'stackset_name': stackset_name,
                'template_url': template_url,
                'regions': existing_regions
            }
            
            # Add deployment targets - only use OUs, not specific accounts
            # This ensures new accounts added to the OU will automatically get the stack
            if existing_ous:
                update_params['organizational_unit_ids'] = existing_ous
                Logger.logger.info(f"Using only OUs for deployment targets: {existing_ous}")
            else:
                Logger.logger.warning("No OUs found in StackSet configuration")
            
            update_params['parameters'] = existing_parameters
            Logger.logger.info(f"StackSet update parameters: {len(existing_parameters)} parameters")
            
            # Update the StackSet with the new template
            operation_id = aws_manager.update_stack_set(**update_params)
            
            # Track StackSet for cleanup if not already tracked (it may already be tracked from initial creation)
            if not any(ref.stackset_name == stackset_name for ref in self.tested_stackset_refs):
                stackset_ref = StackSetRef(aws_manager=aws_manager, stackset_name=stackset_name, operation_id=operation_id)
                self.tested_stackset_refs.append(stackset_ref)
            else:
                # Update the operation_id if it changed
                for ref in self.tested_stackset_refs:
                    if ref.stackset_name == stackset_name and operation_id:
                        ref.operation_id = operation_id
                        break
            
            if operation_id and with_wait:
                Logger.logger.info(f"StackSet {stackset_name} update initiated with operation ID: {operation_id}")
                
                # Wait for the update to complete
                final_status = aws_manager.wait_for_stackset_operation(stackset_name, operation_id)
                
                if final_status == 'SUCCEEDED':
                    Logger.logger.info(f"StackSet {stackset_name} updated successfully")
                else:
                    # Get detailed error information
                    aws_manager.get_stackset_instance_errors(stackset_name)
                    raise Exception(f"StackSet update failed with status: {final_status}")
            elif operation_id and not with_wait:
                Logger.logger.info(f"StackSet {stackset_name} update initiated with operation ID: {operation_id} (not waiting for completion)")
            else:
                # Check if there are any recent operations that might indicate success
                Logger.logger.warning(f"No operation ID returned for {stackset_name}, checking recent operations...")
                operations = aws_manager.get_stackset_operations(stackset_name)
                if operations:
                    latest_op = operations[0]
                    Logger.logger.info(f"Latest operation: {latest_op}")
                    if latest_op.get('Status') in ['SUCCEEDED', 'RUNNING']:
                        Logger.logger.info(f"Found recent successful/running operation: {latest_op.get('OperationId')}")
                        if with_wait and latest_op.get('Status') == 'RUNNING':
                            # Wait for this operation to complete
                            op_id = latest_op.get('OperationId')
                            final_status = aws_manager.wait_for_stackset_operation(stackset_name, op_id)
                            if final_status == 'SUCCEEDED':
                                Logger.logger.info(f"StackSet {stackset_name} updated successfully")
                            else:
                                aws_manager.get_stackset_instance_errors(stackset_name)
                                raise Exception(f"StackSet update failed with status: {final_status}")
                        elif latest_op.get('Status') == 'SUCCEEDED':
                            Logger.logger.info(f"StackSet {stackset_name} already updated successfully")
                        else:
                            raise Exception(f"StackSet update failed with status: {latest_op.get('Status')}")
                    else:
                        raise Exception(f"StackSet update failed with status: {latest_op.get('Status')}")
                else:
                    raise Exception("Failed to initiate StackSet update - no operations found")
                
        except Exception as e:
            Logger.logger.error(f"Failed to update StackSet {stackset_name}: {e}")
            raise
        
        # Step 5: Connect the new feature to the organization
        Logger.logger.info(f"Connecting {new_feature_name} feature to organization {org_guid}")
        
        new_feature_list = [new_feature_name]
        # Connect ONLY the new feature to the organization
        body = ConnectCloudOrganizationMembersRequest(
            orgGUID=org_guid,
            features=new_feature_list,  # Only the new feature
            memberRoleExternalID=existing_member_external_id,
            stackRegion=existing_region,
            memberRoleArn=existing_member_role_arn,
            skipScan=True
        ).model_dump()
        
        try:
            res = self.backend.create_cloud_org_connect_members(body=body)
            assert "guid" in res, f"guid not in {res}"
            Logger.logger.info(f"Successfully connected {new_feature_name} feature to organization {org_guid}")
        except Exception as e:
            Logger.logger.error(f"Failed to connect {new_feature_name} feature to organization: {e}")
            raise

        # Validate that all accounts under the organization now have both features
        self.wait_for_report(
            self.validate_org_accounts_have_all_features,
            sleep_interval=30,
            timeout=240,
            org_guid=org_guid,
            account_ids=existing_accounts,
            expected_features=features
        )
        
        return org_guid

    def add_cspm_feature_to_single_account(self, aws_manager: aws.AwsManager, stack_name: str,
                                         cloud_account_guid: str, feature_name: str,
                                         skip_scan: bool = True) -> str:
        """
        Add a CSPM feature to a single account by updating the existing stack with a new template
        that supports both CSPM and VulnScan features, then creating a new cloud account with the feature.
        
        Args:
            aws_manager: AWS manager instance
            stack_name: Name of the existing stack to update
            region: AWS region
            cloud_account_guid: GUID of the existing cloud account (for comparison)
            feature_name: Name of the feature to add (COMPLIANCE_FEATURE_NAME or VULN_SCAN_FEATURE_NAME)
            cloud_account_name: Name of the cloud account (optional, will be fetched if not provided)
            skip_scan: Whether to skip the initial scan
            
        Returns:
            The new cloud account GUID
        """
        Logger.logger.info(f"Adding {feature_name} feature to account {cloud_account_guid}")
        
        # Step 1: Get existing account details for comparison
        existing_account = self.get_cloud_account_by_guid(cloud_account_guid)
        existing_arn = None
        existing_external_id = None
        existing_region = None
        
        # Extract existing configuration from the account
        if COMPLIANCE_FEATURE_NAME in existing_account["features"]:
            existing_config = existing_account["features"][COMPLIANCE_FEATURE_NAME]["config"]
            existing_arn = existing_config["crossAccountsRoleARN"]
            existing_external_id = existing_config.get("externalID", "")
            existing_region = existing_config["stackRegion"]
        elif VULN_SCAN_FEATURE_NAME in existing_account["features"]:
            existing_config = existing_account["features"][VULN_SCAN_FEATURE_NAME]["config"]
            existing_arn = existing_config["crossAccountsRoleARN"]
            existing_external_id = existing_config.get("externalID", "")
            existing_region = existing_config["stackRegion"]
        
        Logger.logger.info(f"Existing ARN: {existing_arn}")
        Logger.logger.info(f"Existing External ID: {existing_external_id}")
        Logger.logger.info(f"Existing Region: {existing_region}")
        
        # Step 2: Get template link with both CSPM and VulnScan features
        Logger.logger.info("Getting template link with both CSPM and VulnScan features")
        features = [COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME]
        stack_response = self.get_and_validate_cspm_link_with_external_id(features=features, region=existing_region)
        
        
        # Extract template URL only (no parameters needed for template-only update)
        _, template_url, _, _ = extract_parameters_from_url(stack_response.stackLink)
        
        Logger.logger.info(f"Updating stack {stack_name} with new template {template_url} (template only)")
        Logger.logger.info(f"Template supports features: {features}")
        
        # Step 3: Update the existing stack using the new CloudFormationManager
        try:
            # The new function is called here.
            # We explicitly pass capabilities, as security templates almost always create IAM roles.
            # 'use_previous_parameters' is true by default, achieving the "template only" update.
            aws_manager.update_stack(
                stack_name=stack_name,
                template_url=template_url,
                capabilities=["CAPABILITY_IAM","CAPABILITY_NAMED_IAM"],  # Acknowledge IAM resource creation
                wait_for_completion=True
            )
            # The new update_stack doesn't return an ID, so the log message is simplified.
            Logger.logger.info(f"Stack {stack_name} updated successfully.")
        except Exception as e:
            Logger.logger.error(f"Failed to update stack {stack_name}: {e}")
            raise
        
        # Step 4: Get the updated role ARN from the stack
        new_arn = aws_manager.get_stack_output_role_arn(stack_name)
        if not new_arn:
            raise Exception(f"Failed to get role ARN from updated stack {stack_name}")
        
        Logger.logger.info(f"New role ARN from updated stack: {new_arn}")
        
        # Step 5: Compare ARN, external_id, and region
        if existing_arn and new_arn != existing_arn:
            raise Exception(f"ARN mismatch: existing={existing_arn}, new={new_arn}")
        
        # Step 7: Create new cloud account with the feature based on feature type
        Logger.logger.info(f"updating {feature_name} feature for {cloud_account_guid}")
    
        if feature_name == COMPLIANCE_FEATURE_NAME:
            # Use CSPM configuration
        
            body = {
                "cspmConfig": {
                    "crossAccountsRoleARN": new_arn,
                    "stackRegion": existing_region,
                    "externalID": existing_external_id
                },
                "skipScan": skip_scan,
            }
        elif feature_name == VULN_SCAN_FEATURE_NAME:
            # Use VulnScan configuration
            body = {
                "vulnerabilityScanConfig": {
                    "crossAccountsRoleARN": new_arn,
                    "stackRegion": existing_region,
                    "externalID": existing_external_id
                },
            }
        else:
            raise Exception(f"Unsupported feature name: {feature_name}")
        
        # Create/update the cloud account with the feature
        try:
            res = self.backend.create_cloud_account(body=body, provider=PROVIDER_AWS)
            new_cloud_account_guid = res["guid"]
            assert new_cloud_account_guid == cloud_account_guid, f"{new_cloud_account_guid} is not {cloud_account_guid}"
            # Track for cleanup if not already tracked
            if new_cloud_account_guid not in self.test_cloud_accounts_guids:
                self.test_cloud_accounts_guids.append(new_cloud_account_guid)
            Logger.logger.info(f"Successfully updated cloud account with {feature_name} feature")            

        except Exception as e:
            Logger.logger.error(f"Failed to create cloud account with {feature_name} feature: {e}")
            raise Exception(f"Failed to create cloud account with {feature_name} feature: {e}")
        
        self.validate_account_status(cloud_account_guid, CSPM_STATUS_HEALTHY)
        return new_cloud_account_guid
    
    def connect_cspm_single_account_suppose_to_be_blocked(self, region:str, arn:str,external_id:str)->bool:
        Logger.logger.info(f"Creating and validating CSPM cloud account: need-to-block, ARN: {arn}, region: {region}, external_id: {external_id}")
        try:
            cloud_account_guid = self.create_and_validate_cloud_account_with_cspm_aws("need-to-block", arn, region=region, external_id=external_id, expect_failure=True)
            if cloud_account_guid:
                return False
            else:
                return True
        except Exception as e:
            Logger.logger.info(f"Expected error: {e}")
            return True
        


    def connect_cspm_bad_arn(self, region, arn, cloud_account_name)->str:
        Logger.logger.info(f"Attempting to connect CSPM with bad ARN: {arn} for account: {cloud_account_name}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm_aws(cloud_account_name, arn, region=region, external_id="", expect_failure=True)
        Logger.logger.info(f"Resulting cloud_account_guid for bad ARN: {cloud_account_guid}")
        return cloud_account_guid



    def create_stack(self, aws_manager: aws.AwsManager, stack_name: str, template_url: str, parameters: List[Dict[str, str]]) -> str:
        Logger.logger.info(f"Initiating stack creation: {stack_name}, template_url: {template_url}, parameters: {parameters}")
        stack_id =  aws_manager.create_stack(template_url, parameters, stack_name)
        assert stack_id, f"failed to create stack {stack_name}"
        Logger.logger.info(f"Stack creation initiated for: {stack_name}, stack id is {stack_id}")
        try:
            aws_manager.wait_for_stack_creation(stack_name)
        except Exception as e:
            Logger.logger.error(f"An error occurred while waiting for stack creation: {e}")
            failure_reason = aws_manager.get_stack_failure_reason(stack_name)
            Logger.logger.error(f"Stack failure reason: {failure_reason}")
            raise Exception(f"failed to create stack {stack_name}, failure_reason is {failure_reason}, exception is {e}")
        # Track with region-aware reference for accurate cleanup
        self.tested_stack_refs.append(StackRef(manager=aws_manager, stack_name=stack_name, region=aws_manager.region))

    def _test_delegated_admin_permissions(self, aws_manager: aws.AwsManager) -> bool:
        """
        Test if the delegated admin role has all necessary permissions for StackSet creation.
        Returns True if all tests pass, False otherwise.
        """
        Logger.logger.info("Testing delegated admin permissions before StackSet creation...")
        
        try:
            # Test if we can list OUs
            ous = aws_manager.organizations.list_organizational_units_for_parent(
                ParentId='r-fo1t'  # Root OU ID
            )
            Logger.logger.info(f"✅ Can list OUs: {len(ous.get('OrganizationalUnits', []))}")
        except Exception as e:
            Logger.logger.error(f"❌ Cannot list OUs: {e}")
            return False
        
        try:
            # Test if we can list accounts
            accounts = aws_manager.organizations.list_accounts()
            Logger.logger.info(f"✅ Can list accounts: {len(accounts.get('Accounts', []))}")
        except Exception as e:
            Logger.logger.error(f"❌ Cannot list accounts: {e}")
            return False
        
        try:
            # Test if we can describe the organization
            org = aws_manager.organizations.describe_organization()
            Logger.logger.info(f"✅ Can describe organization: {org.get('Organization', {}).get('Id', 'N/A')}")
        except Exception as e:
            Logger.logger.error(f"❌ Cannot describe organization: {e}")
            return False
        
        try:
            # Test if we can list StackSets
            stacksets = aws_manager.cloudformation.list_stack_sets()
            Logger.logger.info(f"✅ Can list StackSets: {len(stacksets.get('Summaries', []))}")
        except Exception as e:
            Logger.logger.error(f"❌ Cannot list StackSets: {e}")
            return False
        
        try:
            # Test if we can describe CloudFormation account limits
            limits = aws_manager.cloudformation.describe_account_limits()
            Logger.logger.info(f"✅ Can describe CloudFormation account limits")
        except Exception as e:
            Logger.logger.error(f"❌ Cannot describe CloudFormation account limits: {e}")
            return False
        
        Logger.logger.info("✅ All delegated admin permission tests passed")
        return True
        
    def connect_cspm_features_to_org(self, aws_manager: aws.AwsManager, stack_name: str, region: str, features: List[str], org_guid: str,
                                 organizational_unit_ids: List[str] = None,
                                 account_ids: List[str] = None,skip_wait: bool = False)->(str,str,str):
        """
        Create and deploy a StackSet for Armo Compliance capabilities.
        """
        # Test permissions right before StackSet creation
        if not self._test_delegated_admin_permissions(aws_manager):
            raise Exception("Delegated admin permission tests failed - cannot proceed with StackSet creation")
        
        aws_response = self.get_org_members_stack_link(region=region, stack_name=stack_name, features=features)
        external_id = aws_response.externalID

        generated_role_name = self.generate_timestamped_role_name(role_prefix="armo-org-member-role")
        
        parameters = [
            {
                'ParameterKey': 'ExternalID',   
                'ParameterValue': external_id
            },
            {
                'ParameterKey': 'RoleName',
                'ParameterValue': generated_role_name
            }
        ]
        
        # Call the new wrapper function that handles both creation and deployment
        final_status, operation_id = aws_manager.create_and_deploy_stackset(
            stackset_name=stack_name,
            template_url=aws_response.s3TemplatePath,
            parameters=parameters,
            regions=[region],  # The new function expects a list of regions
            organizational_unit_ids=organizational_unit_ids,
            account_ids=account_ids,
            skip_wait=skip_wait
        )

    
        if final_status != 'SUCCEEDED' and final_status != 'SKIPPED':
            raise Exception(f"StackSet deployment failed: {final_status}")

        # This part remains the same
        body = ConnectCloudOrganizationMembersRequest(
            orgGUID=org_guid,
            features=features,
            memberRoleExternalID=external_id,
            stackRegion=region,
            memberRoleArn=generated_role_name,
            skipScan=True
        ).model_dump()
        res = self.backend.create_cloud_org_connect_members(body=body)
        assert "guid" in res, f"guid not in {res}"
        # Track StackSet for cleanup
        stackset_ref = StackSetRef(aws_manager=aws_manager, stackset_name=stack_name, operation_id=operation_id)
        # Check if already tracked to avoid duplicates
        if not any(ref.stackset_name == stack_name for ref in self.tested_stackset_refs):
            self.tested_stackset_refs.append(stackset_ref)
        return generated_role_name, external_id, operation_id

    def connect_cspm_features_to_org_existing_stack_set(self, org_guid: str,member_role_arn: str,member_role_external_id: str,region: str, features: List[str]):        
        """
        Create and deploy a StackSet for Armo Compliance capabilities.
        """
    
        # This part remains the same
        body = ConnectCloudOrganizationMembersRequest(
            orgGUID=org_guid,
            features=features,
            memberRoleExternalID=member_role_external_id,
            stackRegion=region,
            memberRoleArn=member_role_arn,
            skipScan=True
        ).model_dump()
        res = self.backend.create_cloud_org_connect_members(body=body)
        assert "guid" in res, f"guid not in {res}"

    def connect_cadr_bad_log_location(self, region: str, cloud_account_name: str, trail_log_location: str) -> str:
        cloud_account_guid = self.create_and_validate_cloud_account_with_cadr(cloud_account_name, trail_log_location, PROVIDER_AWS, region=region, expect_failure=True)
        return cloud_account_guid

    def connect_cadr_new_account(self, region: str, stack_name: str, cloud_account_name: str, log_location: str, validate_apis: bool = True) ->     str:
        Logger.logger.info(f"Connecting new CADR account: {cloud_account_name}, log_location: {log_location}, region: {region}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cadr(cloud_account_name, log_location, PROVIDER_AWS, region=region, expect_failure=False)
        
        Logger.logger.info('Validate feature status Pending')
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        assert account["features"][CADR_FEATURE_NAME]["featureStatus"] == FEATURE_STATUS_PENDING, f"featureStatus is not {FEATURE_STATUS_PENDING} but {account['features'][CADR_FEATURE_NAME]['featureStatus']}"
        
        self.create_stack_cadr(region, stack_name, cloud_account_guid)
        Logger.logger.info(f"CADR account {cloud_account_guid} connected and stack created.")
        return cloud_account_guid


    def create_stack_cadr(self, region: str, stack_name: str, cloud_account_guid: str) -> str:
        Logger.logger.info('Get and validate cadr link')
        stack_link = self.get_and_validate_cadr_link(region, cloud_account_guid)

        _, template_url, region, parameters = extract_parameters_from_url(stack_link)

        Logger.logger.info(f"Creating stack with name: {stack_name}, template_url: {template_url}, parameters: {parameters}")
        _ =  self.create_stack(self.aws_manager, stack_name, template_url, parameters)

    def connect_cadr_new_organization(self, region: str, stack_name: str, log_location: str) -> str:
        Logger.logger.info(f"Connecting new CADR org, log_location: {log_location}, region: {region}")
        org_guid = self.create_and_validate_cloud_org_with_cadr(trail_log_location=log_location, region=region, expect_failure=False)

        Logger.logger.info('Validate feature status Pending')
        assert self.verify_cadr_status(org_guid, CloudEntityTypes.ORGANIZATION, FEATURE_STATUS_PENDING)
       
        self.create_stack_cadr_org(region, stack_name, org_guid)
        Logger.logger.info(f"CADR org {org_guid} connected and stack created.")
        return org_guid
    
    def connect_cspm_new_organization(self,aws_manager: aws.AwsManager, stack_name: str, region: str, external_id: Union[str, None] = None) -> CreateOrUpdateCloudOrganizationResponse:
        Logger.logger.info(f"Connecting new cspm org")
        awsResponse = self.get_org_admin_stack_link(region, stack_name, external_id)
        external_id = awsResponse.externalID
        _, template_url, region, parameters = extract_parameters_from_url(awsResponse.stackLink)
        generated_role_name = self.generate_timestamped_role_name(role_prefix="armo-discovery-role")
        parameters.append({"ParameterKey": "RoleName", "ParameterValue": generated_role_name})
        self.create_stack(aws_manager, stack_name, template_url, parameters)
        test_arn =  aws_manager.get_stack_output_role_arn(stack_name)
        body = AWSOrgCreateCloudOrganizationAdminRequest(
            stackRegion=region,
            adminRoleArn=test_arn,
            adminRoleExternalID=external_id,
            skipScan=True
        )
        res = self.backend.create_cloud_org_with_admin(body=body.model_dump())
        assert "guid" in res, f"guid not in {res}"
        org_guid = res["guid"]
        # Track org for cleanup
        if org_guid not in self.test_cloud_orgs_guids:
            self.test_cloud_orgs_guids.append(org_guid)
        return CreateOrUpdateCloudOrganizationResponse(guid=org_guid)

    def connect_existing_cspm_organization(self,region: str,test_arn: str, external_id: Union[str, None] = None ,org_guid: Union[str, None] = None) -> CreateOrUpdateCloudOrganizationResponse:
        if org_guid is not None:
            #for updating existing org entity - for reconecting org
            body = AWSOrgCreateCloudOrganizationAdminRequest(
                stackRegion=region,
                adminRoleArn=test_arn,
                adminRoleExternalID=external_id,
                skipScan=True,
                orgGUID=org_guid
            )
        else:
            body = AWSOrgCreateCloudOrganizationAdminRequest(
                stackRegion=region,
                adminRoleArn=test_arn,
                adminRoleExternalID=external_id,
                skipScan=True
            )
        
        res = self.backend.create_cloud_org_with_admin(body=body.model_dump())
        assert "guid" in res, f"guid not in {res}"
        returned_org_guid = res["guid"]
        # Track org for cleanup (may be new or existing)
        if returned_org_guid not in self.test_cloud_orgs_guids:
            self.test_cloud_orgs_guids.append(returned_org_guid)
        return CreateOrUpdateCloudOrganizationResponse(guid=returned_org_guid)

    def create_stack_cadr_org(self, region: str, stack_name: str, org_guid: str) -> str:
        Logger.logger.info('Get and validate cadr org link')
        stack_link = self.get_and_validate_cadr_org_link(region, org_guid)

        _, template_url, region, parameters = extract_parameters_from_url(stack_link)

        Logger.logger.info(f"Creating stack with name: {stack_name}, template_url: {template_url}, parameters: {parameters}")
        _ =  self.create_stack(self.aws_manager, stack_name, template_url, parameters)

    def verify_cadr_status(self, guid: str, cloud_entity_type: CloudEntityTypes, expected_status: str) -> bool:
        if cloud_entity_type == CloudEntityTypes.ACCOUNT:
            res = self.get_cloud_account_by_guid(guid)
        else:
            res = self.get_cloud_org_by_guid(guid)
            
        assert res["features"][CADR_FEATURE_NAME]["featureStatus"] == expected_status, f"featureStatus is not {expected_status} but {res['features'][CADR_FEATURE_NAME]['featureStatus']}"
        return True


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

    def get_org_admin_stack_link(self, region: str, stack_name: str, external_id: Union[str, None] = None) -> AwsStackResponse:
        # Always send a body, but externalID is optional
        body = {}
        if external_id is not None and external_id != "":
            body["externalID"] = external_id
        
        data = self.backend.get_cspm_admin_org_link(region, stack_name, body)
        return AwsStackResponse(
            stackLink=data["stackLink"],
            externalID=data.get("externalID", "")
        )
    
    def get_org_members_stack_link(self, region: str, stack_name: str, features: List[str]) -> AwsMembersStackResponse:
        data = self.backend.get_cspm_members_org_link(region, stack_name, features)
        return AwsMembersStackResponse(
            s3TemplatePath=data["s3TemplatePath"],
            externalID=data["externalID"]
        )

    
    def get_and_validate_cspm_link_with_external_id(self, region: str ,features: List[str]) -> AwsStackResponse:
        """
        Get and validate cspm link.
        Returns AwsStackResponse with stackLink and externalID.
        """
        data = self.backend.get_cspm_single_link(feature_name=features, region=region, external_id="true")

        return AwsStackResponse(
            stackLink=data["stackLink"],
            externalID=data["externalID"]
        )


    def get_and_validate_cadr_link(self, region, cloud_account_guid) -> str:
        """
        Get and validate cadr link.
        """

        stack_link = self.backend.get_cadr_link(region=region, cloud_account_guid=cloud_account_guid)
        return stack_link

    def get_and_validate_cadr_org_link(self, region: str, org_guid: str) -> str:
        """
        Get and validate cadr org link.
        """

        stack_link = self.backend.get_cadr_org_link(region=region, org_guid=org_guid)
        return stack_link
    
    def create_and_validate_cloud_account_with_feature(self, cloud_account_name: str, provider: str, feature_config: dict, 
                                                      skip_scan: bool = False, expect_failure: bool = False) -> str:
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

    def create_and_validate_cloud_account_with_cspm_vulnscan(self, cloud_account_name: str, arn: str, provider: str, 
                                                           region: str, external_id: str = "", expect_failure: bool = False):
        """Create and validate cloud account with vulnerability scan feature."""
        feature_config = {
            "vulnerabilityScanConfig": {
                "crossAccountsRoleARN": arn,
                "stackRegion": region,
                "externalID": external_id  
            }
        }
        return self.create_and_validate_cloud_account_with_feature(cloud_account_name, provider, feature_config, expect_failure=expect_failure)
    
    def create_and_validate_cloud_account_with_cspm_aws(self, cloud_account_name: str, arn: str, region: str, external_id: str = "", skip_scan: bool = False, expect_failure: bool = False):
        """Create and validate cloud account with CSPM feature."""
        cspm_config = {
            "crossAccountsRoleARN": arn,
            "stackRegion": region,
        }
        if external_id:
            cspm_config["externalID"] = external_id
            
        feature_config = {"cspmConfig": cspm_config}
        return self.create_and_validate_cloud_account_with_feature(cloud_account_name, PROVIDER_AWS, feature_config, skip_scan=skip_scan, expect_failure=expect_failure)

    def create_and_validate_cloud_account_with_cspm_azure(
        self,
        cloud_account_name: str,
        subscription_id: str,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        services: List[str] = None,
        skip_scan: bool = False,
        expect_failure: bool = False,
    ) -> str:
        """
        Create and validate Azure cloud account with CSPM feature using Service Principal credentials.
        """
        compliance_azure_config: Dict[str, Any] = {
            "subscriptionID": subscription_id,
            "tenantID": tenant_id,
            "clientID": client_id,
            "clientSecret": client_secret,
        }

        feature_config = {"complianceAzureConfig": compliance_azure_config}
        return self.create_and_validate_cloud_account_with_feature(
            cloud_account_name,
            PROVIDER_AZURE,
            feature_config,
            skip_scan=skip_scan,
            expect_failure=expect_failure,
        )
            
    def create_and_validate_cloud_account_with_cadr(self, cloud_account_name: str, trail_log_location: str, 
                                                   provider: str, region: str, expect_failure: bool = False) -> str:
        """Create and validate cloud account with CADR feature."""
        feature_config = {
            "cadrConfig": {
                "trailLogLocation": trail_log_location,
                "stackRegion": region,
            }
        }
        return self.create_and_validate_cloud_account_with_feature(cloud_account_name, provider, feature_config, expect_failure=expect_failure)
    
    def create_and_validate_cloud_account(self, body, provider, expect_failure:bool=False)->str:
        """
        Create and validate cloud account.
        Automatically tracks created accounts for cleanup if a GUID is returned.
        """

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
    
    def reconnect_cloud_account_cspm_feature(self, cloud_account_guid: str, feature_name: str, arn: str, region: str, external_id: str , skip_scan: bool = False):
        config_name = ""
        if feature_name == COMPLIANCE_FEATURE_NAME:
            config_name = "cspmConfig"
        elif feature_name == VULN_SCAN_FEATURE_NAME:
            config_name = "vulnerabilityScanConfig"
        else:
            raise Exception(f"Invalid feature name: {feature_name}")
        
        if external_id:
            body = {
                    "guid": cloud_account_guid,
                    config_name: {
                        "crossAccountsRoleARN": arn,
                        "stackRegion": region,
                        "externalID" :external_id  
                    },
                    "skipScan": skip_scan,
                }
        else:
            body = {
                    "guid": cloud_account_guid,
                    config_name: {
                        "crossAccountsRoleARN": arn,
                        "stackRegion": region,
                    },
                    "skipScan": skip_scan,
                }
        self.backend.update_cloud_account(body=body, provider=PROVIDER_AWS)
        return cloud_account_guid
    
    def create_and_validate_cloud_org_with_cadr(self, trail_log_location: str, region: str, expect_failure: bool=False) -> str:
        """
        Create and validate cloud org with cadr.
        """

        body = {
                "trailLogLocation": trail_log_location,
                "stackRegion": region,
            }

        failed = False
        org_guid = None
        try:
            res = self.backend.create_cloud_org_with_cadr(body=body)
            if "guid" in res:
                org_guid = res["guid"]
                # Track org for cleanup if created
                if org_guid not in self.test_cloud_orgs_guids:
                    self.test_cloud_orgs_guids.append(org_guid)
        except Exception as e:
            if not expect_failure:
                Logger.logger.error(f"failed to create cloud org, body used: {body}, error is {e}")
            failed = True
        
        assert failed == expect_failure, f"expected_failure is {expect_failure}, but failed is {failed}, body used: {body}"

        if not expect_failure:
            assert org_guid is not None, f"guid not found in response, body used: {body}"
            return org_guid
        
        return org_guid  # Returns None if failed, or GUID if it was created despite failure

    def validate_accounts_cloud_list_cspm_compliance_aws(self, cloud_account_guid:str, arn:str ,scan_status: str ,feature_status :str ,skipped_scan: bool = False):
        """
        Validate accounts cloud list.
        """
        
        body = self.build_get_cloud_entity_by_guid_request(cloud_account_guid)
        acount_list = self.backend.get_cloud_accounts(body=body)
        assert "response" in acount_list, f"response not in {acount_list}"
        assert len(acount_list["response"]) > 0, f"response is empty"
        account = acount_list["response"][0]
        assert "features" in account, f"features not in {account}"
        assert COMPLIANCE_FEATURE_NAME in account["features"], f"cspm not in {account['features']}"
        assert account["features"][COMPLIANCE_FEATURE_NAME]["featureStatus"] == feature_status, f"featureStatus is not {feature_status} it is {account['features'][COMPLIANCE_FEATURE_NAME]['featureStatus']}"
        assert "config" in account["features"][COMPLIANCE_FEATURE_NAME], f"config not in {account['features']['cspm']} it is {account['features'][COMPLIANCE_FEATURE_NAME]['config']}"
        assert "crossAccountsRoleARN" in account["features"][COMPLIANCE_FEATURE_NAME]["config"], f"crossAccountsRoleARN not in {account['features']['cspm']['config']} it is {account['features'][COMPLIANCE_FEATURE_NAME]['config']}"
        assert account["features"][COMPLIANCE_FEATURE_NAME]["config"]["crossAccountsRoleARN"] == arn, f"crossAccountsRoleARN is not {arn} it is {account['features'][COMPLIANCE_FEATURE_NAME]['config']['crossAccountsRoleARN']}"
        if not skipped_scan:
            assert account["features"][COMPLIANCE_FEATURE_NAME]["scanState"] == scan_status, f"scanState is not {scan_status} it is {account['features'][COMPLIANCE_FEATURE_NAME]['scanState']}"
            assert "nextScanTime" in account["features"][COMPLIANCE_FEATURE_NAME], f"nextScanTime key is missing from account features. Available keys: {list(account['features'][COMPLIANCE_FEATURE_NAME].keys())}"
            assert account["features"][COMPLIANCE_FEATURE_NAME]["nextScanTime"] != "", f"nextScanTime is empty"
            if scan_status==CSPM_SCAN_STATE_COMPLETED:
                assert account["features"][COMPLIANCE_FEATURE_NAME]["lastTimeScanSuccess"] != "", f"lastTimeScanSuccess is empty"
                assert account["features"][COMPLIANCE_FEATURE_NAME]["lastSuccessScanID"] != "", f"lastSuccessScanID is empty"
            elif scan_status==CSPM_SCAN_STATE_FAILED:
                assert account["features"][COMPLIANCE_FEATURE_NAME]["lastTimeScanFailed"] != "", f"lastTimeScanFailed is empty"
        Logger.logger.info(f"validated cspm list for {cloud_account_guid} successfully")
        return account

    def validate_accounts_cloud_list_cspm_compliance_azure(self, cloud_account_guid: str, subscription_id: str, scan_status: str = None, feature_status: str = FEATURE_STATUS_CONNECTED, skipped_scan: bool = False):
        """
        Validate Azure CSPM account listing and status.
        
        Args:
            cloud_account_guid: GUID of the cloud account
            subscription_id: Expected subscription ID
            scan_status: Expected scan status (CSPM_SCAN_STATE_IN_PROGRESS, CSPM_SCAN_STATE_COMPLETED, etc.)
                         Required when skipped_scan=False, can be None when skipped_scan=True
            feature_status: Expected feature status
            skipped_scan: Whether scan was skipped. When False, scan_status must be provided.
        """
        body = self.build_get_cloud_entity_by_guid_request(cloud_account_guid)
        account_list = self.backend.get_cloud_accounts(body=body)
        assert "response" in account_list, f"response not in {account_list}"
        assert len(account_list["response"]) > 0, f"response is empty"
        account = account_list["response"][0]

        assert account["provider"] == PROVIDER_AZURE, f"provider is not azure: {account}"
        assert COMPLIANCE_FEATURE_NAME in account["features"], f"cspm not in {account['features']}"
        feature = account["features"][COMPLIANCE_FEATURE_NAME]
        assert feature["featureStatus"] == feature_status, f"featureStatus is not {feature_status} it is {feature['featureStatus']}"
        assert "config" in feature, f"config not in {feature}"
        config = feature["config"]
        assert config["subscriptionID"] == subscription_id, f"subscriptionID mismatch: {config}"
        assert config["tenantID"], f"tenantID missing in config: {config}"
        assert config["clientID"], f"clientID missing in config: {config}"
        # TODO: clientSecret should not be returned back; ensure it is not exposed
        assert config["clientSecret"], f"clientSecret missing in config: {config}"

        provider_info = account["providerInfo"]
        assert provider_info, f"providerInfo missing in account: {account}"
        assert provider_info["subscriptionID"] == subscription_id, f"providerInfo subscriptionID mismatch: {provider_info}"
        assert provider_info["tenantID"], f"providerInfo tenantID missing: {provider_info}"

        if not skipped_scan:
            assert feature["scanState"] == scan_status, f"scanState is not {scan_status} it is {feature['scanState']}"
            assert "nextScanTime" in feature, f"nextScanTime key is missing from account features. Available keys: {list(feature.keys())}"
            assert feature["nextScanTime"] != "", f"nextScanTime is empty"
            if scan_status == CSPM_SCAN_STATE_COMPLETED:
                assert feature["lastTimeScanSuccess"] != "", f"lastTimeScanSuccess is empty"
                assert feature["lastSuccessScanID"] != "", f"lastSuccessScanID is empty"
            elif scan_status == CSPM_SCAN_STATE_FAILED:
                assert feature["lastTimeScanFailed"] != "", f"lastTimeScanFailed is empty"
        Logger.logger.info(f"validated azure cspm list for {cloud_account_guid} successfully")
        return account

    def connect_azure_cspm_bad_credentials(self, subscription_id: str, tenant_id: str, client_id: str, client_secret: str, cloud_account_name: str) -> str:
        """
        Attempt to connect Azure CSPM with invalid credentials (should fail).
        Returns the cloud_account_guid if account was created despite failure, None otherwise.
        """
        Logger.logger.info(f"Attempting to connect Azure CSPM with bad credentials for account: {cloud_account_name}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm_azure(cloud_account_name, subscription_id, tenant_id, client_id, client_secret, expect_failure=True)
        Logger.logger.info(f"Resulting cloud_account_guid for bad credentials: {cloud_account_guid}")
        return cloud_account_guid

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
        assert len(res["fields"]) > 0, f"response is empty for name {cloud_account_name}, and request {unique_values_body}, res is {res}"
        assert len(res["fields"]["name"]) == 1, f"response is empty for name {cloud_account_name}, and request {unique_values_body}, res is {res}"
        assert res["fields"]["name"][0] == cloud_account_name, f"name is not {cloud_account_name}, request: {unique_values_body}, res: {res}"

    def update_and_validate_cloud_account(self, guid: str, cloud_account_name: str, provider: str = PROVIDER_AWS):
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
        """
        Delete and validate feature.
        """
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
        """
        Delete and validate org feature.
        """
        org = self.get_cloud_org_by_guid(guid)
        assert org is not None, f"Cloud org with guid {guid} was not found"
        assert feature_name in org["features"], f"'{feature_name}' feature was not found in {org['features']}"
        
        orgNeedToBeDeleted = False
        #check if it is last feature - features is a dict
        if len(list(org["features"].keys())) == 1:
            orgNeedToBeDeleted = True

        self.backend.delete_org_feature(org_guid=guid, feature_name=feature_name)
        self.validate_feature_deleted_from_entity(guid, feature_name, orgNeedToBeDeleted, CloudEntityTypes.ORGANIZATION)

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


    def validate_scan_data(self, cloud_account_guid: str, cloud_account_name: str, last_success_scan_id: str, with_accepted_resources: bool = False, with_jira: bool = False, provider: str = PROVIDER_AWS):
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
        self.validate_compliance_frameworks(cloud_account_guid, last_success_scan_id, provider)
        control_hash = self.validate_compliance_controls(last_success_scan_id, with_accepted_resources, with_jira, provider)
        rule_hash = self.validate_compliance_rules(last_success_scan_id, control_hash, with_accepted_resources, with_jira, provider)
        resource_hash ,resource_name = self.validate_compliance_resources_under_rule(last_success_scan_id, rule_hash, with_accepted_resources, with_jira, provider)
        self.validate_resource_summaries_response(last_success_scan_id, resource_name, with_accepted_resources, with_jira, provider)
        self.validate_control_and_checks_under_resource(last_success_scan_id, resource_hash, with_accepted_resources, with_jira, provider)

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

    def validate_compliance_frameworks(self, cloud_account_guid: str, last_success_scan_id: str, provider: str = PROVIDER_AWS):
        """Validate compliance frameworks data."""
        # Validate frameworks API
        body = {
            "innerFilters": [{"cloudAccountGUID": cloud_account_guid}],
        }

        frameworks_res = self.backend.get_cloud_compliance_framework(body=body)
        frameworks = [ComplianceFramework(**f) for f in frameworks_res["response"]]

        self._validate_frameworks(frameworks, last_success_scan_id, provider)

        # Validate frameworks over time
        body = {
            "pageSize": 10000,
            "pageNum": 1,
            "innerFilters": [{"cloudAccountGUID": cloud_account_guid}],
        }

        framework_over_time_resp = self.backend.get_cloud_compliance_framework_over_time(body=body)
        assert len(framework_over_time_resp["response"]) > 0, f"framework_over_time response is empty. This may indicate the backend hasn't fully processed the scan data yet. Response: {framework_over_time_resp}"
        framework_over_time = ComplianceFrameworkOverTime(**framework_over_time_resp["response"][0])

        self._validate_framework_over_time(framework_over_time, cloud_account_guid, last_success_scan_id, provider)

    def _validate_frameworks(self, frameworks: List[ComplianceFramework], last_success_scan_id: str, provider : str = PROVIDER_AWS):
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

    def _validate_framework_over_time(self, framework_over_time: ComplianceFrameworkOverTime, cloud_account_guid: str, last_success_scan_id: str, provider: str = PROVIDER_AWS):
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


    def validate_compliance_controls(self, last_success_scan_id: str, with_accepted_resources: bool, with_jira: bool = False, provider: str = PROVIDER_AWS) -> str:
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

        expected_response = get_expected_control_response(with_accepted_resources, provider)
        for key, value in expected_response.items():
            if value != "":  # Skip empty string values as they're placeholders
                assert getattr(control, key) == value, f"Expected {key}: {value}, got: {getattr(control, key)}"
            elif key == "section":
                assert getattr(control, key) != "", f"Expected non-empty section, got empty string"

        if with_jira:
            assert control.tickets is not None and len(control.tickets) > 0, "Expected tickets to be present"

        return control.cloudControlHash

    def validate_compliance_rules(self, last_success_scan_id: str, control_hash: str, with_accepted_resources: bool = False, with_jira: bool = False, provider: str = PROVIDER_AWS) ->str:
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

        expected_response = get_expected_rules_response(with_accepted_resources, provider)
        for key, value in expected_response.items():
            assert getattr(rule, key) == value, f"Expected {key}: {value}, got: {getattr(rule, key)}"

        assert len(rule.affectedControls) > 0

        if with_jira:
            assert rule.tickets is not None and len(rule.tickets) > 0, "Expected tickets to be present"

        return rule.cloudCheckHash
    def validate_compliance_resources_under_rule(self, last_success_scan_id: str, rule_hash: str, with_accepted_resources: bool, with_jira: bool, provider: str = PROVIDER_AWS) -> Tuple[str, str]:
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

        expected_response = get_expected_resources_under_check_response(with_accepted_resources, provider)
        for key, value in expected_response.items():
            if value != "":  # Skip empty string values as they're placeholders
                assert getattr(resource, key) == value, f"Expected {key}: {value}, got: {getattr(resource, key)}"

        if with_jira:
            assert resource.tickets is not None and len(resource.tickets) > 0, "Expected tickets to be present"

        return resource.cloudResourceHash, resource.cloudResourceName

    def validate_resource_summaries_response(self,last_success_scan_id:str,resource_name:str,with_accepted_resources:bool,with_jira:bool, provider: str = PROVIDER_AWS):
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

        expected_response = get_expected_resource_summaries_response(with_accepted_resources, provider)
        Logger.logger.info(f"resource: {resource}\n expected_response: {expected_response}")
        for key, value in expected_response.items():
            if value != "":  # Skip empty string values as they're placeholders
                assert getattr(resource, key) == value, f"Expected {key}: {value}, got: {getattr(resource, key)}"

        if with_jira:
            assert resource.tickets is not None and len(resource.tickets) > 0, "Expected tickets to be present"

    def validate_control_and_checks_under_resource(self,last_success_scan_id:str,resource_hash:str,with_accepted_resources:bool ,with_jira:bool, provider: str = PROVIDER_AWS):
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

        expected_response = get_expected_only_check_under_control_response(with_accepted_resources, provider)
        for key, value in expected_response.items():
            if value != "":
                assert getattr(rule, key) == value, f"Expected {key}: {value}, got: {getattr(rule, key)}"

        if with_jira:
            assert control_with_checks.tickets is not None and len(control_with_checks.tickets) > 0, "Expected tickets to be present in control"
            assert rule.tickets is not None and len(rule.tickets) > 0, "Expected tickets to be present in rule"

    def create_jira_issue_for_cspm(self, last_success_scan_id: str, site_name: str = DEFAULT_JIRA_SITE_NAME, provider: str = PROVIDER_AWS):
        """Create and validate a Jira issue for CSPM resource.
        Args:
            last_success_scan_id (str): The ID of the last successful scan
            site_name (str): The Jira site name (default: cyberarmor-io)
        """
        # Setup Jira configuration if not already done
        if not hasattr(self, 'site') or not hasattr(self, 'project') or not hasattr(self, 'issueType'):
            self.setup_jira_config(site_name)

        # Get control data first to use in the ticket
        control_hash = self.validate_compliance_controls(last_success_scan_id, False, False, provider)
        rule_hash = self.validate_compliance_rules(last_success_scan_id, control_hash, False, False, provider)
        resource_hash, resource_name = self.validate_compliance_resources_under_rule(last_success_scan_id, rule_hash, False, False, provider)

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
        self.validate_compliance_controls(last_success_scan_id, False, True, provider)
        self.validate_compliance_rules(last_success_scan_id, control_hash, False, True, provider)
        self.validate_compliance_resources_under_rule(last_success_scan_id, rule_hash, False, True, provider)
        self.validate_resource_summaries_response(last_success_scan_id, resource_name, False, True, provider)
        self.validate_control_and_checks_under_resource(last_success_scan_id, resource_hash, False, True, provider)

        Logger.logger.info(f"Unlink Jira issue")
        self.backend.unlink_issue(ticket['guid'])

        return ticket
    
    def accept_cspm_risk(self, cloud_account_guid: str, cloud_account_name: str, last_success_scan_id: str, provider: str = PROVIDER_AWS):
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
        control_hash = self.validate_compliance_controls(last_success_scan_id, False, False, provider)
        rule_hash = self.validate_compliance_rules(last_success_scan_id, control_hash, False, False, provider)
        resource_hash, _ = self.validate_compliance_resources_under_rule(last_success_scan_id, rule_hash, False, False, provider)

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
            with_accepted_resources=True,
            provider=provider
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
            with_accepted_resources=True,
            provider=provider
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
            cloud_account_guid=cloud_account_guid,
            cloud_account_name=cloud_account_name,
            last_success_scan_id=last_success_scan_id,
            with_accepted_resources=False,
            provider=provider
        )

    def disconnect_cspm_account_without_deleting_cloud_account(self, stack_name: str ,cloud_account_guid: str, feature_name: str):
        self.aws_manager.delete_stack(stack_name)
        Logger.logger.info("Disconnecting CSPM account without deleting cloud account")
        self.backend.cspm_scan_now(cloud_account_guid=cloud_account_guid, with_error=True)
        self.wait_for_report(self.validate_account_feature_status, timeout=30, sleep_interval=5, cloud_account_guid=cloud_account_guid, feature_name=feature_name, expected_status=FEATURE_STATUS_DISCONNECTED)

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
    
    def create_aws_cdr_runtime_policy(self, policy_name: str, incident_type_ids: List[str]):
        runtime_policy_body =  {    
            "name": policy_name,   
            "enabled": True,
            "scope": {"designators":[{"cloudProvider": "aws", "service": "CDR", "region": "*/*", "accountID": "*/*"}]},
            "ruleSetType": "Custom",
            "incidentTypeIDs": incident_type_ids,
        }
        policy_guid = self.validate_new_policy(runtime_policy_body)
        self.test_runtime_policies.append(policy_guid)
    
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

    def validate_entity_status(self, entity_guid: str, status_path: str, expected_status: str, entity_type: str = "account"):
        """
        Generic function to validate status of accounts or organizations.
        
        Args:
            entity_guid: GUID of the account or organization
            status_path: JSON path to the status field (e.g., "cspmSpecificData.cspmStatus")
            expected_status: Expected status value
            entity_type: Type of entity ("account" or "org")
        """
        if entity_type == "account":
            entity = self.get_cloud_account_by_guid(entity_guid)
        else:
            entity = self.get_cloud_org_by_guid(entity_guid)
        
        # Navigate through the status path
        current = entity
        for key in status_path.split('.'):
            current = current[key]
        
        assert current == expected_status, f"Expected status: {expected_status}, got: {current}"

    def validate_account_feature_status(self, cloud_account_guid: str, feature_name: str, expected_status: str):
        """Validate account feature status."""
        self.validate_entity_status(cloud_account_guid, f"features.{feature_name}.featureStatus", expected_status, "account")

    def validate_account_status(self, cloud_account_guid: str, expected_status: str):
        """Validate account CSPM status."""
        self.validate_entity_status(cloud_account_guid, "cspmSpecificData.cspmStatus", expected_status, "account")
   
    def validate_account_feature_managed_by_org(self, account_id: str, feature_name: str, org_guid: str = None):
        """Validate if account feature is managed by organization."""
        body = self.build_get_cloud_aws_org_by_accountID_request(account_id)
        res = self.backend.get_cloud_accounts(body=body)
            
        if len(res["response"]) == 0:
            assert False, f"Account {account_id} not found"
        account = res["response"][0]
        
        if org_guid is not None:
            assert account["features"][feature_name]["managedByOrg"] == org_guid, f"Expected status: {org_guid}, got: {account['features'][feature_name]['managedByOrg']}"
        else:
            assert "managedByOrg" not in account["features"][feature_name] or account["features"][feature_name]["managedByOrg"] is None, f"Expected managedByOrg field to not exist, but it exists with value: {account['features'][feature_name].get('managedByOrg')}"
    
    def validate_org_status(self, org_guid: str, expected_status: str):
        """Validate organization CSPM status."""
        self.validate_entity_status(org_guid, "cspmSpecificData.cspmStatus", expected_status, "org")

    def validate_org_feature_status(self, org_guid: str, feature_name: str, expected_status: str):
        """Validate organization feature status."""
        self.validate_entity_status(org_guid, f"features.{feature_name}.featureStatus", expected_status, "org")

    def validate_admin_status(self, org_guid: str, expected_status: str):
        """Validate organization admin status."""
        self.validate_entity_status(org_guid, "orgScanData.featureStatus", expected_status, "org")
    
    def validate_no_accounts_exists_by_id(self, provider: str, ids: List[str], feature_name: Union[str, List[str]]):
        """
        Validate that accounts with the specified IDs do NOT exist with the given feature(s).
        If any accounts exist with any of the features, fail the test with an informative message.
        
        Args:
            provider: Cloud provider (PROVIDER_AWS, PROVIDER_AZURE, etc.)
            ids: List of account IDs to check (account_id for AWS, subscription_id for Azure)
            feature_name: Name of the feature(s) to check. Can be a single feature name (str) 
                         or a list of feature names (List[str]) (e.g., CADR_FEATURE_NAME, 
                         COMPLIANCE_FEATURE_NAME, or [COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME])
        
        Raises:
            AssertionError: If any accounts exist with any of the specified features, with detailed information
        """
        identifier_field = PROVIDER_IDENTIFIER_FIELD_MAP.get(provider)
        if not identifier_field:
            raise Exception(f"Unknown provider {provider}, supported providers: {list(PROVIDER_IDENTIFIER_FIELD_MAP.keys())}")
        
        # Normalize feature_name to a list
        if isinstance(feature_name, str):
            feature_names = [feature_name]
        else:
            feature_names = feature_name
        
        existing_accounts_with_feature = []
        
        for identifier in ids:
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
            
            if "response" in res and len(res["response"]) > 0:
                account = res["response"][0]
                # Get features dict, handling None case
                features = account.get("features") or {}
                # Check if account has any of the specified features
                found_features = [f for f in feature_names if f in features]
                
                if found_features:
                    # Extract required information
                    account_info = {
                        "guid": account.get("guid", "N/A"),
                        identifier_field: account.get("providerInfo", {}).get(identifier_field, identifier),
                        "name": account.get("name", "N/A"),
                        "connectedFeatures": list(features.keys()),
                        "foundFeatures": found_features,
                    }
                    if provider == PROVIDER_AWS:
                        # Add managedByOrg for each found feature
                        account_info["managedByOrg"] = {}
                        for feat in found_features:
                            account_info["managedByOrg"][feat] = features.get(feat, {}).get("managedByOrg", "N/A")
                    
                    existing_accounts_with_feature.append(account_info)
        
        # If any accounts exist with any of the features, fail with informative message
        if existing_accounts_with_feature:
            features_str = ", ".join([f"'{f}'" for f in feature_names])
            error_lines = [
                f"There are leftover accounts from another run - Found {len(existing_accounts_with_feature)} existing {provider} account(s) with feature(s) {features_str}:"
            ]
            for idx, acc in enumerate(existing_accounts_with_feature, 1):
                error_lines.append(
                    f"  Account {idx}:\n"
                    f"    GUID: {acc['guid']}\n"
                    f"    {identifier_field}: {acc[identifier_field]}\n"
                    f"    Name: {acc['name']}\n"
                    f"    Connected Features: {', '.join(acc['connectedFeatures'])}\n"
                    f"    Found Features: {', '.join(acc['foundFeatures'])}\n"
                )
                if provider == PROVIDER_AWS:
                    managed_by_org_lines = []
                    for feat in acc["foundFeatures"]:
                        managed_by_org_lines.append(f"      {feat}: {acc['managedByOrg'][feat]}")
                    error_lines.append(f"    Managed By Org:\n" + "\n".join(managed_by_org_lines))
            error_message = "\n".join(error_lines)
            assert False, error_message

    def validate_org_not_exists_by_id(self, org_id: str, feature_name: str):
        """
        Validate that an organization with the specified ID does NOT exist with the given feature.
        If the organization exists with the feature, fail the test with an informative message.
        
        Args:
            org_id: AWS organization ID (e.g., "o-63kbjphubt")
            feature_name: Name of the feature to check (e.g., CADR_FEATURE_NAME, COMPLIANCE_FEATURE_NAME)
        
        Raises:
            AssertionError: If the organization exists with the specified feature, with detailed information
        """
        body = self.build_get_cloud_aws_org_by_orgID_request(org_id)
        res = self.backend.get_cloud_orgs(body=body)
        
        if "response" in res and len(res["response"]) > 0:
            org = res["response"][0]
            # Get features dict, handling None case
            features = org.get("features") or {}
            # Check if org has the specified feature
            if feature_name in features:
                # Extract required information - only keys
                org_info = {
                    "guid": org.get("guid", "N/A"),
                    "id": org.get("providerInfo", {}).get("accountID", org_id),
                    "name": org.get("name", "N/A"),
                    "featurelist": list(features.keys())
                }
                
                error_message = (
                    f"Organization with ID '{org_id}' exists with feature '{feature_name}' (this is bad):\n"
                    f"  GUID: {org_info['guid']}\n"
                    f"  ID: {org_info['id']}\n"
                    f"  Name: {org_info['name']}\n"
                    f"  Feature List: {', '.join(org_info['featurelist'])}"
                )
                assert False, error_message

    def validate_org_manged_account_list(self, org_guid: str, account_ids: List[str] ,feature_name: str):
        missing_accounts = []
        unmanaged_accounts = []
        
        # Collect all results first
        for account_id in account_ids:
            body = self.build_get_cloud_aws_org_by_accountID_request(account_id)
            res = self.backend.get_cloud_accounts(body=body)
            
            if len(res["response"]) == 0:
                missing_accounts.append(account_id)
                continue
                
            account = res["response"][0]
            managed_by_org_feature = account["features"][feature_name]
            managed_by_org = managed_by_org_feature.get("managedByOrg",None)
            assert managed_by_org is not None, f"managedByOrg is not found in {managed_by_org_feature}"
            if managed_by_org != org_guid:
                unmanaged_accounts.append(account_id)
        
        # Assert after collecting all results
        assert len(missing_accounts) == 0, f"Missing accounts: {missing_accounts}"
        assert len(unmanaged_accounts) == 0, f"Unmanaged accounts: {unmanaged_accounts}"

    def validate_org_accounts_have_all_features(self, org_guid: str, account_ids: List[str], expected_features: List[str]):
        """
        Validate that all accounts under the organization have all expected features.
        
        Args:
            org_guid: GUID of the organization
            account_ids: List of account IDs to validate
            expected_features: List of feature names that should be present
        """
        Logger.logger.info(f"Validating that all accounts under org {org_guid} have features: {expected_features}")
        
        missing_accounts = []
        accounts_missing_features = []
        accounts_not_managed_by_org = []
        
        # Collect all results first
        for account_id in account_ids:
            body = self.build_get_cloud_aws_org_by_accountID_request(account_id)
            res = self.backend.get_cloud_accounts(body=body)
            
            if len(res["response"]) == 0:
                missing_accounts.append(account_id)
                continue
                
            account = res["response"][0]
            account_features = account.get("features", {})
            
            # Check if account has all expected features
            missing_features = []
            for feature_name in expected_features:
                if feature_name not in account_features:
                    missing_features.append(feature_name)
                else:
                    # Check if the feature is managed by the organization
                    feature_data = account_features[feature_name]
                    managed_by_org = feature_data.get("managedByOrg")
                    if managed_by_org != org_guid:
                        accounts_not_managed_by_org.append(f"{account_id}:{feature_name}")
            
            if missing_features:
                accounts_missing_features.append(f"{account_id}:{missing_features}")
        
        # Assert after collecting all results
        assert len(missing_accounts) == 0, f"Missing accounts: {missing_accounts}"
        assert len(accounts_missing_features) == 0, f"Accounts missing features: {accounts_missing_features}"
        assert len(accounts_not_managed_by_org) == 0, f"Accounts not managed by org: {accounts_not_managed_by_org}"
        
        Logger.logger.info(f"✅ All {len(account_ids)} accounts under org {org_guid} have all expected features: {expected_features}")

    def validate_org_feature_deletion_complete(self, org_guid: str, deleted_feature: str, expected_features: List[str], expected_account_ids: List[str]):
        """
        Comprehensive validation that an organization feature deletion worked correctly.
        Validates that:
        1. The deleted feature is completely removed from all accounts
        2. All accounts have only the expected features
        3. All features are managed by the same organization
        4. No accounts are missing or have unexpected features
        
        Args:
            org_guid: GUID of the organization
            deleted_feature: Name of the feature that was deleted
            expected_features: List of feature names that should remain
            account_ids: List of account IDs to validate
        """
        Logger.logger.info(f"Validating complete feature deletion for org {org_guid}: deleted '{deleted_feature}', expected features: {expected_features}")
        
        missing_accounts = []
        accounts_with_deleted_feature = []
        accounts_missing_expected_features = []
        accounts_with_unexpected_features = []
        accounts_not_managed_by_org = []
        
        # Collect all validation results first
        for account_id in expected_account_ids:
            body = self.build_get_cloud_aws_org_by_accountID_request(account_id)
            res = self.backend.get_cloud_accounts(body=body)
            
            if len(res["response"]) == 0:
                missing_accounts.append(account_id)
                continue
                
            account = res["response"][0]
            account_features = account.get("features", {})
            
            # Check if deleted feature still exists (should not)
            if deleted_feature in account_features:
                accounts_with_deleted_feature.append(account_id)
            
            # Check for unexpected features (features not in expected list)
            unexpected_features = []
            for feature_name in account_features.keys():
                if feature_name not in expected_features:
                    unexpected_features.append(feature_name)
            
            if unexpected_features:
                accounts_with_unexpected_features.append(f"{account_id}:{unexpected_features}")
            
            # Check if account has all expected features and they're managed by the org
            missing_features = []
            for feature_name in expected_features:
                if feature_name not in account_features:
                    missing_features.append(feature_name)
                else:
                    # Check if the feature is managed by the organization
                    feature_data = account_features[feature_name]
                    managed_by_org = feature_data.get("managedByOrg")
                    if managed_by_org != org_guid:
                        accounts_not_managed_by_org.append(f"{account_id}:{feature_name}")
            
            if missing_features:
                accounts_missing_expected_features.append(f"{account_id}:{missing_features}")
        
        # Assert after collecting all results
        assert len(missing_accounts) == 0, f"Missing accounts: {missing_accounts}"
        assert len(accounts_with_deleted_feature) == 0, f"Accounts still have deleted feature '{deleted_feature}': {accounts_with_deleted_feature}"
        assert len(accounts_missing_expected_features) == 0, f"Accounts missing expected features: {accounts_missing_expected_features}"
        assert len(accounts_with_unexpected_features) == 0, f"Accounts have unexpected features: {accounts_with_unexpected_features}"
        assert len(accounts_not_managed_by_org) == 0, f"Accounts not managed by org: {accounts_not_managed_by_org}"
        
        Logger.logger.info(f"✅ Feature deletion validation complete for org {org_guid}:")
        Logger.logger.info(f"   - Deleted feature '{deleted_feature}' successfully removed from all accounts")
        Logger.logger.info(f"   - All {len(expected_account_ids)} accounts have only expected features: {expected_features}")
        Logger.logger.info(f"   - All features are managed by the same organization")

    def validate_no_accounts_managed_by_org(self, org_guid: str, expected_account_ids: List[str]):
        """
        Validates that no accounts are managed by the specified organization anymore.
        This is useful after deleting all features from an organization to ensure
        complete disconnection.
        
        Args:
            org_guid: GUID of the organization
            account_ids: List of account IDs to check
        """
        Logger.logger.info(f"Validating that no accounts are managed by org {org_guid} anymore")
        
        accounts_still_managed = []
        accounts_with_features = []
        
        # Check each account to ensure no features are managed by the org
        for account_id in expected_account_ids:
            body = self.build_get_cloud_aws_org_by_accountID_request(account_id)
            res = self.backend.get_cloud_accounts(body=body)
            
            if len(res["response"]) == 0:
                # Account not found - this is expected if it was completely removed
                continue
                
            account = res["response"][0]
            account_features = account.get("features", {})
            
            # Check if any features are still managed by this org
            for feature_name, feature_data in account_features.items():
                managed_by_org = feature_data.get("managedByOrg")
                if managed_by_org == org_guid:
                    accounts_still_managed.append(f"{account_id}:{feature_name}")
            
            # Also track accounts that still have any features (for debugging)
            if account_features:
                accounts_with_features.append(f"{account_id}:{list(account_features.keys())}")
        
        # Assert that no accounts are still managed by the org
        assert len(accounts_still_managed) == 0, f"Accounts still managed by org {org_guid}: {accounts_still_managed}"
        
        Logger.logger.info(f"✅ No accounts are managed by org {org_guid} anymore")
        if accounts_with_features:
            Logger.logger.info(f"   - Found {len(accounts_with_features)} accounts with features, but none managed by org {org_guid}")
        else:
            Logger.logger.info(f"   - All {len(expected_account_ids)} accounts have been completely disconnected")

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
    
    def validate_account_feature_status(self, cloud_account_guid: str, feature_name: str, expected_status: str):
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        assert account["features"][feature_name]["featureStatus"] == expected_status, f"Expected status: {expected_status}, got: {account['features'][feature_name]['featureStatus']}"

    def validate_account__cspm_status(self, cloud_account_guid: str, expected_status: str):
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        assert account["cspmSpecificData"]["cspmStatus"] == expected_status, f"Expected status: {expected_status}, got: {account['cspmSpecificData']['cspmStatus']}"

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
    
    def update_role_external_id(self, aws_manager: aws.AwsManager, role_arn: str, new_external_id: str) -> bool:
        if aws_manager.update_role_external_id(role_arn, new_external_id):
            def check_external_id():
                current_external_id = aws_manager.get_role_external_id_by_arn(role_arn)
                return current_external_id == new_external_id
            
            self.wait_for_report(check_external_id, timeout=30, sleep_interval=5)
            return True
        
        return False
    
    def update_and_validate_admin_external_id(self, aws_manager: aws.AwsManager, org_guid: str, admin_role_arn: str):
        new_external_id = str(uuid.uuid4())
        old_external_id = aws_manager.get_role_external_id_by_arn(admin_role_arn)
        assert old_external_id is not None, f"Old external id is not found"
        assert old_external_id != new_external_id, f"New external id is the same as the old one"
        update_result = self.update_role_external_id(aws_manager, admin_role_arn, new_external_id)
        assert update_result, f"Failed to update role {admin_role_arn} external id {new_external_id}"
        self.backend.sync_org_now(SyncCloudOrganizationRequest(orgGUID=org_guid, skipScan=True))
        self.wait_for_report(self.validate_admin_status, timeout=90, sleep_interval=10, org_guid=org_guid, expected_status=FEATURE_STATUS_DISCONNECTED)
        self.validate_org_status(org_guid, CSPM_STATUS_DEGRADED)

        update_result = self.update_role_external_id(aws_manager, admin_role_arn, old_external_id)
        assert update_result, f"Failed to update role {admin_role_arn} external id {old_external_id}"
        self.wait_for_report(self.connect_existing_cspm_organization, timeout=90, sleep_interval=10 ,region=aws_manager.region, test_arn=admin_role_arn, external_id=old_external_id, org_guid=org_guid)
        self.wait_for_report(self.validate_admin_status, timeout=90, sleep_interval=10, org_guid=org_guid, expected_status=FEATURE_STATUS_CONNECTED)
        self.validate_org_status(org_guid, CSPM_STATUS_HEALTHY)
    
    def update_and_validate_member_external_id(self, aws_manager: aws.AwsManager, org_guid: str, account_guid: str ,feature_name: str):
        cloud_account = self.get_cloud_account_by_guid(account_guid)
        feature = cloud_account["features"][feature_name]
        if feature_name == COMPLIANCE_FEATURE_NAME:
            role_arn = feature["config"]["crossAccountsRoleARN"]
            new_external_id = str(uuid.uuid4())
            old_external_id = aws_manager.get_role_external_id_by_arn(role_arn)
            assert old_external_id is not None, f"Old external id is not found"
            assert old_external_id != new_external_id, f"New external id is the same as the old one"
            update_result = self.update_role_external_id(aws_manager, role_arn, new_external_id)
            assert update_result, f"Failed to update role {role_arn} external id {new_external_id}"
            time.sleep(10)

            self.backend.cspm_scan_now(cloud_account_guid=account_guid, with_error=True)
            self.wait_for_report(self.validate_account_feature_status, timeout=180, sleep_interval=10, cloud_account_guid=account_guid, feature_name=COMPLIANCE_FEATURE_NAME, expected_status=FEATURE_STATUS_DISCONNECTED)
            self.validate_org_status(org_guid, CSPM_STATUS_DEGRADED)
            self.validate_org_feature_status(org_guid, feature_name, FEATURE_STATUS_PARTIALLY_CONNECTED)

            update_result = self.update_role_external_id(aws_manager, role_arn, old_external_id)
            assert update_result, f"Failed to update role {role_arn} external id {old_external_id}"

            self.wait_for_report(self.reconnect_cloud_account_cspm_feature,timeout=90, sleep_interval=10, cloud_account_guid=account_guid, feature_name=COMPLIANCE_FEATURE_NAME, arn=role_arn, region=aws_manager.region, external_id=old_external_id ,skip_scan=True)
            self.wait_for_report(self.validate_account_feature_status, timeout=180, sleep_interval=10, cloud_account_guid=account_guid, expected_status=FEATURE_STATUS_CONNECTED ,feature_name=COMPLIANCE_FEATURE_NAME)
            self.validate_org_status(org_guid, CSPM_STATUS_HEALTHY)
            self.validate_org_feature_status(org_guid, COMPLIANCE_FEATURE_NAME, FEATURE_STATUS_CONNECTED)

        elif feature_name == VULN_SCAN_FEATURE_NAME:
            Logger.logger.info(f"there is no scan now capability to vuln scan")
        return
        

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
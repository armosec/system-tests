import os
import datetime
import json
import time
import uuid
from dateutil import parser
from enum import Enum
from typing import List, Tuple, Any, Dict, Union

from infrastructure import aws
from systest_utils import Logger, statics
from urllib.parse import parse_qs, quote, urlparse
from tests_scripts import base_test
from tests_scripts.helm.jira_integration import setup_jira_config, DEFAULT_JIRA_SITE_NAME
from tests_scripts.runtime.policies import POLICY_CREATED_RESPONSE
from pydantic import BaseModel
from tests_scripts.models import SyncCloudOrganizationRequest
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


class AwsStackResponse(BaseModel):
    """Response model for AWS stack operations."""
    stackLink: str
    externalID: str


class AwsMembersStackResponse(BaseModel):
    """Response model for AWS members stack operations."""
    s3TemplatePath: str
    externalID: str


class AWSOrgCreateCloudOrganizationAdminRequest(BaseModel):
    """Request model for creating AWS cloud organization with admin."""
    orgGUID: Union[str, None] = None
    stackRegion: str
    adminRoleArn: str
    adminRoleExternalID: Union[str, None] = None
    withoutScan: bool = False


class CreateOrUpdateCloudOrganizationResponse(BaseModel):
    """Response model for creating or updating cloud organization."""
    guid: str


class ConnectCloudOrganizationMembersRequest(BaseModel):
    """Request model for connecting cloud organization members."""
    orgGUID: str
    features: List[str]
    memberRoleArn: Union[str, None] = None
    memberRoleExternalID: str
    stackRegion: str
    skipScan: bool = False


class UpdateCloudOrganizationMetadataRequest(BaseModel):
    """Request model for updating cloud organization metadata."""
    orgGUID: str
    newName: Union[str, None] = None
    featureNames: List[str] = []
    excludeAccounts: Union[List[str], None] = None
    
    def model_validate(self, data):
        """Custom validation to match Go struct validation logic."""
        # Validate that excludeAccounts and featureNames are set together
        if (self.excludeAccounts is None) != (len(self.featureNames) == 0):
            raise ValueError("excludeAccounts and featureNames must be set together")
        return super().model_validate(data)


SCAN_TIME_WINDOW = 2000

PROVIDER_AWS = "aws"
PROVIDER_AZURE = "azure"
PROVIDER_GCP = "gcp"

CADR_FEATURE_NAME = "cadr"
COMPLIANCE_FEATURE_NAME = "cspm"
VULN_SCAN_FEATURE_NAME = "vuln-scan"


FEATURE_STATUS_CONNECTED = "Connected"
FEATURE_STATUS_DISCONNECTED = "Disconnected"
FEATURE_STATUS_PENDING = "Pending"
FEATURE_STATUS_PARTIALLY_CONNECTED = "Partially connected"
CSPM_SCAN_STATE_IN_PROGRESS = "In Progress"
CSPM_SCAN_STATE_COMPLETED = "Completed"
CSPM_SCAN_STATE_FAILED = "Failed"

CSPM_STATUS_HEALTHY = "healthy"
CSPM_STATUS_DEGRADED = "degraded"
CSPM_STATUS_DISCONNECTED = "disconnected"

class CloudEntityTypes(Enum):
    ACCOUNT = "account"
    ORGANIZATION = "organization"

class ExclusionActions(Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"
    OVERRIDE = "override"

class Accounts(base_test.BaseTest):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)
        self.test_cloud_accounts_guids = []
        self.test_cloud_orgs_guids = []
        self.test_runtime_policies = []
        self.tested_stacks = []
        self.tested_stacksets = []
        self.tested_cloud_trails = []
        self.aws_manager: aws.AwsManager
        self.delegated_admin_aws_manager: aws.AwsManager



    def cleanup(self, **kwargs):
        for guid in self.test_cloud_accounts_guids:
            self.backend.delete_cloud_account(guid=guid)
            Logger.logger.info(f"Deleted cloud account with guid {guid}")
        for guid in self.test_cloud_orgs_guids:
            self.backend.delete_cloud_organization(guid=guid)
            Logger.logger.info(f"Deleted cloud organization with guid {guid}")
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

    def setup_jira_config(self, site_name=DEFAULT_JIRA_SITE_NAME):
        """Setup Jira configuration using the standalone function."""
        self.site, self.project, self.issueType, self.jiraCollaborationGUID = setup_jira_config(self.backend, site_name)

    def get_cloud_account(self, cloud_account_guid):
        body = self.build_get_cloud_entity_by_guid_request(cloud_account_guid)
        res = self.backend.get_cloud_accounts(body=body)
        assert "response" in res, f"failed to get cloud accounts, body used: {body}, res is {res}"
        assert len(res["response"]) > 0, f"response is empty"
        return res["response"][0]
    
    def get_cloud_org(self, cloud_org_guid: str):
        body = self.build_get_cloud_entity_by_guid_request(cloud_org_guid)
        res = self.backend.get_cloud_orgs(body=body)
        assert "response" in res, f"failed to get cloud orgs, body used: {body}, res is {res}"
        assert len(res["response"]) > 0, f"response is empty"
        return res["response"][0]

    def create_stack_cspm(self, aws_manager: aws.AwsManager, stack_name: str, template_url: str, parameters: List[Dict[str, Any]]) -> str:
        generted_role_name = "armo-scan-role-" + datetime.datetime.now().strftime("%Y%m%d%H%M")
        parameters.append({"ParameterKey": "RoleName", "ParameterValue": generted_role_name})
        self.create_stack(aws_manager, stack_name, template_url, parameters)
        test_arn =  aws_manager.get_stack_output_role_arn(stack_name)
        return test_arn


    def connect_cspm_new_account(self, region, account_id, arn, cloud_account_name,external_id, skip_scan: bool = False, validate_apis=True, is_to_cleanup_accounts=True)->str:
        if is_to_cleanup_accounts:   
            Logger.logger.info(f"Cleaning up existing AWS cloud accounts for account_id {account_id}")
            self.cleanup_existing_aws_cloud_accounts(account_id)
        Logger.logger.info(f"Creating and validating CSPM cloud account: {cloud_account_name}, ARN: {arn}, region: {region}, external_id: {external_id}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm(cloud_account_name, arn, PROVIDER_AWS, region=region, external_id=external_id, skip_scan=skip_scan, expect_failure=False)
        Logger.logger.info(f"connected cspm to new account {cloud_account_name}, cloud_account_guid is {cloud_account_guid}")
        Logger.logger.info('Validate accounts cloud with cspm list')
        account = self.validate_accounts_cloud_list_cspm(cloud_account_guid, arn ,CSPM_SCAN_STATE_IN_PROGRESS , FEATURE_STATUS_CONNECTED, skip_scan=skip_scan)
        self.test_cloud_accounts_guids.append(cloud_account_guid)
        Logger.logger.info(f"validated cspm list for {cloud_account_guid} successfully")
        if validate_apis:
            Logger.logger.info('Validate accounts cloud with cspm uniquevalues')
            self.validate_accounts_cloud_uniquevalues(cloud_account_name)
            Logger.logger.info('Edit name and validate cloud account with cspm')
            self.update_and_validate_cloud_account(cloud_account_guid, cloud_account_name + "-updated", arn)
        return cloud_account_guid
    
    def connect_cspm_single_account_suppose_to_be_blocked(self, region:str, arn:str,external_id:str)->bool:
        Logger.logger.info(f"Creating and validating CSPM cloud account: need-to-block, ARN: {arn}, region: {region}, external_id: {external_id}")
        try:
            cloud_account_guid = self.create_and_validate_cloud_account_with_cspm("need-to-block", arn, PROVIDER_AWS, region=region, external_id=external_id, expect_failure=True)
            if cloud_account_guid:
                return False
            else:
                return True
        except Exception as e:
            Logger.logger.info(f"Expected error: {e}")
            return True
        


    def connect_cspm_bad_arn(self, region, arn, cloud_account_name)->str:
        Logger.logger.info(f"Attempting to connect CSPM with bad ARN: {arn} for account: {cloud_account_name}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm(cloud_account_name, arn, PROVIDER_AWS, region=region,external_id="", expect_failure=True)
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
            failuer_reason = aws_manager.get_stack_failure_reason(stack_name)
            Logger.logger.error(f"Stack failure reason: {failuer_reason}")
            raise Exception(f"failed to create stack {stack_name}, failuer_reason is {failuer_reason}, exception is {e}")
        self.tested_stacks.append(stack_name)
    
    def create_stackset(self, aws_manager: aws.AwsManager, stack_name: str, template_url: str, parameters: List[Dict[str, Any]], ou_id: str = None) -> str:
        stack_id =  aws_manager.create_stackset(template_url, parameters, stack_name, ou_id)
        assert stack_id, f"failed to create stackset {stack_name}"
        Logger.logger.info(f"Stackset creation initiated for: {stack_name}, stack id is {stack_id}")
        try:
            aws_manager.wait_for_stackset_creation(stack_name)
        except Exception as e:
            Logger.logger.error(f"An error occurred while waiting for stackset creation: {e}")
            failuer_reason = aws_manager.get_stackset_failure_reason(stack_name)
            Logger.logger.error(f"Stackset failure reason: {failuer_reason}")
            raise Exception(f"failed to create stackset {stack_name}, failuer_reason is {failuer_reason}, exception is {e}")
        self.tested_stacks.append(stack_name)

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
        
        aws_response = self.get_org_memebers_stack_link(region=region, stack_name=stack_name, features=features)
        external_id = aws_response.externalID

        generted_role_name = "armo-org-member-role-" + datetime.datetime.now().strftime("%Y%m%d%H%M")
        
        parameters = [
            {
                'ParameterKey': 'ExternalID',   
                'ParameterValue': external_id
            },
            {
                'ParameterKey': 'RoleName',
                'ParameterValue': generted_role_name
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
            memberRoleArn=generted_role_name
        ).model_dump()
        res = self.backend.create_cloud_org_connect_members(body=body)
        assert "guid" in res, f"guid not in {res}"
        return generted_role_name, external_id, operation_id

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
            memberRoleArn=member_role_arn
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
        account = self.get_cloud_account(cloud_account_guid)
        assert account["features"][CADR_FEATURE_NAME]["featureStatus"] == FEATURE_STATUS_PENDING, f"featureStatus is not {FEATURE_STATUS_PENDING} but {account['features'][CADR_FEATURE_NAME]['featureStatus']}"
        
        self.create_stack_cadr(region, stack_name, cloud_account_guid)
        self.test_cloud_accounts_guids.append(cloud_account_guid)
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
        self.test_cloud_orgs_guids.append(org_guid)

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
        self.create_stack(aws_manager, stack_name, template_url, parameters)
        test_arn =  aws_manager.get_stack_output_role_arn(stack_name)
        body = AWSOrgCreateCloudOrganizationAdminRequest(
            stackRegion=region,
            adminRoleArn=test_arn,
            adminRoleExternalID=external_id,
            withoutScan=True
        )
        res = self.backend.create_cloud_org_with_admin(body=body.model_dump())
        assert "guid" in res, f"guid not in {res}"
        return CreateOrUpdateCloudOrganizationResponse(guid=res["guid"])

    def connect_existing_cspm_organization(self,region: str,test_arn: str, external_id: Union[str, None] = None ,org_guid: Union[str, None] = None) -> CreateOrUpdateCloudOrganizationResponse:
        if org_guid is not None:
            #for updating existing org entity - for reconecting org
            body = AWSOrgCreateCloudOrganizationAdminRequest(
                stackRegion=region,
                adminRoleArn=test_arn,
                adminRoleExternalID=external_id,
                withoutScan=True,
                orgGUID=org_guid
            )
        else:
            body = AWSOrgCreateCloudOrganizationAdminRequest(
                stackRegion=region,
                adminRoleArn=test_arn,
                adminRoleExternalID=external_id,
                withoutScan=True
            )
        
        res = self.backend.create_cloud_org_with_admin(body=body.model_dump())
        assert "guid" in res, f"guid not in {res}"
        return CreateOrUpdateCloudOrganizationResponse(guid=res["guid"])

    def create_stack_cadr_org(self, region: str, stack_name: str, org_guid: str) -> str:
        Logger.logger.info('Get and validate cadr org link')
        stack_link = self.get_and_validate_cadr_org_link(region, org_guid)

        _, template_url, region, parameters = extract_parameters_from_url(stack_link)

        Logger.logger.info(f"Creating stack with name: {stack_name}, template_url: {template_url}, parameters: {parameters}")
        _ =  self.create_stack(self.aws_manager, stack_name, template_url, parameters)

    def verify_cadr_status(self, guid: str, cloud_entity_type: CloudEntityTypes, expected_status: str) -> bool:
        expected_feature_connected = False

        if expected_status == FEATURE_STATUS_CONNECTED:
            expected_feature_connected = True

        if cloud_entity_type == CloudEntityTypes.ACCOUNT:
            res = self.get_cloud_account(guid)
        else:
            res = self.get_cloud_org(guid)
            
        assert res["features"][CADR_FEATURE_NAME]["featureStatus"] == expected_status, f"featureStatus is not {expected_status} but {res['features'][CADR_FEATURE_NAME]['featureStatus']}"
        if expected_status == FEATURE_STATUS_PENDING:
            assert "isConnected" not in res["features"][CADR_FEATURE_NAME], f"isConnected should not be in {res['features'][CADR_FEATURE_NAME]} when status is {FEATURE_STATUS_PENDING}"
            return True
        assert res["features"][CADR_FEATURE_NAME]["isConnected"] == expected_feature_connected, f"isConnected is not {expected_feature_connected} but {res['features'][CADR_FEATURE_NAME]['isConnected']}"
        return True


    def create_cloudtrail(self, trail_name, bucket_name, kms_key_id=None):

        # have to clean up since there is a limit of 5 trails per region
        self.aws_manager.delete_all_cloudtrails("systest-cloud-trail")

        trail_arn = self.aws_manager.create_cloudtrail(trail_name, bucket_name)
        Logger.logger.info(f"Created CloudTrail with ARN: {trail_arn}, cloud_trail_name is {trail_name}, bucket_name is {bucket_name}")
       

        log_location, kms_key = self.aws_manager.get_cloudtrail_details(trail_name)
        Logger.logger.info(f"CloudTrail details retrieved: Log Location: {log_location}, KMS Key: {kms_key}")

        self.tested_cloud_trails.append(trail_arn)
        return log_location, kms_key


    def cleanup_existing_aws_cloud_accounts(self, account_id):
        """
        Cleanup existing aws cloud accounts.
        """
        Logger.logger.info(f"Cleaning up existing AWS cloud accounts for account_id: {account_id}")
        if not account_id:
            Logger.logger.error("account_id is required for cleanup_existing_aws_cloud_accounts")
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
    
    def get_org_memebers_stack_link(self, region: str, stack_name: str, features: List[str]) -> AwsMembersStackResponse:
        data = self.backend.get_cspm_members_org_link(region, stack_name, features)
        return AwsMembersStackResponse(
            s3TemplatePath=data["s3TemplatePath"],
            externalID=data["externalID"]
        )

    
    def get_and_validate_cspm_link_with_external_id(self, region: str) -> AwsStackResponse:
        """
        Get and validate cspm link.
        Returns AwsStackResponse with stackLink and externalID.
        """
        data = self.backend.get_cspm_link(region=region, external_id="true")
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
    
    def create_and_validate_cloud_account_with_cspm(self, cloud_account_name:str, arn:str, provider:str, region:str, external_id:str ="", skip_scan: bool = False, expect_failure:bool=False):
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
                    "skipScan": skip_scan,
                }
        else:
            body = {
                    "name": cloud_account_name,
                    "cspmConfig": {
                        "crossAccountsRoleARN": arn,
                        "stackRegion": region,
                    },
                    "skipScan": skip_scan,
                }

        return self.create_and_validate_cloud_account(body=body, provider=provider, expect_failure=expect_failure)
            
    def create_and_validate_cloud_account_with_cadr(self, cloud_account_name: str, trail_log_location: str, provider: str, region: str, expect_failure: bool=False) -> str:
        """
        Create and validate cloud account.
        """

        body = {
                "name": cloud_account_name,
                "cadrConfig": {
                    "trailLogLocation": trail_log_location,
                    "stackRegion": region,
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
        updated_cloud_account_guid = self.backend.update_cloud_account(body=body, provider=PROVIDER_AWS)
        assert updated_cloud_account_guid == cloud_account_guid, f"{updated_cloud_account_guid} is not {cloud_account_guid}"
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
        try:
            res = self.backend.create_cloud_org_with_cadr(body=body)
        except Exception as e:
            if not expect_failure:
                Logger.logger.error(f"failed to create cloud org, body used: {body}, error is {e}")
            failed = True
        
        assert failed == expect_failure, f"expected_failure is {expect_failure}, but failed is {failed}, body used: {body}"

        if not expect_failure:
            assert "guid" in res, f"guid not in {res}"
            return res["guid"]
        
        return None

    def validate_accounts_cloud_list_cspm(self, cloud_account_guid:str, arn:str ,scan_status: str ,feature_status :str ,skip_scan: bool = False):
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
        if not skip_scan:
            assert account["features"][COMPLIANCE_FEATURE_NAME]["scanState"] == scan_status, f"scanState is not {scan_status} it is {account['features'][COMPLIANCE_FEATURE_NAME]['scanState']}"
            assert account["features"][COMPLIANCE_FEATURE_NAME]["nextScanTime"] != "", f"nextScanTime is empty"
            if scan_status==CSPM_SCAN_STATE_COMPLETED:
                assert account["features"][COMPLIANCE_FEATURE_NAME]["lastTimeScanSuccess"] != "", f"lastTimeScanSuccess is empty"
                assert account["features"][COMPLIANCE_FEATURE_NAME]["lastSuccessScanID"] != "", f"lastSuccessScanID is empty"
            elif scan_status==CSPM_SCAN_STATE_FAILED:
                assert account["features"][COMPLIANCE_FEATURE_NAME]["lastTimeScanFailed"] != "", f"lastTimeScanFailed is empty"
        Logger.logger.info(f"validated cspm list for {cloud_account_guid} successfully")
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
        assert len(res["fields"]) > 0, f"response is empty for name {cloud_account_name}, and request {unique_values_body}, res is {res}"
        assert len(res["fields"]["name"]) == 1, f"response is empty for name {cloud_account_name}, and request {unique_values_body}, res is {res}"
        assert res["fields"]["name"][0] == cloud_account_name, f"name is not {cloud_account_name}, request: {unique_values_body}, res: {res}"

    def update_and_validate_cloud_account(self, guid:str, cloud_account_name:str, arn:str):
        Logger.logger.info(f"Updating cloud account {guid} to new name '{cloud_account_name}'")
        body = {
        "guid": guid,
        "name": cloud_account_name,
        }

        res = self.backend.update_cloud_account(body=body, provider=PROVIDER_AWS)
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
        account = self.get_cloud_account(guid)
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
        org = self.get_cloud_org(guid)
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
        self.aws_manager.delete_stack(stack_name)
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

        body = self.build_get_cloud_entity_by_guid_request(cloud_account_guid)
        res = self.backend.get_cloud_accounts(body=body)
        assert len(res["response"]) == 1, f"Expected 1 cloud account, got: {len(res['response'])}"
        account= res["response"][0]
        assert account["features"][COMPLIANCE_FEATURE_NAME]["lastTimeScanFailed"] is not None, f"Expected lastTimeScanFail to be set, got: {account['features'][COMPLIANCE_FEATURE_NAME]['lastTimeScanFail']}"
        assert account["features"][COMPLIANCE_FEATURE_NAME]["scanFailureReason"] is not None, f"Expected scanFailureReason to be set, got: {account['features'][COMPLIANCE_FEATURE_NAME]['scanFailureReason']}"
        assert account["features"][COMPLIANCE_FEATURE_NAME]["scanState"] is not None, f"Expected scanState to be set, got: {account['features'][COMPLIANCE_FEATURE_NAME]['scanState']}"

        Logger.logger.info("the account has been successfully disconnected")

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
        
        # Compare each config field
        for key, value in expected_feature.items():
            assert key in feature, f"{key} not in {feature}"
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

    def validate_account_feature_status(self, cloud_account_guid: str, feature_name: str, expected_status: str):
        account = self.get_cloud_account(cloud_account_guid)
        assert account["features"][feature_name]["featureStatus"] == expected_status, f"Expected status: {expected_status}, got: {account['features'][feature_name]['featureStatus']}"

    def validate_org_status(self, org_guid: str, expected_status: str):
        org = self.get_cloud_org(org_guid)
        assert org["cspmSpecificData"]["cspmStatus"] == expected_status, f"Expected status: {expected_status}, got: {org['cspmSpecificData']['cspmStatus']}"

    def validate_org_feature_status(self, org_guid: str, feature_name: str, expected_status: str):
        org = self.get_cloud_org(org_guid)
        assert org["features"][feature_name]["featureStatus"] == expected_status, f"Expected status: {expected_status}, got: {org['features'][feature_name]['featureStatus']}"

    def validate_admin_status(self, org_guid: str, expected_status: str):
        org = self.get_cloud_org(org_guid)
        assert org["orgScanData"]["featureStatus"] == expected_status, f"Expected status: {expected_status}, got: {org['orgScanData']['featureStatus']}"

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
            managed_by_org = account["features"][feature_name]["managedByOrg"]
            
            if managed_by_org != org_guid:
                unmanaged_accounts.append(account_id)
        
        # Assert after collecting all results
        assert len(missing_accounts) == 0, f"Missing accounts: {missing_accounts}"
        assert len(unmanaged_accounts) == 0, f"Unmanaged accounts: {unmanaged_accounts}"

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
    
    def vlaidte_account_feautre_is_managed(self, cloud_account_guid: str, feature_name: str, is_managed: str = None):
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

    
    def update_org_metadata_and_validate(self, metadata: UpdateCloudOrganizationMetadataRequest):
        """Update cloud organization metadata using the proper request model."""
        body = metadata.model_dump()
        self.backend.update_org_metadata(body)
        org = self.get_cloud_org(metadata.orgGUID)
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
        self.backend.sync_org_now(SyncCloudOrganizationRequest(orgGUID=org_guid, withoutScan=True))
        self.wait_for_report(self.validate_admin_status, timeout=90, sleep_interval=10, org_guid=org_guid, expected_status=FEATURE_STATUS_DISCONNECTED)
        self.validate_org_status(org_guid, CSPM_STATUS_DEGRADED)

        update_result = self.update_role_external_id(aws_manager, admin_role_arn, old_external_id)
        assert update_result, f"Failed to update role {admin_role_arn} external id {old_external_id}"
        self.connect_existing_cspm_organization(aws_manager.region, admin_role_arn, old_external_id, org_guid)
        self.wait_for_report(self.validate_admin_status, timeout=90, sleep_interval=10, org_guid=org_guid, expected_status=FEATURE_STATUS_CONNECTED)
        self.validate_org_status(org_guid, CSPM_STATUS_HEALTHY)
    
    def update_and_validate_member_external_id(self, aws_manager: aws.AwsManager, org_guid: str, account_guid: str ,feature_name: str):
        cloud_account = self.get_cloud_account(account_guid)
        feature = cloud_account["features"][feature_name]
        if feature_name == COMPLIANCE_FEATURE_NAME:
            role_arn = feature["config"]["crossAccountsRoleARN"]
            new_external_id = str(uuid.uuid4())
            old_external_id = aws_manager.get_role_external_id_by_arn(role_arn)
            assert old_external_id is not None, f"Old external id is not found"
            assert old_external_id != new_external_id, f"New external id is the same as the old one"
            update_result = self.update_role_external_id(aws_manager, role_arn, new_external_id)
            assert update_result, f"Failed to update role {role_arn} external id {new_external_id}"

            self.backend.cspm_scan_now(account_guid)
            self.wait_for_report(self.validate_account_feature_status, timeout=180, sleep_interval=10, cloud_account_guid=account_guid, feature_name=COMPLIANCE_FEATURE_NAME, expected_status=FEATURE_STATUS_DISCONNECTED)
            self.validate_org_status(org_guid, CSPM_STATUS_DEGRADED)
            self.validate_org_feature_status(org_guid, feature_name, FEATURE_STATUS_PARTIALLY_CONNECTED)

            update_result = self.update_role_external_id(aws_manager, role_arn, old_external_id)
            assert update_result, f"Failed to update role {role_arn} external id {old_external_id}"

            self.reconnect_cloud_account_cspm_feature(account_guid, COMPLIANCE_FEATURE_NAME, role_arn, aws_manager.region, old_external_id ,skip_scan=True)
            self.wait_for_report(self.validate_account_feature_status, timeout=180, sleep_interval=10, org_guid=org_guid, expected_status=FEATURE_STATUS_CONNECTED)
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
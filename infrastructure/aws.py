import boto3
import json
import logging
import re
import time
import uuid
from botocore.exceptions import ClientError
from systest_utils import Logger

from typing import List, Dict


class AwsManager:
    def __init__(self, region: str, aws_access_key_id: str, aws_secret_access_key: str, aws_session_token: str = None):
        self.region = region
        self.base_session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region
        )
        
        # Initialize clients
        self._init_clients()
    
    def _init_clients(self):
        """Initialize all AWS service clients"""
        self.cloudformation = self.base_session.client("cloudformation")
        self.cloudtrail = self.base_session.client("cloudtrail")
        self.s3 = self.base_session.client("s3")
        self.logs = self.base_session.client("logs")
        self.sts = self.base_session.client("sts")
        self.iam = self.base_session.client('iam')
        self.organizations = self.base_session.client('organizations')
        self.ec2 = self.base_session.client('ec2')

    def assume_role_in_account(self,target_account_id: str, role_name: str = "OrganizationAccountAccessRole", session_name: str = "CrossAccountSession"):
        """
        Assume a role in a target account and return new manager instance
        """
        try:
            role_arn = f"arn:aws:iam::{target_account_id}:role/{role_name}"
            response = self.sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=3600
            )
            credentials = response['Credentials']
            return AwsManager(
                region=self.region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                Logger.logger.error(f"Access denied when assuming role {role_arn}. Check if the role exists and trusts your management account.")
                raise Exception(f"Access denied when assuming role {role_arn}. Check if the role exists and trusts your management account.")
            elif error_code == 'InvalidParameterValue':
                Logger.logger.error(f"Invalid role ARN: {role_arn}. Check the account ID and role name.")
                raise Exception(f"Invalid role ARN: {role_arn}. Check the account ID and role name.")
            else:
                Logger.logger.error(f"Failed to assume role: {e}")
                raise Exception(f"Failed to assume role: {e}")

    def list_organization_accounts(self):
        """
        List all accounts in the organization (requires organizations permissions)
        """
        try:
            paginator = self.organizations.get_paginator('list_accounts')
            accounts = []
            for page in paginator.paginate():
                accounts.extend(page['Accounts'])
            return accounts
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                Logger.logger.error("Access denied to Organizations API. Make sure you're using management account credentials.")
                raise Exception("Access denied to Organizations API. Make sure you're using management account credentials.")
            else:
                Logger.logger.error(f"Failed to list organization accounts: {e}")
                raise Exception(f"Failed to list organization accounts: {e}")

    def get_account_id(self):
        try:
            account_id = self.sts.get_caller_identity()["Account"]
            return account_id
        except ClientError as e:
            Logger.logger.error(f"Failed to get account ID: {e}")
            return None

    def get_caller_identity(self):
        """
        Get the caller identity information including Account, UserId, and Arn
        """
        try:
            identity = self.sts.get_caller_identity()
            return identity
        except ClientError as e:
            Logger.logger.error(f"Failed to get caller identity: {e}")
            return None

    def get_all_delegated_admins(self):
        """
        Get all delegated administrators for CloudFormation StackSets
        """
        try:
            response = self.organizations.list_delegated_administrators(
                ServicePrincipal='member.org.stacksets.cloudformation.amazonaws.com'
            )
            
            admins = response.get('DelegatedAdministrators', [])
            Logger.logger.info(f"Found {len(admins)} delegated admins for CloudFormation StackSets")
            for admin in admins:
                Logger.logger.info(f"  - Account: {admin['Id']}, Name: {admin.get('Name', 'N/A')}")
            return admins
            
        except ClientError as e:
            Logger.logger.error(f"Failed to list delegated admins: {e}")
            return []

    def verify_trusted_access_enabled(self):
        """Verify trusted access is enabled for StackSets."""
        try:
            response = self.organizations.list_aws_service_access_for_organization()
            enabled_services = [service['ServicePrincipal'] for service in response.get('EnabledServicePrincipals', [])]
            is_enabled = 'member.org.stacksets.cloudformation.amazonaws.com' in enabled_services
            if is_enabled:
                Logger.logger.info("✅ CloudFormation StackSets trusted access is enabled")
            else:
                Logger.logger.error("❌ CloudFormation StackSets trusted access is NOT enabled")
            return is_enabled
        except Exception as e:
            Logger.logger.error(f"Error checking trusted access: {e}")
            return False

    def verify_delegation_status(self, account_id):
        """Verify this account is properly delegated."""
        try:
            response = self.organizations.list_delegated_administrators(
                ServicePrincipal='member.org.stacksets.cloudformation.amazonaws.com'
            )
            delegated_accounts = [admin['Id'] for admin in response.get('DelegatedAdministrators', [])]
            is_delegated = account_id in delegated_accounts
            if is_delegated:
                Logger.logger.info(f"✅ Account {account_id} is properly delegated for StackSets")
            else:
                Logger.logger.error(f"❌ Account {account_id} is NOT delegated for StackSets")
            return is_delegated
        except Exception as e:
            Logger.logger.error(f"Error checking delegation status: {e}")
            return False

    def create_stack(self, template_url: str, parameters: List[Dict[str, str]], stack_name: str = None):
        try:
            # Create the stack
            response = self.cloudformation.create_stack(
                StackName=stack_name,
                TemplateURL=template_url,
                Parameters=parameters,
                Capabilities=["CAPABILITY_NAMED_IAM"] # Required for creating IAM resources
            )
            Logger.logger.info(f"Stack creation initiated for: {stack_name}")
            return response["StackId"]

        except ClientError as e:
            Logger.logger.error(f"An error occurred during stack creation: {e}")
            return None

    def wait_for_stack_creation(self, stack_name: str, delay=15, max_attempts=80):
        try:
            # Wait for the stack creation to complete
            Logger.logger.info(f"Waiting for stack {stack_name} to be created...")
            waiter = self.cloudformation.get_waiter("stack_create_complete")
            waiter.wait(StackName=stack_name,
                        WaiterConfig={
                            "Delay": delay,  # Polling interval in seconds
                            "MaxAttempts": max_attempts  # Maximum number of attempts (total time = Delay * MaxAttempts)
                        })
            Logger.logger.info(f"Stack {stack_name} created successfully.")

        except ClientError as e:
            Logger.logger.error(f"An error occurred while waiting for stack creation: {e}")
            raise e

    def get_stack_failure_reason(self, stack_name: str):
        try:
            response = self.cloudformation.describe_stack_events(StackName=stack_name)
            for event in response.get("StackEvents", []):
                if "ROLLBACK_FAILED" in event.get("ResourceStatus", "") or "ROLLBACK_IN_PROGRESS" in event.get("ResourceStatus", ""):
                    Logger.logger.error(f"Stack failure reason: {event.get('ResourceStatusReason', 'No reason provided')}")
                    return event.get("ResourceStatusReason", "No reason provided")
            Logger.logger.info("No failure reason found in stack events.")
            return "No failure reason found."
        except ClientError as e:
            Logger.logger.error(f"An error occurred while fetching stack events: {e}")
            return None
    def get_stack_output_role_arn(self, stack_name: str):
        try:
            return self.get_stack_output(stack_name, "ArmoRoleArn")
        except Exception as e:
            Logger.logger.error(f"An error occurred while getting stack output role ARN: {e}")
            return None

    def get_stack_output(self, stack_name: str, output_key: str):
        try:
            # Describe the stack to fetch outputs
            response = self.cloudformation.describe_stacks(StackName=stack_name)
            stacks = response.get("Stacks", [])
            if not stacks:
                Logger.logger.error("No stacks found.")
                return None
            
            outputs = stacks[0].get("Outputs", [])
            for output in outputs:
                if output_key == output.get("OutputKey"):
                    return output.get("OutputValue")

            Logger.logger.error(f"No output found with key '{output_key}' in stack outputs.")
            return None

        except ClientError as e:
            Logger.logger.error(f"An error occurred: {e}")
            return None

    def update_stack(self, stack_name: str, template_url: str = None, parameters: List[Dict[str, str]] = None, 
                     capabilities: List[str] = None, wait_for_completion: bool = True):
        """
        Update a CloudFormation stack with a new template and/or parameters.
        
        Args:
            stack_name: Name of the stack to update
            template_url: URL of the new template (optional)
            parameters: List of parameter dictionaries (optional)
            capabilities: List of capabilities required (optional)
            wait_for_completion: Whether to wait for update to complete (default: True)
        
        Returns:
            Stack ID if successful, None otherwise
        """
        try:
            # Prepare update parameters
            update_params = {
                'StackName': stack_name
            }
            
            if template_url:
                update_params['TemplateURL'] = template_url
            
            if parameters:
                update_params['Parameters'] = parameters
            
            if capabilities:
                update_params['Capabilities'] = capabilities
            else:
                # Default to IAM capabilities if not specified
                update_params['Capabilities'] = ["CAPABILITY_NAMED_IAM"]
            
            # Update the stack
            response = self.cloudformation.update_stack(**update_params)
            stack_id = response["StackId"]
            Logger.logger.info(f"Stack update initiated for: {stack_name}")
            
            if wait_for_completion:
                self.wait_for_stack_update(stack_name)
            
            return stack_id

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ValidationError' and 'No updates are to be performed' in str(e):
                Logger.logger.info(f"No updates needed for stack {stack_name}")
                return stack_id if 'stack_id' in locals() else None
            else:
                Logger.logger.error(f"An error occurred during stack update: {e}")
                return None

    def wait_for_stack_update(self, stack_name: str, delay=15, max_attempts=80):
        """
        Wait for a stack update to complete.
        
        Args:
            stack_name: Name of the stack being updated
            delay: Polling interval in seconds (default: 15)
            max_attempts: Maximum number of attempts (default: 80)
        """
        try:
            Logger.logger.info(f"Waiting for stack {stack_name} update to complete...")
            waiter = self.cloudformation.get_waiter("stack_update_complete")
            waiter.wait(StackName=stack_name,
                        WaiterConfig={
                            "Delay": delay,
                            "MaxAttempts": max_attempts
                        })
            Logger.logger.info(f"Stack {stack_name} updated successfully.")

        except ClientError as e:
            Logger.logger.error(f"An error occurred while waiting for stack update: {e}")
            raise e

    def delete_stack(self, stack_name: str):
        try:
            # Delete the stack
            Logger.logger.info(f"Deleting stack {stack_name}...")
            self.cloudformation.delete_stack(StackName=stack_name)

            # Wait for the stack deletion to complete
            waiter = self.cloudformation.get_waiter("stack_delete_complete")
            waiter.wait(StackName=stack_name)
            Logger.logger.info(f"Stack {stack_name} deleted successfully.")

        except ClientError as e:
            Logger.logger.error(f"An error occurred while deleting the stack: {e}")
            raise e
    
    def create_cloudtrail(self, trail_name, s3_bucket_name=None):
        try:
            # Get AWS Account ID dynamically
            account_id = self.get_account_id()

            if s3_bucket_name is None:
                s3_bucket_name = f"cloudtrail-logs-{uuid.uuid4()}"

                # Create S3 bucket
                if self.region == "us-east-1":
                    self.s3.create_bucket(Bucket=s3_bucket_name)
                else:
                    self.s3.create_bucket(
                        Bucket=s3_bucket_name,
                        CreateBucketConfiguration={"LocationConstraint": self.region}
                    )

                Logger.logger.info(f"Created new S3 bucket for CloudTrail logs: {s3_bucket_name}")

                # Add S3 bucket policy to allow CloudTrail to write logs
                bucket_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AWSCloudTrailAclCheck",
                            "Effect": "Allow",
                            "Principal": {"Service": "cloudtrail.amazonaws.com"},
                            "Action": "s3:GetBucketAcl",
                            "Resource": f"arn:aws:s3:::{s3_bucket_name}"
                        },
                        {
                            "Sid": "AWSCloudTrailWrite",
                            "Effect": "Allow",
                            "Principal": {"Service": "cloudtrail.amazonaws.com"},
                            "Action": "s3:PutObject",
                            "Resource": f"arn:aws:s3:::{s3_bucket_name}/AWSLogs/{account_id}/*",
                            "Condition": {
                                "StringEquals": {
                                    "s3:x-amz-acl": "bucket-owner-full-control"
                                }
                            }
                        }
                    ]
                }
                
                self.s3.put_bucket_policy(
                    Bucket=s3_bucket_name,
                    Policy=json.dumps(bucket_policy)
                )
                Logger.logger.info(f"Applied S3 bucket policy for CloudTrail logging: {s3_bucket_name}")

            # Create CloudTrail
            response = self.cloudtrail.create_trail(
                Name=trail_name,
                S3BucketName=s3_bucket_name,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
                IncludeGlobalServiceEvents=True
            )
            
            # Start logging
            self.cloudtrail.start_logging(Name=trail_name)
            Logger.logger.info(f"CloudTrail {trail_name} created and logging started successfully.")
            
            return response["TrailARN"]
        
        except ClientError as e:
            Logger.logger.error(f"An error occurred while creating CloudTrail: {e}")
            return None
        
    def get_cloudtrail_details(self, trail_name):
        try:
            response = self.cloudtrail.get_trail(Name=trail_name)
            trail_response = response.get("Trail", {})
            account_id = extract_account_id_from_traillog_arn(trail_response.get("TrailARN", ""))
            bucket_name = trail_response.get("S3BucketName", "")
            log_location = f"{bucket_name}/AWSLogs/{account_id}"
            kms_key = response.get("KmsKeyId", "")
            Logger.logger.info(f"CloudTrail details retrieved: Log Location: {log_location}, KMS Key: {kms_key}")
            return log_location, kms_key
        except ClientError as e:
            Logger.logger.error(f"An error occurred while retrieving CloudTrail details: {e}")
            return None, None

    def delete_cloudtrail(self, trail_name):
        try:
            self.cloudtrail.delete_trail(Name=trail_name)
            Logger.logger.info(f"CloudTrail {trail_name} deleted successfully.")
        except ClientError as e:
            Logger.logger.error(f"An error occurred while deleting CloudTrail: {e}")

    def delete_all_cloudtrails(self, prefix=None):
        try:
            response = self.cloudtrail.list_trails()
            trails = response.get("Trails", [])
            for trail in trails:
                if prefix and not trail["Name"].startswith(prefix):
                    continue
                trail_name = trail["Name"]
                self.delete_cloudtrail(trail_name)
                Logger.logger.info(f"Deleted CloudTrail: {trail_name}")
        except ClientError as e:
            Logger.logger.error(f"An error occurred while listing or deleting CloudTrails: {e}")

    def delete_stack_log_groups(self, stack_name):
        """Delete log groups associated with a particular stack"""
        try:
            # Define log group patterns to delete
            log_group_patterns = [
                f"/aws/lambda/{stack_name}-log-processing-function",
                f"/aws/lambda/{stack_name}-notification-config"
            ]

            # Try to delete each log group
            for log_group_name in log_group_patterns:
                try:
                    self.logs.delete_log_group(logGroupName=log_group_name)
                    Logger.logger.info(f"Log group {log_group_name} deleted successfully.")
                except self.logs.exceptions.ResourceNotFoundException:
                    Logger.logger.info(f"Log group {log_group_name} not found, skipping.")
                except Exception as e:
                    Logger.logger.error(f"Error deleting log group {log_group_name}: {e}")

        except Exception as e:
            Logger.logger.error(f"An error occurred while deleting log groups for stack {stack_name}: {e}")
    
    def create_user(self, user_name: str):
        try:
            self.iam.create_user(UserName=user_name)
            Logger.logger.info(f"IAM user {user_name} created successfully.")
        except ClientError as e:
            Logger.logger.error(f"An error occurred while creating IAM user: {e}")
            raise Exception(f"An error occurred while creating IAM user: {e}")
    
    def delete_user(self, user_name: str):
        try:
            self.iam.delete_user(UserName=user_name)
            Logger.logger.info(f"IAM user {user_name} deleted successfully.")
        except ClientError as e:
            Logger.logger.error(f"An error occurred while deleting IAM user: {e}")
            raise Exception(f"An error occurred while deleting IAM user: {e}")
        
    def create_stackset(self, template_url: str, parameters: List[Dict[str, str]], stackset_name: str = None, 
                       organizational_unit_ids: List[str] = None, account_ids: List[str] = None,
                       regions: List[str] = None, operation_preferences: Dict = None):
        """
        Creates a CloudFormation StackSet container (Step 1) for SERVICE_MANAGED permission model.
        """
        Logger.logger.info(self.get_caller_identity())
        try:
            # Required parameters for SERVICE_MANAGED stacksets with delegated admin
            create_stack_set_params = {
                'StackSetName': stackset_name,
                'TemplateURL': template_url,
                'Parameters': parameters,
                'Capabilities': ['CAPABILITY_NAMED_IAM'],
                'PermissionModel': 'SERVICE_MANAGED',
                'CallAs': 'DELEGATED_ADMIN',  # CRITICAL: This was missing!
                'AutoDeployment': {           # CRITICAL: This was missing!
                    'Enabled': True,
                    'RetainStacksOnAccountRemoval': False
                }
            }
            
            response = self.cloudformation.create_stack_set(**create_stack_set_params)
            Logger.logger.info(f"StackSet container '{stackset_name}' created successfully.")
            return response.get("StackSetId")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NameAlreadyExistsException':
                Logger.logger.warning(f"StackSet '{stackset_name}' already exists. Reusing it.")
                stack_set_details = self.describe_stackset(stackset_name)
                return stack_set_details.get('StackSetId') if stack_set_details else None
            Logger.logger.error(f"An error occurred during StackSet creation: {e}")
            return None

    def create_stack_instances(self, stackset_name: str, regions: List[str],
                               organizational_unit_ids: List[str] = None,
                               account_ids: List[str] = None,
                               operation_preferences: Dict = None):
        """
        Creates stack instances in specified accounts/OUs and regions (Step 2).
        """
        if not (organizational_unit_ids or account_ids):
            Logger.logger.error("Either 'organizational_unit_ids' or 'account_ids' must be provided.")
            return None

        deployment_targets = {}
        if organizational_unit_ids:
            deployment_targets['OrganizationalUnitIds'] = organizational_unit_ids
        if account_ids:
            deployment_targets['Accounts'] = account_ids

        if operation_preferences is None:
            operation_preferences = {'FailureTolerancePercentage': 0, 'MaxConcurrentPercentage': 100}

        try:
            create_instances_params = {
                'StackSetName': stackset_name,
                'DeploymentTargets': deployment_targets,
                'Regions': regions,
                'OperationPreferences': operation_preferences,
                'CallAs': 'DELEGATED_ADMIN' 
            }
            
            response = self.cloudformation.create_stack_instances(**create_instances_params)
            operation_id = response.get('OperationId')
            Logger.logger.info(f"Stack instances creation initiated with operation ID: {operation_id}")
            return operation_id
            
        except ClientError as e:
            Logger.logger.error(f"Failed to create stack instances: {e}")
            return None

    def create_and_deploy_stackset(self, stackset_name: str, template_url: str, parameters: List[Dict[str, str]],
                                   regions: List[str], organizational_unit_ids: List[str] = None,
                                   account_ids: List[str] = None,skip_wait: bool = False) -> (str,str):
        """
        Wrapper function to create a StackSet and deploy its instances in one go.
        Returns 'SUCCEEDED' on success, or detailed failure message on failure.
        """
        Logger.logger.info(f"Starting creation and deployment for StackSet: {stackset_name}")

        stack_set_id = self.create_stackset(
            template_url=template_url,
            parameters=parameters,
            stackset_name=stackset_name
        )
        if not stack_set_id:
            error_msg = "Failed to create the StackSet container. Aborting deployment."
            Logger.logger.error(error_msg)
            return error_msg, None

        # Get detailed StackSet information
        self.diagnose_stackset_info(stackset_name)

        # Optionally, also get recent operations summary
        self.get_stackset_operations_summary(stackset_name)

        operation_id = self.create_stack_instances(
            stackset_name=stackset_name,
            regions=regions,
            organizational_unit_ids=organizational_unit_ids,
            account_ids=account_ids
        )
        if not operation_id:
            error_msg = "Failed to initiate StackSet instance creation."
            Logger.logger.error(error_msg)
            return error_msg, None
        if skip_wait:
            return 'SKIPPED' ,operation_id

        Logger.logger.info(f"Waiting for operation {operation_id} to complete...")
        result = self.wait_for_stackset_operation(stackset_name, operation_id)
      
    
        if result == 'SUCCEEDED':
            return 'SUCCEEDED', None
        else:
            # Get detailed failure information
            try:
                operation_details = self.get_stackset_operation_status(stackset_name, operation_id)
                if operation_details and operation_details != 'SUCCEEDED':
                    return f"StackSet deployment failed with status: {operation_details}", None
                else:
                    return f"StackSet deployment failed with status: {result}"
            except Exception as e:
                return f"StackSet deployment failed with status: {result}. Error getting details: {e}", None

    def update_stack_set(self, stackset_name: str, template_url: str = None, parameters: List[Dict[str, str]] = None,
                         organizational_unit_ids: List[str] = None, account_ids: List[str] = None,
                         regions: List[str] = None, operation_preferences: Dict = None):
        """
        Update a CloudFormation StackSet configuration.
        """
        try:
            update_params = {
                'StackSetName': stackset_name,
                'CallAs': 'DELEGATED_ADMIN'
            }
            if template_url: update_params['TemplateURL'] = template_url
            if parameters: update_params['Parameters'] = parameters
            if regions: update_params['Regions'] = regions
            if operation_preferences: update_params['OperationPreferences'] = operation_preferences
            
            if organizational_unit_ids or account_ids:
                deployment_targets = {}
                if organizational_unit_ids: deployment_targets['OrganizationalUnitIds'] = organizational_unit_ids
                if account_ids: deployment_targets['Accounts'] = account_ids
                update_params['DeploymentTargets'] = deployment_targets

            response = self.cloudformation.update_stack_set(**update_params)
            
            Logger.logger.info(f"StackSet update initiated for: {stackset_name}")
            return response.get("OperationId")
        except ClientError as e:
            Logger.logger.error(f"An error occurred during StackSet update: {e}")
            return None
    
    def delete_stacksets_by_names(self, stackset_names: List[str]) -> bool:
        """
        Delete multiple StackSets by searching for them and using their original deployment configuration.
        Returns True if all deletions succeeded, False otherwise.
        """
        Logger.logger.info(f"🗑️  Starting deletion of {len(stackset_names)} StackSets...")
        
        all_successful = True
        
        for stackset_name in stackset_names:
            Logger.logger.info(f"Processing StackSet: {stackset_name}")
            success = self.delete_stackset_with_discovery(stackset_name)
            if not success:
                all_successful = False
                Logger.logger.error(f"❌ Failed to delete StackSet: {stackset_name}")
            else:
                Logger.logger.info(f"✅ Successfully deleted StackSet: {stackset_name}")
        
        return all_successful

    def delete_stackset_with_discovery(self, stackset_name: str) -> bool:
        """
        Delete a single StackSet by discovering its deployment configuration first.
        """
        try:
            # Step 1: Check if StackSet exists
            stackset_info = self._get_stackset_deployment_info(stackset_name)
            if not stackset_info:
                Logger.logger.warning(f"StackSet {stackset_name} not found - skipping")
                return True  # Consider this successful (already cleaned up)
            
            # Step 2: Delete stack instances using discovered configuration
            if stackset_info['instances']:
                success = self._delete_stack_instances_properly(stackset_name, stackset_info)
                if not success:
                    return False
            
            # Step 3: Delete the StackSet container
            return self._delete_stackset_container(stackset_name)
            
        except Exception as e:
            Logger.logger.error(f"Unexpected error deleting StackSet {stackset_name}: {e}")
            return False

    def _get_stackset_deployment_info(self, stackset_name: str) -> dict:
        """
        Get StackSet deployment information including instances and their targets.
        """
        try:
            Logger.logger.info(f"🔍 Discovering deployment info for StackSet: {stackset_name}")
            
            # Get StackSet details
            try:
                stackset_response = self.cloudformation.describe_stack_set(
                    StackSetName=stackset_name,
                    CallAs='DELEGATED_ADMIN'
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'StackSetNotFoundException':
                    Logger.logger.info(f"StackSet {stackset_name} not found")
                    return None
                raise
            
            stackset = stackset_response['StackSet']
            permission_model = stackset.get('PermissionModel', 'UNKNOWN')
            
            Logger.logger.info(f"StackSet permission model: {permission_model}")
            
            # Get stack instances
            instances_response = self.cloudformation.list_stack_instances(
                StackSetName=stackset_name,
                CallAs='DELEGATED_ADMIN'
            )
            
            instances = instances_response.get('Summaries', [])
            Logger.logger.info(f"Found {len(instances)} stack instances")
            
            # Organize deployment information
            deployment_info = {
                'stackset_name': stackset_name,
                'permission_model': permission_model,
                'instances': instances,
                'regions': list(set([instance['Region'] for instance in instances])),
                'accounts': list(set([instance['Account'] for instance in instances])),
                'organizational_unit_ids': stackset.get('OrganizationalUnitIds', [])
            }
            
            Logger.logger.info(f"Deployment info: {len(deployment_info['regions'])} regions, "
                            f"{len(deployment_info['accounts'])} accounts, "
                            f"{len(deployment_info['organizational_unit_ids'])} OUs")
            
            return deployment_info
            
        except Exception as e:
            Logger.logger.error(f"Failed to get deployment info for {stackset_name}: {e}")
            return None

    def _delete_stack_instances_properly(self, stackset_name: str, deployment_info: dict) -> bool:
        """
        Delete stack instances using the correct targeting method based on permission model.
        """
        try:
            instances = deployment_info['instances']
            permission_model = deployment_info['permission_model']
            regions = deployment_info['regions']
            
            Logger.logger.info(f"Deleting {len(instances)} stack instances...")
            Logger.logger.info(f"Permission model: {permission_model}")
            Logger.logger.info(f"Targeting regions: {regions}")
            
            # Prepare deletion parameters based on permission model
            delete_params = {
                'StackSetName': stackset_name,
                'Regions': regions,
                'RetainStacks': False,
                'CallAs': 'DELEGATED_ADMIN',
                'OperationPreferences': {
                    'RegionConcurrencyType': 'PARALLEL',
                    'MaxConcurrentPercentage': 100,
                    'FailureToleranceCount': 0
                }
            }
            
            if permission_model == 'SERVICE_MANAGED':
                # For SERVICE_MANAGED, we need to use DeploymentTargets
                deployment_targets = {}
                
                # Use organizational unit IDs if available
                if deployment_info['organizational_unit_ids']:
                    deployment_targets['OrganizationalUnitIds'] = deployment_info['organizational_unit_ids']
                    deployment_targets['AccountFilterType'] = 'UNION'
                    # AWS requires Accounts to be specified even when using OUs for deletion
                    deployment_targets['Accounts'] = deployment_info['accounts']
                    Logger.logger.info(f"Using OU targets: {deployment_info['organizational_unit_ids']}")
                    Logger.logger.info(f"Including accounts for deletion: {deployment_info['accounts']}")
                else:
                    # If no OUs configured on StackSet, we need to discover them from instances
                    ou_ids = self._discover_ous_from_instances(instances)
                    if ou_ids:
                        deployment_targets['OrganizationalUnitIds'] = ou_ids
                        deployment_targets['AccountFilterType'] = 'UNION'
                        deployment_targets['Accounts'] = deployment_info['accounts']
                        Logger.logger.info(f"Discovered OU targets from instances: {ou_ids}")
                        Logger.logger.info(f"Including accounts for deletion: {deployment_info['accounts']}")
                    else:
                        Logger.logger.error("Cannot determine OU targets for SERVICE_MANAGED StackSet")
                        return False
                
                delete_params['DeploymentTargets'] = deployment_targets
                
            else:
                # For SELF_MANAGED, use account list
                delete_params['Accounts'] = deployment_info['accounts']
                Logger.logger.info(f"Using account targets: {deployment_info['accounts']}")
            
            Logger.logger.info(f"Delete parameters: {delete_params}")
            
            # Execute deletion
            delete_response = self.cloudformation.delete_stack_instances(**delete_params)
            operation_id = delete_response.get('OperationId')
            
            if operation_id:
                Logger.logger.info(f"Stack instances deletion initiated. Operation ID: {operation_id}")
                
                # Wait for deletion to complete
                result = self.wait_for_stackset_operation(stackset_name, operation_id)
                if result == 'SUCCEEDED':
                    Logger.logger.info("Stack instances deleted successfully")
                    return True
                else:
                    Logger.logger.error(f"Stack instances deletion failed: {result}")
                    return False
            else:
                Logger.logger.error("No operation ID returned from delete_stack_instances")
                return False
            
        except ClientError as e:
            Logger.logger.error(f"AWS error deleting stack instances: {e}")
            Logger.logger.error(f"Error code: {e.response['Error']['Code']}")
            Logger.logger.error(f"Error message: {e.response['Error']['Message']}")
            return False
        except Exception as e:
            Logger.logger.error(f"Unexpected error deleting stack instances: {e}")
            return False
    def _discover_ous_from_instances(self, instances: List[dict]) -> List[str]:
        """
        Try to discover organizational unit IDs from the account IDs in instances.
        This is a fallback when OU info is not available on the StackSet.
        """
        try:
            Logger.logger.info("🔍 Trying to discover OUs from instance accounts...")
            
            unique_accounts = list(set([instance['Account'] for instance in instances]))
            Logger.logger.info(f"Checking {len(unique_accounts)} unique accounts")
            
            discovered_ous = set()
            
            for account_id in unique_accounts:
                try:
                    # List parents for this account
                    parents_response = self.organizations.list_parents(
                        ChildId=account_id
                    )
                    
                    for parent in parents_response.get('Parents', []):
                        if parent['Type'] == 'ORGANIZATIONAL_UNIT':
                            discovered_ous.add(parent['Id'])
                            Logger.logger.info(f"Account {account_id} is in OU {parent['Id']}")
                    
                except Exception as e:
                    Logger.logger.warning(f"Could not get parents for account {account_id}: {e}")
            
            ou_list = list(discovered_ous)
            Logger.logger.info(f"Discovered OUs: {ou_list}")
            return ou_list
            
        except Exception as e:
            Logger.logger.error(f"Failed to discover OUs from instances: {e}")
        return []

    def _delete_stackset_container(self, stackset_name: str) -> bool:
        """
        Delete the StackSet container after all instances are removed.
        """
        try:
            Logger.logger.info(f"🗑️  Deleting StackSet container: {stackset_name}")
            
            self.cloudformation.delete_stack_set(
                StackSetName=stackset_name,
                CallAs='DELEGATED_ADMIN'
            )
            
            Logger.logger.info(f"✅ StackSet {stackset_name} container deleted successfully")
            return True
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'StackSetNotFoundException':
                Logger.logger.info(f"StackSet {stackset_name} not found during container deletion - already cleaned up")
                return True
            else:
                Logger.logger.error(f"Error deleting StackSet container {stackset_name}: {e}")
                return False
        except Exception as e:
            Logger.logger.error(f"Unexpected error deleting StackSet container {stackset_name}: {e}")
            return False
    
    def wait_for_stackset_operation(self, stackset_name: str, operation_id: str, delay: int = 15, max_attempts: int = 80):
        """
        Wait for a StackSet operation to complete.
        """
        try:
            for attempt in range(max_attempts):
                response = self.cloudformation.describe_stack_set_operation(
                    StackSetName=stackset_name,
                    OperationId=operation_id,
                    CallAs='DELEGATED_ADMIN'
                )
                status = response['StackSetOperation']['Status']
                
                if status == 'SUCCEEDED':
                    Logger.logger.info(f"StackSet operation {operation_id} completed successfully.")
                    return status
                elif status in ['FAILED', 'STOPPED']:
                    Logger.logger.error(f"StackSet operation {operation_id} finished with status: {status} , status reason: {response['StackSetOperation']['StatusReason']}")
                    return status
                
                Logger.logger.info(f"StackSet operation status is '{status}'. Waiting... (attempt {attempt + 1}/{max_attempts})")
                time.sleep(delay)
            
            Logger.logger.error(f"StackSet operation {operation_id} timed out after {max_attempts} attempts.")
            return 'TIMED_OUT'
        except ClientError as e:
            Logger.logger.error(f"An error occurred while waiting for StackSet operation: {e}")
            return False

    def list_stacksets(self):
        """
        List all StackSets in the account
        
        Returns:
            List of StackSet summaries
        """
        try:
            response = self.cloudformation.list_stack_sets(CallAs='DELEGATED_ADMIN')
            return response.get('Summaries', [])
        except ClientError as e:
            Logger.logger.error(f"An error occurred while listing StackSets: {e}")
            return []

    def describe_stackset(self, stackset_name: str):
        """
        Get detailed information about a StackSet with delegated admin permissions.
        """
        try:
            response = self.cloudformation.describe_stack_set(
                StackSetName=stackset_name,
                CallAs='DELEGATED_ADMIN'
            )
            return response.get('StackSet', {})
        except ClientError as e:
            Logger.logger.error(f"Error describing StackSet {stackset_name}: {e}")
            return None
    
    def update_stackset_external_id(self, stackset_name: str, new_external_id: str):
        """
        Update the External ID parameter for an existing StackSet
        
        Args:
            stackset_name: Name of the StackSet to update
            new_external_id: New External ID value
        
        Returns:
            Operation ID if successful, None otherwise
        """
        parameters = [
            {
                'ParameterKey': 'ExternalID',
                'ParameterValue': new_external_id
            }
        ]
        
        return self.update_stackset(
            stackset_name=stackset_name,
            parameters=parameters
        )

    def list_stack_instances(self, stackset_name: str):
        """
        List all stack instances for a StackSet.
        """
        try:
            paginator = self.cloudformation.get_paginator('list_stack_instances')
            instances = []
            for page in paginator.paginate(
                StackSetName=stackset_name,
                CallAs='DELEGATED_ADMIN'
            ):
                instances.extend(page['Summaries'])
            return instances
        except ClientError as e:
            Logger.logger.error(f"An error occurred while listing stack instances: {e}")
            return []

    def get_stackset_operation_status(self, stackset_name: str, operation_id: str):
        """
        Get the status of a StackSet operation
        
        Args:
            stackset_name: Name of the StackSet
            operation_id: Operation ID to check
        
        Returns:
            Operation status or None if error
        """
        try:
            response = self.cloudformation.describe_stack_set_operation(
                StackSetName=stackset_name,
                OperationId=operation_id,
                CallAs='DELEGATED_ADMIN'
            )
            return response.get('StackSetOperation', {}).get('Status')
        except ClientError as e:
            Logger.logger.error(f"An error occurred while getting operation status: {e}")
            return None
        
    def diagnose_stackset_info(self, stackset_name: str):
        """
        Get detailed StackSet information for debugging.
        """
        try:
            Logger.logger.info(f"📋 Getting detailed StackSet information for: {stackset_name}")
            
            response = self.cloudformation.describe_stack_set(
                StackSetName=stackset_name,
                CallAs='DELEGATED_ADMIN'
            )
            
            stackset = response['StackSet']
            
            # Basic info
            Logger.logger.info(f"StackSet Name: {stackset['StackSetName']}")
            Logger.logger.info(f"StackSet ID: {stackset.get('StackSetId', 'Not available')}")
            Logger.logger.info(f"Status: {stackset['Status']}")
            Logger.logger.info(f"Permission Model: {stackset.get('PermissionModel', 'Not specified')}")
            
            # Auto deployment settings
            auto_deployment = stackset.get('AutoDeployment', {})
            Logger.logger.info(f"Auto Deployment Enabled: {auto_deployment.get('Enabled', False)}")
            Logger.logger.info(f"Retain Stacks on Account Removal: {auto_deployment.get('RetainStacksOnAccountRemoval', 'Not specified')}")
            
            # Organizational settings
            org_unit_ids = stackset.get('OrganizationalUnitIds', [])
            Logger.logger.info(f"Organizational Unit IDs: {org_unit_ids if org_unit_ids else 'None'}")
            
            # Capabilities
            capabilities = stackset.get('Capabilities', [])
            Logger.logger.info(f"Capabilities: {capabilities}")
            
            # Parameters
            parameters = stackset.get('Parameters', [])
            Logger.logger.info(f"Parameters count: {len(parameters)}")
            for param in parameters:
                param_key = param.get('ParameterKey', 'Unknown')
                param_value = param.get('ParameterValue', 'Unknown')
                # Mask sensitive values
                if 'password' in param_key.lower() or 'secret' in param_key.lower() or 'key' in param_key.lower():
                    param_value = '***MASKED***'
                Logger.logger.info(f"  - {param_key}: {param_value}")
            
            # Template description
            description = stackset.get('Description', 'No description')
            Logger.logger.info(f"Description: {description}")
            
            # Drift detection
            drift_detection = stackset.get('StackSetDriftDetectionDetails', {})
            if drift_detection:
                Logger.logger.info(f"Drift Detection Status: {drift_detection.get('DriftStatus', 'Not available')}")
                Logger.logger.info(f"Drift Detection Time: {drift_detection.get('LastDriftCheckTimestamp', 'Not available')}")
            
            # Operation preferences (if any)
            operation_preferences = stackset.get('OperationPreferences', {})
            if operation_preferences:
                Logger.logger.info("Default Operation Preferences:")
                for key, value in operation_preferences.items():
                    Logger.logger.info(f"  - {key}: {value}")
            
            # Managed execution
            managed_execution = stackset.get('ManagedExecution', {})
            if managed_execution:
                Logger.logger.info(f"Managed Execution Active: {managed_execution.get('Active', False)}")
            
            Logger.logger.info("✅ StackSet info diagnosis completed")
            return stackset
            
        except ClientError as e:
            Logger.logger.error(f"❌ Failed to get StackSet info: {e}")
            Logger.logger.error(f"Error code: {e.response['Error']['Code']}")
            Logger.logger.error(f"Error message: {e.response['Error']['Message']}")
            return None
        except Exception as e:
            Logger.logger.error(f"❌ Unexpected error getting StackSet info: {e}")
            return None

    def get_stackset_operations_summary(self, stackset_name: str, max_results: int = 5):
        """
        Get a summary of recent StackSet operations.
        """
        try:
            Logger.logger.info(f"📝 Getting recent operations for StackSet: {stackset_name}")
            
            response = self.cloudformation.list_stack_set_operations(
                StackSetName=stackset_name,
                CallAs='DELEGATED_ADMIN',
                MaxResults=max_results
            )
            
            operations = response.get('Summaries', [])
            Logger.logger.info(f"Found {len(operations)} recent operations:")
            
            for i, op in enumerate(operations, 1):
                op_id = op['OperationId']
                status = op['Status']
                action = op['Action']
                creation_time = op['CreationTimestamp']
                end_time = op.get('EndTimestamp', 'In progress')
                
                status_emoji = "✅" if status == "SUCCEEDED" else "❌" if status == "FAILED" else "⏳"
                
                Logger.logger.info(f"  {i}. {status_emoji} Operation {op_id}")
                Logger.logger.info(f"     Action: {action}")
                Logger.logger.info(f"     Status: {status}")
                Logger.logger.info(f"     Created: {creation_time}")
                Logger.logger.info(f"     Ended: {end_time}")
                
                if 'StatusReason' in op and op['StatusReason']:
                    Logger.logger.info(f"     Reason: {op['StatusReason']}")
            
            return operations
            
        except ClientError as e:
            Logger.logger.error(f"❌ Failed to get operations: {e}")
            return []
        except Exception as e:
            Logger.logger.error(f"❌ Unexpected error getting operations: {e}")
            return []
    
    def update_role_external_id(self, role_arn: str, new_external_id: str) -> bool:
        """
        Update the External ID in an IAM role's trust policy directly.
        
        Args:
            role_arn: The ARN of the IAM role to update
            new_external_id: The new external ID value to set
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            Logger.logger.info(f"Updating external ID for role {role_arn} to {new_external_id}")
            
            # Extract role name from ARN
            split_role_name = role_arn.split('/')[-1]
            Logger.logger.info(f"Extracted role name: {split_role_name}")
            
            # Step 1: Get the current trust policy
            response = self.iam.get_role(RoleName=split_role_name)
            role = response['Role']
            
            import json
            
            # Handle both dict and URL-encoded string formats
            assume_role_policy = role['AssumeRolePolicyDocument']
            if isinstance(assume_role_policy, dict):
                trust_policy = assume_role_policy
            else:
                # If it's a string, it might be URL-encoded
                import urllib.parse
                current_policy = urllib.parse.unquote(assume_role_policy)
                trust_policy = json.loads(current_policy)
            
            Logger.logger.info(f"Current trust policy: {json.dumps(trust_policy, indent=2)}")
            
            # Step 2: Update the external ID in the trust policy
            updated = False
            for statement in trust_policy.get('Statement', []):
                condition = statement.get('Condition', {})
                string_equals = condition.get('StringEquals', {})
                
                # Look for sts:ExternalId condition
                if 'sts:ExternalId' in string_equals:
                    old_external_id = string_equals['sts:ExternalId']
                    string_equals['sts:ExternalId'] = new_external_id
                    updated = True
                    Logger.logger.info(f"Updated sts:ExternalId from {old_external_id} to {new_external_id}")
            
            if not updated:
                Logger.logger.warning(f"No sts:ExternalId found in trust policy for role {role_arn}")
                return False
            
            # Step 3: Update the role's trust policy
            self.iam.update_assume_role_policy(
                RoleName=split_role_name,
                PolicyDocument=json.dumps(trust_policy)
            )
            
            Logger.logger.info(f"Successfully updated external ID for role {role_arn}")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            Logger.logger.error(f"AWS error updating role {role_arn}: {error_code} - {error_message}")
            return False
        except Exception as e:
            Logger.logger.error(f"Unexpected error updating role {role_arn}: {e}")
            return False

    def get_role_external_id_by_arn(self, role_arn: str) -> str:
        """
        Get the current external ID from an IAM role's trust policy.
        
        Args:
            role_arn: The ARN of the IAM role
        
        Returns:
            str: The external ID if found, None otherwise
        """
        try:
            # Extract role name from ARN
            split_role_name = role_arn.split('/')[-1]
            Logger.logger.info(f"Extracted role name from ARN {role_arn}: {split_role_name}")
            
            response = self.iam.get_role(RoleName=split_role_name)
            role = response['Role']
            
            import json
            
            # Handle both dict and URL-encoded string formats
            assume_role_policy = role['AssumeRolePolicyDocument']
            if isinstance(assume_role_policy, dict):
                trust_policy = assume_role_policy
            else:
                # If it's a string, it might be URL-encoded
                import urllib.parse
                current_policy = urllib.parse.unquote(assume_role_policy)
                trust_policy = json.loads(current_policy)
            
            # Look for sts:ExternalId in the trust policy
            for statement in trust_policy.get('Statement', []):
                condition = statement.get('Condition', {})
                string_equals = condition.get('StringEquals', {})
                
                if 'sts:ExternalId' in string_equals:
                    external_id = string_equals['sts:ExternalId']
                    Logger.logger.info(f"Found external ID for role {role_arn}: {external_id}")
                    return external_id
            
            Logger.logger.warning(f"No external ID found in trust policy for role {role_arn}")
            return None
            
        except Exception as e:
            Logger.logger.error(f"Error getting external ID for role {role_arn}: {e}")
            return None

    def check_snapshot_by_tags(self, tags: Dict[str, str], owner_ids: List[str] = None) -> str:
        """
        Check if a snapshot exists with specific tags and return its ID
        
        Args:
            tags: Dictionary of tag key-value pairs to filter by
            owner_ids: List of AWS account IDs to filter snapshots by owner (optional)
                      If None, defaults to 'self' (current account)
        
        Returns:
            Snapshot ID if found, empty string if not found
        """
        try:
            # Build filters for tags
            filters = []
            for key, value in tags.items():
                filters.append({
                    'Name': f'tag:{key}',
                    'Values': [value]
                })
            
            # Set default owner to current account if not specified
            if owner_ids is None:
                account_id = self.get_account_id()
                if account_id:
                    owner_ids = [account_id]
                else:
                    owner_ids = ['self']
            
            # Get snapshots with the specified filters
            response = self.ec2.describe_snapshots(
                Filters=filters,
                OwnerIds=owner_ids
            )
            
            snapshots = response.get('Snapshots', [])
            
            if snapshots:
                snapshot_id = snapshots[0].get('SnapshotId', '')
                Logger.logger.info(f"Found snapshot with specified tags: {snapshot_id}")
                return snapshot_id
            else:
                Logger.logger.info("No snapshots found with the specified tags")
                return ""
            
        except ClientError as e:
            Logger.logger.error(f"An error occurred while checking for snapshots: {e}")
            return ""


def extract_account_id(arn):
    """
    Extracts the AWS account ID from an IAM ARN string.
    """
    match = re.search(r"arn:aws:iam::(\d{12}):", arn)
    return match.group(1) if match else None

def extract_account_id_from_traillog_arn(arn: str):
    """
    Extracts the AWS account ID from a CloudTrail ARN string.
    """
    match = re.search(r":(\d{12}):trail/", arn)
    return match.group(1) if match else None
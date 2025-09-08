import json
import os
import uuid
import boto3
from botocore.exceptions import ClientError
import time
from urllib.parse import urlparse, parse_qs
from systest_utils import Logger
import re
from typing import List, Tuple, Any, Dict


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
        self.ec2 = self.base_session.client('ec2')

    def assume_role_in_account(self, target_account_id: str, role_name: str = "OrganizationAccountAccessRole", session_name: str = "CrossAccountSession"):
        """
        Assume a role in a target account and return new manager instance
        
        Args:
            target_account_id: The 12-digit account ID to assume role in
            role_name: The role name to assume (default: OrganizationAccountAccessRole)
            session_name: A unique session name for this assumption
        
        Returns:
            New CloudFormationManager instance with assumed role credentials
        """
        try:
            # Construct the role ARN
            role_arn = f"arn:aws:iam::{target_account_id}:role/{role_name}"
            
            # Assume the role
            response = self.sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=3600  # 1 hour (adjust as needed)
            )
            
            # Extract temporary credentials
            credentials = response['Credentials']
            
            # Create new manager instance with assumed role credentials
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
            org_client = self.base_session.client('organizations')
            response = org_client.list_accounts()
            return response['Accounts']
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

    def wait_for_stack_creation(self, stack_name, delay=15, max_attempts=80):
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

    def get_stack_failure_reason(self, stack_name):
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

    def get_stack_output_role_arn(self, stack_name):
        return self.get_stack_output(stack_name, "ArmoRoleArn")
    
    def get_stack_output(self, stack_name, output_key):
        try:
            # Describe the stack to fetch outputs
            response = self.cloudformation.describe_stacks(StackName=stack_name)

            # Retrieve the outputs section
            stacks = response.get("Stacks", [])
            if not stacks:
                Logger.logger.error("No stacks found.")
                return None

            # Assuming only one stack is returned (by stack_name)
            stack = stacks[0]
            outputs = stack.get("Outputs", [])

            # Extract ARN from outputs (if available)
            for output in outputs:
                if output_key == output.get("OutputKey"):
                    return output.get("OutputValue")

            Logger.logger.error(f"No output found with key '{output_key}' in stack outputs.")
            return None

        except ClientError as e:
            Logger.logger.error(f"An error occurred: {e}")
            return None

    def delete_stack(self, stack_name):
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
    Extracts the AWS account ID from an ARN string.

    :param arn: The ARN string (e.g., "arn:aws:iam::12345678:role/armo-scan-role-cross-with_customer-12345678")
    :return: The extracted account ID as a string or None if not found.
    """
    match = re.search(r"arn:aws:iam::(\d+):", arn)
    return match.group(1) if match else None


def extract_account_id_from_traillog_arn(arn):
    """
    Extracts the AWS account ID from an ARN string.

    :param arn: The ARN string (e.g., "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail")
    :return: The extracted account ID as a string or None if not found.
    """
    match = re.search(r"arn:aws:cloudtrail:\w+-\w+-\d+:(\d+):", arn)
    return match.group(1) if match else None

    
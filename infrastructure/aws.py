import os
import boto3
from botocore.exceptions import ClientError
import time
from urllib.parse import urlparse, parse_qs
from systest_utils import Logger
import re



class CloudFormationManager:
    def __init__(self, url, aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None):
        self.stack_name, self.template_url, self.region, self.parameters = self.extract_parameters_from_url(url)
        self.cloudformation = boto3.client(
            "cloudformation",
            region_name=self.region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token
        )

    def extract_parameters_from_url(self, url):
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

    def create_stack(self, stack_name=None):
        try:
            if stack_name:
                self.stack_name = stack_name
            # Create the stack
            response = self.cloudformation.create_stack(
                StackName=self.stack_name,
                TemplateURL=self.template_url,
                Parameters=self.parameters,
                Capabilities=["CAPABILITY_NAMED_IAM"] # Required for creating IAM resources
            )
            Logger.logger.info(f"Stack creation initiated for: {self.stack_name}")
            return response["StackId"]

        except ClientError as e:
            Logger.logger.error(f"An error occurred during stack creation: {e}")
            return None

    def wait_for_stack_creation(self, delay=15, max_attempts=80):
        try:
            # Wait for the stack creation to complete
            Logger.logger.info(f"Waiting for stack {self.stack_name} to be created...")
            waiter = self.cloudformation.get_waiter("stack_create_complete")
            waiter.wait(StackName=self.stack_name,
                        WaiterConfig={
                            "Delay": delay,  # Polling interval in seconds
                            "MaxAttempts": max_attempts  # Maximum number of attempts (total time = Delay * MaxAttempts)
                        })
            Logger.logger.info(f"Stack {self.stack_name} created successfully.")

        except ClientError as e:
            Logger.logger.error(f"An error occurred while waiting for stack creation: {e}")
            raise e

    def get_stack_output_role_arn(self):
        return self.get_stack_output("RoleArn")
    
    def get_stack_output(self, output_key):
        try:
            # Describe the stack to fetch outputs
            response = self.cloudformation.describe_stacks(StackName=self.stack_name)

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

    def delete_stack(self):
        try:
            # Delete the stack
            Logger.logger.info(f"Deleting stack {self.stack_name}...")
            self.cloudformation.delete_stack(StackName=self.stack_name)

            # Wait for the stack deletion to complete
            waiter = self.cloudformation.get_waiter("stack_delete_complete")
            waiter.wait(StackName=self.stack_name)
            Logger.logger.info(f"Stack {self.stack_name} deleted successfully.")

        except ClientError as e:
            Logger.logger.error(f"An error occurred while deleting the stack: {e}")
            raise e




def extract_account_id(arn):
    """
    Extracts the AWS account ID from an ARN string.

    :param arn: The ARN string (e.g., "arn:aws:iam::12345678:role/armo-scan-role-cross-with_customer-12345678")
    :return: The extracted account ID as a string or None if not found.
    """
    match = re.search(r"arn:aws:iam::(\d+):", arn)
    return match.group(1) if match else None


import time
import uuid
from typing import List, Dict, Any, Union
from infrastructure import aws
from systest_utils import Logger
from .cspm_test_models import PROVIDER_AWS, AwsStackResponse, AwsMembersStackResponse, AWSOrgCreateCloudOrganizationAdminRequest, CreateOrUpdateCloudOrganizationResponse, ConnectCloudOrganizationMembersRequest


class AwsAccountsMixin:
    """AWS-specific methods for Accounts class."""

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

    def create_stack_cspm(self, aws_manager: aws.AwsManager, stack_name: str, template_url: str, parameters: List[Dict[str, Any]]) -> str:
        generated_role_name = self.generate_timestamped_role_name(role_prefix="armo-scan-role")
        parameters.append({"ParameterKey": "RoleName", "ParameterValue": generated_role_name})
        self.create_stack(aws_manager, stack_name, template_url, parameters)
        test_arn = aws_manager.get_stack_output_role_arn(stack_name)
        return test_arn

    def create_stack(self, aws_manager: aws.AwsManager, stack_name: str, template_url: str, parameters: List[Dict[str, str]]) -> str:
        from .accounts import StackRef
        Logger.logger.info(f"Initiating stack creation: {stack_name}, template_url: {template_url}, parameters: {parameters}")
        stack_id = aws_manager.create_stack(template_url, parameters, stack_name)
        assert stack_id, f"failed to create stack {stack_name}"
        Logger.logger.info(f"Stack creation initiated for: {stack_name}, stack id is {stack_id}")
        try:
            aws_manager.wait_for_stack_creation(stack_name)
        except Exception as e:
            Logger.logger.error(f"An error occurred while waiting for stack creation: {e}")
            failure_reason = aws_manager.get_stack_failure_reason(stack_name)
            Logger.logger.error(f"Stack failure reason: {failure_reason}")
            raise Exception(f"failed to create stack {stack_name}, failure_reason is {failure_reason}, exception is {e}")
        self.tested_stack_refs.append(StackRef(manager=aws_manager, stack_name=stack_name, region=aws_manager.region))

    def create_and_validate_cloud_account_with_cspm_aws(self, cloud_account_name: str, arn: str, region: str, external_id: str = "", skip_scan: bool = False, expect_failure: bool = False):
        cspm_config = {
            "crossAccountsRoleARN": arn,
            "stackRegion": region,
        }
        if external_id:
            cspm_config["externalID"] = external_id
        feature_config = {"cspmConfig": cspm_config}
        return self.create_and_validate_cloud_account_with_feature(cloud_account_name, PROVIDER_AWS, feature_config, skip_scan=skip_scan, expect_failure=expect_failure)

    def connect_cspm_vulnscan_new_account(self, region: str, account_id: str, arn: str, cloud_account_name: str, external_id: str, validate_apis: bool = True, is_to_cleanup_accounts: bool = True) -> str:
        if is_to_cleanup_accounts:
            Logger.logger.info(f"Cleaning up existing AWS cloud accounts for account_id {account_id}")
            self.cleanup_existing_cloud_accounts(PROVIDER_AWS, account_id)
        Logger.logger.info(f"Creating and validating CSPM cloud account: {cloud_account_name}, ARN: {arn}, region: {region}, external_id: {external_id}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm_vulnscan(cloud_account_name, arn, PROVIDER_AWS, region, external_id, expect_failure=False)
        Logger.logger.info(f"connected cspm to new account {cloud_account_name}, cloud_account_guid is {cloud_account_guid}")
        Logger.logger.info("Validate accounts cloud with cspm list")
        Logger.logger.info(f"validated cspm list for {cloud_account_guid} successfully")
        return cloud_account_guid

    def connect_aws_cspm_new_account(self, region: str, account_id: str, arn: str, cloud_account_name: str, external_id: str, skip_scan: bool = False, validate_apis: bool = True, expect_failure: bool = False, is_to_cleanup_accounts: bool = True) -> str:
        if is_to_cleanup_accounts:
            Logger.logger.info(f"Cleaning up existing AWS cloud accounts for account_id {account_id}")
            self.cleanup_existing_cloud_accounts(PROVIDER_AWS, account_id)
        Logger.logger.info(f"Creating and validating CSPM cloud account: {cloud_account_name}, ARN: {arn}, region: {region}, external_id: {external_id}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm_aws(cloud_account_name, arn, region, external_id, skip_scan, expect_failure)
        Logger.logger.info(f"connected cspm to new account {cloud_account_name}, cloud_account_guid is {cloud_account_guid}")
        Logger.logger.info("Validate accounts cloud with cspm list")
        from .accounts import CSPM_SCAN_STATE_IN_PROGRESS, FEATURE_STATUS_CONNECTED
        self.validate_accounts_cloud_list_cspm_compliance(PROVIDER_AWS, cloud_account_guid, arn, CSPM_SCAN_STATE_IN_PROGRESS, FEATURE_STATUS_CONNECTED, skipped_scan=skip_scan)
        Logger.logger.info(f"validated cspm list for {cloud_account_guid} successfully")
        if validate_apis:
            Logger.logger.info("Validate accounts cloud with cspm unique values")
            self.validate_accounts_cloud_uniquevalues(cloud_account_name)
            Logger.logger.info("Edit name and validate cloud account with cspm")
            self.update_and_validate_cloud_account(PROVIDER_AWS, cloud_account_guid, cloud_account_name + "-updated")
        return cloud_account_guid

    def connect_cspm_single_account_suppose_to_be_blocked(self, region: str, arn: str, external_id: str) -> bool:
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

    def _test_delegated_admin_permissions(self, aws_manager: aws.AwsManager) -> bool:
        Logger.logger.info("Testing delegated admin permissions before StackSet creation...")
        try:
            ous = aws_manager.organizations.list_organizational_units_for_parent(ParentId='r-fo1t')
            Logger.logger.info(f"✅ Can list OUs: {len(ous.get('OrganizationalUnits', []))}")
        except Exception as e:
            Logger.logger.error(f"❌ Cannot list OUs: {e}")
            return False
        try:
            accounts = aws_manager.organizations.list_accounts()
            Logger.logger.info(f"✅ Can list accounts: {len(accounts.get('Accounts', []))}")
        except Exception as e:
            Logger.logger.error(f"❌ Cannot list accounts: {e}")
            return False
        try:
            org = aws_manager.organizations.describe_organization()
            Logger.logger.info(f"✅ Can describe organization: {org.get('Organization', {}).get('Id', 'N/A')}")
        except Exception as e:
            Logger.logger.error(f"❌ Cannot describe organization: {e}")
            return False
        try:
            stacksets = aws_manager.cloudformation.list_stack_sets()
            Logger.logger.info(f"✅ Can list StackSets: {len(stacksets.get('Summaries', []))}")
        except Exception as e:
            Logger.logger.error(f"❌ Cannot list StackSets: {e}")
            return False
        try:
            limits = aws_manager.cloudformation.describe_account_limits()
            Logger.logger.info("✅ Can describe CloudFormation account limits")
        except Exception as e:
            Logger.logger.error(f"❌ Cannot describe CloudFormation account limits: {e}")
            return False
        Logger.logger.info("✅ All delegated admin permission tests passed")
        return True

    def connect_cspm_features_to_org(self, aws_manager: aws.AwsManager, stack_name: str, region: str, features: List[str], org_guid: str, organizational_unit_ids: List[str] = None, account_ids: List[str] = None, skip_wait: bool = False):
        from .accounts import StackSetRef
        if not self._test_delegated_admin_permissions(aws_manager):
            raise Exception("Delegated admin permission tests failed - cannot proceed with StackSet creation")
        aws_response = self.get_org_members_stack_link(region=region, stack_name=stack_name, features=features)
        external_id = aws_response.externalID
        generated_role_name = self.generate_timestamped_role_name(role_prefix="armo-org-member-role")
        parameters = [
            {'ParameterKey': 'ExternalID', 'ParameterValue': external_id},
            {'ParameterKey': 'RoleName', 'ParameterValue': generated_role_name}
        ]
        final_status, operation_id = aws_manager.create_and_deploy_stackset(
            stackset_name=stack_name,
            template_url=aws_response.s3TemplatePath,
            parameters=parameters,
            regions=[region],
            organizational_unit_ids=organizational_unit_ids,
            account_ids=account_ids,
            skip_wait=skip_wait
        )
        if final_status != 'SUCCEEDED' and final_status != 'SKIPPED':
            raise Exception(f"StackSet deployment failed: {final_status}")
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
        stackset_ref = StackSetRef(aws_manager=aws_manager, stackset_name=stack_name, operation_id=operation_id)
        if not any(ref.stackset_name == stack_name for ref in self.tested_stackset_refs):
            self.tested_stackset_refs.append(stackset_ref)
        return generated_role_name, external_id, operation_id

    def connect_cspm_features_to_org_existing_stack_set(self, org_guid: str, member_role_arn: str, member_role_external_id: str, region: str, features: List[str]):
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

    def add_cspm_feature_to_organization(self, aws_manager: aws.AwsManager, stackset_name: str, org_guid: str, new_feature_name: str, with_wait: bool = True, existing_accounts: List[str] = None) -> str:
        from .accounts import COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME, StackSetRef
        Logger.logger.info(f"Adding {new_feature_name} feature to organization {org_guid}")
        existing_org = self.get_cloud_org_by_guid(org_guid)
        existing_cspm_config = None
        existing_region = None
        existing_member_role_arn = None
        existing_member_external_id = None
        existing_feature_name = None
        features = [COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME]
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
        stackset_info = aws_manager._get_stackset_deployment_info(stackset_name)
        if not stackset_info:
            raise Exception(f"Could not get StackSet deployment info for {stackset_name}")
        existing_regions = stackset_info.get('regions', [existing_region])
        existing_ous = stackset_info.get('organizational_unit_ids', [])
        existing_accounts = stackset_info.get('accounts', [])
        existing_parameters = aws_manager.get_stackset_parameters(stackset_name)
        if not existing_parameters:
            raise Exception(f"Could not get existing parameters from StackSet {stackset_name}")
        Logger.logger.info(f"StackSet Regions: {existing_regions}")
        Logger.logger.info(f"StackSet OUs: {existing_ous}")
        Logger.logger.info(f"StackSet Accounts: {existing_accounts}")
        Logger.logger.info(f"StackSet Existing Parameters: {existing_parameters}")
        Logger.logger.info("Getting template link with both CSPM and VulnScan features for organization")
        aws_response = self.get_org_members_stack_link(region=existing_region, stack_name=stackset_name, features=features)
        template_url = aws_response.s3TemplatePath
        Logger.logger.info(f"Updating StackSet {stackset_name} with new template {template_url}")
        Logger.logger.info(f"Template supports features: {features}")
        try:
            update_params = {
                'stackset_name': stackset_name,
                'template_url': template_url,
                'regions': existing_regions
            }
            if existing_ous:
                update_params['organizational_unit_ids'] = existing_ous
                Logger.logger.info(f"Using only OUs for deployment targets: {existing_ous}")
            else:
                Logger.logger.warning("No OUs found in StackSet configuration")
            update_params['parameters'] = existing_parameters
            Logger.logger.info(f"StackSet update parameters: {len(existing_parameters)} parameters")
            operation_id = aws_manager.update_stack_set(**update_params)
            if not any(ref.stackset_name == stackset_name for ref in self.tested_stackset_refs):
                stackset_ref = StackSetRef(aws_manager=aws_manager, stackset_name=stackset_name, operation_id=operation_id)
                self.tested_stackset_refs.append(stackset_ref)
            else:
                for ref in self.tested_stackset_refs:
                    if ref.stackset_name == stackset_name and operation_id:
                        ref.operation_id = operation_id
                        break
            if operation_id and with_wait:
                Logger.logger.info(f"StackSet {stackset_name} update initiated with operation ID: {operation_id}")
                final_status = aws_manager.wait_for_stackset_operation(stackset_name, operation_id)
                if final_status == 'SUCCEEDED':
                    Logger.logger.info(f"StackSet {stackset_name} updated successfully")
                else:
                    aws_manager.get_stackset_instance_errors(stackset_name)
                    raise Exception(f"StackSet update failed with status: {final_status}")
            elif operation_id and not with_wait:
                Logger.logger.info(f"StackSet {stackset_name} update initiated with operation ID: {operation_id} (not waiting for completion)")
            else:
                Logger.logger.warning(f"No operation ID returned for {stackset_name}, checking recent operations...")
                operations = aws_manager.get_stackset_operations(stackset_name)
                if operations:
                    latest_op = operations[0]
                    Logger.logger.info(f"Latest operation: {latest_op}")
                    if latest_op.get('Status') in ['SUCCEEDED', 'RUNNING']:
                        Logger.logger.info(f"Found recent successful/running operation: {latest_op.get('OperationId')}")
                        if with_wait and latest_op.get('Status') == 'RUNNING':
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
        Logger.logger.info(f"Connecting {new_feature_name} feature to organization {org_guid}")
        new_feature_list = [new_feature_name]
        body = ConnectCloudOrganizationMembersRequest(
            orgGUID=org_guid,
            features=new_feature_list,
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
        self.wait_for_report(
            self.validate_org_accounts_have_all_features,
            sleep_interval=30,
            timeout=240,
            org_guid=org_guid,
            account_ids=existing_accounts,
            expected_features=features
        )
        return org_guid

    def add_cspm_feature_to_single_account(self, aws_manager: aws.AwsManager, stack_name: str, cloud_account_guid: str, feature_name: str, skip_scan: bool = True) -> str:
        from .accounts import COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME, extract_parameters_from_url
        Logger.logger.info(f"Adding {feature_name} feature to account {cloud_account_guid}")
        existing_account = self.get_cloud_account_by_guid(cloud_account_guid)
        existing_arn = None
        existing_external_id = None
        existing_region = None
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
        Logger.logger.info("Getting template link with both CSPM and VulnScan features")
        features = [COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME]
        stack_response = self.get_and_validate_cspm_link_with_external_id(features=features, region=existing_region)
        _, template_url, _, _ = extract_parameters_from_url(stack_response.stackLink)
        Logger.logger.info(f"Updating stack {stack_name} with new template {template_url} (template only)")
        Logger.logger.info(f"Template supports features: {features}")
        try:
            aws_manager.update_stack(
                stack_name=stack_name,
                template_url=template_url,
                capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                wait_for_completion=True
            )
            Logger.logger.info(f"Stack {stack_name} updated successfully.")
        except Exception as e:
            Logger.logger.error(f"Failed to update stack {stack_name}: {e}")
            raise
        new_arn = aws_manager.get_stack_output_role_arn(stack_name)
        if not new_arn:
            raise Exception(f"Failed to get role ARN from updated stack {stack_name}")
        Logger.logger.info(f"New role ARN from updated stack: {new_arn}")
        if existing_arn and new_arn != existing_arn:
            raise Exception(f"ARN mismatch: existing={existing_arn}, new={new_arn}")
        Logger.logger.info(f"updating {feature_name} feature for {cloud_account_guid}")
        if feature_name == COMPLIANCE_FEATURE_NAME:
            body = {
                "cspmConfig": {
                    "crossAccountsRoleARN": new_arn,
                    "stackRegion": existing_region,
                    "externalID": existing_external_id
                },
                "skipScan": skip_scan,
            }
        elif feature_name == VULN_SCAN_FEATURE_NAME:
            body = {
                "vulnerabilityScanConfig": {
                    "crossAccountsRoleARN": new_arn,
                    "stackRegion": existing_region,
                    "externalID": existing_external_id
                },
            }
        else:
            raise Exception(f"Unsupported feature name: {feature_name}")
        try:
            res = self.backend.create_cloud_account(body=body, provider=PROVIDER_AWS)
            new_cloud_account_guid = res["guid"]
            assert new_cloud_account_guid == cloud_account_guid, f"{new_cloud_account_guid} is not {cloud_account_guid}"
            if new_cloud_account_guid not in self.test_cloud_accounts_guids:
                self.test_cloud_accounts_guids.append(new_cloud_account_guid)
            Logger.logger.info(f"Successfully updated cloud account with {feature_name} feature")
        except Exception as e:
            Logger.logger.error(f"Failed to create cloud account with {feature_name} feature: {e}")
            raise Exception(f"Failed to create cloud account with {feature_name} feature: {e}")
        from .accounts import CSPM_STATUS_HEALTHY
        self.validate_account_status(cloud_account_guid, CSPM_STATUS_HEALTHY)
        return new_cloud_account_guid

    def connect_cadr_bad_log_location(self, region: str, cloud_account_name: str, trail_log_location: str) -> str:
        cloud_account_guid = self.create_and_validate_cloud_account_with_cadr(cloud_account_name, trail_log_location, PROVIDER_AWS, region=region, expect_failure=True)
        return cloud_account_guid

    def connect_cadr_new_account(self, region: str, stack_name: str, cloud_account_name: str, log_location: str, validate_apis: bool = True) -> str:
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
        _ = self.create_stack(self.aws_manager, stack_name, template_url, parameters)

    def connect_cadr_new_organization(self, region: str, stack_name: str, log_location: str) -> str:
        from .accounts import CloudEntityTypes, FEATURE_STATUS_PENDING
        Logger.logger.info(f"Connecting new CADR org, log_location: {log_location}, region: {region}")
        org_guid = self.create_and_validate_cloud_org_with_cadr(trail_log_location=log_location, region=region, expect_failure=False)
        Logger.logger.info('Validate feature status Pending')
        assert self.verify_cadr_status(org_guid, CloudEntityTypes.ORGANIZATION, FEATURE_STATUS_PENDING)
        self.create_stack_cadr_org(region, stack_name, org_guid)
        Logger.logger.info(f"CADR org {org_guid} connected and stack created.")
        return org_guid

    def create_stack_cadr_org(self, region: str, stack_name: str, org_guid: str) -> str:
        from .accounts import extract_parameters_from_url
        Logger.logger.info('Get and validate cadr org link')
        stack_link = self.get_and_validate_cadr_org_link(region, org_guid)
        _, template_url, region, parameters = extract_parameters_from_url(stack_link)
        Logger.logger.info(f"Creating stack with name: {stack_name}, template_url: {template_url}, parameters: {parameters}")
        _ = self.create_stack(self.aws_manager, stack_name, template_url, parameters)

    def connect_cspm_new_organization(self, aws_manager: aws.AwsManager, stack_name: str, region: str, external_id: Union[str, None] = None) -> CreateOrUpdateCloudOrganizationResponse:
        from .accounts import extract_parameters_from_url
        Logger.logger.info(f"Connecting new cspm org")
        awsResponse = self.get_org_admin_stack_link(region, stack_name, external_id)
        external_id = awsResponse.externalID
        _, template_url, region, parameters = extract_parameters_from_url(awsResponse.stackLink)
        generated_role_name = self.generate_timestamped_role_name(role_prefix="armo-discovery-role")
        parameters.append({"ParameterKey": "RoleName", "ParameterValue": generated_role_name})
        self.create_stack(aws_manager, stack_name, template_url, parameters)
        test_arn = aws_manager.get_stack_output_role_arn(stack_name)
        body = AWSOrgCreateCloudOrganizationAdminRequest(
            stackRegion=region,
            adminRoleArn=test_arn,
            adminRoleExternalID=external_id,
            skipScan=True
        )
        res = self.backend.create_cloud_org_with_admin(body=body.model_dump())
        assert "guid" in res, f"guid not in {res}"
        org_guid = res["guid"]
        if org_guid not in self.test_cloud_orgs_guids:
            self.test_cloud_orgs_guids.append(org_guid)
        return CreateOrUpdateCloudOrganizationResponse(guid=org_guid)

    def connect_existing_cspm_organization(self, region: str, test_arn: str, external_id: Union[str, None] = None, org_guid: Union[str, None] = None) -> CreateOrUpdateCloudOrganizationResponse:
        if org_guid is not None:
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
        if returned_org_guid not in self.test_cloud_orgs_guids:
            self.test_cloud_orgs_guids.append(returned_org_guid)
        return CreateOrUpdateCloudOrganizationResponse(guid=returned_org_guid)

    def get_org_admin_stack_link(self, region: str, stack_name: str, external_id: Union[str, None] = None) -> AwsStackResponse:
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

    def get_and_validate_cspm_link_with_external_id(self, region: str, features: List[str]) -> AwsStackResponse:
        data = self.backend.get_cspm_single_link(feature_name=features, region=region, external_id="true")
        return AwsStackResponse(
            stackLink=data["stackLink"],
            externalID=data["externalID"]
        )

    def get_and_validate_cadr_link(self, region, cloud_account_guid) -> str:
        stack_link = self.backend.get_cadr_link(region=region, cloud_account_guid=cloud_account_guid)
        return stack_link

    def get_and_validate_cadr_org_link(self, region: str, org_guid: str) -> str:
        stack_link = self.backend.get_cadr_org_link(region=region, org_guid=org_guid)
        return stack_link

    def reconnect_cloud_account_cspm_feature(self, cloud_account_guid: str, feature_name: str, arn: str, region: str, external_id: str, skip_scan: bool = False):
        from .accounts import COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME
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
                    "externalID": external_id
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

    def disconnect_cspm_account_without_deleting_cloud_account(self, stack_name: str, cloud_account_guid: str, feature_name: str):
        self.aws_manager.delete_stack(stack_name)
        Logger.logger.info("Disconnecting CSPM account without deleting cloud account")
        self.backend.cspm_scan_now(cloud_account_guid=cloud_account_guid, with_error=True)
        from .accounts import FEATURE_STATUS_DISCONNECTED
        self.wait_for_report(self.validate_account_feature_status, timeout=30, sleep_interval=5, cloud_account_guid=cloud_account_guid, feature_name=feature_name, expected_status=FEATURE_STATUS_DISCONNECTED)

    def update_role_external_id(self, aws_manager: aws.AwsManager, role_arn: str, new_external_id: str) -> bool:
        if aws_manager.update_role_external_id(role_arn, new_external_id):
            def check_external_id():
                current_external_id = aws_manager.get_role_external_id_by_arn(role_arn)
                return current_external_id == new_external_id
            self.wait_for_report(check_external_id, timeout=30, sleep_interval=5)
            return True
        return False

    def update_and_validate_admin_external_id(self, aws_manager: aws.AwsManager, org_guid: str, admin_role_arn: str):
        from .accounts import SyncCloudOrganizationRequest, FEATURE_STATUS_DISCONNECTED, FEATURE_STATUS_CONNECTED, CSPM_STATUS_DEGRADED, CSPM_STATUS_HEALTHY
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
        self.wait_for_report(self.connect_existing_cspm_organization, timeout=90, sleep_interval=10, region=aws_manager.region, test_arn=admin_role_arn, external_id=old_external_id, org_guid=org_guid)
        self.wait_for_report(self.validate_admin_status, timeout=90, sleep_interval=10, org_guid=org_guid, expected_status=FEATURE_STATUS_CONNECTED)
        self.validate_org_status(org_guid, CSPM_STATUS_HEALTHY)

    def update_and_validate_member_external_id(self, aws_manager: aws.AwsManager, org_guid: str, account_guid: str, feature_name: str):
        from .accounts import FEATURE_STATUS_DISCONNECTED, FEATURE_STATUS_CONNECTED, FEATURE_STATUS_PARTIALLY_CONNECTED, CSPM_STATUS_DEGRADED, CSPM_STATUS_HEALTHY, COMPLIANCE_FEATURE_NAME, VULN_SCAN_FEATURE_NAME
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
            self.wait_for_report(self.reconnect_cloud_account_cspm_feature, timeout=90, sleep_interval=10, cloud_account_guid=account_guid, feature_name=COMPLIANCE_FEATURE_NAME, arn=role_arn, region=aws_manager.region, external_id=old_external_id, skip_scan=True)
            self.wait_for_report(self.validate_account_feature_status, timeout=180, sleep_interval=10, cloud_account_guid=account_guid, expected_status=FEATURE_STATUS_CONNECTED, feature_name=COMPLIANCE_FEATURE_NAME)
            self.validate_org_status(org_guid, CSPM_STATUS_HEALTHY)
            self.validate_org_feature_status(org_guid, COMPLIANCE_FEATURE_NAME, FEATURE_STATUS_CONNECTED)
        elif feature_name == VULN_SCAN_FEATURE_NAME:
            Logger.logger.info(f"there is no scan now capability to vuln scan")
        return

    def _cleanup_stacksets(self, stackset_refs):
        from .accounts import StackSetRef
        if not stackset_refs:
            Logger.logger.info("No StackSets to clean up")
            return
        Logger.logger.info(f"🧹 Starting cleanup of {len(stackset_refs)} StackSets")
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
                                    time.sleep(5)
                                except Exception as e:
                                    Logger.logger.error(f"Failed to stop operation {op_id} for StackSet {ref.stackset_name}: {e}")
                    except Exception as e:
                        Logger.logger.warning(f"Failed to check operations for StackSet {ref.stackset_name}: {e}, proceeding with cleanup")
            except Exception as e:
                Logger.logger.error(f"Error while waiting for StackSet {ref.stackset_name} operation {ref.operation_id}: {e}, proceeding with cleanup")
        stacksets_by_manager = {}
        for ref in stackset_refs:
            if ref.aws_manager:
                manager_key = id(ref.aws_manager)
                if manager_key not in stacksets_by_manager:
                    stacksets_by_manager[manager_key] = (ref.aws_manager, [])
                stacksets_by_manager[manager_key][1].append(ref.stackset_name)
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

    def create_and_validate_cloud_account_with_cspm_vulnscan(self, cloud_account_name: str, arn: str, provider: str, region: str, external_id: str = "", expect_failure: bool = False):
        feature_config = {
            "vulnerabilityScanConfig": {
                "crossAccountsRoleARN": arn,
                "stackRegion": region,
                "externalID": external_id
            }
        }
        return self.create_and_validate_cloud_account_with_feature(cloud_account_name, provider, feature_config, expect_failure=expect_failure)

    def create_and_validate_cloud_account_with_cadr(self, cloud_account_name: str, trail_log_location: str, provider: str, region: str, expect_failure: bool = False) -> str:
        feature_config = {
            "cadrConfig": {
                "trailLogLocation": trail_log_location,
                "stackRegion": region,
            }
        }
        return self.create_and_validate_cloud_account_with_feature(cloud_account_name, provider, feature_config, expect_failure=expect_failure)

    def create_and_validate_cloud_org_with_cadr(self, trail_log_location: str, region: str, expect_failure: bool = False) -> str:
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
        return org_guid

    def cleanup_aws_orgs_by_id(self, org_id: str, features_to_cleanup: List[str]):
        Logger.logger.info(f"Cleaning up AWS organizations for org_id: {org_id}, features: {features_to_cleanup}")
        body = self.build_get_cloud_aws_org_by_orgID_request(org_id)
        res = self.backend.get_cloud_orgs(body=body)
        if "response" not in res or len(res["response"]) == 0:
            Logger.logger.info(f"No AWS organizations found for org_id: {org_id}")
            return
        deleted_org_guids = []
        for org in res["response"]:
            org_guid = org.get("guid")
            if not org_guid:
                continue
            features = org.get("features") or {}
            for feature_name in features_to_cleanup:
                if feature_name in features:
                    try:
                        self.delete_and_validate_org_feature(org_guid, feature_name)
                        deleted_org_guids.append(org_guid)
                        Logger.logger.info(f"Deleted feature '{feature_name}' from org GUID: {org_guid}")
                    except Exception as e:
                        Logger.logger.error(f"Failed to delete feature '{feature_name}' from org {org_guid}: {e}")
        if deleted_org_guids:
            Logger.logger.info(f"Cleanup completed. Deleted org GUIDs: {', '.join(set(deleted_org_guids))}")
            for org_guid in set(deleted_org_guids):
                self._validate_accounts_managed_by_org_deleted(org_guid, features_to_cleanup)
        else:
            Logger.logger.info("No organizations were deleted during cleanup")

    def _validate_accounts_managed_by_org_deleted(self, org_guid: str, deleted_features: List[str]):
        Logger.logger.info(f"Validating that all accounts managed by org {org_guid} are deleted")
        accounts_still_managed = []
        page_num = 0
        page_size = 100
        while True:
            body = {
                "pageSize": page_size,
                "pageNum": page_num,
                "innerFilters": [
                    {
                        "provider": PROVIDER_AWS
                    }
                ]
            }
            res = self.backend.get_cloud_accounts(body=body)
            if "response" not in res:
                Logger.logger.warning(f"Failed to query accounts for validation at page {page_num}: {res}")
                break
            accounts = res.get("response", [])
            if len(accounts) == 0:
                break
            for account in accounts:
                account_guid = account.get("guid")
                account_id = account.get("providerInfo", {}).get("accountID")
                if not account_guid:
                    continue
                features = account.get("features") or {}
                for feature_name in deleted_features:
                    if feature_name in features:
                        managed_by_org = features[feature_name].get("managedByOrg")
                        if managed_by_org == org_guid:
                            accounts_still_managed.append({
                                "account_id": account_id,
                                "account_guid": account_guid,
                                "feature_name": feature_name
                            })
            if len(accounts) < page_size:
                break
            page_num += 1
        if accounts_still_managed:
            account_details = [f"{acc['account_id']}:{acc['feature_name']}" for acc in accounts_still_managed]
            assert False, f"Accounts still managed by org {org_guid} after feature deletion: {account_details}"
        Logger.logger.info(f"✅ All accounts managed by org {org_guid} have been deleted")

    def create_aws_cdr_runtime_policy(self, policy_name: str, incident_type_ids: List[str]):
        runtime_policy_body = {
            "name": policy_name,
            "enabled": True,
            "scope": {"designators": [{"cloudProvider": "aws", "service": "CDR", "region": "*/*", "accountID": "*/*"}]},
            "ruleSetType": "Custom",
            "incidentTypeIDs": incident_type_ids,
        }
        policy_guid = self.validate_new_policy(runtime_policy_body)
        self.test_runtime_policies.append(policy_guid)

    def validate_account_feature_managed_by_org(self, account_id: str, feature_name: str, org_guid: str = None):
        body = self.build_get_cloud_aws_org_by_accountID_request(account_id)
        res = self.backend.get_cloud_accounts(body=body)
        if len(res["response"]) == 0:
            assert False, f"Account {account_id} not found"
        account = res["response"][0]
        if org_guid is not None:
            assert account["features"][feature_name]["managedByOrg"] == org_guid, f"Expected status: {org_guid}, got: {account['features'][feature_name]['managedByOrg']}"
        else:
            assert "managedByOrg" not in account["features"][feature_name] or account["features"][feature_name]["managedByOrg"] is None, f"Expected managedByOrg field to not exist, but it exists with value: {account['features'][feature_name].get('managedByOrg')}"

    def validate_org_manged_account_list(self, org_guid: str, account_ids: List[str], feature_name: str):
        missing_accounts = []
        unmanaged_accounts = []
        for account_id in account_ids:
            body = self.build_get_cloud_aws_org_by_accountID_request(account_id)
            res = self.backend.get_cloud_accounts(body=body)
            if len(res["response"]) == 0:
                missing_accounts.append(account_id)
                continue
            account = res["response"][0]
            managed_by_org_feature = account["features"][feature_name]
            managed_by_org = managed_by_org_feature.get("managedByOrg", None)
            assert managed_by_org is not None, f"managedByOrg is not found in {managed_by_org_feature}"
            if managed_by_org != org_guid:
                unmanaged_accounts.append(account_id)
        assert len(missing_accounts) == 0, f"Missing accounts: {missing_accounts}"
        assert len(unmanaged_accounts) == 0, f"Unmanaged accounts: {unmanaged_accounts}"

    def validate_org_accounts_have_all_features(self, org_guid: str, account_ids: List[str], expected_features: List[str]):
        Logger.logger.info(f"Validating that all accounts under org {org_guid} have features: {expected_features}")
        missing_accounts = []
        accounts_missing_features = []
        accounts_not_managed_by_org = []
        for account_id in account_ids:
            body = self.build_get_cloud_aws_org_by_accountID_request(account_id)
            res = self.backend.get_cloud_accounts(body=body)
            if len(res["response"]) == 0:
                missing_accounts.append(account_id)
                continue
            account = res["response"][0]
            account_features = account.get("features", {})
            missing_features = []
            for feature_name in expected_features:
                if feature_name not in account_features:
                    missing_features.append(feature_name)
                else:
                    feature_data = account_features[feature_name]
                    managed_by_org = feature_data.get("managedByOrg")
                    if managed_by_org != org_guid:
                        accounts_not_managed_by_org.append(f"{account_id}:{feature_name}")
            if missing_features:
                accounts_missing_features.append(f"{account_id}:{missing_features}")
        assert len(missing_accounts) == 0, f"Missing accounts: {missing_accounts}"
        assert len(accounts_missing_features) == 0, f"Accounts missing features: {accounts_missing_features}"
        assert len(accounts_not_managed_by_org) == 0, f"Accounts not managed by org: {accounts_not_managed_by_org}"
        Logger.logger.info(f"✅ All {len(account_ids)} accounts under org {org_guid} have all expected features: {expected_features}")

    def validate_org_feature_deletion_complete(self, org_guid: str, deleted_feature: str, expected_features: List[str], expected_account_ids: List[str]):
        Logger.logger.info(f"Validating complete feature deletion for org {org_guid}: deleted '{deleted_feature}', expected features: {expected_features}")
        missing_accounts = []
        accounts_with_deleted_feature = []
        accounts_missing_expected_features = []
        accounts_with_unexpected_features = []
        accounts_not_managed_by_org = []
        for account_id in expected_account_ids:
            body = self.build_get_cloud_aws_org_by_accountID_request(account_id)
            res = self.backend.get_cloud_accounts(body=body)
            if len(res["response"]) == 0:
                missing_accounts.append(account_id)
                continue
            account = res["response"][0]
            account_features = account.get("features", {})
            if deleted_feature in account_features:
                accounts_with_deleted_feature.append(account_id)
            unexpected_features = []
            for feature_name in account_features.keys():
                if feature_name not in expected_features:
                    unexpected_features.append(feature_name)
            if unexpected_features:
                accounts_with_unexpected_features.append(f"{account_id}:{unexpected_features}")
            missing_features = []
            for feature_name in expected_features:
                if feature_name not in account_features:
                    missing_features.append(feature_name)
                else:
                    feature_data = account_features[feature_name]
                    managed_by_org = feature_data.get("managedByOrg")
                    if managed_by_org != org_guid:
                        accounts_not_managed_by_org.append(f"{account_id}:{feature_name}")
            if missing_features:
                accounts_missing_expected_features.append(f"{account_id}:{missing_features}")
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
        Logger.logger.info(f"Validating that no accounts are managed by org {org_guid} anymore")
        accounts_still_managed = []
        accounts_with_features = []
        for account_id in expected_account_ids:
            body = self.build_get_cloud_aws_org_by_accountID_request(account_id)
            res = self.backend.get_cloud_accounts(body=body)
            if len(res["response"]) == 0:
                continue
            account = res["response"][0]
            account_features = account.get("features", {})
            for feature_name, feature_data in account_features.items():
                managed_by_org = feature_data.get("managedByOrg")
                if managed_by_org == org_guid:
                    accounts_still_managed.append(f"{account_id}:{feature_name}")
            if account_features:
                accounts_with_features.append(f"{account_id}:{list(account_features.keys())}")
        assert len(accounts_still_managed) == 0, f"Accounts still managed by org {org_guid}: {accounts_still_managed}"
        Logger.logger.info(f"✅ No accounts are managed by org {org_guid} anymore")
        if accounts_with_features:
            Logger.logger.info(f"   - Found {len(accounts_with_features)} accounts with features, but none managed by org {org_guid}")
        else:
            Logger.logger.info(f"   - All {len(expected_account_ids)} accounts have been completely disconnected")

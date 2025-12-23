import time
import uuid
from typing import Dict, Any
from systest_utils import Logger
from .cspm_test_models import PROVIDER_AZURE


class AzureAccountsMixin:
    """Azure-specific methods for Accounts class."""

    def create_and_validate_cloud_account_with_cspm_azure(self, cloud_account_name: str, subscription_id: str, tenant_id: str, client_id: str, client_secret: str, skip_scan: bool = False, expect_failure: bool = False) -> str:
        compliance_azure_config: Dict[str, Any] = {
            "subscriptionID": subscription_id,
            "tenantID": tenant_id,
            "clientID": client_id,
            "clientSecret": client_secret,
        }
        feature_config = {"complianceAzureConfig": compliance_azure_config}
        return self.create_and_validate_cloud_account_with_feature(cloud_account_name, PROVIDER_AZURE, feature_config, skip_scan, expect_failure)

    def connect_azure_cspm_new_account(self, subscription_id: str, tenant_id: str, client_id: str, client_secret: str, cloud_account_name: str, skip_scan: bool = False, validate_apis: bool = True, expect_failure: bool = False, is_to_cleanup_accounts: bool = True) -> str:
        from .accounts import CSPM_SCAN_STATE_IN_PROGRESS, FEATURE_STATUS_CONNECTED
        if is_to_cleanup_accounts:
            Logger.logger.info(f"Cleaning up existing Azure cloud accounts for subscription {subscription_id}")
            self.cleanup_existing_cloud_accounts(PROVIDER_AZURE, subscription_id)

        Logger.logger.info(f"Creating and validating Azure CSPM cloud account: {cloud_account_name}, subscription: {subscription_id}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm_azure(cloud_account_name, subscription_id, tenant_id, client_id, client_secret, skip_scan, expect_failure)

        if cloud_account_guid is not None:
            Logger.logger.info(f"connected azure cspm to new account {cloud_account_name}, cloud_account_guid is {cloud_account_guid}")
            Logger.logger.info("Validate accounts cloud with azure cspm list")
            self.validate_accounts_cloud_list_cspm_compliance(PROVIDER_AZURE, cloud_account_guid, subscription_id, CSPM_SCAN_STATE_IN_PROGRESS, FEATURE_STATUS_CONNECTED, skipped_scan=skip_scan)
            Logger.logger.info(f"validated azure cspm list for {cloud_account_guid} successfully")

            if validate_apis:
                Logger.logger.info("Validate accounts cloud with cspm unique values")
                self.validate_accounts_cloud_uniquevalues(cloud_account_name)
                Logger.logger.info("Edit name and validate cloud account with cspm")
                self.update_and_validate_cloud_account(PROVIDER_AZURE, cloud_account_guid, cloud_account_name + "-updated")
        else:
            if expect_failure:
                Logger.logger.info("expected failure, returning None")
        return cloud_account_guid

    def remove_azure_reader_role(self, subscription_id: str, tenant_id: str, client_id: str, client_secret: str) -> bool:
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.authorization import AuthorizationManagementClient

            from .accounts import AZURE_READER_ROLE_DEFINITION_PATH
            Logger.logger.info(f"Trying to remove Reader role from client {client_id} in subscription {subscription_id}")
            credential = ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
            auth_client = AuthorizationManagementClient(credential=credential, subscription_id=subscription_id)
            scope = f"/subscriptions/{subscription_id}"
            reader_role_definition_id = f"{scope}{AZURE_READER_ROLE_DEFINITION_PATH}"

            role_assignments = auth_client.role_assignments.list_for_scope(scope=scope)
            for assignment in role_assignments:
                if assignment.role_definition_id == reader_role_definition_id:
                    Logger.logger.info("Removing Reader role...")
                    auth_client.role_assignments.delete_by_id(role_assignment_id=assignment.id)
                    Logger.logger.info(f"Successfully removed Reader role for client {client_id} in subscription {subscription_id}")
                    return True

            Logger.logger.warning(f"No Reader role found for client {client_id} in subscription {subscription_id}")
            return False

        except ImportError:
            Logger.logger.warning("Azure SDK not available")
            return False
        except Exception as e:
            Logger.logger.error(f"Failed to remove Reader role: {str(e)}")
            return False

    def create_azure_reader_role(self, subscription_id: str, tenant_id: str, client_id: str, client_object_id: str, client_secret: str) -> bool:
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            from azure.mgmt.authorization.models import RoleAssignmentCreateParameters

            from .accounts import AZURE_READER_ROLE_DEFINITION_PATH
            Logger.logger.info(f"Trying to create Reader role for client {client_id} in subscription {subscription_id}")
            credential = ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
            auth_client = AuthorizationManagementClient(credential=credential, subscription_id=subscription_id)
            scope = f"/subscriptions/{subscription_id}"
            reader_role_definition_id = f"{scope}{AZURE_READER_ROLE_DEFINITION_PATH}"

            role_assignment_name = str(uuid.uuid4())
            role_assignment_params = RoleAssignmentCreateParameters(role_definition_id=reader_role_definition_id, principal_id=client_object_id, principal_type="ServicePrincipal")

            Logger.logger.info("Creating Reader role...")
            auth_client.role_assignments.create(scope=scope, role_assignment_name=role_assignment_name, parameters=role_assignment_params)
            Logger.logger.info(f"Successfully created Reader role for client {client_id} in subscription {subscription_id}")
            return True

        except ImportError:
            Logger.logger.warning("Azure SDK not available")
            return False
        except Exception as e:
            Logger.logger.error(f"Failed to create Reader role: {str(e)}")
            return False

    def reconnect_azure_cspm_account(self, cloud_account_guid: str, subscription_id: str, tenant_id: str, client_id: str, client_secret: str):
        Logger.logger.info(f"Reconnecting Azure CSPM account {cloud_account_guid}")
        compliance_azure_config = {
            "subscriptionID": subscription_id,
            "tenantID": tenant_id,
            "clientID": client_id,
            "clientSecret": client_secret,
        }

        body = {"guid": cloud_account_guid, "complianceAzureConfig": compliance_azure_config, "skipScan": True}

        res = self.backend.update_cloud_account(body, PROVIDER_AZURE)
        assert "Cloud account updated" in res or "updated" in str(res).lower(), f"Failed to reconnect Azure account: {res}"

        Logger.logger.info(f"Azure account {cloud_account_guid} reconnected successfully")

    def break_and_reconnect_azure_account(self, cloud_account_guid: str, subscription_id: str, tenant_id: str, client_id: str, client_object_id: str, client_secret: str):
        from .accounts import FEATURE_STATUS_DISCONNECTED, COMPLIANCE_FEATURE_NAME
        Logger.logger.info("Breaking Azure connection by removing Reader role from Service Principal")
        reader_role_removed = self.remove_azure_reader_role(subscription_id, tenant_id, client_id, client_secret)
        assert reader_role_removed, "Failed to remove Reader role from Service Principal"
        Logger.logger.info("Reader role removed successfully, waiting for propagation")
        time.sleep(150)

        Logger.logger.info("Triggering scan now (should fail)")
        try:
            self.backend.cspm_scan_now(cloud_account_guid, with_error=True)
        except Exception as e:
            Logger.logger.info(f"Expected scan failure after role removal: {e}")

        Logger.logger.info("Validating account feature status is disconnected")
        self.wait_for_report(
            self.validate_account_feature_status,
            timeout=300,
            sleep_interval=30,
            cloud_account_guid=cloud_account_guid,
            feature_name=COMPLIANCE_FEATURE_NAME,
            expected_status=FEATURE_STATUS_DISCONNECTED,
        )

        Logger.logger.info("Restoring Reader role with Azure API")
        reader_role_restored = self.create_azure_reader_role(subscription_id, tenant_id, client_id, client_object_id, client_secret)
        assert reader_role_restored, "Failed to restore Reader role to Service Principal"
        Logger.logger.info("Waiting for the role restoration to propagate")
        time.sleep(150)

        Logger.logger.info("Reconnecting by updating the account")
        self.wait_for_report(
            self.reconnect_azure_cspm_account,
            timeout=300,
            sleep_interval=30,
            cloud_account_guid=cloud_account_guid,
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

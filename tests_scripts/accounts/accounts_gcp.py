import json
from typing import Dict, Any
from infrastructure import gcp as gcp_module
from systest_utils import Logger
from .cspm_test_models import PROVIDER_GCP


class GcpAccountsMixin:
    """GCP-specific methods for Accounts class."""

    def create_and_validate_cloud_account_with_cspm_gcp(self, cloud_account_name: str, project_id: str, service_account_key: str, skip_scan: bool = False, expect_failure: bool = False) -> str:
        if not isinstance(service_account_key, str):
            raise ValueError(f"service_account_key must be a string, got {type(service_account_key)}")
        try:
            parsed = json.loads(service_account_key)
        except json.JSONDecodeError as e:
            raise ValueError(f"service_account_key is not valid JSON: {e}")
        if not expect_failure:
            if parsed.get("project_id") == "invalid":
                raise ValueError("service_account_key contains 'invalid' project_id - wrong credentials detected! This should only happen when expect_failure=True")
            if parsed.get("project_id") != project_id:
                Logger.logger.warning(
                    f"service_account_key project_id ({parsed.get('project_id')}) doesn't match "
                    f"provided project_id ({project_id})"
                )
        compliance_gcp_config: Dict[str, Any] = {
            "projectID": project_id,
            "serviceAccountKey": service_account_key,
        }
        feature_config = {"complianceGCPConfig": compliance_gcp_config}
        key_snippet = service_account_key[:100] + "..." if len(service_account_key) > 100 else service_account_key
        Logger.logger.debug(f"Creating GCP account with project_id={project_id}, expect_failure={expect_failure}, serviceAccountKey snippet: {key_snippet}")
        return self.create_and_validate_cloud_account_with_feature(cloud_account_name, PROVIDER_GCP, feature_config, skip_scan, expect_failure)

    def reconnect_cloud_account_cspm_feature_gcp(self, cloud_account_guid: str, project_id: str, service_account_key: str, skip_scan: bool = False):
        body = {
            "guid": cloud_account_guid,
            "complianceGCPConfig": {
                "projectID": project_id,
                "serviceAccountKey": service_account_key,
            },
            "skipScan": skip_scan,
        }
        self.backend.update_cloud_account(body=body, provider=PROVIDER_GCP)
        return cloud_account_guid

    def connect_gcp_cspm_new_account(self, project_id: str, service_account_key: str, cloud_account_name: str, skip_scan: bool = False, validate_apis: bool = True, is_to_cleanup_accounts: bool = True, expect_failure: bool = False) -> str:
        if is_to_cleanup_accounts:
            Logger.logger.info(f"Cleaning up existing GCP cloud accounts for project {project_id}")
            self.cleanup_existing_cloud_accounts(PROVIDER_GCP, project_id)

        from .accounts import CSPM_SCAN_STATE_IN_PROGRESS, FEATURE_STATUS_CONNECTED
        Logger.logger.info(f"Creating and validating GCP CSPM cloud account: {cloud_account_name}, project: {project_id}")
        cloud_account_guid = self.create_and_validate_cloud_account_with_cspm_gcp(
            cloud_account_name, project_id, service_account_key, skip_scan, expect_failure
        )
        Logger.logger.info(f"connected gcp cspm to new account {cloud_account_name}, cloud_account_guid is {cloud_account_guid}")
        Logger.logger.info("Validate accounts cloud with gcp cspm list")
        self.validate_accounts_cloud_list_cspm_compliance(
            PROVIDER_GCP, cloud_account_guid, project_id, CSPM_SCAN_STATE_IN_PROGRESS, FEATURE_STATUS_CONNECTED, skipped_scan=skip_scan
        )
        Logger.logger.info(f"validated gcp cspm list for {cloud_account_guid} successfully")

        if validate_apis:
            Logger.logger.info("Validate accounts cloud with cspm unique values")
            self.validate_accounts_cloud_uniquevalues(cloud_account_name)
            Logger.logger.info("Edit name and validate cloud account with cspm")
            self.update_and_validate_cloud_account(PROVIDER_GCP, cloud_account_guid, cloud_account_name + "-updated")
        return cloud_account_guid

    def break_and_reconnect_gcp_service_account(self, cloud_account_guid: str, project_id: str, original_service_account_key: str, gcp_manager: gcp_module.GcpManager):
        """Break GCP service account permissions by removing roles/viewer, trigger scanNow, validate disconnected status, restore permissions, and reconnect with skipScan."""
        from .accounts import FEATURE_STATUS_DISCONNECTED, FEATURE_STATUS_CONNECTED, COMPLIANCE_FEATURE_NAME
        role_to_remove = "roles/viewer"
        Logger.logger.info(f"Removing {role_to_remove} from service account to break permissions")

        remove_success = gcp_manager.remove_role(role_to_remove)
        assert remove_success, f"Failed to remove role {role_to_remove} from service account"
        Logger.logger.info(f"Successfully removed {role_to_remove} from service account")

        Logger.logger.info("Triggering scanNow to detect broken permissions")
        self.backend.cspm_scan_now(cloud_account_guid=cloud_account_guid, with_error=True)

        Logger.logger.info("Validating feature status is disconnected")
        self.wait_for_report(
            self.validate_account_feature_status,
            timeout=180,
            sleep_interval=10,
            cloud_account_guid=cloud_account_guid,
            feature_name=COMPLIANCE_FEATURE_NAME,
            expected_status=FEATURE_STATUS_DISCONNECTED,
        )
        Logger.logger.info("Feature status validated as disconnected")

        Logger.logger.info(f"Restoring {role_to_remove} to service account")
        gcp_manager.add_role(role_to_remove)
        Logger.logger.info(f"Successfully restored {role_to_remove} to service account")

        Logger.logger.info("Reconnecting account with skipScan=True")
        body = {
            "guid": cloud_account_guid,
            "complianceGCPConfig": {"projectID": project_id, "serviceAccountKey": original_service_account_key},
            "skipScan": True,
        }
        self.backend.update_cloud_account(body=body, provider=PROVIDER_GCP)
        Logger.logger.info("Reconnected account with skipScan=True")

        Logger.logger.info("Validating feature status is connected after reconnection")
        self.wait_for_report(
            self.validate_account_feature_status,
            timeout=180,
            sleep_interval=10,
            cloud_account_guid=cloud_account_guid,
            feature_name=COMPLIANCE_FEATURE_NAME,
            expected_status=FEATURE_STATUS_CONNECTED,
        )
        Logger.logger.info("Feature status validated as connected after reconnection")

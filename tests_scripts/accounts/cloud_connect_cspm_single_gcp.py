import os
import json
import random
from typing import Tuple, Dict

from infrastructure import gcp
from systest_utils import Logger
from tests_scripts.accounts.accounts import (
    Accounts,
    COMPLIANCE_FEATURE_NAME,
    CSPM_SCAN_STATE_COMPLETED,
    PROVIDER_GCP,
)

TEST_PROJECT_ID = "elated-pottery-310110"
class CloudConnectCSPMSingleGCP(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.skip_apis_validation = False
        self.skip_jira_validation = False
        self.gcp_manager = None
    
    def _parse_and_validate_service_account_key(self, service_account_key_raw: str, expected_project_id: str) -> Tuple[str, Dict]:
        """
        Parse, validate, and normalize GCP service account key JSON.
        
        Args:
            service_account_key_raw: Raw service account key as JSON string
            expected_project_id: Expected project ID to validate against
            
        Returns:
            Tuple of (normalized_json_string, parsed_dict)
            
        Raises:
            ValueError: If JSON is invalid or project_id doesn't match
        """
        try:
            # Parse to validate and normalize - this handles any extra escaping
            parsed_key = json.loads(service_account_key_raw)
            
            # Validate that the parsed key has the correct project_id
            parsed_project_id = parsed_key.get("project_id")
            if parsed_project_id != expected_project_id:
                raise ValueError(
                    f"Service account key project_id ({parsed_project_id}) does not match "
                    f"expected project_id ({expected_project_id}). Please verify your environment variables."
                )
            if parsed_project_id == "invalid":
                raise ValueError(
                    "Service account key contains 'invalid' project_id. "
                    "This suggests the wrong credentials are being used. Please check GCP_SERVICE_ACCOUNT_KEY_CLOUD_TESTS."
                )
            
            # Re-serialize with compact formatting to ensure clean JSON string
            # This ensures consistent formatting regardless of how it was stored in env
            normalized_json = json.dumps(parsed_key, separators=(',', ':'))
            Logger.logger.info(f"Successfully parsed and normalized GCP service account key (project_id: {expected_project_id})")
            return normalized_json, parsed_key
            
        except json.JSONDecodeError as e:
            Logger.logger.error(f"Failed to parse GCP_SERVICE_ACCOUNT_KEY_CLOUD_TESTS as JSON: {e}")
            raise ValueError(f"GCP_SERVICE_ACCOUNT_KEY_CLOUD_TESTS must be a valid JSON string. Error: {e}")

    def start(self):
        """
        GCP CSPM-only test (single project via Service Account)
        Agenda:
        1. Read GCP service account key and project id from env
        2. Validate no existing accounts with CSPM feature
        3. Test bad credentials (should fail)
        4. Connect GCP CSPM account (single project)
        5. Wait for CSPM scan to complete successfully
        6. Validate all scan results
        7. Create Jira issue for resource (if enabled)
        8. Accept the risk
        9. Break service account permissions and reconnect
        10. Delete CSPM feature and validate
        """
        assert self.backend is not None, f"the test {self.test_driver.test_name} must run with backend"

        # generate random suffix for uniqueness
        self.test_identifier_rand = str(random.randint(10000000, 99999999))

        Logger.logger.info("Stage 0: Cleanup existing GCP single accounts")
        project_id = TEST_PROJECT_ID
        self.cleanup_gcp_single_accounts_by_id(project_id, [COMPLIANCE_FEATURE_NAME])

        Logger.logger.info("Stage 1: Read GCP service account key and project id from env")
        service_account_key_raw = os.environ.get("GCP_SERVICE_ACCOUNT_KEY_CLOUD_TESTS")

        assert service_account_key_raw, "GCP_SERVICE_ACCOUNT_KEY_CLOUD_TESTS is not set"

        # Parse, validate, and normalize the JSON to ensure proper formatting
        service_account_key, parsed_key = self._parse_and_validate_service_account_key(service_account_key_raw, project_id)
        
        self.gcp_manager = gcp.GcpManager(service_account_key)

        cloud_account_name = f"systest-{self.test_identifier_rand}-gcp-cspm"
        bad_cloud_account_name = f"systest-{self.test_identifier_rand}-gcp-cspm-bad"

        Logger.logger.info("Stage 2: Test bad credentials (should fail)")
        # Create bad credentials as a separate variable to avoid any confusion
        bad_service_account_key = '{"type": "service_account", "project_id": "invalid", "private_key_id": "invalid", "private_key": "invalid", "client_email": "invalid@invalid.iam.gserviceaccount.com", "client_id": "invalid", "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token", "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs", "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/invalid%40invalid.iam.gserviceaccount.com"}'
        
        Logger.logger.info(f"Attempting to connect GCP CSPM with bad credentials for account: {bad_cloud_account_name}")
        cloud_account_guid_bad = self.create_and_validate_cloud_account_with_cspm_gcp(bad_cloud_account_name, project_id, bad_service_account_key, expect_failure=True)
        Logger.logger.info(f"Resulting cloud_account_guid for bad credentials: {cloud_account_guid_bad}")
        # Verify that account creation failed (expect_failure=True should return None)
        assert cloud_account_guid_bad is None, f"Expected bad credentials to fail, but got account GUID: {cloud_account_guid_bad}"
        # Double-check: verify no account was created with this name
        body = {
            "pageSize": 100,
            "pageNum": 0,
            "innerFilters": [
                {
                    "name": bad_cloud_account_name,
                    "provider": PROVIDER_GCP,
                }
            ]
        }
        res = self.backend.get_cloud_accounts(body=body)
        assert "response" in res, f"Failed to query accounts: {res}"
        assert len(res["response"]) == 0, f"Expected no account to be created with bad credentials, but found: {res['response']}"

        Logger.logger.info("Stage 3: Connect GCP CSPM account")
        # Credentials already validated in _parse_and_validate_service_account_key above
        cloud_account_guid = self.connect_gcp_cspm_new_account(project_id, service_account_key, cloud_account_name, validate_apis=not self.skip_apis_validation)

        # Store account name for later validation
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        self.gcp_cloud_account_name = account["name"]

        Logger.logger.info("Stage 5: Fail to connect same GCP CSPM account")
        cloud_account_guid_fail = self.connect_gcp_cspm_new_account(project_id, service_account_key, cloud_account_name, validate_apis=False, is_to_cleanup_accounts=False, expect_failure=True)
        assert cloud_account_guid_fail is None, f"Expected same account to fail, but got account GUID: {cloud_account_guid_fail}"


        if not self.skip_apis_validation:
            Logger.logger.info("Stage 4: Wait for CSPM scan to complete successfully")
            # wait for success
            self.wait_for_report(
                self.validate_accounts_cloud_list_cspm_compliance,
                timeout=1600,
                sleep_interval=60,
                provider=PROVIDER_GCP,
                cloud_account_guid=cloud_account_guid,
                identifier=project_id,
                scan_status=CSPM_SCAN_STATE_COMPLETED,
            )
            Logger.logger.info("the account has been scanned successfully")

            account = self.get_cloud_account_by_guid(cloud_account_guid)
            last_success_scan_id = account["features"][COMPLIANCE_FEATURE_NAME]["lastSuccessScanID"]
            Logger.logger.info(f"extracted last success scan id from created account: {last_success_scan_id}")

            Logger.logger.info("Stage 5: Validate all scan results")
            self.validate_scan_data(PROVIDER_GCP, cloud_account_guid, self.gcp_cloud_account_name, last_success_scan_id)
            Logger.logger.info("all scan data is being validated successfully")

            if not self.skip_jira_validation:
                Logger.logger.info("Stage 6: Create Jira issue for resource")
                self.create_jira_issue_for_cspm(PROVIDER_GCP, last_success_scan_id)
                Logger.logger.info("Jira issue for resource has been created successfully")

            Logger.logger.info("Stage 7: Accept the risk")
            self.accept_cspm_risk(PROVIDER_GCP, cloud_account_guid, self.gcp_cloud_account_name, last_success_scan_id)
            Logger.logger.info("risk has been accepted successfully")

            Logger.logger.info("Stage 8: Break service account permissions and reconnect")
            # Break permissions by removing roles/viewer, scanNow, validate disconnected, restore, reconnect with skipScan
            
            self.break_and_reconnect_gcp_service_account(
                cloud_account_guid=cloud_account_guid,
                project_id=project_id,
                original_service_account_key=service_account_key,
                gcp_manager=self.gcp_manager
            )
            Logger.logger.info("Service account permissions broken and reconnected successfully")

        Logger.logger.info("Stage 9: Delete CSPM feature and validate")
        self.delete_and_validate_account_feature(cloud_account_guid, COMPLIANCE_FEATURE_NAME)

        Logger.logger.info("GCP CSPM single project test completed successfully")
        return self.cleanup()

import os
import random

from systest_utils import Logger
from tests_scripts.accounts.accounts import (
    Accounts,
    COMPLIANCE_FEATURE_NAME,
    CSPM_SCAN_STATE_COMPLETED,
    FEATURE_STATUS_CONNECTED,
    PROVIDER_AZURE,
)


class CloudConnectCSPMSingleAzure(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.skip_apis_validation = False
        self.skip_jira_validation = False

    def start(self):
        """
        Azure CSPM-only test (single subscription via Service Principal)
        Agenda:
        1. Read Azure Service Principal credentials from env
        2. Validate no existing accounts with CSPM feature
        3. Test bad credentials (should fail)
        4. Connect Azure CSPM account (single subscription)
        5. Wait for CSPM scan to complete successfully
        6. Validate all scan results
        7. Create Jira issue for resource (if enabled)
        8. Accept the risk
        9. Delete CSPM feature and validate
        """
        assert self.backend is not None, f"the test {self.test_driver.test_name} must run with backend"

        # generate random suffix for uniqueness
        self.test_identifier_rand = str(random.randint(10000000, 99999999))

        Logger.logger.info("Stage 1: Read Azure Service Principal credentials from env")
        client_id = os.environ.get("AZURE_CLIENT_ID_CLOUD_TESTS")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET_CLOUD_TESTS")
        tenant_id = os.environ.get("AZURE_TENANT_ID_CLOUD_TESTS")
        subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID_CLOUD_TESTS")

        assert client_id, "AZURE_CLIENT_ID_CLOUD_TESTS is not set"
        assert client_secret, "AZURE_CLIENT_SECRET_CLOUD_TESTS is not set"
        assert tenant_id, "AZURE_TENANT_ID_CLOUD_TESTS is not set"
        assert subscription_id, "AZURE_SUBSCRIPTION_ID_CLOUD_TESTS is not set"

        cloud_account_name = f"systest-{self.test_identifier_rand}-azure-cspm"
        bad_cloud_account_name = f"systest-{self.test_identifier_rand}-azure-cspm-bad"

        Logger.logger.info("Stage 2: Validate no existing accounts with CSPM feature")
        self.validate_no_accounts_exists_by_id(PROVIDER_AZURE, [subscription_id], COMPLIANCE_FEATURE_NAME)

        Logger.logger.info("Stage 3: Test bad credentials (should fail)")
        bad_client_secret = "invalid-secret-12345"
        cloud_account_guid_bad = self.connect_azure_cspm_bad_credentials(
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=bad_client_secret,
            cloud_account_name=bad_cloud_account_name,
        )
        # Verify that account creation failed (expect_failure=True should return None)
        assert cloud_account_guid_bad is None, f"Expected bad credentials to fail, but got account GUID: {cloud_account_guid_bad}"
        # Double-check: verify no account was created with this name
        body = {
            "pageSize": 100,
            "pageNum": 0,
            "innerFilters": [
                {
                    "name": bad_cloud_account_name,
                    "provider": PROVIDER_AZURE,
                }
            ]
        }
        res = self.backend.get_cloud_accounts(body=body)
        assert "response" in res, f"Failed to query accounts: {res}"
        assert len(res["response"]) == 0, f"Expected no account to be created with bad credentials, but found: {res['response']}"

        Logger.logger.info("Stage 4: Connect Azure CSPM account")
        cloud_account_guid = self.connect_azure_cspm_new_account(subscription_id, tenant_id, client_id, client_secret, cloud_account_name, validate_apis=not self.skip_apis_validation)

        # Store account name for later validation
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        self.azure_cloud_account_name = account["name"]

        if not self.skip_apis_validation:
            Logger.logger.info("Stage 5: Wait for CSPM scan to complete successfully")
            # wait for success
            self.wait_for_report(
                self.validate_accounts_cloud_list_cspm_compliance_azure,
                timeout=1600,
                sleep_interval=60,
                cloud_account_guid=cloud_account_guid,
                subscription_id=subscription_id,
                scan_status=CSPM_SCAN_STATE_COMPLETED,
            )
            Logger.logger.info("the account has been scanned successfully")

            account = self.get_cloud_account_by_guid(cloud_account_guid)
            last_success_scan_id = account["features"][COMPLIANCE_FEATURE_NAME]["lastSuccessScanID"]
            Logger.logger.info(f"extracted last success scan id from created account: {last_success_scan_id}")

            Logger.logger.info("Stage 6: Validate all scan results")
            self.validate_scan_data(cloud_account_guid, self.azure_cloud_account_name, last_success_scan_id)
            Logger.logger.info("all scan data is being validated successfully")

            if not self.skip_jira_validation:
                Logger.logger.info("Stage 7: Create Jira issue for resource")
                self.create_jira_issue_for_cspm(last_success_scan_id)
                Logger.logger.info("Jira issue for resource has been created successfully")

            Logger.logger.info("Stage 8: Accept the risk")
            self.accept_cspm_risk(cloud_account_guid, self.azure_cloud_account_name, last_success_scan_id)
            Logger.logger.info("risk has been accepted successfully")

        Logger.logger.info("Stage 9: Delete CSPM feature and validate")
        self.delete_and_validate_account_feature(cloud_account_guid, COMPLIANCE_FEATURE_NAME)

        Logger.logger.info("Azure CSPM single subscription test completed successfully")
        return self.cleanup()


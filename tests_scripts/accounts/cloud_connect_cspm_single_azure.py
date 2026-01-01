import os
import random

from systest_utils import Logger, statics
from tests_scripts.accounts.accounts import (
    Accounts,
    COMPLIANCE_FEATURE_NAME,
    CSPM_SCAN_STATE_COMPLETED,
    PROVIDER_AZURE,
)

PROD_US_CUSTOMER_GUID = "1cc202aa-e4a0-418d-a7f5-b3d1e85ce04d"
AZURE_TENANT_ID_CLOUD_TESTS = "50a70646-52e3-4e46-911e-6ca1b46afba3"
AZURE_SUBSCRIPTION_ID_CLOUD_TESTS = "57e3175c-71ce-45f8-8bfc-34d966223068"

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
        if self.backend.get_customer_guid() == PROD_US_CUSTOMER_GUID:
            return statics.SUCCESS, "Skipping for PROD US"
        assert self.backend is not None, f"the test {self.test_driver.test_name} must run with backend"

        # generate random suffix for uniqueness
        self.test_identifier_rand = str(random.randint(10000000, 99999999))

        Logger.logger.info("Stage 0: Cleanup existing Azure single accounts")
        subscription_id = AZURE_SUBSCRIPTION_ID_CLOUD_TESTS
        self.cleanup_single_accounts_by_id(PROVIDER_AZURE, subscription_id, [COMPLIANCE_FEATURE_NAME])

        Logger.logger.info("Stage 1: Read Azure Service Principal credentials from env")
        client_id = os.environ.get("AZURE_CLIENT_ID_CLOUD_TESTS")
        client_object_id = os.environ.get("AZURE_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID_CLOUD_TESTS")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET_CLOUD_TESTS")
        tenant_id = AZURE_TENANT_ID_CLOUD_TESTS

        assert client_id, "AZURE_CLIENT_ID_CLOUD_TESTS is not set"
        assert client_object_id, "AZURE_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID_CLOUD_TESTS is not set"
        assert client_secret, "AZURE_CLIENT_SECRET_CLOUD_TESTS is not set"

        cloud_account_name = f"systest-{self.test_identifier_rand}-azure-cspm"
        bad_cloud_account_name = f"systest-{self.test_identifier_rand}-azure-cspm-bad"

        Logger.logger.info("Stage 2: Test bad credentials (should fail)")
        bad_client_secret = "invalid-secret-12345"
        Logger.logger.info(f"Attempting to connect Azure CSPM with bad credentials for account: {bad_cloud_account_name}")
        cloud_account_guid_bad = self.create_and_validate_cloud_account_with_cspm_azure(bad_cloud_account_name, subscription_id, tenant_id, client_id, bad_client_secret, expect_failure=True)
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
                    "provider": PROVIDER_AZURE,
                }
            ]
        }
        res = self.backend.get_cloud_accounts(body=body)
        assert "response" in res, f"Failed to query accounts: {res}"
        assert len(res["response"]) == 0, f"Expected no account to be created with bad credentials, but found: {res['response']}"

        Logger.logger.info("Stage 3: Connect Azure CSPM account")
        cloud_account_guid = self.connect_azure_cspm_new_account(subscription_id, tenant_id, client_id, client_secret, cloud_account_name, validate_apis=not self.skip_apis_validation)

        # Store account name for later validation
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        self.azure_cloud_account_name = account["name"]

        Logger.logger.info("Stage 5: Try to connect the same account again (should fail)")
        duplicate_account_name = f"systest-{self.test_identifier_rand}-azure-cspm-duplicate"
        # This should fail because the subscription is already connected
        duplicate_cloud_account_guid = self.connect_azure_cspm_new_account(
            subscription_id, tenant_id, client_id, client_secret, duplicate_account_name,
            validate_apis=False, expect_failure=True, is_to_cleanup_accounts=False
        )
        assert duplicate_cloud_account_guid is None, \
            f"Expected duplicate connection to fail (return None), but got {duplicate_cloud_account_guid}"
        
        # Verify the original account still exists
        account = self.get_cloud_account_by_guid(cloud_account_guid)
        assert account is not None, "Original account should still exist after duplicate connection attempt"

        if not self.skip_apis_validation:
            Logger.logger.info("Stage 4: Wait for CSPM scan to complete successfully")
            # wait for success
            self.wait_for_report(
                self.validate_accounts_cloud_list_cspm_compliance,
                timeout=1600,
                sleep_interval=60,
                provider=PROVIDER_AZURE,
                cloud_account_guid=cloud_account_guid,
                identifier=subscription_id,
                scan_status=CSPM_SCAN_STATE_COMPLETED,
            )
            Logger.logger.info("the account has been scanned successfully")

            account = self.get_cloud_account_by_guid(cloud_account_guid)
            last_success_scan_id = account["features"][COMPLIANCE_FEATURE_NAME]["lastSuccessScanID"]
            Logger.logger.info(f"extracted last success scan id from created account: {last_success_scan_id}")

            Logger.logger.info("Stage 5: Validate all scan results")
            self.validate_scan_data(PROVIDER_AZURE, cloud_account_guid, self.azure_cloud_account_name, last_success_scan_id)
            Logger.logger.info("all scan data is being validated successfully")

            if not self.skip_jira_validation:
                Logger.logger.info("Stage 6: Create Jira issue for resource")
                self.create_jira_issue_for_cspm(PROVIDER_AZURE, last_success_scan_id)
                Logger.logger.info("Jira issue for resource has been created successfully")

            Logger.logger.info("Stage 7: Accept the risk")
            self.accept_cspm_risk(PROVIDER_AZURE, cloud_account_guid, self.azure_cloud_account_name, last_success_scan_id)
            Logger.logger.info("risk has been accepted successfully")

            Logger.logger.info("Stage 10: Break Azure connection and reconnect")
            self.break_and_reconnect_azure_account(cloud_account_guid, subscription_id, tenant_id, client_id, client_object_id, client_secret)
            Logger.logger.info("Azure connection has been broken and reconnected successfully")

        Logger.logger.info("Stage 11: Delete CSPM feature and validate")
        self.delete_and_validate_account_feature(cloud_account_guid, COMPLIANCE_FEATURE_NAME)

        Logger.logger.info("Azure CSPM single subscription test completed successfully")
        return self.cleanup()


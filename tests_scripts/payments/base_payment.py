from tests_scripts import base_test
import requests
from  http import client
from systest_utils import Logger


payingCustomer = "paying"
freeCustomer    = "free"
trialCustomer   = "trial"
blockedCustomer = "blocked"


class BasePayment(base_test.BaseTest):
        

    def __init__(self, test_obj=None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)
        self.test_tenants_ids = []

    
    @staticmethod
    def http_status_ok(http_status: int):
        assert http_status == client.OK


    def tenants_subscription_active(self, activeSubscription: str):
        assert activeSubscription["licenseType"] == "Team", f"expected license type 'Team', found '{activeSubscription['licenseType']}'"
        assert activeSubscription["subscriptionStatus"] == "active", f"expected subscription status 'active', found '{activeSubscription['subscriptionStatus']}'"

    def tenants_subscription_canceled(self, activeSubscription: str):
        assert activeSubscription["cancelAtPeriodEnd"] == True, f"expected cancelAtPeriodEnd to be True, found '{activeSubscription['CancelAtPeriodEnd']}'"

    def tenants_access_state_paying(self, accessState: str):
        assert accessState == payingCustomer, f"expected access state '{payingCustomer}', found '{accessState}'"

    def tenants_access_state_free(self, accessState: str):
        assert accessState == freeCustomer, f"expected access state '{freeCustomer}', found '{accessState}'"

    def create_new_tenant(self) -> requests.Response:
        return self.backend.create_tenant()

    def delete_tenants(self) -> requests.Response:
        for tenantID in self.test_tenants_ids:
            response = self.backend.delete_tenant(tenantID)
            assert response.status_code == client.OK, f"delete tenant failed"
            Logger.logger.info(f"deleted tenant {tenantID}")
            

    def cleanup(self, **kwargs):
        self.delete_tenants()
        return super().cleanup(**kwargs)

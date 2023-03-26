from tests_scripts import base_test
import requests
from  http import client
from systest_utils import Logger


payingCustomer = "paying"
freeCustomer    = "free"
trialCustomer   = "trial"
blockedCustomer = "blocked"


SUBSCRIPTION_PAYING_STATUS = ["active", "trialing", "incomplete"]

class BasePayment(base_test.BaseTest):
        

    def __init__(self, test_obj=None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)
        self.test_tenants_ids = []

    
    @staticmethod
    def http_status_ok(http_status: int):
        assert http_status == client.OK


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

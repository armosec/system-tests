from tests_scripts import base_test
import requests
from  http import client
from systest_utils import Logger
import time



payingCustomer = "paying"
freeCustomer    = "free"
trialCustomer   = "trial"
blockedCustomer = "blocked"


SUBSCRIPTION_PAYING_STATUS = ["active", "trialing", "incomplete"]

class BasePayment(base_test.BaseTest):
        

    def __init__(self, test_obj=None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)

    
    @staticmethod
    def http_status_ok(http_status: int):
        assert http_status == client.OK
            


    def cancel_test_subscriptions(self):
        for tenantID in self.test_tenants_ids:
            response = self.backend.cancel_subscription(tenantID)
            if response.status_code != client.OK:
                Logger.logger.error(f"cancel subscription for tenant {tenantID} failed")
            else:
                Logger.logger.info(f"canceled subscription for tenant {tenantID}")

    def cleanup(self, **kwargs):
        super().delete_tenants()
        return super().cleanup(**kwargs)

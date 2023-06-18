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
            
    def get_tenant_active_subscription(self, tenant_id) -> str:
        response = self.backend.get_tenant_details(tenant_id)
        active_subscription = response.json().get("activeSubscription", {})
        assert active_subscription != {}, "activeSubscription is empty"
        return active_subscription

    def cancel_test_subscriptions(self):
        response = self.backend.cancel_subscription(self.test_tenant_id)
        if response.status_code != client.OK:
            Logger.logger.error(f"cancel subscription for tenant {self.test_tenant_id} failed")
        else:
            Logger.logger.info(f"canceled subscription for tenant {self.test_tenant_id}")

    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)


 
from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import statics
import requests
from  http import client
import time
from time import sleep


from tests_scripts.payments.base_payment import *


class BaseStripe(BasePayment):
        

    def __init__(self, test_obj :TestConfiguration =None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)

        # expects a list of dict, for each item in list "name" is the name of the plan on our internal systems, "price" is the price in cents as expected to be defined in Stripe
        self.expected_prices = self.test_obj.get_arg("expected_prices")
        self.test_stripe_customer_id = self.test_obj.get_arg("test_stripe_customer_id")
    
    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""
    
    def is_subscription_canceled(self, activeSubscription: str) -> bool:
        return activeSubscription["cancelAtPeriodEnd"] == True

    def is_subscription_active(self, activeSubscription: str) -> bool:
        return activeSubscription["cancelAtPeriodEnd"] == False and activeSubscription["subscriptionStatus"] in SUBSCRIPTION_PAYING_STATUS


    def wait_for_paying(self, tenant_id, timeout=0.5, sleep_interval=0.1) -> bool:

        timeout_start = time.time()
        updated = False

        while time.time() < timeout_start + timeout and not updated:
            response = self.get_tenant_details(tenant_id)

            customerAccessStatus = response.json().get("customerAccessStatus", {})
            if customerAccessStatus == payingCustomer:
                updated = True
            else:
                sleep(sleep_interval)
        
        return updated

    def get_tenant_details(self, tenantID: str) -> requests.Response:
        response = self.backend.get_tenant_details(tenantID)
        assert response.status_code == client.OK, f"get tenant details failed"
        return response
    
    def create_subscription(self, priceID: str, stripeCustomerID :str, tenantID: str) -> requests.Response:
        try:
            response = self.backend.create_subscription(priceID, stripeCustomerID, tenantID)
        except Exception as e:
            assert False, f"create subscription failed with priceID: {priceID} and error: {e}"
        assert response.status_code == client.OK, f"stripe checkout failed with priceID: {priceID}"
        return response
    
        
    def cancel_subscription(self, tenantID: str) -> requests.Response:
        response = self.backend.cancel_subscription(tenantID)
        assert response.status_code == client.OK, f"cancel subscription failed"
        return response
    
    def renew_subscription(self, tenantID: str) -> requests.Response:
        response = self.backend.renew_subscription(tenantID)
        assert response.status_code == client.OK, f"renew subscription failed"
        return response


    def stripe_checkout(self, priceID) -> requests.Response:
        response = self.backend.stripe_checkout(priceID)
        assert response.status_code == client.CREATED, f"stripe checkout failed with priceID: {priceID}"
        return response

    def stripe_billing_portal(self) -> requests.Response:
        response = self.backend.stripe_billing_portal()
        assert response.status_code == client.CREATED, f"stripe billing portal failed. Make sure that 'PortalReturnPath' is well defined in the backend config"
        return response

    
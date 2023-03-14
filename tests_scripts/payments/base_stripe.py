
 
from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import statics
import requests
from  http import client

from tests_scripts.payments.base_payment import BasePayment

WEBHOOK_SLEEP = 1

class BaseStripe(BasePayment):
        

    def __init__(self, test_obj :TestConfiguration =None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)

        # expects a list of dict, for each item in list "name" is the name of the plan on our internal systems, "price" is the price in cents as expected to be defined in Stripe
        self.expected_prices = self.test_obj.get_arg("expected_prices")
        self.test_stripe_customer_id = self.test_obj.get_arg("test_stripe_customer_id")
    
    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""
    

    def tenants_subscription_active(self, activeSubscription: str):
        super().tenants_subscription_active(activeSubscription)
        assert activeSubscription["cancelAtPeriodEnd"] == False, "cancelAtPeriodEnd is True"
        assert activeSubscription["stripeSubscriptionID"] != "", "stripeSubscriptionID is empty"
        assert activeSubscription["stripeCustomerID"] != "", "stripeCustomerID is empty"


    def tenants_subscription_canceled(self, activeSubscription: str):
        super().tenants_subscription_canceled(activeSubscription)
        assert activeSubscription["cancelAtPeriodEnd"] == True, "cancelAtPeriodEnd is False"

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

    
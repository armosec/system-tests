
 
from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import statics
import requests
from  http import client
import time
from time import sleep


from tests_scripts.payments.base_payment import *

WEBHOOK_TIMEOUT = 5
WEBHOOK_SLEEP_INTERVAL = 1


class BaseStripe(BasePayment):
        

    def __init__(self, test_obj :TestConfiguration =None, backend=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)

        # expects a list of dict, for each item in list "name" is the name of the plan on our internal systems, "price" is the price in cents as expected to be defined in Stripe
        self.expected_prices = self.test_obj.get_arg("expected_prices")
        self.test_stripe_customer_id = self.test_obj.get_arg("test_stripe_customer_id")
    
    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""
    
    def is_subscription_canceled(self, tenant_id: str) -> bool:
        activeSubscription = self.get_tenant_active_subscription(tenant_id)
        assert activeSubscription.get("cancelAtPeriodEnd", {}) == True, "cancelAtPeriodEnd is not True"
        return True

    def is_subscription_active(self, tenant_id: str) -> bool:
        activeSubscription = self.get_tenant_active_subscription(tenant_id)
        assert activeSubscription.get("cancelAtPeriodEnd", {}) == False and activeSubscription.get("subscriptionStatus", {}) in SUBSCRIPTION_PAYING_STATUS, "cancelAtPeriodEnd is not False or subscriptionStatus is not paying"
        return True

    def is_subscription_updated(self, tenant_id, stripeSubscriptionID: str) -> bool:
        activeSubscription = self.get_tenant_active_subscription(tenant_id)
        assert activeSubscription.get("stripeSubscriptionID", {}) == stripeSubscriptionID, "stripeSubscriptionID is not updated"
        return True

        

    def get_tenant_details(self, tenant_id) -> requests.Response:
        return self.backend.get_tenant_details(tenant_id)
    

    def create_subscription(self, priceID: str, stripeCustomerID :str, quantity:int, tenantID: str) -> requests.Response:
        response = self.backend.create_subscription(priceID, stripeCustomerID, quantity, tenantID)

        Logger.logger.info(f"Subscription created successfully for tenantID: {tenantID} with priceID: {priceID}")

        stripeSubscriptionID = response.json().get("id", {})

        Logger.logger.info("Validate tenants details after subscription creation")
        updated, t = self.wait_for_report(report_type=self.is_subscription_updated,
                                               tenant_id=tenantID,
                                               stripeSubscriptionID=stripeSubscriptionID,
                                               timeout=WEBHOOK_TIMEOUT,
                                               sleep_interval=WEBHOOK_SLEEP_INTERVAL)

        # updated = self.wait_for_webhook_create_subscription(tenantID, stripeSubscriptionID, timeout=WEBHOOK_TIMEOUT, sleep_interval=WEBHOOK_SLEEP_INTERVAL)
        assert updated == True, "validate create subscription failed - stripeSubscriptionID is not updated"
        return response
    
        
    def cancel_subscription(self, tenantID: str) -> requests.Response:
        response = self.backend.cancel_subscription(tenantID)
        Logger.logger.info(f"Subscription canceled successfully for tenantID: {tenantID}")

        Logger.logger.info("Validate tenants details after subscription canceled")
        update, t = self.wait_for_report(report_type=self.is_subscription_canceled,
                                                  tenant_id=tenantID,
                                                    timeout=WEBHOOK_TIMEOUT,
                                                    sleep_interval=WEBHOOK_SLEEP_INTERVAL)
        assert update == True, "validate cancel subscription failed - cancelAtPeriodEnd is not True"
        return response
    
    def renew_subscription(self, tenantID: str) -> requests.Response:
        response = self.backend.renew_subscription(tenantID)
        Logger.logger.info(f"Subscription renewed successfully for tenantID: {tenantID}")

        Logger.logger.info("Validate tenants details after subscription renewed")
        updated, t = self.wait_for_report(report_type=self.is_subscription_active,
                                                    tenant_id=tenantID,
                                                    timeout=WEBHOOK_TIMEOUT,
                                                    sleep_interval=WEBHOOK_SLEEP_INTERVAL)
        assert updated == True, "validate renew subscription failed - cancelAtPeriodEnd is not False"
        return response


    def stripe_checkout(self,priceID) -> requests.Response:
        quantity = 5
        return self.backend.stripe_checkout(priceID, quantity)

    def stripe_billing_portal(self) -> requests.Response:
        return self.backend.stripe_billing_portal()

    
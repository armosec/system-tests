
from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger
from .base_stripe import BaseStripe
from time import sleep
import requests
import time


WEBHOOK_TIMEOUT = 2
WEBHOOK_SLEEP_INTERVAL = 0.5

class StripeWebhook(BaseStripe):

    '''
        check subscription is renewed successfully and expected data is updated in tenant details (via webhook)
    '''

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(StripeWebhook, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def wait_for_webhook_create_subscription(self, tenant_id, stripeSubscriptionID, timeout=2, sleep_interval=0.5) -> bool:


        timeout_start = time.time()
        updated = False

        while time.time() < timeout_start + timeout and not updated:
            response = self.get_tenant_details(tenant_id)
            if response.json().get("activeSubscription", {}).get("stripeSubscriptionID", {}) == stripeSubscriptionID:
                updated = True
            else:
                sleep(sleep_interval)
        
        return updated
    
    def wait_for_webhook_cancel_subscription(self, tenant_id, timeout=2, sleep_interval=0.5) -> bool:

        timeout_start = time.time()
        updated = False

        while time.time() < timeout_start + timeout and not updated:
            response = self.get_tenant_details(tenant_id)
            activeSubscription = response.json().get("activeSubscription", {})
        
            if self.is_subscription_canceled(activeSubscription):
                updated = True
            else:
                sleep(sleep_interval)
        
        return updated
    
    def wait_for_webhook_renew_subscription(self, tenant_id, timeout=2, sleep_interval=0.5) -> bool:

        timeout_start = time.time()
        updated = False

        while time.time() < timeout_start + timeout and not updated:
            response = self.get_tenant_details(tenant_id)
            activeSubscription = response.json().get("activeSubscription", {})
        
            if self.is_subscription_active(activeSubscription):
                updated = True
            else:
                sleep(sleep_interval)
        
        return updated


    def start(self):
        res = self.create_new_tenant()

        test_tenant_id = res.json().get("tenantId", {})

        self.test_tenants_ids.append(test_tenant_id)
        
        Logger.logger.info("Stage 1: create a subscription")
        response = self.create_subscription(self.expected_prices[0]["name"], self.test_stripe_customer_id, test_tenant_id)
        stripeSubscriptionID = response.json()["id"]

        Logger.logger.info("Stage 2: Validate tenants details after subscription creation")

        updated = self.wait_for_webhook_create_subscription(test_tenant_id, stripeSubscriptionID, timeout=WEBHOOK_TIMEOUT, sleep_interval=WEBHOOK_SLEEP_INTERVAL)
        assert updated == True, "create subscription - stripeSubscriptionID is not updated"

        Logger.logger.info("Stage 4: cancel a subscription")
        response = self.cancel_subscription(test_tenant_id)

        Logger.logger.info("Stage 5: Validate tenants details after subscription canceled")
        updated = self.wait_for_webhook_cancel_subscription(test_tenant_id, timeout=WEBHOOK_TIMEOUT, sleep_interval=WEBHOOK_SLEEP_INTERVAL)
        assert updated == True, "cancel subscription - cancelAtPeriodEnd is not True"

        Logger.logger.info("Stage 6: renew a subscription")
        response = self.renew_subscription(test_tenant_id)
        
        Logger.logger.info("Stage 7: Validate tenants details after subscription renewed")
        updated = self.wait_for_webhook_renew_subscription(test_tenant_id, timeout=WEBHOOK_TIMEOUT, sleep_interval=WEBHOOK_SLEEP_INTERVAL)
        assert updated == True, "renew subscription - cancelAtPeriodEnd is not False"


        return self.cleanup()
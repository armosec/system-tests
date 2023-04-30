
from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger
from .base_stripe import BaseStripe
from time import sleep
import requests
import time


class StripeWebhook(BaseStripe):

    '''
        check subscription is created, canceled and renewed successfully and expected data is updated in tenant details (via webhook)
        
    '''

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(StripeWebhook, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)


    def start(self):
        test_tenant_id = self.create_new_tenant()

        Logger.logger.info("Stage 1: create a subscription")
        response = self.create_subscription(self.expected_prices[0]["name"], self.test_stripe_customer_id, test_tenant_id)

        Logger.logger.info("Stage 2: cancel a subscription")
        response = self.cancel_subscription(test_tenant_id)

        Logger.logger.info("Stage 3: renew a subscription")
        response = self.renew_subscription(test_tenant_id)
   
        return self.cleanup()
    
    def cleanup(self, **kwargs):
        self.cancel_test_subscriptions()
        return super().cleanup(**kwargs)
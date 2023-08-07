from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger
from .base_stripe import BaseStripe


class Portal(BaseStripe):
    '''
        check stripe customer billing portal page
    '''
    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(Portal, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        quantity = 5

        Logger.logger.info("Stage 1: create a subscription")
        response = self.create_subscription(self.expected_prices[0]["name"], self.test_stripe_customer_id, quantity, self.test_tenant_id)

        Logger.logger.info("Stage 2: Get billing portal URL")
        response = self.stripe_billing_portal()

        Logger.logger.info("Stage 3: cancel a subscription")
        response = self.cancel_subscription(self.test_tenant_id)

        return self.cleanup()
    
    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)
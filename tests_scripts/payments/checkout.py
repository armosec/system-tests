
from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger
from .base_stripe import BaseStripe
from time import sleep


PROVISION_ACCESS_TIMEOUT = 1
PROVISION_ACCESS_SLEEP_INTERVAL = 0.2

class Checkout(BaseStripe):
    '''
        check stripe checkout page.
    '''

    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(Checkout, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        Logger.logger.info("Stage 1: Go to stripe checkout page for each price")

        for price in self.expected_prices:
            response = self.stripe_checkout(price["name"])

        return self.cleanup()

from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger
from .base_stripe import BaseStripe
from time import sleep


class Portal(BaseStripe):
    '''
        check stripe customer billing portal page - if returns 200 is means that the page is up and running
    '''
    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(Portal, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):
        Logger.logger.info("Create new tenant")
        self.create_new_tenant()

        Logger.logger.info("Get Tenants details")
        response = self.get_tenant_details()

        Logger.logger.info("Stage 1: Go to stripe billing portal")

        response = self.stripe_billing_portal()

        return self.cleanup()
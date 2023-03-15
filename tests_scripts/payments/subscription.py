
from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger
from .base_stripe import BaseStripe
from time import sleep


PROVISION_ACCESS_TIMEOUT = 1
PROVISION_ACCESS_SLEEP_INTERVAL = 0.2

class Checkout(BaseStripe):
    '''
        check stripe checkout page - if returns 200 is means that the page is up and running
    '''

    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(Checkout, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):

        Logger.logger.info("Stage 1: Go to stripe checkout page for each price")

        for price in self.expected_prices:
            response = self.stripe_checkout(price["name"])

        return self.cleanup()

class Create(BaseStripe):
    '''
        check subscription is created successfully and expected access data is updated in tenant details
    '''

    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(Create, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)


    def start(self):

        res = self.create_new_tenant()

        test_tenant_id = res.json().get("tenantId", {})

        self.test_tenants_ids.append(test_tenant_id)
        
        Logger.logger.info("Stage 1: create a subscription")
        response = self.create_subscription(self.expected_prices[0]["name"], self.test_stripe_customer_id, test_tenant_id)

        Logger.logger.info("Stage 2: Validate tenants subscription is active")
        updated = self.wait_for_paying(test_tenant_id, timeout=PROVISION_ACCESS_TIMEOUT, sleep_interval=PROVISION_ACCESS_SLEEP_INTERVAL)
        assert updated == True, "tenant is not updated to paying"


        return self.cleanup()
    


class Cancel(BaseStripe):

    '''
        check subscription is canceled successfully and expected access data is updated in tenant details
    '''
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(Cancel, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):
        res = self.create_new_tenant()

        test_tenant_id = res.json().get("tenantId", {})

        self.test_tenants_ids.append(test_tenant_id)
        
        Logger.logger.info("Stage 1: create a subscription")
        response = self.create_subscription(self.expected_prices[0]["name"], self.test_stripe_customer_id, test_tenant_id)

        Logger.logger.info("Stage 2: Validate tenants subscription is active")
        updated = self.wait_for_paying(test_tenant_id, timeout=PROVISION_ACCESS_TIMEOUT, sleep_interval=PROVISION_ACCESS_SLEEP_INTERVAL)
        assert updated == True, "tenant is not updated to paying"

        Logger.logger.info("Stage 3: cancel a subscription")
        response = self.cancel_subscription(test_tenant_id)

        Logger.logger.info("Stage 4: Validate tenants details after subscription canceled")
        updated = self.wait_for_paying(test_tenant_id, timeout=PROVISION_ACCESS_TIMEOUT, sleep_interval=PROVISION_ACCESS_SLEEP_INTERVAL)
        assert updated == True, "tenant is not updated to paying"

        return self.cleanup()
    

class Renew(BaseStripe):

    '''
        check subscription is renewed successfully and expected access is updated in tenant details 
    '''

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(Renew, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):
        res = self.create_new_tenant()

        test_tenant_id = res.json().get("tenantId", {})

        self.test_tenants_ids.append(test_tenant_id)
        
        Logger.logger.info("Stage 1: create a subscription")
        response = self.create_subscription(self.expected_prices[0]["name"], self.test_stripe_customer_id, test_tenant_id)

        Logger.logger.info("Stage 2: Validate tenants subscription is active")
        updated = self.wait_for_paying(test_tenant_id, timeout=PROVISION_ACCESS_TIMEOUT, sleep_interval=PROVISION_ACCESS_SLEEP_INTERVAL)
        assert updated == True, "tenant is not updated to paying"

        Logger.logger.info("Stage 3: cancel a subscription")
        response = self.cancel_subscription(test_tenant_id)

        Logger.logger.info("Stage 4: Validate tenants details after subscription canceled")
        updated = self.wait_for_paying(test_tenant_id, timeout=PROVISION_ACCESS_TIMEOUT, sleep_interval=PROVISION_ACCESS_SLEEP_INTERVAL)
        assert updated == True, "tenant is not updated to paying"

        Logger.logger.info("Stage 5: renew a subscription")
        response = self.renew_subscription(test_tenant_id)
        
        Logger.logger.info("Stage 6: Validate tenants details after subscription renewed")
        updated = self.wait_for_paying(test_tenant_id, timeout=PROVISION_ACCESS_TIMEOUT, sleep_interval=PROVISION_ACCESS_SLEEP_INTERVAL)
        assert updated == True, "tenant is not updated to paying"

        return self.cleanup()

from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger
from .base_stripe import BaseStripe
from time import sleep



class Checkout(BaseStripe):
    '''
        check stripe checkout page - if returns 200 is means that the page is up and running
    '''

    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(Checkout, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):
        Logger.logger.info("Create new tenant")
        self.create_new_tenant()

        Logger.logger.info("Stage 1: Go to stripe checkout page for each price")

        for price in self.expected_prices:
            response = self.stripe_checkout(price["name"])

        return self.cleanup()

class Create(BaseStripe):
    '''
        check subscription is created successfully and expected data is updated in tenant details (via webhook)
    '''

    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(Create, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):
        Logger.logger.info("Create new tenant")
        self.create_new_tenant()

        Logger.logger.info("Get Tenants details")
        response = self.get_tenant_details()

        Logger.logger.info("Stage 1: create a subscription")
        response = self.create_subscription(self.expected_prices[0]["name"])
        stripeSubscriptionID = response.json()["id"]

        Logger.logger.info("Stage 2: Validate tenants details after subscription creation")

        # sleep to let webhook update tenant details
        sleep(2)
        response = self.get_tenant_details()
        assert response.json().get("activeSubscription", {}).get("stripeSubscriptionID", {}) == stripeSubscriptionID, "stripeSubscriptionID is not updated"

        Logger.logger.info("Stage 3: Validate tenants subscription is active")
        self.tenants_subscription_active(response.json().get("activeSubscription", {}))

        return self.cleanup()
    


class Cancel(BaseStripe):

    '''
        check subscription is canceled successfully and expected data is updated in tenant details (via webhook)
    '''
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(Cancel, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):
        Logger.logger.info("Create new tenant")
        self.create_new_tenant()

        Logger.logger.info("Get Tenants details")
        response = self.get_tenant_details()


        Logger.logger.info("Stage 1: create a subscription")
        response = self.create_subscription(self.expected_prices[0]["name"])
        # sleep to let webhook update tenant details
        sleep(2)

        Logger.logger.info("Stage 2: cancel a subscription")
        response = self.cancel_subscription()

        Logger.logger.info("Stage 3: Validate tenants details after subscription canceled")
        sleep(2)
        response = self.get_tenant_details()
        self.tenants_subscription_canceled(response.json().get("activeSubscription", {}))

        return self.cleanup()
    

class Renew(BaseStripe):

    '''
        check subscription is renewed successfully and expected data is updated in tenant details (via webhook)
    '''

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(Renew, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):
        Logger.logger.info("Create new tenant")
        self.create_new_tenant()

        Logger.logger.info("Stage 1: create a subscription")
        response = self.create_subscription(self.expected_prices[0]["name"])
        self.http_status_ok(response.status_code)
        # sleep to let webhook update tenant details
        sleep(2)

        Logger.logger.info("Stage 2: cancel a subscription")
        response = self.cancel_subscription()

        Logger.logger.info("Stage 3: Validate tenants details after subscription canceled")
        sleep(2)
        response = self.get_tenant_details()
        self.tenants_subscription_canceled(response.json().get("activeSubscription", {}))
        self.tenants_access_state_paying(response.json().get("customerAccessStatus", {}))

        Logger.logger.info("Stage 4: renew a subscription")
        response = self.renew_subscription()
        
        Logger.logger.info("Stage 5: Validate tenants details after subscription renewed")
        sleep(2)
        response = self.get_tenant_details()
        self.tenants_subscription_active(response.json().get("activeSubscription", {}))

        return self.cleanup()
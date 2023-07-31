from .base_stripe import BaseStripe
from time import sleep
from systest_utils import Logger


class Plans(BaseStripe):
    '''
        check that the plans are configured correctly on backend, and have the expected prices on process.
        result is compared to 'self.expected_prices'
    '''
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(Plans, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)
    
    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
    
        response = self.backend.get_stripe_plans()
        assert "plans" in response.json(), "'plans' not found in response"

        for plan in response.json()["plans"]:
            name = plan["name"]
            price = plan["price"]
            assert name in [price["name"] for price in self.expected_prices], f"price plan '{name}' not found in response"
            expected_price = [price["price"] for price in self.expected_prices if price["name"] == name][0]
            assert price == expected_price, f"expected price of plan '{name}' = '{expected_price}', found '{price}' "

        return self.cleanup()




import inspect
from .structures import PaymentConfiguration


# plan names and their price per unit in cents.
# the name is an internal identifier which is assigned to a stripe priceId object. 
# The price is the price in cents as defined in Stripe price object.
EXPECTED_PRICES = [{"name":"MonthlyPriceID","price":4900},{"name":"YearlyPriceID","price":48000}]
TEST_STRIPE_CUSTOMER_ID = "cus_NT8XoDsp5Alqwc"



class PaymentTests(object):
    '''
    NOTE: 
    1. Tests depends on launching the stripe new backend APIs.
    2. User tested must have a valid stripe customer with a valid test CC. The stripeCustomerID need to be defined in activeSubscripiton.StripeCustomerID. Example fo such a stripe test customer id is "cus_NT8XoDsp5Alqwc"
    3. Tests rely on Admin permissions - this can be achieved by properly configuring the AllowAnyCustomer in the backend environment.
    4. Tests must run on frontEgg supported environments.
    '''
    
    @staticmethod
    def stripe_webhook():
        from tests_scripts.payments.webhook import StripeWebhook
        return PaymentConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=StripeWebhook,
            expected_prices = EXPECTED_PRICES,
            test_stripe_customer_id = TEST_STRIPE_CUSTOMER_ID,
            create_test_tenant = True


        )    

    @staticmethod
    def stripe_checkout():
        from tests_scripts.payments.checkout import Checkout
        return PaymentConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Checkout,
            expected_prices = EXPECTED_PRICES,
            test_stripe_customer_id = TEST_STRIPE_CUSTOMER_ID,
            create_test_tenant = True

        )   

    @staticmethod
    def stripe_billing_portal():
        from tests_scripts.payments.portal import Portal
        return PaymentConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Portal,
            expected_prices = EXPECTED_PRICES,
            test_stripe_customer_id = TEST_STRIPE_CUSTOMER_ID,
            create_test_tenant = True

        )          

    @staticmethod
    def stripe_plans():
        from tests_scripts.payments.plans import Plans
        return PaymentConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Plans,
            expected_prices = EXPECTED_PRICES,
            create_test_tenant = True

        )    


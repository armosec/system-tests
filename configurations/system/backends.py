
from infrastructure.backend_api import *


class Backend(object):

    def __init__(self, name: str, dashboard: str, 
                 auth_url: str = None, 
                 tls_verify: bool = True, 
                 login_method = LOGIN_METHOD_KEYCLOAK, customer_guid: str = None):
        self.name = name
        self.dashboard = dashboard
        self.auth_url = auth_url
        self.tls_verify = tls_verify
        self.login_method = login_method
        self.customer_guid = customer_guid

    def get_dashboard_url(self):
        return self.dashboard

    def get_auth_url(self):
        return self.auth_url

    def get_name(self):
        return self.name

    def use_tls(self):
        return self.tls_verify
    
    def get_login_method(self):
        return self.login_method

    def get_customer_guid(self):
        return self.customer_guid


def set_backends():
    backends = list()

    
    # development frontEgg
    backends.append(Backend(name='development',
                            dashboard='https://eggdashbe-dev.armosec.io',
                            auth_url='https://eggauth-dev.armosec.io',
                            tls_verify=False,
                            login_method=LOGIN_METHOD_FRONTEGG_SECRET))

    
    # staging frontEgg
    backends.append(Backend(name='staging',
                            dashboard='http://eggdashbe-stage.armosec.io',
                            auth_url='https://eggauth-stage.armosec.io',
                            tls_verify=False,
                            login_method=LOGIN_METHOD_FRONTEGG_SECRET))

    # staging frontEgg
    backends.append(Backend(name='production',
                            dashboard='https://api.armosec.io',
                            auth_url='https://auth.armosec.io',
                            tls_verify=False,
                            login_method=LOGIN_METHOD_FRONTEGG_SECRET))


    # # development
    # backends.append(Backend(name='development',
    #                         dashboard='https://dashbe.eudev3.cyberarmorsoft.com',
    #                         login_method=LOGIN_METHOD_KEYCLOAK,
    #                         tls_verify=False))


    #     # staging
    # backends.append(Backend(name='staging',
    #                             dashboard='https://dashbe.eustage2.cyberarmorsoft.com',
    #                             login_method=LOGIN_METHOD_KEYCLOAK,
    # ))

    # # production
    # backends.append(Backend(name='production',
    #                         dashboard='https://dashbe.euprod1.cyberarmorsoft.com',
    #                         login_method=LOGIN_METHOD_KEYCLOAK,
    #                         tls_verify=False))

    
    # local
    # backends.append(Backend(name='local',
    #                         dashboard='http://localhost:7666',
    #                         auth_url='https://eggauth-dev.armosec.io',
    #                         tls_verify=False,
    #                         login_method=LOGIN_METHOD_FRONTEGG_USERNAME))

    # backends.append(Backend(name='local',
    #                         dashboard='http://localhost:7666',
    #                         auth_url='https://eggauth-dev.armosec.io',
    #                         tls_verify=False,
    #                         login_method=LOGIN_METHOD_FRONTEGG_SECRET))


    backends.append(Backend(name='local',
                            dashboard='http://localhost:7666',
                            auth_url='https://eggauth-dev.armosec.io',
                            tls_verify=False,
                            login_method=LOGIN_METHOD_FRONTEGG_USERNAME,
                            customer_guid='SOME_CUSTOMER_GUID'))

    return {backend.get_name(): backend for backend in backends}


BACKENDS = set_backends()

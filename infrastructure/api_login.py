import requests
import jwt
from re import findall
import inspect
from systest_utils.tests_logger import Logger


class NotExistingCustomer(Exception):
    pass


API_OPENID_CUSTOMERS = "/api/v1/openid_customers"
API_FRONTEGG_APITOKEN = "/identity/resources/auth/v1/api-token"

class APILogin(object):
    def __init__(self):
        self.session = requests.Session()
        pass

    def login(self):
        raise NotImplementedError
    
    def getCookie(self, base_url, auth: str, customer_guid):
        data = {"selectedCustomer":f"{customer_guid}"}

        if self.__class__ == KeycloakAPILogin:
            headers = {'Authorization': f'Bearer: {auth}' if 'bearer' not in auth.lower() else ' '.join(findall('[a-zA-Z0-9._\- ]+', auth))}
        else:   
            headers = {'Authorization': f'Bearer: {auth}'}

        response =  self.session.post(f'{base_url}{API_OPENID_CUSTOMERS}',headers= headers, json=data)
        assert response.status_code == 200, f"getCookie failed for customer_guid {customer_guid}: {response.text}, status: {response.status_code}"
        return response.cookies
    

class FrontEggSecretAPILogin(APILogin):
    def __init__(self, auth_url, base_url, client_id, secret_key):
        super().__init__()
        self.auth_url = auth_url
        self.base_url = base_url
        self.api_keys = {
                "clientId": f"{client_id}",
                "secret": f"{secret_key}"
        }


    def decode_jwt(self, token: str):
        return jwt.decode(token, options={"verify_signature": False}, algorithms=['HS256', 'ES256'])
    
    def encode_jwt(self, jwt_token: str):
        return jwt.encode(jwt_token, self.api_keys['secret'])


    def getToken(self):
        response =  self.session.post(f'{self.auth_url}{API_FRONTEGG_APITOKEN}',json=self.api_keys)
        assert response.status_code == 200, f"got error: {response.text}, status: {response.status_code}"
        json_res = response.json()
        return json_res["accessToken"]

    
    def login(self):
        auth = self.getToken()        
        response =  self.session.get(f'{self.base_url}{API_OPENID_CUSTOMERS}',headers= {'Authorization': f'Bearer: {auth}'})
        assert response.status_code == 200, f"got error: {response.text}, status: {response.status_code}"
        json_res = response.json()
        customer_guid = json_res[0]["customerGUID"]
        cookie = super().getCookie(self.base_url, auth, customer_guid)
        return customer_guid, cookie, cookie["auth"]
    
    

class KeycloakAPILogin(APILogin):

    def __init__(self, server, customer, username, password, verify=True):
        super().__init__()
        self.customer = customer
        self.server = server
        self.username = username
        self.password = password
        self.verify = verify
        self.auth = None


    def login(self, r=3):
        """
        Login keycloak using openID method. for more information view the flow here -
        https://obelix.cyberarmor.io/attachment/ticket/249/CyberArmor%20OpenID%20login%20portal%20%20%20dashboard.png

        :return: session cookie
        """
        # Start session with portal
        url = '{}{}'.format(self.server, '/open_id_url')
        response_from_portal = requests.get(url, headers={'Referer': self.server.replace('dashbe', 'dash') + '/login'},
                                            allow_redirects=False)
        assert response_from_portal.status_code == 200, 'Received status code {}\nfrom url: {}\nmessage: {}'.format(
            response_from_portal.status_code, url, response_from_portal.text)

        url = response_from_portal.json()['openIDURL']

        # Get url to the keycloak
        openid_login_url = requests.get(url, headers={'Referer': self.server.replace('dashbe', 'dash') + '/login'},
                                        allow_redirects=False)
        assert openid_login_url.status_code == 200, 'Received status code {}\nfrom url: {}\nmessage: {}'.format(
            openid_login_url.status_code, url, openid_login_url.text)

        # We received a html page so extract keycloak url out of it
        # parsed_html = BeautifulSoup(openid_login_url.text, features="html5lib")
        # url = parsed_html.body.find('form', attrs={'id': "kc-form-login"})['action']
        url = findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ])+', openid_login_url.text)[-1].replace('amp;',
                                                                                                                '')

        # login to keycloak. we use the cookies we received from portal
        keycloak_session = requests.post(url, cookies=openid_login_url.cookies,
                                         data={'username': self.username, 'password': self.password}, verify=self.verify,
                                         timeout=10, allow_redirects=False)

        if keycloak_session.status_code == 200 and keycloak_session.text.count('Invalid username or password'):
            raise Exception('Invalid username or password')

        assert keycloak_session.status_code == 302, 'Received status code {}\nfrom url: {}\nmessage: {}'.format(
            keycloak_session.status_code, url, keycloak_session.text)

        url = '{}/{}?{}'.format(self.server, 'open_id_callback',
                                keycloak_session.headers['Location'].split('?')[1])

        r = requests.get(
            url, headers={'Referer': self.server.replace('dashbe', 'dash') + '/login'})
        assert r.status_code == 200, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"

        auth = r.text

        auth_header = {
            'Authorization': 'bearer ' + r.text if 'bearer' not in r.text else ' '.join(
                findall('[a-zA-Z0-9._\- ]+', r.text))}

        # Received a list of dicts that are customer name and uid in a string format (thats way we split the response)
        received_customers = findall('[a-zA-Z0-9._\-]+',
                                     requests.get('{}/{}'.format(self.server, 'openid_customers'),
                                                  headers=auth_header).text)

        # We clear the names and uid from the unnecessary. and create a dict
        customers = {received_customers[i + 1]: received_customers[i + 3]
                     for i in range(0, len(received_customers), 4)}

        Logger.logger.debug('Available customers: %s' % str(customers))

        if not self.customer:
            self.customer = list(customers)[0]
        else:
            if not self.customer in customers:
                raise NotExistingCustomer('%s is not associated with user %s (available customers: %s)' % (
                    self.customer, self.username, ','.join(customers.keys())))
        customer_guid = customers[self.customer]

        # # Finally, get session cookie
        cookie = super().getCookie(self.server, auth, customer_guid)

        Logger.logger.debug('Session cookie set for user: {}'.format(self.username))
        return customer_guid, cookie, auth


class FrontEggUsernameAPILogin(APILogin):
    """
    ONLY TESTED FOR LOCAL ENVIRONMENT WITH CUSTOMER GUID DEFINED IN AllowedAnyCustomer.
    """
    def __init__(self, server, customer, username, password, customer_guid):
        self.customer = customer
        self.server = server
        self.username = username
        self.password = password
        self.customer_guid = customer_guid
        self.auth = None

    def login(self):
        payload = {"email": self.username, "customer": self.customer, "password": self.password, "customerGUID": self.customer_guid}
        res = requests.post(self.server + "/login", data=payload)
        auth = {"Cookie" : "auth=" + res.cookies.get("auth")}
        login_customer_cookie = res.cookies
        return self.customer_guid, login_customer_cookie, auth

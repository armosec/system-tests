# encoding: utf-8
import math
import sys
import time
import traceback
from datetime import datetime
import inspect
from typing import Dict, List
import dateutil.parser
import requests
import websocket
from  http import client
from systest_utils import statics

from systest_utils.tests_logger import Logger
from systest_utils.wlid import Wlid

import json
from infrastructure.api_login import *


class NotExistingCustomer(Exception):
    pass


INTEGRITY_STATUS_CLEAR = 0
INTEGRITY_STATUS_PROTECTED = 2
INTEGRITY_STATUS_BLOCKED = -1


LOGIN_METHOD_KEYCLOAK = "keycloak"
LOGIN_METHOD_FRONTEGG_SECRET = "frontegg_secret"
LOGIN_METHOD_FRONTEGG_USERNAME = "frontegg_username"

API_FRONTEGG_IDENTITY_RESOURCES_USERS_V2_USERS_V2_ME_TENANTS = "/frontegg/identity/resources/users/v2/me/tenants"


API_STRIPE_BILLING_PORTAL = "/api/v1/tenants/stripe/portal"
API_STRIPE_CHECKOUT = "/api/v1/tenants/stripe/checkout"
API_STRIPE_PLANS = "/api/v1/tenants/stripe/plans"
API_TENANT_DETAILS = "/api/v1/tenants/tenantDetails"
API_TENANT_CREATE= "/api/v1/tenants/createTenant"
API_CLUSTER = "/api/v1/cluster"
API_IMAGE_SCAN_STATS = "/api/v1/customerState/reports/imageScan" 
API_JOBREPORTS = "/api/v1/jobReports"
API_POSTURE_CLUSTERSOVERTIME = "/api/v1/posture/clustersOvertime"
API_POSTURE_FRAMEWORKS =  "/api/v1/posture/frameworks"
API_POSTURE_CONTROLS = "/api/v1/posture/controls"
API_POSTURE_TOPFAILEDCONTROLS = "/api/v1/posture/topFailedControls"
API_POSTURE_RESOURCES = "/api/v1/posture/resources"
API_POSTURE_SCAN = "/api/v1/posture/scan"

API_VULNERABILITYEXCEPTIONPOLICY = "/api/v1/vulnerabilityExceptionPolicy"
API_VULNERABILITY_SCANRESULTSSUMSUMMARY = "/api/v1/vulnerability/scanResultsSumSummary"
API_VULNERABILITY_SCAN_V2 = "/api/v1/vulnerability/scan/v2/"
API_VULNERABILITY_SCANRESULTSDETAILS = "/api/v1/vulnerability/scanResultsDetails"
API_VULNERABILITY_UNIQUE_VALUES_SUMMARY =   "/api/v1/uniqueValues/vulnerability/scanResultsSumSummary"


API_REPOSITORYPOSTURE = "/api/v1/repositoryPosture"
API_REPOSITORYPOSTURE_REPOSITORIES =  "/api/v1/repositoryPosture/repositories"
API_REPOSITORYPOSTURE_FILES = "/api/v1/repositoryPosture/files"
API_REPOSITORYPOSTURE_RESOURCES = "/api/v1/repositoryPosture/resources"

API_REGISTRY_SCANRESULTSSUMSUMMARY = "/api/v1/registry/scanResultsSumSummary"
API_REGISTRY_SCANRESULTSSUMSUMMARY_DELETE = "/api/v1/registry/scanResultsSumSummary/delete"
API_REGISTRY_SCANRESULTSDETAILS = "/api/v1/registry/scanResultsDetails"
API_REGISTRY_SCANRESULTSLAYERSUMMARY = "/api/v1/registry/scanResultsLayerSummary"
API_REGISTRY_SCAN = "/api/v1/registry/scan/"
API_REGISTRY_JOBREPORTSSTATUS = "/api/v1/registry/jobReportsStatus"
API_REGISTRY_RESPOSITORIESLIST = "/api/v1/registry/repositoriesList"

API_FRAMEWORK = "/api/v1/framework"

API_CUSTOMERCONFIGURATION = "/api/v1/customerConfiguration"

API_POSTUREEXCEPTIONPOLICY = "/api/v1/postureExceptionPolicy"


API_ADMIN_TENANTS = "/api/v1/admin/tenants"
API_ADMIN_CREATE_SUBSCRIPTION = "/api/v1/admin/createSubscription"
API_ADMIN_CANCEL_SUBSCRIPTION = "/api/v1/admin/cancelSubscription"
API_ADMIN_RENEW_SUBSCRIPTION = "/api/v1/admin/renewSubscription"

API_NOTIFICATIONS_UNSUBSCRIBE = "/api/v1/notifications/unsubscribe"
API_NOTIFICATIONS_ALERTCHANNEL = "/api/v1/notifications/alertChannel"


def deco_cookie(func):

    def apply_cookie(*args, **kwargs):
        ControlPanelAPIObj = args[0]
        if type(ControlPanelAPIObj) != ControlPanelAPI:
            raise Exception("In 'apply_cookie': First argument must be ControlPanelAPI object")
        
        if "params" not in kwargs:
            kwargs["params"] = {}

        url = args[1] if len(args) > 1 else kwargs.get("url", "")

        if url == "":
            raise Exception("In 'apply_cookie': No url was given")

        if "cookies" not in kwargs:
            if "/api/v1/admin/" in url:
                kwargs["cookies"] = ControlPanelAPIObj.login_customer_cookie
                if "customerGUID" not in kwargs["params"]:
                    kwargs["params"]["customerGUID"] = ControlPanelAPIObj.login_customer_guid
            else:
                kwargs["cookies"] = ControlPanelAPIObj.selected_tenant_cookie
                if "customerGUID" not in kwargs["params"]:
                    kwargs["params"]["customerGUID"] = ControlPanelAPIObj.selected_tenant_id

        kwargs['headers'] = kwargs.get("headers", ControlPanelAPIObj.auth)
        kwargs["timeout"] = kwargs.get("timeout", 21)
        kwargs["verify"] = kwargs.get("verify", ControlPanelAPIObj.verify)

        result = func(*args, **kwargs)
        return result
    return apply_cookie


class ControlPanelAPI(object):
    """
    This class is used to interact with the backend APIs.

    Attributes
    ----------
    server  : str
        backend url we run APIS against.
    login_method : str
        the login_method to use. Can be either "keycloak" or "frontegg"
    username : str
        the username to use for login_method "keycloak"
    password : str
        the password to use for login_method "keycloak"
    customer : str
        the customer to use for login_method "keycloak"
    client_id : str
        the client_id to use for login_method "frontegg"
    secret_key : str
        the secret_key to use for login_method "frontegg"
    login_customer_cookie : str
        the cookie used for login the API. 
    login_customer_guid : str
        the customer_guid used for login the API. In order to access the admin APIS, this customer must be configured in AllowedAnyCustomer.
    selected_tenant_cookie : str
        the cookie to use for selected tenant APIs actions. By default, the login_customer_cookie is used.
    selected_tenant_ud : str
        the tenant id to use for selected tenant APIs actions. By default, the login_customer_guid is used.
    auth : str
        the auth to use for admin APIs actions
    auth_url : str
        the url to use for login to get the auth
    verify : bool
        whether to verify the SSL certificate or not. Default is True.
    api_login : APILogin
        the api_login object constructed from the login_method.

    
    """

    def __init__(self, user_name, password, customer, client_id, secret_key, url, auth_url=None, login_method=LOGIN_METHOD_KEYCLOAK, customer_guid=None):
        self.server = url
        self.login_method = login_method
        self.customer_guid = customer_guid

        # Required for login_method == LOGIN_METHOD_KEYCLOAK
        self.username = user_name
        self.password = password
        self.customer = customer

        # Required for login_method == LOGIN_METHOD_FRONTEGG
        self.client_id = client_id 
        self.secret_key = secret_key
        self.auth_url = auth_url

        # the cookie retrieved on login - this is usually and admin tenant cookie to allow "admin" actions.
        self.login_customer_cookie = None
        self.login_customer_guid = None

        # the cookie of the selected tenant - by default, admin login_cookie unless selected other tenant.
        self.selected_tenant_cookie = None
        self.selected_tenant_id = None

        # the auth retrieved for the admin tenant
        self.auth = None

        self.api_login = APILogin()

        self.verify = True
        
        self.login(self.login_method)
 

    def login(self, login_method):
        if login_method == LOGIN_METHOD_KEYCLOAK:
            self.api_login = KeycloakAPILogin(username=self.username, password=self.password, customer=self.customer, server=self.server, verify=self.verify)
        elif login_method == LOGIN_METHOD_FRONTEGG_SECRET:
            self.api_login = FrontEggSecretAPILogin(auth_url=self.auth_url, base_url=self.server, client_id=self.client_id, secret_key=self.secret_key)
        elif login_method == LOGIN_METHOD_FRONTEGG_USERNAME:
            self.api_login = FrontEggUsernameAPILogin(server=self.server, username=self.username, password=self.password, customer=self.customer, customer_guid=self.customer_guid)
        else:
            raise Exception(f"Login method '{login_method}' not supported")
        
        self.login_customer_guid, self.login_customer_cookie, auth = self.api_login.login()  
        Logger.logger.info(f"Customer guid  {self.login_customer_guid} authenticated successfully")
        if login_method == LOGIN_METHOD_FRONTEGG_USERNAME:
            self.auth = {"Cookie" : "auth=" + auth}
        else:
            self.auth = {'Authorization': f'Bearer {auth}'} if 'bearer' not in auth.lower() else {'Authorization': f'{auth}'}

        self.selected_tenant_id = self.login_customer_guid
        self.selected_tenant_cookie = self.login_customer_cookie

    ## ************** Tenants Backend APIs ************** ##


    def get_selected_tenant(self) -> str:
        """
        Returns the current selected tenant id
        """
        return self.selected_tenant_id

    
    def get_tenant_cookie(self, tenant_id: str) -> requests.Response:
        """
        Get the cookie of the given tenant.
        """
        if tenant_id == self.selected_tenant_id:
            return self.selected_tenant_cookie
        
        return self.api_login.getCookie(self.server, self.api_login.frontEgg_auth, tenant_id)

    def select_tenant(self, tenant_id: str):
        """ 
        Configure tenant_id as the current selected tenant. 
        Once selected, all APIs will be executed on this tenant except for the admin APIs.
        """
        if self.get_selected_tenant() != tenant_id:
            self.selected_tenant_cookie = self.get_tenant_cookie(tenant_id)
            self.selected_tenant_id = tenant_id
            Logger.logger.info(f"Selected tenant: {tenant_id}")
    
    def get_tenant_details(self, tenant_id=None) -> requests.Response:
        """
        Get tenant details for tenant_id. If None, get details of the selected tenant.
        """
        if tenant_id == self.selected_tenant_id or tenant_id is None:
            cookies = self.selected_tenant_cookie
        else:
            cookies = self.get_tenant_cookie(tenant_id)
        res = self.get(API_TENANT_DETAILS, cookies=cookies, json={"tenantId": tenant_id})
        assert res.status_code == client.OK, f"Failed to get tenant {tenant_id} details. Response: {res.text}"
        if not res.json()["guid"] == tenant_id:
            raise Exception(f"Requested {tenant_id} details, got {res.text['guid']}. Make sure to first select the customer using select_tenant()")

        return res
    
    def create_tenant(self, tenantName: str):
        """
        Creates a new tenant with name tenantName.

        params:
            tenantName: The name of the tenant to create.

        returns: The response of the request.
        """

        if self.login_method != LOGIN_METHOD_FRONTEGG_SECRET:
            raise Exception(f"create_tenant() is only supported for {LOGIN_METHOD_FRONTEGG_SECRET} login_method")
  

        res = self.post(API_TENANT_CREATE, json={"customerName": tenantName, "userId": self.api_login.get_frontEgg_user_id()}, cookies=None, headers={"Authorization": f"Bearer {self.api_login.get_frontEgg_auth_user_id()}"})
        assert res.status_code in [client.CREATED, client.OK], f"Failed to create tenant {tenantName}: {res.text}"
        assert res.json().get("tenantId", {}) != {}, f"TenantId is empty: {res.text}"
        return res, res.json()["tenantId"]
    
    def delete_tenant(self, tenant_id) -> requests.Response:
        """
        Deletes a tenant. .

        params:
            tenant_id: The id of the tenant to delete.

        returns: 
            The response of the request.

        Exceptions:
            Exception: If tenant_id is the admin customer.
        """

        if tenant_id == self.login_customer_guid:
            raise Exception (f"Deleting the login customer '{tenant_id}' is not allowed.")


        res = self.delete(API_ADMIN_TENANTS, json={"tenantsIds": [tenant_id]})
        assert res.status_code == client.OK, f"delete tenant failed {tenant_id}: {res.status_code} {res.text}"
        return res

    


    ## ************** Stripe Backend APIs ************** ##

    def stripe_billing_portal(self) -> requests.Response:
        """
            Creates a stripe billing portal url for the selected tenant.
        """
        res = self.get(API_STRIPE_BILLING_PORTAL) 
        assert res.status_code == client.CREATED, f"stripe billing portal failed to create url for tenant_id {self.selected_tenant_id}. Response: {res.text}"
        return res

    def stripe_checkout(self, priceID: str, qauntity: int) -> requests.Response:
        """
            Creates a stripe checkout url for the selected tenant.
        """
        res = self.post(API_STRIPE_CHECKOUT, json={"priceID": priceID, "quantity": qauntity},)
        assert res.status_code == client.CREATED, f"stripe checkout failed to create url for tenant_id {self.selected_tenant_id}. Response: {res.text}"
        return res
    
    def get_stripe_plans(self) -> requests.Response:
        """
            Get all stripe plans.
        """
        res = self.get(API_STRIPE_PLANS)
        assert res.status_code == client.OK, f"get_stripe_plans Failed. expected status code 200, found {res.status_code}. response: {res.text} Make sure you have a valid stripe secret key and priceIdsMap is well configured"
        return res

    
    def create_subscription(self, priceID: str, stripeCustomerID: str, quantity: int, tenantID: str)-> requests.Response:
        """
            Creates a subscription for a tenant.

            params:
                priceID: The price id of the plan to subscribe to.
                stripeCustomerID: The stripe customer id of the tenant. The customer id is expected to already exist in Stripe.
                tenantID: The id of the tenant to create subscription for.

            returns: The response of the request.
        """
        res = self.post(
            API_ADMIN_CREATE_SUBSCRIPTION,
            json={
                "priceID": priceID,
                "stripeCustomerID": stripeCustomerID,
                "tenantID": tenantID,
                "quantity": quantity,
            },
        )
        assert res.status_code == client.OK, f"stripe create subscription failed with priceID: {priceID}, response.text: {res.text}"
        return res
    
    def cancel_subscription(self, tenantID: str)-> dict:
        """
            Cancels a subscription for a tenant.

            params:
                tenantID: The id of the tenant to cancel subscription for.
        """
        res = self.post(
            API_ADMIN_CANCEL_SUBSCRIPTION,
            json={
                "tenantID": tenantID
            },
        )
        assert res.status_code == client.OK, f"cancel subscription failed for tenantID: {tenantID}"
        return res
    
    def renew_subscription(self, tenantID: str)-> dict:
        """
            Renews a subscription for a tenant.

            params:
                tenantID: The id of the tenant to renew subscription for.
        """
        res = self.post(
            API_ADMIN_RENEW_SUBSCRIPTION,
            json={
                "tenantID": tenantID
            },
        )        
        assert res.status_code == client.OK, f"renew subscription failed for tenantID: {tenantID}"
        return res
    
    def get_customer_guid(self):
        return self.selected_tenant_id

    def get_client_id(self):
        return self.client_id

    def get_secret_key(self):
        return self.secret_key

    def cleanup(self, namespace=str(), ca_cluster=str()):
        Logger.logger.info("ControlPanelAPI Clean Up")

    def delete_ca_cluster(self, ca_cluster='default'):
        r = self.delete(API_CLUSTER, params={"customerGUID": self.selected_tenant_id,
                                     "cluster": ca_cluster}
                        )
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Fail To Delete CA Cluster. Request: customer tree of customer "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

        return r.status_code

    def get_full_clusters_list(self):
        r = self.get(API_CLUSTER, params={"customerGUID": self.selected_tenant_id})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{API_CLUSTER}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json(), len(r.content)

    def get_finished_jobs_of_wlid(self, wlid: str):
        # TODO: page on if need for
        post_body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [
                {
                    "target": wlid,
                    "status": "failure,done"
                }
            ]
        }
        r = self.post(
            API_JOBREPORTS, params={"customerGUID": self.selected_tenant_id}, json=post_body)
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{API_JOBREPORTS}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_info_from_wlid(self, wlid):
        # TODO update to v2
        url = "/v1/microservicesOverview"
        r = self.get(
            url, params={"customerGUID": self.selected_tenant_id, "wlid": wlid})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_full_customer_overview(self):
        # TODO update to v2
        url = "/v1/microservicesOverview"
        r = self.get(
            url, params={"customerGUID": self.selected_tenant_id, "active": ('true', 'false')})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json(), len(r.content)

    def get_secret(self, sid):
        url = "/k8srestapi/v1/secret"
        r = self.get(
            url, params={"customerGUID": self.selected_tenant_id, "sid": sid})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_processes_of_wlid(self, wlid):
        # TODO update to v2
        url = "/v1/session"
        r = self.get(
            url, params={"customerGUID": self.selected_tenant_id, "wlid": wlid})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_processe_full_info(self, session_id):
        # TODO update to v2
        url = "/v1/session"
        r = self.get(
            url, params={"customerGUID": self.selected_tenant_id, "sessionID": session_id})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_all_namespace_wlids(self, cluster: str, namespace: str):
        # TODO update to v2
        url = "/v1/microservicesOverview"
        r = self.get(url, params={
            "customerGUID": self.selected_tenant_id, "cluster": cluster, "namespace": namespace})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_neighbours(self):
        # TODO update to v2
        url = "/v1/neighbours"
        r = self.get(url, params={"customerGUID": self.selected_tenant_id})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_job_events_for_job(self, job_id: str):
        r = self.post(API_JOBREPORTS, params={"customerGUID": self.selected_tenant_id}, json={
            "pageNum": 1, "pageSize": 100, "innerFilters": [{"jobID": job_id}]})
        Logger.logger.debug("return_job_status: {0}".format(r.status_code))
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{API_JOBREPORTS}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_incidents(self, **kwargs):
        # TODO update to v2
        url = "/v1/incidents"
        params = {"customerGUID": self.selected_tenant_id}
        if kwargs:
            params.update(**kwargs)
        r = self.get(url, params=params)
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    @staticmethod
    def sort_table_response_by_time(table, time_field: str, date_format: str = '%Y-%m-%dT%H:%M:%SZ'):
        if len(table) == 0:
            raise Exception("received empty response")
        index = table[0].index(time_field)
        return [table[0]] + sorted(table[1:], key=lambda x: datetime.strptime(x[index], date_format))[::-1]

    def get_outbound_connections(self, server_wlid: str = None, client_wlid: str = None, protection_status: int = None):
        url = "/v2/outboundConnectionsOpenLog"
        params = {"customerGUID": self.selected_tenant_id}
        if client_wlid:
            params["wlid"] = client_wlid
        inner_filters = {}
        # TODO temporary, waiting for enrichment feature
        if server_wlid and protection_status and protection_status > 0:
            inner_filters["peerWlid"] = server_wlid
        if protection_status:
            inner_filters["protected"] = str(protection_status)
        data = {"innerFilters": [inner_filters]}
        r = self.post(url, params=params, data=json.dumps(data))
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        assert r.text, f'no outbound connections found between client {client_wlid} and server {server_wlid}'
        return r.json()

    def get_inbound_connections(self, server_wlid: str = None, client_wlid: str = None,
                                protection_status: int = None):
        url = "/v2/inboundConnectionsOpenLog"
        params = {"customerGUID": self.selected_tenant_id}
        if server_wlid:
            params["wlid"] = server_wlid
        inner_filters = {}
        # TODO temporary, waiting for enrichment feature
        if client_wlid and protection_status and protection_status > 0:
            inner_filters["peerWlid"] = client_wlid
        if protection_status:
            inner_filters["protected"] = protection_status
        data = {"innerFilters": [inner_filters]}
        r = self.post(url, params=params, data=json.dumps(data))
        assert 200 <= r.status_code < 300, f"'{inspect.currentframe().f_code.co_name}, url: {url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        assert r.text, f'no inbound connections found between client {client_wlid} and server {server_wlid}'
        return r.json()

    def get_microservice_instances(self, wlid: str = None, instance_id: str = None):
        # TODO update to v2
        url = "/v1/microserviceInstance"
        params_dict = {"customerGUID": self.selected_tenant_id,
                       "active": ["false", "true"]}
        if wlid is not None:
            params_dict["wlid"] = wlid
        if instance_id is not None:
            params_dict["instanceID"] = instance_id
        r = self.get(url, params=params_dict)
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def is_secret_protected(self, sid: str, protection_status: int = 1):
        c_panel_info = self.get_secret(sid=sid)
        assert c_panel_info['isActive'], f"reported inactive, {sid}"
        assert c_panel_info["protected"] == protection_status, \
            f"unexpected secret protected status. received: {c_panel_info['protected']}, " \
            f"expected: {protection_status}, {sid}, last update: {c_panel_info['caLastUpdate']}"
        return c_panel_info

    def is_detached(self, wlid: str):
        c_panel_info = self.get_info_from_wlid(wlid=wlid)
        Logger.logger.info(c_panel_info)
        assert c_panel_info['isActive'], f"reported inactive, {wlid}"
        assert not c_panel_info['isCAAttached'], f"reported attached, {wlid}"
        assert c_panel_info[
                   "armoIntegrityStatus"] == "Unattached", f"wrong armoIntegrityStatus for unattached workload {c_panel_info['armoIntegrityStatus']}"
        if Wlid.is_k8s(kind=Wlid.get_kind(wlid=wlid)):
            assert 'Running' in c_panel_info['instancesStatus'] and c_panel_info['instancesStatus']['Running'] > 0, \
                f"instancesStatus not reported as running, instancesStatus: {c_panel_info['instancesStatus']}, {wlid}"
        assert c_panel_info['numOfProcesses'] > 0, \
            f"reported numOfProcesses == {c_panel_info['numOfProcesses']}, {wlid}"
        return c_panel_info

    def is_attached(self, wlid: str):
        c_panel_info = self.get_info_from_wlid(wlid=wlid)
        Logger.logger.info(c_panel_info)
        last_update_time = c_panel_info['caLastUpdate']
        assert c_panel_info['isActive'], f"reported inactive, {wlid}; {last_update_time}"
        assert c_panel_info['isCAAttached'], f"reported not attached, {wlid}; {last_update_time}"
        assert 'Running' in c_panel_info['instancesStatus'] and c_panel_info['instancesStatus']['Running'] > 0, \
            f"instancesStatus not reported as running, instancesStatus: {c_panel_info['instancesStatus']}, {wlid}; {last_update_time}"
        assert c_panel_info['numOfProcesses'] > 0, \
            f"reported numOfProcesses == {c_panel_info['numOfProcesses']}, {wlid}; {last_update_time}"
        return c_panel_info

    def is_signed(self, wlid=str()):
        c_panel_info = self.is_attached(wlid=wlid)
        assert c_panel_info['caIntegrityStatus'] > 0, \
            f"reported caIntegrityStatus == {c_panel_info['caIntegrityStatus']}, last update: {c_panel_info['caLastUpdate']}, wlid: {wlid}"
        return c_panel_info

    def is_encrypting(self, wlid=str(), expected_number: int = -1):
        c_panel_info = self.is_attached(wlid=wlid)
        if expected_number == -1:
            assert c_panel_info['numOfEncryptedFiles'] > 0, \
                f"reported {c_panel_info['numOfEncryptedFiles']} == 0, {wlid}; {c_panel_info['caLastUpdate']}"
        else:
            assert c_panel_info['numOfEncryptedFiles'] == expected_number, \
                f"{c_panel_info['numOfEncryptedFiles']} != {expected_number}, {wlid}; {c_panel_info['caLastUpdate']}"
        return c_panel_info

    def get_execution_info_from_wlid(self, wlid: str):
        url = "/v1/microserviceCodeExecution"
        r = self.get(
            url, params={"customerGUID": self.selected_tenant_id, "wlid": wlid})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: customer tree of customer "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def remove_microservice_data(self, wlid: str):
        Logger.logger.info("remove_microservice_data {}".format(wlid))
        url = "/v1/microservice"
        r = self.delete(
            url, params={"customerGUID": self.selected_tenant_id, "wlid": wlid})
        return r.text

    def get_customer_tree(self):
        r = self.get("/customertree", params={"custguid": self.selected_tenant_id})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: customer tree of customer "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

        return r.json()

    def get_solutions_list(self):
        solutions = []
        if self.customer is None:
            return solutions

        for solution in self.get_customer_tree():
            solutions.append(Solution(self, solution["ca_guid"]))

        return solutions

    def get_component_info(self, component):
        r = requests.get(self.server + "/component",
                         params={'componentguid': component.guid,
                                 'solguid': component.solution_guid},
                         cookies=self.login_customer_cookie, verify=self.verify, timeout=20)

        assert (200 <= r.status_code < 300), \
            'Error accessing dashboard! component guid: {com},  solution guid: {sol},\nError details- code: ' \
            '{status_code}, message: {text}'.format(status_code=r.status_code, text=r.text, com=component.guid,
                                                    sol=component.solution_guid)

        return r.json()

    def get_service_info(self, session_id, service_id):
        r = requests.get(self.server + "/session", params={'sessionid': session_id},
                         cookies=self.login_customer_cookie, verify=self.verify, timeout=20)
        if r.status_code < 200 or 300 <= r.status_code:
            raise Exception('Error accessing dashboard. Request: session info "%s" (code: %d, message: %s)' % (
                session_id, r.status_code, r.text))
        return r.json()

    def get_session_alerts(self, session_id):
        r = requests.get(self.server + "/alerts", params={'id': session_id},
                         cookies=self.login_customer_cookie, verify=self.verify, timeout=20)
        if r.status_code < 200 or 300 <= r.status_code:
            raise Exception('Error accessing dashboard. Request: session info "%s"  (code: %d, message: %s)' % (
                session_id, r.status_code, r.text))
        return r.json()

    def get_sessions(self, container, component):
        """get sessions list by passing Container and Component objects."""

        # compare container id with session mechine id or with
        # the start of the session id for every session since the container uptime.
        # return a list of sessions for cases that there is more than 1 session fit the container id
        # (just on rare situations).
        Logger.logger.info("Searching for sessions of container '{}' and component '{}'".format(
            container, component))
        container_uptime = dateutil.parser.parse(
            container.attrs['State']['StartedAt']) if container is not None else None
        container_id = container.short_id if container is not None else None

        comp_data = self.get_component_info(component)
        sessions = []
        for session in comp_data["componentInstances"]:
            if container is None:
                # probably not docker test
                sessions.append(Session(self, session["sessionID"]))
                continue
            session_uptime = dateutil.parser.parse(session["uptime"])
            if container_uptime is not None and container_uptime > session_uptime:
                break
            try:
                if container_id is not None and session["processInfo"]["machineID"][:-2] == container_id:
                    sessions.append(Session(self, session["sessionID"]))
            except:
                if session["sessionID"].startswith(container_id):
                    sessions.append(Session(self, session["sessionID"]))
        Logger.logger.info(
            "Found {} sessions of container '{}' and component '{}'".format(len(sessions), container, component))

        return sessions

    def get_posture_clusters_overtime(self, cluster_name: str, framework_name: str = ""):
        params = {"pageNum": 1, "pageSize": 1, "orderBy": "timestamp:desc", "innerFilters": [{
            "clusterName": cluster_name, "frameworkName": framework_name}]}

        if framework_name in statics.SECURITY_FRAMEWORKS:
            params["innerFilters"][0]["typeTags"] = statics.SECURITY_FRAMEWORK_TYPETAG

        r = self.post(API_POSTURE_CLUSTERSOVERTIME,
                      json=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of posture clustersOvertime "%s" (code: %d, message: %s)' %
                (self.customer, r.status_code, r.text))
        if len(r.json()['response']) == 0:
            return []
        last_framework = r.json()['response'][0]['frameworks'][0]

        return {'frameworkName': last_framework['frameworkName'], 'cords': last_framework['cords'][0]}

    def get_repository_posture_repositories(self, inner_filters: List[Dict]):
        params = {
            "pageNum": 1,
            "pageSize": 1,
            "orderBy": "timestamp:desc",
            "innerFilters": inner_filters,
        }

        r = self.post(
            API_REPOSITORYPOSTURE_REPOSITORIES,
            params={"customerGUID": self.selected_tenant_id, "onlyLastScans": True},
            json=params,
        )
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of repositoryPosture/repositories "%s" (code: %d, message: %s)'
                % (self.customer, r.status_code, r.text)
            )
        return r.json()["response"]

    def get_repository_posture_repositories_by_name(
            self, repository_owner: str, repository_name: str, repository_branch: str
    ):
        return self.get_repository_posture_repositories(
            [
                {
                    "designators.attributes.repoName": repository_name,
                    "designators.attributes.repoOwner": repository_owner,
                    "designators.attributes.branch": repository_branch,
                }
            ]
        )

    def get_repository_posture_repositories_by_report_guid(self, report_guid: str):
        return self.get_repository_posture_repositories([{"reportGUID": report_guid}])

    def get_repository_posture_files(self, report_guid: str):
        params = {
            "pageNum": 1,
            "pageSize": 1000,
            "orderBy": "timestamp:desc",
            "innerFilters": [{"reportGUID": report_guid}],
        }

        r = self.post(
            API_REPOSITORYPOSTURE_FILES,
            params={"customerGUID": self.selected_tenant_id},
            json=params,
        )
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of repositoryPosture/files "%s" (code: %d, message: %s)'
                % (self.customer, r.status_code, r.text)
            )
        return r.json()["response"]

    def get_repository_posture_resources(self, report_guid: str):
        params = {
            "pageNum": 1,
            "pageSize": 1000,
            "orderBy": "timestamp:desc",
            "innerFilters": [{"reportGUID": report_guid}],
        }

        r = self.post(
            API_REPOSITORYPOSTURE_RESOURCES,
            params={"customerGUID": self.selected_tenant_id},
            json=params,
        )
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of repositoryPosture/resources "%s" (code: %d, message: %s)'
                % (self.customer, r.status_code, r.text)
            )
        return r.json()["response"]

    def get_job_report_info(self, report_guid: str, cluster_wlid):
        json = {"pageNum": 1, "pageSize": 100,
                "innerFilters": [
                    {
                        "target": cluster_wlid
                    }
                ]
                }
        r = self.post("/v2/jobReports", params={"customerGUID": self.selected_tenant_id}, json=json)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of posture frameworks "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if len(r.json()['response']) == 0:
            raise Exception('Error accessing dashboard. Request: results of posture frameworks is empty')
        return r.json()['response']

    def get_posture_frameworks(self, report_guid: str, framework_name: str = ""):
        params = {"pageNum": 1, "pageSize": 1000, "orderBy": "timestamp:desc", "innerFilters": [{
            "reportGUID": report_guid, "name": framework_name}]}
        
        if framework_name in statics.SECURITY_FRAMEWORKS:
            params["innerFilters"][0]["typeTags"] = statics.SECURITY_FRAMEWORK_TYPETAG

        r = self.post(API_POSTURE_FRAMEWORKS, params={"customerGUID": self.selected_tenant_id},
                      json=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of posture frameworks "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if len(r.json()['response']) == 0:
            raise Exception('Error accessing dashboard. Request: results of posture frameworks is empty')
        return r.json()['response']

    # Get framework by name
    def get_framework(self, framework_name: str):
        params = {"customerGUID": self.selected_tenant_id, "frameworkName": framework_name} if framework_name else \
            {"customerGUID": self.selected_tenant_id}
        r = self.get(API_FRAMEWORK, params=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of posture frameworks "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if len(r.json()) == 0:
            raise Exception('Error accessing dashboard. Request: results of posture framework is empty')
        return r.json()

    def get_posture_controls(self, framework_name: str, report_guid: str):
        r = self.post(API_POSTURE_CONTROLS, params={"customerGUID": self.selected_tenant_id},
                      json={"pageNum": 1, "pageSize": 150, "orderBy": "timestamp:desc", "innerFilters": [{
                          "frameworkName": framework_name, "reportGUID": report_guid}]})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of posture controls "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if len(r.json()['response']) == 0:
            raise Exception('Error accessing dashboard. Request: results of posture controls is empty')
        return r.json()['response']

    def get_top_controls_results(self, cluster_name):
        # TODO: change to "topControls" when it will be deprecated 
        r = self.post(API_POSTURE_TOPFAILEDCONTROLS, params={"customerGUID": self.selected_tenant_id, "cluster": cluster_name},
                      json={"pageNum": 1, "pageSize": 5, "innerFilters": [{
                          }]})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of posture top failed controls "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        j = r.json()
        if 'response' not in j or len(j['response']) == 0:
            raise Exception('Error accessing dashboard. Request: results of posture top failed controls is empty')
        return r.json()['response']


    def get_posture_resources(self, framework_name: str, report_guid: str, resource_name: str = "", related_exceptions: str = "false", namespace=None):
        body={"pageNum": 1, "pageSize": 150, "orderBy": "timestamp:desc", "innerFilters": [{
                          "frameworkName": framework_name, "reportGUID": report_guid,
                          "designators.attributes.name": resource_name}]}
        if namespace is not None:
            body["innerFilters"][0]["designators.attributes.namespace"] = namespace
        r = self.post(API_POSTURE_RESOURCES, params={"customerGUID": self.customer_guid, "relatedExceptions": related_exceptions, "ignoreRulesSummary": related_exceptions},
                      json=body)
        
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of posture resources "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        j = r.json()
        if 'response' not in j or len(j['response']) == 0:
            raise Exception('Error accessing dashboard. Request: results of posture resources is empty')
        return r.json()['response']

    def get_posture_resources_by_control(self, framework_name: str, report_guid: str, control_id: str,
                                         control_name: str, related_exceptions: str = "false"):
        r = self.post(API_POSTURE_RESOURCES,
                      params={"customerGUID": self.selected_tenant_id, "controlName": control_name,
                              "relatedExceptions": related_exceptions, "ignoreRulesSummary": related_exceptions},
                      json={"pageNum": 1, "pageSize": 150, "orderBy": "designators.attributes.namespace:asc",
                            "innerFilters": [{
                                "frameworkName": framework_name, "reportGUID": report_guid,
                                "failedControls": control_id}]})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of posture resources by control "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if len(r.json()['response']) == 0:
            raise Exception(
                'Error accessing dashboard. Request: results of posture resources by control is empty')
        return r.json()['response']

    
    def get_image_scan_stats(self):
        r = self.get(API_IMAGE_SCAN_STATS, params={"customerGUID": self.selected_tenant_id, "includeLastReport": False})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of imageScan "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if len(r.json()) == 0:
            raise Exception(
                'Expected to receive real imageScan object in results of get imageScan "%s", and received "%s"'
                % (self.selected_tenant_id, r.text))
        return r.json()

    def get_cluster(self, cluster_name: str, expected_status_code: int = None):
        r = self.get(API_CLUSTER, params={"customerGUID": self.selected_tenant_id, "name": cluster_name})
        if expected_status_code:
            if r.status_code == expected_status_code:
                return True
            else:
                raise Exception(
                    'Expected to receive status-code "%d" in results of get clusters "%s", and received "%d"'
                    % (expected_status_code, cluster_name, r.status_code))
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of clusters "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if len(r.json()) == 0:
            raise Exception(
                'Expected to receive real cluster object in results of get clusters "%s", and received "%s"'
                % (cluster_name, r.text))
        return r.json()

    def get_cluster_with_risk_status(self, cluster_name: str, expected_status_code: int = None):
        r = self.get(API_CLUSTER, params={"customerGUID": self.selected_tenant_id,
                                                "name": cluster_name,
                                                "riskStatus": "true",
                                                "priorityOrder": "true"})
        if expected_status_code:
            if r.status_code == expected_status_code:
                return True
            else:
                raise Exception(
                    'Expected to receive status-code "%d" in results of get clusters "%s", and received "%d"'
                    % (expected_status_code, cluster_name, r.status_code))
        if not "traceparent" in r.headers:
            raise Exception(
                'Error accessing dashboard, no "traceparent" header presented. Check opentelemetry is all set in BE. Request: results of clusters "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of clusters "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if len(r.json()) == 0:
            raise Exception(
                'Expected to receive real cluster object in results of get clusters "%s", and received "%s"'
                % (cluster_name, r.text))
        return r.json()

    def delete_cluster(self, cluster_name: str):
        r = self.delete(API_CLUSTER, params={"customerGUID": self.selected_tenant_id, "name": cluster_name})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of clusters "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

        return r.text

    def get_repositories(self):
        r = self.get(API_REPOSITORYPOSTURE, params={"customerGUID": self.selected_tenant_id})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get repositories "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def delete_repository(self, repository_hash: str):
        r = self.delete(API_REPOSITORYPOSTURE,
                        params={"customerGUID": self.selected_tenant_id, "repoHash": repository_hash})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: delete repository "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

        return r.text

    def post_posture_exception(self, exception_object: json):
        r = self.post(API_POSTUREEXCEPTIONPOLICY, params={"customerGUID": self.selected_tenant_id},
                      json=exception_object)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: create posture exception "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_all_posture_exception_by_cluster(self, cluster_name: str):
        r = self.get(API_POSTUREEXCEPTIONPOLICY, params={"customerGUID": self.selected_tenant_id,
                                                               "scope.cluster": cluster_name})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: delete posture exception "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def delete_posture_exception(self, policy_guid: str):
        r = self.delete(API_POSTUREEXCEPTIONPOLICY,
                        params={"customerGUID": self.selected_tenant_id, "policyGUID": policy_guid})
        if not 200 <= r.status_code < 300:  # or not r.json() or not r.json()[0] != 'deleted':
            raise Exception(
                'Error accessing dashboard. Request: delete posture exception "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

    def delete_all_posture_exceptions(self, cluster_name: str):
        policy_guids = self.get_all_posture_exception_by_cluster(cluster_name=cluster_name)
        if len(policy_guids) > 0:
            guids = []
            for policy_guid in policy_guids:
                guids.append(policy_guid['guid'])
            r = self.delete(API_POSTUREEXCEPTIONPOLICY,
                            params={"customerGUID": self.selected_tenant_id, "policyGUID": guids})
            if not 200 <= r.status_code < 300:  # or not r.json() or not r.json()[0] != 'deleted':
                raise Exception(
                    'Error accessing dashboard. Request: delete posture exception "%s" (code: %d, message: %s)' % (
                        self.customer, r.status_code, r.text))

    def post_custom_framework(self, fw_object: json):
        r = self.post(API_FRAMEWORK, params={"customerGUID": self.selected_tenant_id}, json=fw_object)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'failed to post custom framework "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def delete_custom_framework(self, framework_name: str):
        r = self.delete(API_FRAMEWORK,
                        params={"customerGUID": self.selected_tenant_id, "frameworkName": framework_name})
        if not 200 <= r.status_code < 300:  # or not r.json() or not r.json()[0] != 'deleted':
            raise Exception(
                'Error accessing dashboard. Request: delete custom framework "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

    def get_scan_results_sum_summary(self, since_time: str, expected_results: int, namespace: str = None,
                                     cluster_name: str = None, expected_status_code: int = None,
                                     containers_scan_id=None):
        params = {"customerGUID": self.selected_tenant_id}
        if cluster_name:
            params['cluster'] = cluster_name
        if namespace:
            params['namespace'] = namespace
        js = {"since": since_time}
        if containers_scan_id != None:
            innerFilters = []
            innerFilters.extend({"containersScanID": id[1]} for id in containers_scan_id)
            js = {"pageNum": 1, "pageSize": 1, "innerFilters": innerFilters}
        r = self.post(API_VULNERABILITY_SCANRESULTSSUMSUMMARY, params=params, json=js)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if expected_status_code and expected_status_code == 404:
            if r.json()['total']['value'] == 0:
                return True
            else:
                raise Exception(
                    'Expected to receive 0 in results of get_scan_results_sum_summary, and received {}, message {}'.format(
                        (r.json()['total']['value']), r.json()['response']))

        result = r.json()['response']
        # this part is for debug because backend return always error in results
        # result = list(filter(lambda scan: (scan['status'] == 'Error' and
        #                                  print('Delete container %s, Because he has an error' % scan['containerName'])
        #                                    and False) or (scan['status'] != 'Error'), result))

        if len(result) < expected_results:
            scan_names = []
            for r in result:
                scan_names.append(r['containerName'])
            raise Exception('Excepted %d scans, receive %d: %s' % (expected_results,
                                                                   len(result), ', '.join(scan_names)))
        for scan in result:
            if (scan['status'] == 'Pending') or ('isStub' in scan.keys() and scan['isStub']):
                raise Exception(
                    f'Error receive scan result: Result length: {len(result)}. Container {scan["containerName"]}" is still in pending. Full result list: {result}'
                )
        return result

    def get_scan_registry_results_sum_summary(self, since_time: str, expected_results: int, namespace: str = None,
                                              cluster_name: str = None, expected_status_code: int = None,
                                              containers_scan_id=None):
        params = {"customerGUID": self.selected_tenant_id}
        if cluster_name:
            params['cluster'] = cluster_name
        if namespace:
            params['namespace'] = namespace
        js = {"since": since_time}
        if containers_scan_id != None:
            innerFilters = []
            innerFilters.extend({"containersScanID": id[1]} for id in containers_scan_id)
            js = {"pageNum": 1, "pageSize": 1, "innerFilters": innerFilters}
        r = self.post(API_REGISTRY_SCANRESULTSSUMSUMMARY, params=params, json=js)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if expected_status_code and expected_status_code == 404:
            if r.json()['total']['value'] == 0:
                return True
            else:
                raise Exception(
                    'Expected to receive 0 in results of get_scan_results_sum_summary, and received {}, message {}'.format(
                        (r.json()['total']['value']), r.json()['response']))

        result = r.json()['response']
        # this part is for debug because backend return always error in results
        # result = list(filter(lambda scan: (scan['status'] == 'Error' and
        #                                  print('Delete container %s, Because he has an error' % scan['containerName'])
        #                                    and False) or (scan['status'] != 'Error'), result))

        if len(result) < expected_results:
            scan_names = []
            for r in result:
                scan_names.append(r['containerName'])
            raise Exception('Excepted %d scans, receive %d: %s' % (expected_results,
                                                                   len(result), ', '.join(scan_names)))
        for scan in result:
            if (scan['status'] == 'Pending') or ('isStub' in scan.keys() and scan['isStub']):
                raise Exception(
                    'Error receive scan result: Container "%s is still in pending' % (scan['containerName'])
                )
        return result

    def set_cves_exceptions(self, cves_list, cluster_name, namespace, conatiner_name):
        params = {"customerGUID": self.selected_tenant_id}
        vulnerabilities = []
        vulnerabilities.extend({"name": cve_name} for cve_name in cves_list)
        body = {"policyType": "vulnerabilityExceptionPolicy", "name": "{}{}".format(time.time(), len(cves_list)),
                "actions": ["ignore"],
                "designators": [{"designatorType": "Attributes",
                                 "attributes": {"cluster": cluster_name, "containerName": conatiner_name,
                                                "kind": "deployment", "name": "nginx", "namespace": namespace}}],
                "vulnerabilities": vulnerabilities}
        r = self.post(API_VULNERABILITYEXCEPTIONPOLICY, params=params, data=json.dumps(body))
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: set cves exceptions "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        resp = r.json()
        return resp["guid"]

    def scan_image_in_namespace(self, cluster_name, namespace):
        return self.create_vuln_scan_job_request(cluster_name=cluster_name, namespaces_list=[namespace])

    def get_registry_container_cve(self, since_time: str, containers_scan_id: str, total_cve):
        page_size = 100

        params = {"customerGUID": self.selected_tenant_id}
        body = {
            "pageNum": 1,
            "pageSize": page_size,
            "since": since_time,
            "orderBy": "timestamp:desc,name:desc",
            "innerFilters": [{"containersScanID": containers_scan_id}]}

        result_length = self.get_length_of_post_response(url=API_REGISTRY_SCANRESULTSDETAILS, params=params, body=body)

        result = []
        for i in range(1, math.ceil(result_length / page_size)+1):
            body['pageNum'] = i
            r = self.post(API_REGISTRY_SCANRESULTSDETAILS, params=params, json=body)
            if not 200 <= r.status_code < 300 or len(r.json()['response']) == 0:
                raise Exception(
                    'Error accessing dashboard. Request: get scan results details "%s" (code: %d, message: %s)' % (
                        self.customer, r.status_code, r.text))
            result.extend(r.json()['response'])
        Logger.logger.info(
            'container scan id : {} len(result) {} < {} len(expected_results)'.format(containers_scan_id, len(result),
                                                                                      total_cve))

        return result

    def get_registry_container_layers(self, container_scan_id: str):
        page_size = 30

        params = {"customerGUID": self.selected_tenant_id}
        body = {
            "pageNum": 1,
            "pageSize": page_size,
            "orderBy": "severities.critical:desc",
            "innerFilters": [{"containersScanID": container_scan_id}]}

        r = self.post(API_REGISTRY_SCANRESULTSLAYERSUMMARY, params=params, json=body)
        if not 200 <= r.status_code < 300 or len(r.json()['response']) == 0:
                raise Exception(
                    'Error accessing layers summery. Request: get scan layer summery "%s" (code: %d, message: %s). Url: "%s" ContainersScanID "%s" ' % (
                        self.customer, r.status_code, r.text, self.server + API_REGISTRY_SCANRESULTSLAYERSUMMARY, container_scan_id))
        
        Logger.logger.info(
            'layers of container scan id : {} response {}'.format(container_scan_id, r.json()))
        return r.json()
    
    def get_unique_values_for_field_scan_summary(self, since_time, field, customer_guid):
        params = {"customerGUID": customer_guid}
        body = {
            "since": since_time,
            "fields": {
                field: "",
            }
        }

        r = self.post(API_VULNERABILITY_UNIQUE_VALUES_SUMMARY, params=params, json=body)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results details "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        
        return r
        
    def get_summary_with_inner_filters(self, since_time, filter, customer_guid):
        params = {"customerGUID": customer_guid}
        body = {
            "since": since_time,
            "innerFilters": [filter],
        }

        r = self.post(API_VULNERABILITY_SCANRESULTSSUMSUMMARY, params=params, json=body)
        if not 200 <= r.status_code < 300 or len(r.json()['response']) == 0:
            raise Exception(
                'Error accessing dashboard. Request: get scan results details "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_scan_results_details(self, since_time: str, containers_scan_id: str, expected_results, total_cve):
        params = {"customerGUID": self.selected_tenant_id, "ignoreRulesSummary": "true", "relatedExceptions": "true"}
        page_size = 100
        body = {"pageNum": 1, 
                "orderBy": "timestamp:desc,name:desc",
                "pageSize": page_size, 
                "since": since_time,
                "innerFilters": [{"containersScanID": containers_scan_id}]}
        result_length = self.get_length_of_post_response(url=API_VULNERABILITY_SCANRESULTSDETAILS, params=params, body=body)

        assert result_length >= total_cve, \
            f'wait for aggregation to end in the backend, number of CVEs is lower than expected. ' \
            f'received {result_length}, expected: {total_cve}'

        result = []
        for i in range(1, math.ceil(result_length / page_size)+1):
            body['pageNum'] = i
            r = self.post(API_VULNERABILITY_SCANRESULTSDETAILS, params=params, json=body)
            if not 200 <= r.status_code < 300:
                raise Exception(
                    'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                        self.customer, r.status_code, r.text))
            result.extend(r.json()['response'])
            Logger.logger.info(
                'container scan id : {} len(result):{}, len(expected_results):{} '.format(containers_scan_id,
                                                                                          len(result),
                                                                                          total_cve))
    
        if len(result) < total_cve:
            raise Exception(
                f'wait for aggregation to end in the backend, number of CVEs is lower than expected. ' \
                f'received {len(result)}, expected: {total_cve}'
            )
        return result

    def get_customer_configuration(self, scope: str = 'customer'):
        r = self.get(API_CUSTOMERCONFIGURATION, params={"customerGUID": self.selected_tenant_id, "scope": scope})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get customer configuration "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def update_customer_configuration(self, customer_config: dict, scope: str = 'customer'):
        # Add or delete from / to customer configuration
        r = self.put(API_CUSTOMERCONFIGURATION, params={"customerGUID": self.selected_tenant_id, "scope": scope},
                     json=customer_config)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get customer configuration "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_length_of_post_response(self, url: str, params: dict, body: dict):
        r = self.post(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()['total']['value']

    def get_scan_results_sum_summary_CSV(self, namespace: str, expected_results: int,
                                         cluster_name: str = None, severity: str = None, fixable: bool = False):
        Logger.logger.debug("Load csv scan_results_sum_summary %s ", namespace)
        ws = self.ws_export_open("/ws/v1/vulnerability/scanResultsSumSummary")

        message = {"innerFilters": [{'cluster': cluster_name, 'namespace': namespace}]}
        if severity is not None:
            message['innerFilters'][0]['severitiesStats.severity'] = severity  
        if fixable:
            message['innerFilters'][0]['severitiesStats.fixedTotal'] = "1|greater"     
        self.ws_send(ws, json.dumps(message))
        result = self.ws_extract_receive(ws)

        assert len(result) == expected_results, 'Excepted %d scans, receive %d' % (expected_results, len(result))

        return result

    def get_scan_results_details_csv(self, containers_scan_id: str):
        Logger.logger.debug("Load csv scan_results_details %s ", containers_scan_id)
        ws = self.ws_export_open("/ws/v1/vulnerability/scanResultsDetails")

        _CONTAINER_SCAN_ID = 1
        for container in containers_scan_id:
            message = {"innerFilters": [{'containersScanID': container[_CONTAINER_SCAN_ID]}]}

        self.ws_send(ws, json.dumps(message))
        return self.ws_extract_receive(ws)

    @staticmethod
    def get_cron_job_schedule():
        now = datetime.utcnow()
        hour_of_schedual = now.hour
        minute_of_schedual = now.minute
        if now.minute >= 58:
            hour_of_schedual = (hour_of_schedual + 1) % 24
        minute_of_schedual = (now.minute + 2) % 60
        return "{} {} * * *".format(minute_of_schedual, hour_of_schedual)

    def create_kubescape_job_request(self, cluster_name, trigger_by="job", framework_list=[""],
                                     with_host_sensor="true"):
        params = {"customerGUID": self.selected_tenant_id}
        body = []
        if trigger_by == "job":
            Logger.logger.info('create kubescape scan on demand')
            for framework in framework_list:
                body.append({"clusterName": cluster_name, "frameworkName": framework, "hostSensor": with_host_sensor})
        else:
            Logger.logger.info('create kubescape scan cronjob')
            schedule_string = self.get_cron_job_schedule()
            for framework in framework_list:
                body.append(
                    {"clusterName": cluster_name, "frameworkName": framework, "cronTabSchedule": schedule_string,
                     "hostSensor": with_host_sensor})
        r = self.post(API_POSTURE_SCAN, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def create_vuln_scan_job_request(self, cluster_name, namespaces_list: list, schedule_string: str = ''):
        params = {"customerGUID": self.selected_tenant_id}
        body = []
        if schedule_string:
            Logger.logger.info('create vuln scan cronjob')
            for namespace in namespaces_list:
                body.append({"clusterName": cluster_name, "namespace": namespace,
                             "cronTabSchedule": schedule_string})
        else:
            Logger.logger.info('create vuln scan on demand')
            for namespace in namespaces_list:
                body.append({"clusterName": cluster_name, "namespace": namespace})

        r = self.post(API_VULNERABILITY_SCAN_V2, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: create vuln scan cronjob "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def create_registry_scan_job_request_deprecated(self, cluster_name, registry_name: str, schedule_string: str = ''):
        params = {"customerGUID": self.selected_tenant_id}
        body = []
       
        body.append({"clusterName": cluster_name, "registryName": registry_name,
                             "cronTabSchedule": schedule_string})


        r = self.post(API_REGISTRY_SCAN, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: create registry scan cronjob "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def create_registry_scan_job_request(self, cluster_name, registry_name: str,    auth_method: dict, schedule_string: str, registry_type: str, 
    excluded_repositories: list = []):
        return self.send_registry_command(command=statics.CREATE_REGISTRY_CJ_COMMAND, cluster_name=cluster_name,registry_name= registry_name, excluded_repositories= excluded_repositories, registry_type=registry_type, auth_method=auth_method, schedule_string=schedule_string)


    def send_registry_command(self, command, cluster_name, registry_name: str,    registry_type: str, auth_method: dict, schedule_string: str ,  depth: int = 1, excluded_repositories: list = []):
        params = {"customerGUID": self.selected_tenant_id}
        provider = registry_name.split(":")[0]
        provider = provider.split("/")[0]
        body = json.dumps([
            {
            "registryProvider": provider,
            "action": command,
            "clusterName": cluster_name,
            "registryName": registry_name,
            "cronTabSchedule": schedule_string,
            "registryType": registry_type,
            "depth": depth,
            "include": [],
            "exclude": excluded_repositories,
            "isHTTPs": False,
            "skipTLS": True,
            "authMethod": {
                "type": auth_method["type"],
                "username":auth_method["username"],
                "password": auth_method["password"]
            }
            }
        ])
        r = self.post(API_REGISTRY_SCAN, params=params, data=body, timeout=15)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: %s "%s" (code: %d, message: %s)' % (
                   command, self.customer, r.status_code, r.text))
        return r

            


    def get_vuln_scan_cronjob_list(self, cluster_name: str, expected_cjs):
        params = {"customerGUID": self.selected_tenant_id}
        r = self.get(API_VULNERABILITY_SCAN_V2, params=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get vuln scan cronjob list "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        cronjob_list = r.json()
        vuln_scan_cronjob_list = [cj for cj in cronjob_list if cj[statics.CA_VULN_SCAN_CRONJOB_CLUSTER_NAME_FILED] == cluster_name]
        self.compare_vuln_scan_be_cjs_to_expected(expected_cjs=expected_cjs, actual_cjs=vuln_scan_cronjob_list, cluster_name=cluster_name)

        return vuln_scan_cronjob_list

    def compare_vuln_scan_be_cjs_to_expected(self, expected_cjs, actual_cjs, cluster_name):
        if len(expected_cjs) != len(actual_cjs):
            raise Exception(
                f'Error accessing dashboard. Request: get vuln scan cronjob list, expected to receive '
                f'{len(expected_cjs)} cron jobs, and receive {len(actual_cjs)}: {actual_cjs}')

        for actual in actual_cjs:
            for expected in expected_cjs:
                if expected.metadata.name == actual[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED]:
                    assert cluster_name == actual[statics.CA_VULN_SCAN_CRONJOB_CLUSTER_NAME_FILED], f'cluster name is not as expected'
                    assert expected.spec.schedule == actual[statics.CA_VULN_SCAN_CRONJOB_CRONTABSCHEDULE_FILED], f'cronjob schedule is not as expected'
                    assert actual[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED].startswith("kubevuln"), f'cronjob name is not as expected'


    def get_registry_scan_cronjob_list(self, cluster_name: str, expected_cjs):
        params = {"customerGUID": self.selected_tenant_id}
        r = self.get(API_REGISTRY_SCAN, params=params, timeout=15)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get registry scan cronjob list "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        cronjob_list = r.json()
        registry_scan_cronjob_list = [cj for cj in cronjob_list if cj[statics.CA_VULN_SCAN_CRONJOB_CLUSTER_NAME_FILED] == cluster_name]
        self.compare_registry_be_cjs_to_expected(actual_cjs=registry_scan_cronjob_list, expected_cjs=expected_cjs, cluster_name=cluster_name)    
        return registry_scan_cronjob_list


    def get_registry_scan_cronjob_list_deprecated(self, cluster_name: str, expected_cjs):
        params = {"customerGUID": self.selected_tenant_id}
        r = self.get(API_REGISTRY_SCAN, params=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get registry scan cronjob list "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        cronjob_list = r.json()
        registry_scan_cronjob_list = [cj for cj in cronjob_list if cj[statics.CA_VULN_SCAN_CRONJOB_CLUSTER_NAME_FILED] == cluster_name]
        self.compare_registry_be_cjs_to_expected(actual_cjs=registry_scan_cronjob_list, expected_cjs=expected_cjs, cluster_name=cluster_name)    
        return registry_scan_cronjob_list


    def compare_registry_be_cjs_to_expected(self, actual_cjs, expected_cjs, cluster_name):
        if len(actual_cjs) != len(expected_cjs):
            raise Exception(
                f'Error accessing dashboard. Request: get registry scan cronjob list, expected to receive '
                f'{expected_cjs} cron jobs, and receive {len(actual_cjs)}: {actual_cjs}')

        for actual in actual_cjs:
            for expected in expected_cjs:
                if expected.metadata.name == actual[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED]:
                    assert cluster_name == actual[statics.CA_VULN_SCAN_CRONJOB_CLUSTER_NAME_FILED], f'cluster name is not as expected'
                    assert expected.spec.schedule == actual[statics.CA_VULN_SCAN_CRONJOB_CRONTABSCHEDULE_FILED], f'cronjob schedule is not as expected'
                    assert actual[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED].startswith("kubescape-registry-scan"), f'cronjob name is not as expected'
                    assert actual[statics.CA_REGISTRY_SCAN_CRONJOB_REGISTRY_NAME_FIELD] == expected.spec.job_template.spec.template.metadata.annotations[statics.CA_REGISTRY_SCAN_CRONJOB_REGISTRY_NAME_ANNOTATION_FIELD], f'registry name is not as expected'
                
        

    def get_vuln_scan_cronjob(self, cj_name: str, expect_to_results: bool = True):
        params = {"customerGUID": self.selected_tenant_id}
        r = self.get(API_VULNERABILITY_SCAN_V2, params=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get vuln scan cronjob "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        cronjob_list = r.json()

        for cj in cronjob_list:
            if statics.CA_VULN_SCAN_CRONJOB_NAME_FILED in cj and cj[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED] == cj_name:
                return cj
        if not expect_to_results:
            return {}
        raise Exception(
            f'Error accessing dashboard. Request: get vuln scan cronjob, cronjob {cj_name}, not found in backend. '
            f'cronjob-list: {cronjob_list}')



    def get_registry_scan_cronjob(self, cj_name: str, expect_to_results: bool = True):
        params = {"customerGUID": self.selected_tenant_id}
        r = self.get(API_REGISTRY_SCAN, params=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get registry scan cronjob "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        cronjob_list = r.json()

        for cj in cronjob_list:
            if cj[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED] == cj_name:
                return cj
        if not expect_to_results:
            return {}
        raise Exception(
            f'Error accessing dashboard. Request: get registry scan cronjob, cronjob {cj_name}, not found in backend. '
            f'cronjob-list: {cronjob_list}')

    def update_vuln_scan_cronjob(self, cj):
        cj = [cj] if isinstance(cj, dict) else cj
        params = {"customerGUID": self.selected_tenant_id}
        r = self.put(API_VULNERABILITY_SCAN_V2, params=params, json=cj)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: update vuln scan cronjob "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def update_registry_scan_cronjob(self, cj_name, cj_id, cluster_name, registry_name, registry_type, cron_tab_schedule, depth,  auth_method=None ):
        params = {"customerGUID": self.selected_tenant_id}
        provider = registry_name.split(":")[0]
        provider = provider.split("/")[0]
        body = {
        "name":cj_name,
       "id": cj_id,
        "clusterName": cluster_name,
        "registryProvider":provider,
        "registryName": registry_name,
        "registryType": registry_type,
    "cronTabSchedule": cron_tab_schedule,
        "depth": depth,
        "repositories": [],
        "action": statics.UPDATE_REGISTRY_CJ_COMMAND
    }
        if auth_method != None:
            body['authMethod'] = auth_method

        r = self.post(API_REGISTRY_SCAN, params=params, data=json.dumps([body]), timeout=20)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: %s "%s" (code: %d, message: %s)' % (
                    statics.UPDATE_REGISTRY_CJ_COMMAND, self.customer, r.status_code, r.text))
        return r

        

    def update_registry_scan_cronjob_deprecated(self, cj):
        cj = [cj] if isinstance(cj, dict) else cj
        params = {"customerGUID": self.selected_tenant_id}
        r = self.put(API_REGISTRY_SCAN, params=params, json=cj)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: update registry scan cronjob "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def delete_vuln_scan_cronjob(self, cj):
        cj = [cj] if isinstance(cj, dict) else cj
        params = {"customerGUID": self.selected_tenant_id}
        r = self.delete(API_VULNERABILITY_SCAN_V2, params=params, json=cj)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: delete vuln scan cronjob "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()
    
    def delete_registry_scan_cronjob(self, cj):
        params = {"customerGUID": self.selected_tenant_id}
        body = [
            {
                "name": cj["name"],
                "id": cj["id"],
                "clusterName": cj["clusterName"],
                "registryProvider": cj["registryProvider"],
                "registryName": cj["registryName"],
                "action": statics.DELETE_REGISTRY_CJ_COMMAND
            }
            ]

        r = self.delete(API_REGISTRY_SCAN, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request:  %s "%s" (code: %d, message: %s)' % (
                  statics.DELETE_REGISTRY_CJ_COMMAND,  self.customer, r.status_code, r.text))
        try:
            return r.json()
        except Exception as ex:
            Logger.logger.debug("delete_registry_scan_cronjob failed to parse response: {0};{1};{2}".format(cj, ex, r.status_code))
            return {}

    def delete_registry_scan_cronjob_deprecated(self, cj):
        cj = [cj] if isinstance(cj, dict) else cj
        params = {"customerGUID": self.selected_tenant_id}
        r = self.delete(API_REGISTRY_SCAN, params=params, json=cj)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: %s "%s" (code: %d, message: %s)' % (
                statics.DELETE_REGISTRY_CJ_COMMAND,    self.customer, r.status_code, r.text))
        try:
            return r.json()
        except Exception as ex:
            Logger.logger.debug("delete_registry_scan_cronjob failed to parse response: {0};{1};{2}".format(cj, ex, r.status_code))
            return {}


    def is_ks_cronjob_created_in_backend(self, cluster_name: str, framework_name:str):
        params = {"customerGUID": self.selected_tenant_id}
        r = self.get(API_POSTURE_SCAN, params=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        cronjobs = r.json()
        for cj in cronjobs:
            if cj[statics.CA_VULN_SCAN_CRONJOB_CLUSTER_NAME_FILED] == cluster_name and "ks-scheduled-scan-{}".format(framework_name.lower()) in cj[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED]:
                return True
        return False
    
    def is__backend_returning_only_ks_cronjob(self, cluster_name: str):
        params = {"customerGUID": self.selected_tenant_id}
        r = self.get(API_POSTURE_SCAN, params=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        cronjobs = r.json()
        for cj in cronjobs:
            if cj[statics.CA_VULN_SCAN_CRONJOB_CLUSTER_NAME_FILED] == cluster_name:
                assert cj[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED].startswith("ks-scheduled-scan-") or cj[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED].startswith("kubescape-scheduler"), f"ks-scheduled-scan- or kubescape-scheduler not in name: {cronjobs}"



    def update_kubescape_job_request(self, cluster_name, cronjobs_name):
        params = {"customerGUID": self.selected_tenant_id}
        body = []
        for cj in cronjobs_name:
            id = "wlid://cluster-{}/namespace-{}/cronjob-{}".format(cluster_name, statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                                    cj)
            schedule_string = self.get_cron_job_schedule()
            body.append({"clusterName": cluster_name, "cronTabSchedule": schedule_string, "id": id, "name": cj})
        r = self.put(API_POSTURE_SCAN, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def delete_kubescape_job_request(self, cluster_name, schedule, cronjobs_name):
        params = {"customerGUID": self.selected_tenant_id}
        body = []
        for cj in cronjobs_name:
            id = "wlid://cluster-{}/namespace-{}/cronjob-{}".format(cluster_name, statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                                    cj)
            schedule_string = self.get_cron_job_schedule()
            body.append({"clusterName": cluster_name, "cronTabSchedule": schedule_string, "id": id, "name": cj})
        r = self.delete(API_POSTURE_SCAN, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_component(self, component):
        return Component(self, component.guid, component.solution_guid)

    
    @deco_cookie
    def post(self, url, **args):
        if not url.startswith("http://") and not url.startswith("https://"):
            url = self.server + url
        return requests.post(url, **args)
    
    @deco_cookie
    def get(self, url, **args):
        if not url.startswith("http://") and not url.startswith("https://"):
            url = self.server + url
        return requests.get(url, **args)

    @deco_cookie
    def put(self, url, **args):
        return requests.put(self.server + url, **args)

    @deco_cookie
    def delete(self, url, **args):
        # for deletion we need to wait a while
        if not 'timeout' in args or args["timeout"] < 120 :
            args["timeout"] = 120
        return requests.delete(self.server + url, **args)

    def get_cookie(self):
        return self.selected_tenant_cookie

    def get_server(self):
        return self.server

    def ws_export_open(self, url):

        ws = websocket.WebSocket()

        server = self.server
        server = server.replace("https", "wss")
        server = "{}?customerGUID={}".format(server + url, self.selected_tenant_id)
        Logger.logger.debug("WS connection url:{0}".format(server))
        for cookie in self.selected_tenant_cookie:
            cookie = "Cookie: {}={}".format(cookie.name, cookie.value)
        ws.connect(server, header=[cookie])
        return ws

    def ws_send(self, ws, message):
        ws.send(message)

    def ws_extract_receive(self, ws):
        r = ws.recv()
        r = json.loads(r)
        total = r['total']['value']
        totalChunks = int(r['totalChunks'])
        nbmsg = 1
        result = r['response']
        while ws.connected:
            r = ws.recv()
            if r:
                r = json.loads(r)
                Logger.logger.debug("request chunk: {}".format(r))                
                result.extend(r['response'])
                nbmsg += 1
        assert nbmsg == totalChunks, 'Excepted %d chunks, receive %d' % (totalChunks, nbmsg)
        assert total == len(result), 'Excepted %d total, receive %d' % (total, len(result))
        Logger.logger.debug("Loaded {}".format(len(result)))
        return result

    def create_scan_registry_request(self, cluster_name, registry_name):
        params = {"customerGUID": self.selected_tenant_id, "relatedExceptions": True, "ignoreRulesSummary": True}
        body = [{"clusterName": cluster_name, "registryName": registry_name, "cronTabSchedule": ""}]

        r = self.post(API_REGISTRY_SCAN, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_job_report_request(self,  job_id):
        params = {"customerGUID": self.selected_tenant_id, "jobID": job_id}

        for i in range(5):
                r = self.get(API_REGISTRY_JOBREPORTSSTATUS, params=params)
                if 200 <= r.status_code < 300:
                    return r.json()
                time.sleep(5)
                
        raise Exception(
            'Error accessing dashboard. Request: get job report status "%s" (code: %d, message: %s, jobID: "%s")' % (
                            self.customer, r.status_code, r.text, job_id))
    
    def get_repositories_list(self,  job_id):
        params = {"customerGUID": self.selected_tenant_id, "jobID": job_id}

        for i in range(5):
            r = self.get(API_REGISTRY_RESPOSITORIESLIST, params=params)
            if 200 <= r.status_code < 300:
                    return r.json()
            time.sleep(5)

        raise Exception(
                'Error accessing dashboard. Request: get repositories list "%s" (code: %d, message: %s, jobID: %s)' % (
                    self.customer, r.status_code, r.text, job_id))



    def test_registry_connectivity_request(self, cluster_name, registry_name, auth_method, excluded_repositories):
        params = {"customerGUID": self.selected_tenant_id}
        provider = registry_name.split(":")[0]
        provider = provider.split("/")[0]
        body = json.dumps([
            {
            "registryProvider": provider,
            "action": "testRegistryConnectivity",
            "clusterName": cluster_name, 
            "registryName": registry_name, 
            "cronTabSchedule": "",
            "registryType": "public",
            "depth": 3, 
            "include":[],
            "exclude": excluded_repositories,
            "kind":"",
            "isHTTPs": False,
            "skipTLS": True,
            "authMethod": {
                "type": auth_method["type"],
                "username":auth_method["username"],
                "password": auth_method["password"]
            }
            }
        ])

        r = self.post(API_REGISTRY_SCAN, params=params, data=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: test registry connectivity "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()[0]



    def delete_registry_scan(self, containers_scan_id):
        params = {"customerGUID": self.selected_tenant_id}
        payload = {
            "innerFilters": [{"containersScanID": containers_scan_id}],
        }
        r = self.post(API_REGISTRY_SCANRESULTSSUMSUMMARY_DELETE, params=params, json=payload)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r
    
    def get_notifications_unsubscribed(self) -> requests.Response:       
        res = self.get(API_NOTIFICATIONS_UNSUBSCRIBE, cookies=self.selected_tenant_cookie)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan notifications unsubscribe "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res
   
    def add_notifications_unsubscribed(self, notifications_identifiers) -> requests.Response:       
        res = self.post(API_NOTIFICATIONS_UNSUBSCRIBE, cookies=self.selected_tenant_cookie, json=notifications_identifiers)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan notifications unsubscribe "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res
    def remove_notifications_unsubscribed(self, notifications_identifiers) -> requests.Response:       
        res = self.delete(API_NOTIFICATIONS_UNSUBSCRIBE, cookies=self.selected_tenant_cookie, json=notifications_identifiers)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan notifications unsubscribe "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def get_all_alert_channels(self) -> requests.Response:
        res = self.get(API_NOTIFICATIONS_ALERTCHANNEL, cookies=self.selected_tenant_cookie)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get all channel alerts "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def get_alert_channel(self, guid) -> requests.Response:
        res = self.get(API_NOTIFICATIONS_ALERTCHANNEL + "/" + guid, cookies=self.selected_tenant_cookie)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get channel alerts "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def create_alert_channel(self) -> requests.Response:
        payload = json.dumps(
                {
                    "channel": {
                        "name": "My Teams Channel",
                        "provider": "teams",
                        "context": {
                            "webhook": {
                                "name": "webhook",
                                "id": "https://teams/mywebhook"
                            }
                        }
                    },
                    "notifications": [
                        {
                            "notificationType": "push:newClusterAdmin",
                            "disabled": True
                        }
                    ],
                    "scope": [
                        {
                            "cluster": "cluster1",
                            "namespaces": ["test-system"]
                        }
                    ]
                }
        )

        res = self.post(API_NOTIFICATIONS_ALERTCHANNEL, cookies=self.selected_tenant_cookie, data=payload)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: create channel alert "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def update_alert_channel(self, alert_channel) -> requests.Response:
        res = self.put(API_NOTIFICATIONS_ALERTCHANNEL, cookies=self.selected_tenant_cookie, json=alert_channel)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: update channel alert "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def remove_alert_channel(self, guid) -> requests.Response:
        res = self.delete(API_NOTIFICATIONS_ALERTCHANNEL + "/" + guid, cookies=self.selected_tenant_cookie)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: delete channel alert "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

class Solution(object):
    """docstring for Solution"""

    def __init__(self, dashboard_connection, guid):
        super(Solution, self).__init__()

        self.dashboard_connection = dashboard_connection
        self.guid = guid

    def get_full_info(self):
        r = self.dashboard_connection.get(
            "/solution", params={'solguid': self.guid})
        assert (200 <= r.status_code < 300), \
            'Error accessing dashboard! solution guid: {sol}\nError details- code: ' \
            '{status_code}, message: {text}'.format(
                status_code=r.status_code, text=r.text, sol=self.guid)

        return r.json()

    def get_components_list(self):
        components = []
        for component in self.get_full_info()['components']:
            components.append(
                Component(self.dashboard_connection, component["id"], self.guid))

        return components

    def delete(self, force=False, silent_mode=True):
        for component in self.get_components_list():
            component.delete(force=force, silent_mode=silent_mode)


class Component(object):
    """docstring for Component"""

    def __init__(self, dashboard_connection: ControlPanelAPI, guid, solution_guid, customer_guid=None):
        super(Component, self).__init__()
        self.dashboard_connection = dashboard_connection
        self.selected_tenant_id = customer_guid if customer_guid is not None else dashboard_connection.customer_guid
        self.guid = guid
        self.solution_guid = solution_guid

    def get_full_info(self):
        err_msg = ''
        for i in range(3):
            r = self.dashboard_connection.get("/component", params={'componentguid': self.guid,
                                                                    'solguid': self.solution_guid}, timeout=20)
            if 200 <= r.status_code < 300:
                break
            err_msg = 'Error accessing dashboard! component guid: {com},  solution guid: {sol},\nError details- code: ' \
                      '{status_code}, message: {text}. Try num {t_num}'.format(status_code=r.status_code, text=r.text,
                                                                               com=self.guid,
                                                                               sol=self.solution_guid, t_num=i)
            Logger.logger.warning(err_msg)
            time.sleep(3)
        assert (200 <= r.status_code < 300), err_msg

        return r.json()

    def get_total_io(self, container=None, creation_time=None):

        ret = dict()

        ret["totalFSEncryption"] = 0
        ret["totalFSDecryption"] = 0
        ret["totalFSIO"] = 0
        ret["totalProxyIO"] = 0

        # for session_leaf in self.get_component_in_customer_tree():
        #     session = Session(self.dashboard_connection, session_leaf["ca_guid"])
        for session in self.get_sessions(container, creation_time):
            total_io = session.get_total_io()
            for key in total_io:
                ret[key] += total_io[key]

        return ret

    @staticmethod
    def get_creation_time(container):
        return container.attrs["Created"]

    def get_sessions(self, container=None, creation_time=None):
        """Get component sessions list with limits of
        time or container (or both, or not at all...)."""
        Logger.logger.info(
            "Searching for sessions of machineID '{}'...".format(container))
        if container and not creation_time:
            creation_time = dateutil.parser.parse(
                self.get_creation_time(container))

        comp_data = self.get_full_info()
        sessions = []
        for session in comp_data["componentInstances"]:
            if creation_time:
                session_uptime = dateutil.parser.parse(session["uptime"])
                if creation_time > session_uptime:
                    break
            if container:
                try:
                    if session["processInfo"]["machineID"][:-2] == container:
                        sessions.append(
                            Session(self.dashboard_connection, session["sessionID"]))
                except:
                    if session["sessionID"].startswith(container.short_id):
                        sessions.append(
                            Session(self.dashboard_connection, session["sessionID"]))
            else:
                sessions.append(
                    Session(self.dashboard_connection, session["sessionID"]))
        Logger.logger.info("Found {} sessions of machineID '{}'".format(
            len(sessions), container))

        return sessions

    def delete(self, container=None, creation_time=None, force=False, silent_mode=True):
        for session in self.get_sessions(container, creation_time):
            if force:
                try:
                    session.delete(silent_mode=silent_mode)
                except:
                    if not silent_mode:
                        exc_type, exc_obj, exc_tb = sys.exc_info()
                        out = ''.join(traceback.format_tb(exc_tb))
                        print(
                            out + "\n{0}: {1}\n".format(exc_type.__name__, exc_obj))

            else:
                session.delete()

        for session_leaf in self.get_component_in_customer_tree():
            Session(self.dashboard_connection,
                    session_leaf["ca_guid"]).delete()

    def get_component_in_customer_tree(self):
        cust_tree = self.dashboard_connection.get_customer_tree()
        for solution in cust_tree:
            if solution["ca_guid"] != self.solution_guid:
                continue
            for component in solution["children"]:
                if component["ca_guid"] != self.guid:
                    continue
                Logger.logger.info("Found {} sessions of component {} ".format(
                    len(component["children"]), component["ca_guid"]))
                return component["children"]
        Logger.logger.info(
            "Found 0 sessions of component {} ".format(self.guid))
        return []


class Session(object):
    """represent a dashboard session."""

    def __init__(self, dashboard_connection, session_id):
        super(Session, self).__init__()

        self.dashboard_connection = dashboard_connection
        self.id = session_id

    def get_info(self):
        """Get raw data."""
        for i in range(4):
            try:
                r = self.dashboard_connection.get(
                    "/session", params={'sessionid': self.id})
                if 200 <= r.status_code < 300:
                    break
                err_msg = 'Error accessing dashboard! session id: {id}\nError details- code:{status_code}, message: {text}'.format(
                    status_code=r.status_code, text=r.text, id=self.id)
                Logger.logger.warning(err_msg)
            except Exception as ex:
                Logger.logger.warning(
                    "Exception {}. Try num: {}".format(ex, i))
            time.sleep(4)
        assert (200 <= r.status_code < 300), err_msg
        return r.json()

    def get_total_io(self):
        ret = dict()

        ret["totalFSEncryption"] = 0
        ret["totalFSDecryption"] = 0
        ret["totalFSIO"] = 0
        ret["totalProxyIO"] = 0

        for service in self.get_base_services_list():
            if service["type"] == 4:  # Proxy service
                ret["totalProxyIO"] += service["proxyAllDataTransfer"] if not isinstance(
                    service["proxyAllDataTransfer"], list) else service["proxyAllDataTransfer"][0]["value"]
            else:
                encrypted_data = service["encryptedIOData"] if not isinstance(
                    service["encryptedIOData"], list) else service["encryptedIOData"][0]["value"]
                ret["totalFSEncryption"] += encrypted_data
                decrypted_data = service["decryptedIOData"] if not isinstance(
                    service["decryptedIOData"], list) else service["decryptedIOData"][0]["value"]
                ret["totalFSDecryption"] += decrypted_data
                ret["totalFSIO"] += encrypted_data + decrypted_data

        return ret

    def get_alerts(self):
        """Get session alert list."""
        r = self.dashboard_connection.get("/alerts", params={'id': self.id})
        assert (200 <= r.status_code < 300), 'Error getting session alerts from dashboard (code: %d, message: %s)' % (
            r.status_code, r.text)
        return r.json()

    def get_base_services_list(self):
        """Get basic services *info* list."""
        return self.get_info()["services"]

    def get_services_list(self):
        """Get dashboard service objects list."""
        services = []
        for service in self.get_base_services_list():
            services.append(Service(self.dashboard_connection,
                                    self.id, service["instanceID"]))

        return services

    def delete(self, silent_mode=True):
        """Delete the session from dashboard."""

        for i in range(3):
            if not silent_mode:
                Logger.logger.debug(
                    "Deleting dashboard session. guid:{}. Try num {}".format(self.id, i))
            r = self.dashboard_connection.delete(
                "/deleteSession", params={"sessionID": self.id})
            if 200 <= r.status_code < 300:
                break
            err_msg = 'Error deleting session from dashboard (code: %d, message: %s)' % (
                r.status_code, r.text)
            Logger.logger.warning(err_msg)
            time.sleep(3)
        assert (200 <= r.status_code < 300), err_msg

    def is_active(self):
        """The name of the function is talking for itself."""
        return True if self.get_info()["status"] == 1 else False


class Service(object):
    """represent DashBoard Service."""

    def __init__(self, dashboard_connection, session, service_instance_id):
        super(Service, self).__init__()

        self.dashboard_connection = dashboard_connection
        self.session = session
        self.id = service_instance_id

    def get_info(self):

        r = self.dashboard_connection.get("/serviceInstance",
                                          params={'sessionid': self.session, 'serviceinstanceid': self.id})
        assert (
                200 <= r.status_code < 300), 'Error getting session service info from dashboard (code: %d, message: %s)' % (
            r.status_code, r.text)
        return r.json()

# encoding: utf-8
import math
import sys
import time
import traceback
from datetime import datetime, timezone, timedelta
import inspect
from typing import Dict, List, Optional
import dateutil.parser
import requests
import websocket
from http import client
from systest_utils import statics

from systest_utils.tests_logger import Logger
from systest_utils.wlid import Wlid

import json
from infrastructure.api_login import *


class NotExistingCustomer(Exception):
    pass


__TIME_LEN__ = len('2024-05-15T07:10:23.513630')

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
API_TENANT_CREATE = "/api/v1/tenants/createTenant"
API_CLUSTER = "/api/v1/cluster"
API_IMAGE_SCAN_STATS = "/api/v1/customerState/reports/imageScan"
API_POSTURE_CLUSTERSOVERTIME = "/api/v1/posture/clustersOvertime"
API_POSTURE_CLUSTERS = "/api/v1/posture/clusters"
API_POSTURE_FRAMEWORKS = "/api/v1/posture/frameworks"
API_POSTURE_CONTROLS = "/api/v1/posture/controls"
API_POSTURE_TOPFAILEDCONTROLS = "/api/v1/posture/topFailedControls"
API_POSTURE_RESOURCES = "/api/v1/posture/resources"
API_POSTURE_SCAN = "/api/v1/posture/scan"

API_VULNERABILITYEXCEPTIONPOLICY = "/api/v1/vulnerabilityExceptionPolicy"
API_VULNERABILITY_SCANRESULTSSUMSUMMARY = "/api/v1/vulnerability/scanResultsSumSummary"
API_VULNERABILITY_SCAN_V2 = "/api/v1/vulnerability/scan/v2/"
API_VULNERABILITY_SCANRESULTSDETAILS = "/api/v1/vulnerability/scanResultsDetails"
API_VULNERABILITY_UNIQUE_VALUES_SUMMARY = "/api/v1/uniqueValues/vulnerability/scanResultsSumSummary"

API_VULNERABILITY_V2_WORKLOAD = "/api/v1/vulnerability_v2/workload"
API_VULNERABILITY_V2 = "/api/v1/vulnerability_v2/vulnerability"
API_VULNERABILITY_V2_IMAGE = "/api/v1/vulnerability_v2/image"
API_VULNERABILITY_V2_COMPONENT = "/api/v1/vulnerability_v2/component"
API_VULNERABILITY_V2_COMPONENT_UNIQUEVALUES =  "/api/v1/uniqueValues/vulnerability_v2/component"

API_INTEGRATIONS = "/api/v1/integrations"

API_REPOSITORYPOSTURE = "/api/v1/repositoryPosture"
API_REPOSITORYPOSTURE_REPOSITORIES = "/api/v1/repositoryPosture/repositories"
API_REPOSITORYPOSTURE_FILES = "/api/v1/repositoryPosture/files"
API_REPOSITORYPOSTURE_RESOURCES = "/api/v1/repositoryPosture/resources"

API_FRAMEWORK = "/api/v1/framework"

API_CUSTOMERCONFIGURATION = "/api/v1/customerConfiguration"

API_POSTUREEXCEPTIONPOLICY = "/api/v1/postureExceptionPolicy"

API_ACCESS_KEYS = "/api/v1/authentication/accessKeys"
API_ADMIN_TENANTS = "/api/v1/admin/tenants"
API_ADMIN_CREATE_SUBSCRIPTION = "/api/v1/admin/createSubscription"
API_ADMIN_CANCEL_SUBSCRIPTION = "/api/v1/admin/cancelSubscription"
API_ADMIN_RENEW_SUBSCRIPTION = "/api/v1/admin/renewSubscription"

API_ADMIN_ACTIVATE_WORKFLOWS = "/api/v1/admin/activateWorkflows"
API_ADMIN_WORKFLOWS_CONVERT = "/api/v1/admin/convertAndActivateWorkflows"
API_ADMIN_COPY_SLACK_TOKEN = "/api/v1/admin/copySlackToken"


API_NOTIFICATIONS_UNSUBSCRIBE = "/api/v1/notifications/unsubscribe"
API_NOTIFICATIONS_ALERTCHANNEL = "/api/v1/notifications/alertChannel"

API_REGISTRY_MANAGEMENT = "/api/v1/registry/management"

API_ATTACK_CHAINS = "/api/v1/attackchains"

API_NETWORK_POLICIES = "/api/v1/networkpolicies"
API_NETWORK_POLICIES_GENERATE = "/api/v1/networkpolicies/generate"
API_NETWORK_POLICIES_KNOWNSERVERSCACHE = "/api/v1/networkpolicies/knownserverscache"

API_KUBERNETES_RESOURCES = "/api/v1/kubernetesresources"
KUBERNETES_RESOURCES_METADATA_KEY = 'kubernetesResourcesMetadata'
KUBERNETES_RESOURCES_OBJECT_KEY = 'kubernetesResourceObject'

API_SECURITY_RISKS_LIST = "/api/v1/securityrisks/list"
API_SECURITY_RISKS_SEVERITIES = "/api/v1/securityrisks/severities"
API_SECURITY_RISKS_CATEGORIES = "/api/v1/securityrisks/categories"
API_SECURITY_RISKS_TRENDS = "/api/v1/securityrisks/trends"
API_SECURITY_RISKS_LIST_UNIQUEVALUES = "/api/v1/uniqueValues/securityrisks/list"
API_SECURITY_RISKS_RESOURCES = "/api/v1/securityrisks/resources"
API_SCAN_STATUS = "/api/v1/scanStatus"
API_SECURITY_RISKS_TRENDS = "/api/v1/securityrisks/trends"

API_SECURITY_RISKS_EXCEPTIONS_NEW = "/api/v1/securityrisks/exceptions/new"
API_SECURITY_RISKS_EXCEPTIONS_LIST = "/api/v1/securityrisks/exceptions/list"
API_SECURITY_RISKS_EXCEPTIONS = "/api/v1/securityrisks/exceptions"

API_INCIDENTS_UNIQUEVALUES = "/api/v1/uniqueValues/incidents"
API_RUNTIME_INCIDENTS = "/api/v1/runtime/incidents"

API_RUNTIME_INCIDENTSPERSEVERITY = "/api/v1/runtime/incidentsPerSeverity"
API_RUNTIME_INCIDENTSOVERTIME = "/api/v1/runtime/incidentsOvertime"
API_RUNTIME_INCIDENTSRULESET = "/api/v1/runtime/incidentsRuleSet"
API_RUNTIME_INCIDENTTYPES = "/api/v1/runtime/incidentTypes"
API_RUNTIME_POLICIES_LIST = "/api/v1/runtime/policies/list"
API_RUNTIME_POLICIES = "/api/v1/runtime/policies"
API_RUNTIME_POLICIES_UNIQUEVALUES = "/api/v1/uniqueValues/runtimeIncidentPolicy"

API_RUNTIME_EXCEPTION = "/api/v1/runtime/exceptions"
API_RUNTIME_EXCEPTION_NEW = API_RUNTIME_EXCEPTION + "/new"
API_RUNTIME_EXCEPTION_LIST = API_RUNTIME_EXCEPTION + "/list"


API_SECCOMP_LIST = "/api/v1/seccomp/list"
API_SECCOMP_GENERATE = "/api/v1/seccomp/generate"

API_WORKFLOWS = "/api/v1/workflows"

API_TEAMS = "/api/v1/notifications/teams"
API_TEAMS_TEST_MESSAGE = "/api/v1/notifications/teams/testMessage"


API_WEBHOOKS = "/api/v1/notifications/webhooks"
API_WEBHOOKS_TEST_MESSAGE = "/api/v1/notifications/webhooks/testMessage"

API_ACCOUNTS = "/api/v1/accounts"
API_ACCOUNTS_CLOUD_LIST = "/api/v1/accounts/cloud/list"
API_ACCOUNTS_KUBERNETES_LIST = "/api/v1/accounts/kubernetes/list"
BASE_API_ACCOUNTS_AWS = "/api/v1/accounts/aws"
API_ACCOUNTS_AWS_REGIONS = BASE_API_ACCOUNTS_AWS + "/regions"
APT_ACCOUNTS_AWS_REGIONS_DETAILS = BASE_API_ACCOUNTS_AWS + "/regionsdetails"
API_ACCOUNTS_CSPM_LINK = BASE_API_ACCOUNTS_AWS + "/cspmfeatures"
API_ACCOUNTS_CADR_LINK = BASE_API_ACCOUNTS_AWS + "/cadrstack"

BASE_API_ACCOUNTS_AWS_ORG = BASE_API_ACCOUNTS_AWS + "/org"
API_ACCOUNTS_CADR_ORG_LINK = BASE_API_ACCOUNTS_AWS_ORG + "/cadrstack"
API_ACCOUNTS_CSPMM_MEMBERS_ORG_LINK = BASE_API_ACCOUNTS_AWS_ORG + "/cspmmembers"
API_ACCOUNTS_CSPM_ADMIN_ORG_LINK = BASE_API_ACCOUNTS_AWS_ORG + "/cspmadmin"


API_ACCOUNTS_DELETE_FEATURE = "/api/v1/accounts/feature"
API_UNIQUEVALUES_ACCOUNTS_CLOUD= "/api/v1/uniqueValues/accounts/cloud"
API_UNIQUEVALUES_ACCOUNTS_KUBERNETES = "/api/v1/uniqueValues/accounts/kubernetes"

API_CLOUD_COMPLIANCE_BASE = "/api/v1/cloudposture/"
API_CLOUD_COMPLIANCE_ACCOUNTS = API_CLOUD_COMPLIANCE_BASE+"accounts"
API_CLOUD_COMPLIANCE_SEVERITY_COUNTS = API_CLOUD_COMPLIANCE_BASE+"severityCounts"
API_CLOUD_COMPLIANCE_FRAMEWORKS = API_CLOUD_COMPLIANCE_BASE+"frameworks"
API_CLOUD_COMPLIANCE_FRAMEWORKS_OVER_TIME = API_CLOUD_COMPLIANCE_BASE+"frameworksOvertime"
API_CLOUD_COMPLIANCE_CONTROLS = API_CLOUD_COMPLIANCE_BASE+"controls"
API_CLOUD_COMPLIANCE_RULES = API_CLOUD_COMPLIANCE_BASE+"rules"
API_CLOUD_COMPLIANCE_RESOURCES = API_CLOUD_COMPLIANCE_BASE+"resources"
API_CLOUD_COMPLIANCE_EXCEPTIONS = API_CLOUD_COMPLIANCE_BASE+"exceptions"
API_CLOUD_COMPLIANCE_EXCEPTIONS_NEW = API_CLOUD_COMPLIANCE_EXCEPTIONS+"/new"
API_CLOUD_COMPLIANCE_EXCEPTIONS_LIST = API_CLOUD_COMPLIANCE_EXCEPTIONS+"/list"
API_CLOUD_COMPLIANCE_SCAN_NOW = API_CLOUD_COMPLIANCE_BASE+"scanNow"


API_COMMAND_HELM = "/api/v1/commands/helm"

POST_CDR_ALERTS = "/cloud/v1/cdrAlert"

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

        if "timeout" not in kwargs:
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

    def __init__(self, user_name, password, customer, client_id, secret_key, url, auth_url=None,
                 login_method=LOGIN_METHOD_KEYCLOAK, customer_guid=None):
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
        self.access_key = ""

        self.api_login = APILogin()

        self.verify = True

        self.login(self.login_method)

    def login(self, login_method):
        if login_method == LOGIN_METHOD_KEYCLOAK:
            self.api_login = KeycloakAPILogin(username=self.username, password=self.password, customer=self.customer,
                                              server=self.server, referer=self.auth_url, verify=self.verify)
        elif login_method == LOGIN_METHOD_FRONTEGG_SECRET:
            self.api_login = FrontEggSecretAPILogin(auth_url=self.auth_url, base_url=self.server,
                                                    client_id=self.client_id, secret_key=self.secret_key)
        elif login_method == LOGIN_METHOD_FRONTEGG_USERNAME:
            self.api_login = FrontEggUsernameAPILogin(server=self.server, username=self.username,
                                                      password=self.password, customer=self.customer,
                                                      customer_guid=self.customer_guid)
        else:
            raise Exception(f"Login method '{login_method}' not supported")

        self.login_customer_guid, self.login_customer_cookie, auth = self.api_login.login()
        Logger.logger.info(f"Customer guid  {self.login_customer_guid} authenticated successfully")
        if login_method == LOGIN_METHOD_FRONTEGG_USERNAME:
            self.auth = {"Cookie": "auth=" + auth}
        else:
            self.auth = {'Authorization': f'Bearer {auth}'} if 'bearer' not in auth.lower() else {
                'Authorization': f'{auth}'}

        self.selected_tenant_id = self.login_customer_guid
        self.selected_tenant_cookie = self.login_customer_cookie

        # set access keys
        access_keys_response = self.get_access_keys()
        access_keys = access_keys_response.json()
        assert len(access_keys) != 0, f"Expected access keys, found none"
        assert "value" in access_keys[0], f"failed to get access key value"
        self.set_access_key(access_keys[0]["value"])

    def set_access_key(self, access_key: str):
        self.access_key = access_key
        if self.auth is None:
            self.auth = {}
        self.auth["X-API-KEY"] = self.access_key

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
            raise Exception(
                f"Requested {tenant_id} details, got {res.text['guid']}. Make sure to first select the customer using select_tenant()")

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

        res = self.post(API_TENANT_CREATE,
                        json={"customerName": tenantName, "userId": self.api_login.get_frontEgg_user_id()},
                        cookies=None, headers={"Authorization": f"Bearer {self.api_login.get_frontEgg_auth_user_id()}"})
        assert res.status_code in [client.CREATED, client.OK], f"Failed to create tenant {tenantName}: {res.text}"
        json_response = res.json()
        assert json_response.get("tenantId", {}) != {}, f"tenantId is empty: {res.text}"
        assert json_response.get("agentAccessKey", {}).get("value",
                                                           {}) != {}, f"agentAccessKey['value'] is empty: {res.text}"
        return json_response["tenantId"], json_response["agentAccessKey"]["value"]

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
            raise Exception(f"Deleting the login customer '{tenant_id}' is not allowed.")

        res = self.delete(API_ADMIN_TENANTS, json={"tenantsIds": [tenant_id]})
        # assert res.status_code == client.OK, f"delete tenant failed {tenant_id}: {res.status_code} {res.text}"
        return res

    def get_access_keys(self) -> requests.Response:
        """
            Returns the access keys of the selected tenant.
        """
        res = self.get(API_ACCESS_KEYS)
        assert res.status_code == client.OK, f"failed to get access keys for tenant_id {self.selected_tenant_id}. Response: {res.text}"
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
        res = self.post(API_STRIPE_CHECKOUT, json={"priceID": priceID, "quantity": qauntity}, )
        assert res.status_code == client.CREATED, f"stripe checkout failed to create url for tenant_id {self.selected_tenant_id}. Response: {res.text}"
        return res

    def get_stripe_plans(self) -> requests.Response:
        """
            Get all stripe plans.
        """
        res = self.get(API_STRIPE_PLANS)
        assert res.status_code == client.OK, f"get_stripe_plans Failed. expected status code 200, found {res.status_code}. response: {res.text} Make sure you have a valid stripe secret key and priceIdsMap is well configured"
        return res

    def create_subscription(self, priceID: str, stripeCustomerID: str, quantity: int,
                            tenantID: str) -> requests.Response:
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

    def cancel_subscription(self, tenantID: str) -> dict:
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

    def renew_subscription(self, tenantID: str) -> dict:
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

    # ************** Activate Workflows **************
    # relevant for feature transition phase
    def active_workflow(self, tenantID: str) -> dict:
        """
            activate workflow for a tenant.
        """

        res = self.post(
            API_ADMIN_ACTIVATE_WORKFLOWS,
            json={
                "tenantID": tenantID
            },
        )
        assert res.status_code == client.OK, f"activate workflow failed for tenantID: {tenantID}"

        return res

    # ************** Convert and Activate Workflows **************
    # relevant for feature transition phase
    def convert_and_activate_workflows(self, tenantID: str, force_convert=True) -> dict:
        """
            convert and activate workflow for a tenant.
        """

        params = {}
        if force_convert:
            params["forceConvert"] = True


        res = self.post(
            API_ADMIN_WORKFLOWS_CONVERT,
            params=params,
            json={
                "tenantID": tenantID
            },
        )
        assert res.status_code == client.OK, f"convert and activate workflow failed for tenantID: {tenantID}"

        return res

    # ************** Copy Slack Token **************
    # relevant for workflos feature transition phase
    def copy_slack_token(self, tenantID: str) -> dict:
        """
            copy slack token for a tenant.
        """

        res = self.post(
            API_ADMIN_COPY_SLACK_TOKEN,
            json={
                "tenantID": tenantID
            },
        )
        assert res.status_code == client.OK, f"copy slack token failed for tenantID: {tenantID}"

        return res


    def get_customer_guid(self):
        return self.selected_tenant_id

    def get_client_id(self):
        return self.client_id

    def get_secret_key(self):
        return self.secret_key

    def get_access_key(self):
        return self.access_key

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

    # /api/v1/runtime/kdrMonitoredCounters
    def get_kdr_monitored_counters(self, cluster: str):
        url = "/api/v1/runtime/kdrMonitoredCounters"
        params = {"customerGUID": self.selected_tenant_id}
        if cluster:
            params["clusterName"] = cluster
        r = self.get(url, params=params)
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_incidents(self, filters, **kwargs):
        url = API_RUNTIME_INCIDENTS
        params = {"customerGUID": self.selected_tenant_id}
        if kwargs:
            params.update(**kwargs)
        r = self.post(url, params=params, json={"pageNumber": 1, "pageSize": 100,
                                                "orderBy": "createdTimestamp:desc", "innerFilters": [filters]})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_incident(self, incident_id: str):
        url = API_RUNTIME_INCIDENTS + "/" + incident_id
        r = self.get(url, params={"customerGUID": self.selected_tenant_id})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()
    
    def response_incident(self, incident_id: str, body: str):
        url = API_RUNTIME_INCIDENTS + "/" + incident_id + "/response"
        r = self.post(url, params={"customerGUID": self.selected_tenant_id}, json=body)
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()
    
    def audit_log_incident(self, incident_id: str, body: str):
        url = API_RUNTIME_INCIDENTS + "/" + incident_id + "/auditlog"
        r = self.post(url, params={"customerGUID": self.selected_tenant_id}, json=body)
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def resolve_incident(self, incident_id: str, resolution: str):
        url = "/api/v1/runtime/incidents/" + incident_id + "/resolve"
        r = self.post(url, params={"customerGUID": self.selected_tenant_id}, json={"Reason": resolution})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_alerts_of_incident(self, incident_id: str):
        url = API_RUNTIME_INCIDENTS + "/" + incident_id + "/alerts/list"
        r = self.post(url, params={"customerGUID": self.selected_tenant_id},
                      json={"pageNumber": 1, "pageSize": 100, "orderBy": "timestamp:asc"})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        # TODO: get them all
        return r.json()

    def get_process_graph(self, incident_id: str):
        url = "/api/v1/runtime/incidents/" + incident_id + "/process"
        r = self.get(url, params={"customerGUID": self.selected_tenant_id})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_incident_unique_values(self, request: Dict):
        url = API_INCIDENTS_UNIQUEVALUES
        r = self.post(url, params={"customerGUID": self.selected_tenant_id}, json=request)
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_alerts_unique_values(self, incident_id: str, request: Dict):
        url = f"{API_RUNTIME_INCIDENTS}/{incident_id}/alerts/uniqueValues"
        r = self.post(url, params={"customerGUID": self.selected_tenant_id}, json=request)
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_incidents_per_severity(self):
        url = API_RUNTIME_INCIDENTSPERSEVERITY
        r = self.post(url, params={"customerGUID": self.selected_tenant_id}, json={})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_incidents_overtime(self):
        url = API_RUNTIME_INCIDENTSOVERTIME
        now_time = datetime.now(timezone.utc) + timedelta(days=1)
        last_30_days = now_time - timedelta(days=30)
        r = self.post(url, params={"customerGUID": self.selected_tenant_id},
                      json={"since": last_30_days.isoformat("T")[:__TIME_LEN__] + "Z",
                            "until": now_time.isoformat("T")[:__TIME_LEN__] + "Z"})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_raw_alerts_list(self, cursor=None):
        url = "/api/v1/runtime/rawalerts/list"
        last_30_days = datetime.now(timezone.utc) - timedelta(days=30)
        # since is mandatory
        payload = {"pageNumber": 1, "pageSize": 20, "since": last_30_days.isoformat("T")[:__TIME_LEN__] + "Z"}
        if cursor:
            payload["cursorV1"] = {"id": cursor}
        r = self.post(url, params={"customerGUID": self.selected_tenant_id}, json=payload)
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_raw_alerts_overtime(self):
        url = "/api/v1/runtime/rawalerts/overtime"
        now_time = datetime.now(timezone.utc)
        last_30_days = now_time - timedelta(days=30)
        r = self.post(url, params={"customerGUID": self.selected_tenant_id},
                      json={"since": last_30_days.isoformat("T")[:__TIME_LEN__] + "Z",
                            "until": now_time.isoformat("T")[:__TIME_LEN__] + "Z"})
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
            timeout=60
        )
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of repositoryPosture/files "%s" (code: %d, message: %s)'
                % (self.customer, r.status_code, r.text)
            )
        return r.json()["response"]

    def get_repository_posture_resources(self, report_guid: str):
        page_size = 100
        params = {
            "pageNum": 1,
            "pageSize": page_size,
            "orderBy": "timestamp:desc,name:desc",
            "innerFilters": [{"reportGUID": report_guid}],
        }

        r = self.post(API_REPOSITORYPOSTURE_RESOURCES, params={"customerGUID": self.selected_tenant_id}, json=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of repositoryPosture/resources "%s" (code: %d, message: %s)'
                % (self.customer, r.status_code, r.text)
            )
        result_length = r.json()['total']['value']

        result = []
        for i in range(1, math.ceil(result_length / page_size) + 1):
            params['pageNum'] = i
            r = self.post(API_REPOSITORYPOSTURE_RESOURCES, params={"customerGUID": self.selected_tenant_id},
                          json=params)
            if not 200 <= r.status_code < 300:
                raise Exception(
                    'Error accessing dashboard. Request: results of repositoryPosture/resources "%s" (code: %d, message: %s)'
                    % (self.customer, r.status_code, r.text)
                )
            result.extend(r.json()['response'])

        return result

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

    def get_posture_controls(self, framework_name: str, report_guid: str, control_id: str = ""):
        r = self.post(API_POSTURE_CONTROLS, params={"customerGUID": self.selected_tenant_id},
                      json={"pageNum": 1, "pageSize": 150, "orderBy": "timestamp:desc", "innerFilters": [{
                          "frameworkName": framework_name, "reportGUID": report_guid, "id": control_id}]})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of posture controls "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if len(r.json()['response']) == 0:
            raise Exception('Error accessing dashboard. Request: results of posture controls is empty')
        return r.json()['response']

    def get_top_controls_results(self, cluster_name):
        # TODO: change to "topControls" when it will be deprecated
        r = self.post(API_POSTURE_TOPFAILEDCONTROLS,
                      params={"customerGUID": self.selected_tenant_id, "cluster": cluster_name},
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

    def get_posture_resources(self, framework_name: str, report_guid: str, resource_name: str = "",
                              related_exceptions: str = "false", namespace=None, order_by=None):
        if order_by is None:
            order_by = "timestamp:desc"

        body = {"pageNum": 1,
                "pageSize": 150,
                "orderBy": order_by,
                "innerFilters": [{
                    "frameworkName": framework_name, "reportGUID": report_guid,
                    "designators.attributes.name": resource_name}]}
        if namespace is not None:
            body["innerFilters"][0]["designators.attributes.namespace"] = namespace
        r = self.post(API_POSTURE_RESOURCES,
                      params={"customerGUID": self.customer_guid, "relatedExceptions": related_exceptions,
                              "ignoreRulesSummary": related_exceptions},
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

    def get_posture_clusters(self, body):
        r = self.post(API_POSTURE_CLUSTERS, params={"customerGUID": self.selected_tenant_id},
                      json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of posture clusters "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        if len(r.json()['response']) == 0:
            raise Exception('Error accessing dashboard. Request: results of posture controls is empty')
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

    def put_custom_framework(self, fw_object: json):
        r = self.put(API_FRAMEWORK, params={"customerGUID": self.selected_tenant_id}, json=fw_object)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'failed to put custom framework "%s" (code: %d, message: %s)' % (
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
            raise Exception('Expected %d scans, received %d: %s' % (expected_results,
                                                                   len(result), ', '.join(scan_names)))
        for scan in result:
            if (scan['status'] == 'Pending') or ('isStub' in scan.keys() and scan['isStub']):
                raise Exception(
                    f'Error receive scan result: Result length: {len(result)}. Container {scan["containerName"]}" is still in pending. Full result list: {result}'
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
        result_length = self.get_length_of_post_response(url=API_VULNERABILITY_SCANRESULTSDETAILS, params=params,
                                                         body=body)

        assert result_length >= total_cve, \
            f'wait for aggregation to end in the backend, number of CVEs is lower than expected. ' \
            f'received {result_length}, expected: {total_cve}'

        result = []
        for i in range(1, math.ceil(result_length / page_size) + 1):
            body['pageNum'] = i
            r = self.post(API_VULNERABILITY_SCANRESULTSDETAILS, params=params, json=body)
            if not 200 <= r.status_code < 300:
                raise Exception(
                    'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                        self.customer, r.status_code, r.text))
            result.extend(r.json()['response'])
            Logger.logger.info(
                'container scan id : {} len(result):{}, len(expected_results):{} '.format(containers_scan_id,
                                                                                          result,
                                                                                          total_cve))

        if len(result) < total_cve:
            raise Exception(
                f'wait for aggregation to end in the backend, number of CVEs is lower than expected. ' \
                f'received {result}, expected: {total_cve}'
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

        assert len(result) == expected_results, 'Expected %d scans, received %d' % (expected_results, len(result))

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

    def trigger_posture_scan(self, cluster_name, framework_list=[""], with_host_sensor="true", additional_params={}):
        params = {"customerGUID": self.selected_tenant_id}
        if additional_params:
            params.update(additional_params)
        body = []
        for framework in framework_list:
            body.append(
                {"clusterName": cluster_name, "frameworkName": framework, "hostSensor": with_host_sensor})
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

    def get_vuln_scan_cronjob_list(self, cluster_name: str, expected_cjs):
        params = {"customerGUID": self.selected_tenant_id}
        r = self.get(API_VULNERABILITY_SCAN_V2, params=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get vuln scan cronjob list "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        cronjob_list = r.json()
        vuln_scan_cronjob_list = [cj for cj in cronjob_list if
                                  cj[statics.CA_VULN_SCAN_CRONJOB_CLUSTER_NAME_FILED] == cluster_name]
        self.compare_vuln_scan_be_cjs_to_expected(expected_cjs=expected_cjs, actual_cjs=vuln_scan_cronjob_list,
                                                  cluster_name=cluster_name)

        return vuln_scan_cronjob_list

    def compare_vuln_scan_be_cjs_to_expected(self, expected_cjs, actual_cjs, cluster_name):
        if len(expected_cjs) != len(actual_cjs):
            raise Exception(
                f'Error accessing dashboard. Request: get vuln scan cronjob list, expected to receive '
                f'{len(expected_cjs)} cron jobs, and receive {len(actual_cjs)}: {actual_cjs}')

        for actual in actual_cjs:
            for expected in expected_cjs:
                if expected.metadata.name == actual[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED]:
                    assert cluster_name == actual[
                        statics.CA_VULN_SCAN_CRONJOB_CLUSTER_NAME_FILED], f'cluster name is not as expected'
                    assert expected.spec.schedule == actual[
                        statics.CA_VULN_SCAN_CRONJOB_CRONTABSCHEDULE_FILED], f'cronjob schedule is not as expected'
                    assert actual[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED].startswith(
                        "kubevuln"), f'cronjob name is not as expected'

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

    def update_vuln_scan_cronjob(self, cj):
        cj = [cj] if isinstance(cj, dict) else cj
        params = {"customerGUID": self.selected_tenant_id}
        r = self.put(API_VULNERABILITY_SCAN_V2, params=params, json=cj)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: update vuln scan cronjob "%s" (code: %d, message: %s)' % (
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

    def is_ks_cronjob_created_in_backend(self, cluster_name: str, framework_name: str):
        params = {"customerGUID": self.selected_tenant_id} # , "cluster": cluster_name
        r = self.get(API_POSTURE_SCAN, params=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        cronjobs = r.json()
        for cj in cronjobs:
            if cj[statics.CA_VULN_SCAN_CRONJOB_CLUSTER_NAME_FILED] == cluster_name and "ks-scheduled-scan-{}".format(
                    framework_name.lower()) in cj[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED]:
                return True
        raise Exception("kubescape cronjob failed to create in backend")

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
                assert cj[statics.CA_VULN_SCAN_CRONJOB_NAME_FILED].startswith("ks-scheduled-scan-") or cj[
                    statics.CA_VULN_SCAN_CRONJOB_NAME_FILED].startswith(
                    "kubescape-scheduler"), f"ks-scheduled-scan- or kubescape-scheduler not in name: {cronjobs}"

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

    def post_with_ratelimit(self, url, **args):
        # Extract optional parameters with defaults
        rate_limit_retries = args.pop("rate_limit_retries", 3)
        rate_limit_sleep = args.pop("rate_limit_sleep", 60)

        for attempt in range(1, rate_limit_retries + 1):
            r = self.post(url, **args)

            # Check for rate limiting in status code or response text
            if r.status_code == 429 or "retryafter" in r.text.lower():
                Logger.logger.debug(
                    f"Rate limit reached for URL: {url}. Attempt {attempt} of {rate_limit_retries}. "
                    f"Retrying in {rate_limit_sleep} seconds."
                )
                if attempt < rate_limit_retries:
                    time.sleep(rate_limit_sleep)
                else:
                    Logger.logger.warning(
                        f"Rate limit retries exhausted for URL: {url}. Returning last response."
                    )
            else:
                return r

        # Return the last response if retries are exhausted
        return r

    @deco_cookie
    def get(self, url, **args):
        if not url.startswith("http://") and not url.startswith("https://"):
            url = self.server + url
        return requests.get(url, **args)

    def get_with_rate_limit(self, url, **args):
        rate_limit_retries = args.pop("rate_limit_retries", 3)
        rate_limit_sleep = args.pop("rate_limit_sleep", 60)

        for attempt in range(1, rate_limit_retries + 1):
            r = self.get(url, **args)

            if r.status_code == 429 or "retryafter" in r.text.lower():
                Logger.logger.debug(
                    f"Rate limit reached for URL: {url}. Attempt {attempt} of {rate_limit_retries}. "
                    f"Retrying in {rate_limit_sleep} seconds."
                )
                if attempt < rate_limit_retries:
                    time.sleep(rate_limit_sleep)
                else:
                    Logger.logger.warning(
                        f"Rate limit retries exhausted for URL: {url}. Returning last response."
                    )
            else:
                return r

        # Return the last response if retries are exhausted
        return r

    @deco_cookie
    def put(self, url, **args):
        return requests.put(self.server + url, **args)

    @deco_cookie
    def delete(self, url, **args):
        # for deletion we need to wait a while
        if not 'timeout' in args or args["timeout"] < 120:
            args["timeout"] = 120
        url = self.server + url
        return requests.delete(url, **args)


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

        authorization = f"Authorization: Bearer {self.api_login.get_frontEgg_auth_user_id()}"

        ws.connect(server, header=[cookie, authorization])
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
        assert nbmsg == totalChunks, 'Expected %d chunks, received %d' % (totalChunks, nbmsg)
        assert total == len(result), 'Expected %d total, received %d' % (total, len(result))
        Logger.logger.debug("Loaded {}".format(len(result)))
        return result

    def get_notifications_unsubscribed(self) -> requests.Response:
        res = self.get(API_NOTIFICATIONS_UNSUBSCRIBE, cookies=self.selected_tenant_cookie)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan notifications unsubscribe "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def add_notifications_unsubscribed(self, notifications_identifiers) -> requests.Response:
        res = self.post(API_NOTIFICATIONS_UNSUBSCRIBE, cookies=self.selected_tenant_cookie,
                        json=notifications_identifiers)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan notifications unsubscribe "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def remove_notifications_unsubscribed(self, notifications_identifiers) -> requests.Response:
        res = self.delete(API_NOTIFICATIONS_UNSUBSCRIBE, cookies=self.selected_tenant_cookie,
                          json=notifications_identifiers)
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

    def send_test_message(self, guid) -> requests.Response:
        res = self.post(API_NOTIFICATIONS_ALERTCHANNEL + "/" + guid + "/testMessage",
                        cookies=self.selected_tenant_cookie)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: send alert channel test message "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def create_alert_channel(self, payload) -> requests.Response:
        res = self.post(API_NOTIFICATIONS_ALERTCHANNEL, cookies=self.selected_tenant_cookie, data=json.dumps(payload))
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

    def check_registry(self, payload, provider) -> requests.Response:
        res = self.post(API_REGISTRY_MANAGEMENT + "/" + provider + "/repositories", cookies=self.selected_tenant_cookie, data=json.dumps(payload), timeout=60)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: check registry "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def create_registry(self, payload, provider) -> requests.Response:
        res = self.post(API_REGISTRY_MANAGEMENT + "/" + provider, cookies=self.selected_tenant_cookie, data=json.dumps(payload), timeout=60)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: create registry "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def get_registry(self, provider, guid) -> requests.Response:
        res = self.get(API_REGISTRY_MANAGEMENT + "/" + provider + "/" + guid, cookies=self.selected_tenant_cookie)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get registry "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def get_all_registries(self, provider) -> requests.Response:
        res = self.get(API_REGISTRY_MANAGEMENT + "/" + provider, cookies=self.selected_tenant_cookie)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get registry "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def update_registry(self, payload, provider, guid) -> requests.Response:
        res = self.put(API_REGISTRY_MANAGEMENT + "/" + provider + "/" + guid, cookies=self.selected_tenant_cookie, data=json.dumps(payload), timeout=60)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: update registry "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def delete_registry(self, provider, guid) -> requests.Response:
        res = self.delete(API_REGISTRY_MANAGEMENT + "/" + provider + "/" + guid, cookies=self.selected_tenant_cookie)
        if not 200 <= res.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: delete registry "%s" (code: %d, message: %s)' % (
                    self.customer, res.status_code, res.text))
        return res

    def get_attack_chains(self, cluster_name=None, namespace=None):
        params = {"customerGUID": self.selected_tenant_id}

        filters = []
        filter = {}
        if cluster_name is not None:
            filter["clusterName"] = cluster_name
        if namespace is not None:
            filter["resourceNamespace"] = namespace

        if filter:
            filters.append(filter)

        payload = {
            "innerFilters": filters,
        }
        r = self.post(API_ATTACK_CHAINS, params=params, json=payload, timeout=60)
        Logger.logger.info(r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan results sum summary "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_known_servers_cache(self) -> requests.Response:
        params = {"customerGUID": self.selected_tenant_id}
        r = self.get(API_NETWORK_POLICIES_KNOWNSERVERSCACHE, params=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get known servers cache "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_network_policies(self, cluster_name, namespace) -> (requests.Response, dict, dict):
        params = {"customerGUID": self.selected_tenant_id}

        payload = {
            "innerFilters": [{"clusterShortName": cluster_name, "namespace": namespace}],
        }

        r = self.post(API_NETWORK_POLICIES, params=params, json=payload, timeout=60)
        Logger.logger.info(r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get network policies generate "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

        response = json.loads(r.text)
        workloads_list = response.get("response", None)

        assert workloads_list is not None, "network policies response is empty '%s' (code: %d, message: %s)" % (
        self.customer, r.status_code, r.text)

        assert len(workloads_list) > 0, "network policies workloads list is 0 '%s' (code: %d, message: %s)" % (
        self.customer, r.status_code, r.text)

        return r, workloads_list

    def get_network_policies_generate(self, cluster_name, workload_name, namespace) -> (requests.Response, dict, dict):
        params = {"customerGUID": self.selected_tenant_id}

        payload = {
            "innerFilters": [{"cluster": cluster_name, "name": workload_name, "namespace": namespace}],
        }

        r = self.post(API_NETWORK_POLICIES_GENERATE, params=params, json=payload, timeout=60)
        Logger.logger.info(r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get network policies generate "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

        response = json.loads(r.text)

        # verify there is a response
        assert len(response) > 0, "network policies generate response is empty '%s' (code: %d, message: %s)" % (
        self.customer, r.status_code, r.text)

        np = response[0].get("networkPolicies", None).get("kubernetes", None).get("new", None)
        # verify there is a 'new' network policy
        assert np is not None, "no 'new' NetworkPolicy '%s' (code: %d, message: %s)" % (
        self.customer, r.status_code, r.text)

        graph = response[0].get("graph", None)
        # verify there is a 'graph'
        assert graph is not None, "No 'graph' '%s' (code: %d, message: %s)" % (self.customer, r.status_code, r.text)

        return r, np, graph

    def get_active_attack_chains(self, current_datetime=datetime, cluster_name=None, namespace=None) -> requests.Response:
        r = self.get_attack_chains(cluster_name, namespace)
        # checks if respose met conditions to be considered valid:
        # - parameter 'response.attackChainsLastScan' should have a value >= of current time
        # - parameter 'total.value' shoud be > 0
        # result = subprocess.run("kubectl get pods -A", timeout=300, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # print(result.stdout)
        response = json.loads(r.text)
        if response['response']['attackChainsLastScan']:
            last_scan_datetime = datetime.strptime(response['response']['attackChainsLastScan'], '%Y-%m-%dT%H:%M:%SZ')
            last_scan_datetime = last_scan_datetime.replace(tzinfo=timezone.utc)
            current_datetime_utc = current_datetime.astimezone(tz=timezone.utc)
            print("last scan time: ", last_scan_datetime)
            print("current time: ", current_datetime_utc)

            assert last_scan_datetime >= current_datetime_utc, f"attack-chains response is outdated"

        assert response['total']['value'] > 0, f"no attack-chains detected yet"

        return r

    def has_active_attack_chains(self, cluster_name=None, namespace=None) -> bool:
        r = self.get_attack_chains(cluster_name, namespace)

        response = json.loads(r.text)
        assert response['total']['value'] == 0, f"attack-chains not fixed yet"

        return True

    def get_kubernetes_resources(self, cluster_name: str, namespace: str = None, with_resource: bool = False):
        params = {"customerGUID": self.selected_tenant_id}
        if with_resource:
            params["enrichObjects"] = "true"

        payload = {
            "innerFilters": [{"cluster": cluster_name}],
        }

        if namespace == "":
            payload["innerFilters"][0]["namespace"] = "','|missing"
        elif namespace is not None:
            payload["innerFilters"][0]["namespace"] = namespace

        r = self.post(API_KUBERNETES_RESOURCES, params=params, json=payload, timeout=60)
        Logger.logger.info(r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: POST kubernetes resources generate "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

        response = json.loads(r.text)
        be_resources = response.get("response", None)
        assert be_resources is not None, "kubernetes resources response is empty '%s' (code: %d, message: %s)" % (
        self.customer, r.status_code, r.text)

        return be_resources

    def post_details_request(self, url, body: dict):
        r = self.post(url + '/details', params={"customerGUID": self.customer_guid},
                      json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: results of vuln workload details "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        j = r.json()
        if not j:
            raise Exception('Request: results of vuln workload details is empty body: %s' % body)
        return j

    def post_list_request(self, url, body: dict, expected_results: int = 0, params: dict = None):
        if params is None:
            params = {"customerGUID": self.selected_tenant_id}
        else:
            params["customerGUID"] = self.selected_tenant_id
        r = self.post(url + "/list", params=params,
                      json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request to: %s "%s" (code: %d, message: %s)' % (
                    url, self.customer, r.status_code, r.text))
        j = r.json()
        if expected_results == 0:
            return j['response']
        if 'response' not in j:
            raise Exception(f"Response does not contain 'response' key: {j}")
        if len(j['response']) < expected_results:
            raise Exception('Expected %d workloads, received %d' % (expected_results, len(j['response'])))
        return j['response']

    def get_vuln_v2_workloads(self, body: dict, expected_results: int = 0, enrich_tickets=False):
        params = {}
        if not enrich_tickets:
            params = {"enrichTickets": "false"}
        return self.post_list_request(API_VULNERABILITY_V2_WORKLOAD, body, expected_results, params=params)

    def get_vuln_v2_workload_details(self, body: dict):
        return self.post_details_request(API_VULNERABILITY_V2_WORKLOAD, body)

    def get_vulns_v2(self, body: dict, expected_results: int = 0, scope: str = None, enrich_tickets=False):
        params = {}
        if scope:
            params = {"scope": scope}
        if not enrich_tickets:
            params = {"enrichTickets": "false"}
        return self.post_list_request(API_VULNERABILITY_V2, body, expected_results, params=params)

    def get_vuln_v2_details(self, body: dict):
        return self.post_details_request(API_VULNERABILITY_V2, body)

    def get_vuln_v2_images(self, body: dict, expected_results: int = 0, scope: str = None, enrich_tickets=False):
        url = API_VULNERABILITY_V2_IMAGE
        params = {}
        if scope:
            params = {"scope": scope}
        if not enrich_tickets:
            params = {"enrichTickets": "false"}
        return self.post_list_request(url, body, expected_results, params=params)

    def get_vuln_v2_components(self, body: dict, expected_results: int = 0, scope: str = None, enrich_tickets=False):
        params = {}
        if scope:
            params["scope"] = scope
        if not enrich_tickets:
            params["enrichTickets"] = "false"
        return self.post_list_request(API_VULNERABILITY_V2_COMPONENT, body, expected_results, params=params)
    
    def get_vuln_v2_component_uniquevalues(self, body: dict):
        params = {"customerGUID": self.selected_tenant_id}
      
        r = self.post(API_VULNERABILITY_V2_COMPONENT_UNIQUEVALUES, params=params, json=body, timeout=60)
        Logger.logger.info(r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get get_vuln_v2_component_uniquevalues "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_posture_resources_highlights(self, body: dict):
        r = self.post(API_POSTURE_RESOURCES + '/highlights',
                      params={"smEnabled": "true", "customerGUID": self.selected_tenant_id},
                      json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing smart remediation. Request: results of posture resources highlights "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        j = r.json()
        if not j:
            raise Exception('Request: results of posture resources highlights is empty body: %s' % body)
        return j

    # security risks functions
    def get_security_risks_list(self, cluster_name=None, namespace=None, security_risk_ids=[], other_filters={}):
        params = {"customerGUID": self.selected_tenant_id}
        filters = {}

        if other_filters:
            filters = other_filters

        if cluster_name is not None:
            filters["cluster"] = cluster_name

        if namespace is not None:
            filters["namespace"] = namespace

        if len(security_risk_ids):
            filters["securityRiskID"] = ','.join(security_risk_ids)

        innerFilters = []
        if filters:
            innerFilters.append(filters)

        payload = {
            "innerFilters": innerFilters,
            "orderBy": "securityRiskID:asc",
        }
        r = self.post(API_SECURITY_RISKS_LIST, params=params, json=payload, timeout=60)
        Logger.logger.info(r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_security_risks_list "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_security_risks_severities(self, cluster_name=None, namespace=None, security_risk_ids=[]):
        params = {"customerGUID": self.selected_tenant_id}

        filters = {}

        if cluster_name is not None:
            filters["cluster"] = cluster_name

        if namespace is not None:
            filters["namespace"] = namespace

        if len(security_risk_ids):
            filters["securityRiskID"] = ','.join(security_risk_ids)

        innerFilters = []
        if filters:
            innerFilters.append(filters)

        payload = {
            "innerFilters": innerFilters,
        }
        r = self.post(API_SECURITY_RISKS_SEVERITIES, params=params, json=payload, timeout=60)
        Logger.logger.info(r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_security_risks_severities "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_security_risks_categories(self, cluster_name=None, namespace=None, security_risk_ids=[]):
        params = {"customerGUID": self.selected_tenant_id}

        filters = {}

        if cluster_name is not None:
            filters["cluster"] = cluster_name

        if namespace is not None:
            filters["namespace"] = namespace

        if len(security_risk_ids):
            filters["securityRiskID"] = ','.join(security_risk_ids)

        innerFilters = []
        if filters:
            innerFilters.append(filters)

        payload = {
            "innerFilters": innerFilters,
        }
        r = self.post(API_SECURITY_RISKS_CATEGORIES, params=params, json=payload, timeout=60)
        Logger.logger.info(r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_security_risks_categories "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_scan_status(self):
        params = {"customerGUID": self.selected_tenant_id}
        r = self.get(API_SCAN_STATUS, params=params)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get scan status "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_security_risks_list_uniquevalues(self, filters: dict, field):
        params = {"customerGUID": self.selected_tenant_id}

        innerFilters = []
        if filters:
            innerFilters.append(filters)

        payload = {
            "fields": {field: ""},
            "innerFilters": innerFilters,
            "pageNum": 1,
            "pageSize": 100,
        }
        r = self.post(API_SECURITY_RISKS_LIST_UNIQUEVALUES, params=params, json=payload, timeout=60)
        Logger.logger.info(r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get get_security_risks_list_uniquevalues "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_security_risks_resources(self, cluster_name=None, namespace=None, security_risk_id=None,
                                     exception_applied=True, resource_name=None, other_filters={}):
        params = {"customerGUID": self.selected_tenant_id}

        filters = {}

        if other_filters:
            filters = other_filters

        if cluster_name is not None:
            filters["cluster"] = cluster_name

        if namespace is not None:
            filters["namespace"] = namespace

        if security_risk_id is not None:
            filters["securityRiskID"] = security_risk_id

        if exception_applied:
            filters["exceptionApplied"] = "no,|empty"

        if resource_name is not None:
            filters["resourceName"] = resource_name

        innerFilters = []
        if filters:
            innerFilters.append(filters)

        payload = {
            "innerFilters": innerFilters,
        }
        r = self.post(API_SECURITY_RISKS_RESOURCES, params=params, json=payload, timeout=60)
        Logger.logger.info(r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_security_risks_resources "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_security_risks_trends(self, cluster_name=None, namespace=None, security_risk_ids=[]):
        params = {"customerGUID": self.selected_tenant_id}

        filters = {}

        if cluster_name is not None:
            filters["clusterShortName"] = cluster_name

        if namespace is not None:
            filters["namespace"] = namespace

        if security_risk_ids:
            filters["securityRiskID"] = ','.join(security_risk_ids)

        innerFilters = []
        if filters:
            innerFilters.append(filters)

        payload = {
            "innerFilters": innerFilters,
        }
        r = self.post(API_SECURITY_RISKS_TRENDS, params=params, json=payload, timeout=60)
        Logger.logger.info(r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_security_risks_trends "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def add_security_risks_exception(self, security_risk_id, exceptions_resources, reason):
        params = {"customerGUID": self.selected_tenant_id, "newapi": "true"}


        payload = {
            "policyIDs": [security_risk_id],
            "resources": exceptions_resources,
            "reason": reason,
            "policyType": "securityRiskExceptionPolicy"
        }

        r = self.post(API_SECURITY_RISKS_EXCEPTIONS_NEW, params=params, json=payload)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: add_security_risks_exception "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_security_risks_exceptions_list(self, cluster_name):
        params = {"customerGUID": self.selected_tenant_id, "newapi": "true"}

        payload = {
            "pageSize": 50,
            "pageNum": 1,
            "innerFilters": [
                {
                    # TODO: add support cluster filtering for exceptions list
                    "cluster": cluster_name
                }]
        }

        r = self.post(API_SECURITY_RISKS_EXCEPTIONS_LIST, params=params, json=payload)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_security_risks_exceptions_list "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    # edit security risks exception
    def put_security_risks_exception(self, exception_id, security_risk_id, exceptions_resources, reason):
        params = {"customerGUID": self.selected_tenant_id, "newapi": "true"}

        payload = {
            "guid": exception_id,
            "policyIDs": [security_risk_id],
            "resources": exceptions_resources,
            "reason": reason,
            "policyType": "securityRiskExceptionPolicy"

        }

        r = self.put(API_SECURITY_RISKS_EXCEPTIONS, params=params, json=payload)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: put_security_risks_exception "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

        return r

    def delete_security_risks_exception(self, exception_id):
        params = {"customerGUID": self.selected_tenant_id, "newapi": "true"}

        del_url = API_SECURITY_RISKS_EXCEPTIONS + "/" + exception_id

        r = self.delete(del_url, params=params)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: delete_security_risks_exception "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

        return r

    def get_runtime_incidents_rulesets(self, body = None):
        params = {"customerGUID": self.selected_tenant_id}

        if body is None:
            body = {"pageSize": 50, "pageNum": 1}

        Logger.logger.info("get_runtime_incidents_rulesets body: %s" % body)
        r = self.post(API_RUNTIME_INCIDENTSRULESET, params=params, json=body)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_runtime_incidents_rules "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_runtime_incident_types(self, body = None):
        params = {"customerGUID": self.selected_tenant_id}

        if body is None:
            body = {"pageSize": 50, "pageNum": 1}

        Logger.logger.info("get_runtime_incident_types body: %s" % body)
        r = self.post(API_RUNTIME_INCIDENTTYPES, params=params, json=body)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_runtime_incident_types "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r



    def get_runtime_policies_list(self, body = None):
        """
        payload example:

        {
        "pageSize": 50,
        "pageNum": 1,
        "innerFilters": [
            {
            "scope.designators.cluster": "arn-aws-eks-eu-west-1-015253967648-cluster-ca-terraform-eks-dev-stage"
            }
        ]
        }
        """
        params = {"customerGUID": self.selected_tenant_id}

        if body is None:
            body = {"pageSize": 50, "pageNum": 1}

        Logger.logger.info("get_runtime_policies_list body: %s" % body)
        r = self.post(API_RUNTIME_POLICIES_LIST, params=params, json=body)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_runtime_policies_list "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def delete_runtime_policies(self, body):
        params = {"customerGUID": self.selected_tenant_id}

        Logger.logger.info("delete_runtime_policies body: %s" % body)
        r = self.delete(API_RUNTIME_POLICIES, params=params, json=body)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: delete_runtime_policies "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r


    def new_runtime_policy(self, body):
        """
        mandatory fields: name, ruleSetType (Custom or Managed)

        if "ruleSetType": "Managed" then you have to have at least 1 ruleset

        example:
        {
            "name": "Malware-new",
            "description": "Default Malware RuleSet",
            "enabled": true,
            "scope": {"riskFactors":["Internet facing"],"designators":[{"cluster":"bla"}]},
            "ruleSetType": "Managed",
            "managedRuleSetIDs": [
                "c9fe6345-c393-4595-bd7b-22110dbafe62"
            ],
            "notifications": [],
            "actions": []
        }
        """
        params = {"customerGUID": self.selected_tenant_id}

        Logger.logger.info("new_runtime_policy body: %s" % body)
        r = self.post(API_RUNTIME_POLICIES, params=params, json=body)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: new_runtime_policy "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def update_runtime_policy(self, body):

        """
        mandatory fields: guid, name, ruleSetType (Custom or Managed)

        if "ruleSetType": "Managed" then you have to have at least 1 ruleset

        {
            "guid": "093c28b1-894f-4aa2-a8b8-8ed71cb9ddf0",
            "name": "Malware-new",
            "description": "Default Malware RuleSet",
            "enabled": true,
            "scope": {"riskFactors":["Internet facing"],"designators":[{"cluster":"bla"}]},
            "ruleSetType": "Custom",
            "IncidentTypeIDs":["I001","I002"],
            "notifications": [],
            "actions": []
        }
        """
        params = {"customerGUID": self.selected_tenant_id}

        Logger.logger.info("update_runtime_policy body: %s" % body)

        r = self.put(API_RUNTIME_POLICIES, params=params, json=body)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: update_runtime_policy "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_runtime_policies_uniquevalues(self, body):
        params = {"customerGUID": self.selected_tenant_id}

        Logger.logger.info("get_runtime_policies_uniquevalues body: %s" % body)

        r = self.post(API_RUNTIME_POLICIES_UNIQUEVALUES, params=params, json=body)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_runtime_policies_uniquevalues "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def get_integration_status(self, provider: str):
        url = API_INTEGRATIONS + "/connectionV2/status"
        r = self.get(url, params={"customerGUID": self.selected_tenant_id, "provider": provider})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_jira_config(self):
        url = API_INTEGRATIONS + "/jira/configV2"
        r = self.get_with_rate_limit(url, params={"customerGUID": self.selected_tenant_id})
        assert 200 <= r.status_code < 300, f"{inspect.currentframe().f_code.co_name}, url: '{url}', customer: '{self.customer}' code: {r.status_code}, message: '{r.text}'"
        return r.json()

    def get_jira_collaboration_guid_by_site_name(self, site_name: str):
        config = self.get_jira_config()
        jira_connections = config.get("jiraConnections", [])
        if not jira_connections:
            raise Exception("No Jira connections found in the response")

        for connection in jira_connections:
            selected_site = connection.get("selectedSite", {})
            if selected_site.get("name") == site_name:
                collabGUID = connection.get("jiraCollabGUID", "")
                if collabGUID:
                    return collabGUID
                else:
                    raise Exception(f"Jira collaboration GUID is empty or missing for site '{site_name}'")

        raise Exception(f"No Jira collaboration found for site '{site_name}'")

    def update_jira_config(self, body: dict):
        url = API_INTEGRATIONS + "/jira/configV2"
        r = self.post_with_ratelimit(url, params={"customerGUID": self.selected_tenant_id}, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing smart remediation. Request: results of posture resources highlights "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

    def search_jira_projects(self, body: dict):
        url = API_INTEGRATIONS + "/jira/projectsV2/search"
        r = self.post_with_ratelimit(url, params={"customerGUID": self.selected_tenant_id}, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request to: %s "%s" (code: %d, message: %s)' % (
                    url, self.customer, r.status_code, r.text))
        return r.json()

    def search_jira_issue_types(self, body: dict):
        url = API_INTEGRATIONS + "/jira/issueTypesV2/search"
        r = self.post_with_ratelimit(url, params={"customerGUID": self.selected_tenant_id}, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request to: %s "%s" (code: %d, message: %s)' % (
                    url, self.customer, r.status_code, r.text))
        return r.json()

    def search_jira_schema(self, body: dict):
        url = API_INTEGRATIONS + "/jira/issueTypesV2/schema/search"
        r = self.post_with_ratelimit(url, params={"customerGUID": self.selected_tenant_id}, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request to: %s "%s" (code: %d, message: %s)' % (
                    url, self.customer, r.status_code, r.text))
        return r.json()

    def search_jira_issue_field(self, body: dict):
        url = API_INTEGRATIONS + "jira/issueTypes/fields/search"
        r = self.post_with_ratelimit(url, params={"customerGUID": self.selected_tenant_id}, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request to: %s "%s" (code: %d, message: %s)' % (
                    url, self.customer, r.status_code, r.text))
        return r.json()

    def create_jira_issue(self, body: dict):
        url = API_INTEGRATIONS + "/jira/issueV2"
        r = self.post_with_ratelimit(url, params={"customerGUID": self.selected_tenant_id}, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request to: %s "%s" (code: %d, message: %s)' % (
                    url, self.customer, r.status_code, r.text))
        return r.json()

    def unlink_issue(self, guid: str):
        url = API_INTEGRATIONS + "/link/" + guid
        r = self.delete(url, params={"customerGUID": self.customer_guid})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request to: %s "%s" (code: %d, message: %s)' % (
                    url, self.customer, r.status_code, r.text))

    def get_seccomp_workloads_list(self, body: dict):
        params = {"customerGUID": self.selected_tenant_id}

        r = self.post(API_SECCOMP_LIST, params=params, json=body, timeout=60)
        Logger.logger.info("get_seccomp_workloads_list response text: %s" % r.text)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get seccomp workloads list "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def generate_seccomp_profile(self, body: dict):
        r = self.post(API_SECCOMP_GENERATE, params={"customerGUID": self.customer_guid},
                      json=body, timeout=60)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request to: %s "%s" (code: %d, message: %s)' % (
                    API_SECCOMP_GENERATE, self.customer, r.status_code, r.text))
        return r

    def get_workflows(self,  body=None, **kwargs):
        url = API_WORKFLOWS + "/list"
        if body is None:
            body = {
                        "pageSize": 150,
                        "pageNum": 1,
                        "orderBy": "updatedTime:desc"
                  }

        params = {"customerGUID": self.selected_tenant_id}
        if kwargs:
            params.update(**kwargs)
        r = self.post(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing workflows. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()



    def create_workflow(self, body):
        url = API_WORKFLOWS
        params = {"customerGUID": self.selected_tenant_id}
        r = self.post(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error creating workflow. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def delete_workflow(self, guid):
        url = API_WORKFLOWS
        params = {"customerGUID": self.selected_tenant_id}
        body = {
            "innerFilters": [
                {
                    "guid": guid
                }
            ]
        }
        r = self.delete(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error deleting workflow. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()



    def update_workflow(self, body):
        url = API_WORKFLOWS
        params = {"customerGUID": self.selected_tenant_id}
        r = self.put(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error updating workflow. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_teams_webhooks(self):
        url = API_TEAMS
        r = self.get(url, params={"customerGUID": self.selected_tenant_id})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing webhooks. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()


    def create_teams_webhook(self, body):
        url = API_TEAMS
        params = {"customerGUID": self.selected_tenant_id}
        r = self.post(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error creating webhook. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def delete_teams_webhook(self, body):
        url = API_TEAMS
        params = {"customerGUID": self.selected_tenant_id}
        r = self.delete(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error deleting webhook. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def update_teams_webhook(self, body):
        url = API_TEAMS
        params = {"customerGUID": self.selected_tenant_id}
        r = self.put(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error updating webhook. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def test_teams_webhook_message(self, body):
        params = {"customerGUID": self.selected_tenant_id}
        r = self.post(API_TEAMS_TEST_MESSAGE, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error testing webhook. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()


    def get_webhooks(self):
        url = API_WEBHOOKS
        r = self.get(url, params={"customerGUID": self.selected_tenant_id})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing webhooks. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()


    def create_webhook(self, body, testWebhook=True):
        url = API_WEBHOOKS
        params = {"customerGUID": self.selected_tenant_id}

        if not testWebhook:
            params["testWebhook"] = False
    
        r = self.post(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error creating webhook. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def delete_webhook(self, body):
        url = API_WEBHOOKS
        params = {"customerGUID": self.selected_tenant_id}
        r = self.delete(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error deleting webhook. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def update_webhook(self, body):
        url = API_WEBHOOKS
        params = {"customerGUID": self.selected_tenant_id}
        r = self.put(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error updating webhook. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def test_webhook_message(self, body):
        params = {"customerGUID": self.selected_tenant_id}
        r = self.post(API_WEBHOOKS_TEST_MESSAGE, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error testing webhook. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()
    
    def get_cspm_link(self, region : str, external_id : bool = False):
        url = API_ACCOUNTS_CSPM_LINK
        body = {
            "featureNames": ["cspm"]    
        }
        r = self.post(url, params={"customerGUID": self.selected_tenant_id, "region": region, "withExternalID": external_id}, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing CSPM link. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()
    
    def get_cspm_members_org_link(self, region, org_guid , feature_names : List[str], generate_external_id : bool = False):
        url = API_ACCOUNTS_CSPMM_MEMBERS_ORG_LINK + "?region=" + region + "&orgGUID=" + org_guid +"&generateExternalID=" + str(generate_external_id).lower()
        body = {
            "featureNames" : feature_names
        }
        r = self.post(url, params={"customerGUID": self.selected_tenant_id}, json=body  )
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing CSPM org link. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_cspm_admin_org_link(self, region, org_guid):
        #TODO: implement
        return
       
    def get_cadr_link(self, region, cloud_account_guid):
        url = API_ACCOUNTS_CADR_LINK + "?region=" + region + "&cloudAccountGUID=" + cloud_account_guid
        r = self.get(url, params={"customerGUID": self.selected_tenant_id})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing CADR link. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_cadr_org_link(self, region, org_guid):
        url = API_ACCOUNTS_CADR_ORG_LINK + "?region=" + region + "&orgGUID=" + org_guid
        r = self.get(url, params={"customerGUID": self.selected_tenant_id})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing CADR org link. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()


    def delete_accounts_feature(self, account_guid, feature_name):
        url = API_ACCOUNTS_DELETE_FEATURE
        params = {"customerGUID": self.selected_tenant_id}
        body = {
            "guid": account_guid,
            "featureNames": [feature_name]
        }
        r = self.delete(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error deleting account feature. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_cloud_accounts(self,  body=None, **kwargs):
        url = API_ACCOUNTS_CLOUD_LIST
        if body is None:
            body = {"pageSize": 150, "pageNum": 1}

        params = {"customerGUID": self.selected_tenant_id}
        if kwargs:
            params.update(**kwargs)
        r = self.post(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing cloud accounts. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_kubernetes_accounts(self,  body=None, **kwargs):
        url = API_ACCOUNTS_KUBERNETES_LIST
        if body is None:
            body = {"pageSize": 150, "pageNum": 1}

        params = {"customerGUID": self.selected_tenant_id}
        if kwargs:
            params.update(**kwargs)
        r = self.post(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing cloud accounts. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()


    def get_cloud_accounts_uniquevalues(self, body):
        params = {"customerGUID": self.selected_tenant_id}

        Logger.logger.info("get_cloud_accounts_uniquevalues body: %s" % body)

        r = self.post(API_UNIQUEVALUES_ACCOUNTS_CLOUD, params=params, json=body)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_cloud_accounts_uniquevalues "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_kubernetes_accounts_uniquevalues(self, body):
        params = {"customerGUID": self.selected_tenant_id}

        Logger.logger.info("get_kubernetes_accounts_uniquevalues body: %s" % body)

        r = self.post(API_UNIQUEVALUES_ACCOUNTS_KUBERNETES, params=params, json=body)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get_kubernetes_accounts_uniquevalues "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def create_cloud_account(self, body, provider):
        url = API_ACCOUNTS
        params = {"customerGUID": self.selected_tenant_id,
                  "provider": provider}
        r = self.post(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error creating cloud account. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def delete_cloud_account(self, guid):
        url = API_ACCOUNTS
        params = {"customerGUID": self.selected_tenant_id}
        body = {
            "innerFilters": [
                {
                    "guid": guid
                }
            ]
        }
        r = self.delete(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error deleting cloud account. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()



    def update_cloud_account(self, body, provider):
        url = API_ACCOUNTS
        params = {"customerGUID": self.selected_tenant_id,
                  "provider": provider}
        r = self.put(url, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error updating cloud account. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()


    def get_aws_regions(self):
        url = API_ACCOUNTS_AWS_REGIONS
        r = self.get(url, params={"customerGUID": self.selected_tenant_id})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing AWS regions. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_aws_regions_details(self):
        url = APT_ACCOUNTS_AWS_REGIONS_DETAILS
        r = self.get(url, params={"customerGUID": self.selected_tenant_id})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing AWS regions details. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_cloud_severity_count(self):
        url = API_CLOUD_COMPLIANCE_SEVERITY_COUNTS
        r = self.get(url, params={"customerGUID": self.selected_tenant_id})
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing AWS regions. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_cloud_compliance_account(self,body):
        url = API_CLOUD_COMPLIANCE_ACCOUNTS
        r = self.post(url, params={"customerGUID": self.selected_tenant_id},json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing account api "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_cloud_compliance_framework(self,body):
        url = API_CLOUD_COMPLIANCE_FRAMEWORKS
        r = self.post(url, params={"customerGUID": self.selected_tenant_id}, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error getting framework. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))

        return r.json()

    def get_cloud_compliance_framework_over_time(self,body):
        url = API_CLOUD_COMPLIANCE_FRAMEWORKS_OVER_TIME
        r = self.post(url, params={"customerGUID": self.selected_tenant_id}, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error getting framework over time. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_cloud_compliance_controls(self,body,with_rules:bool):
        url = API_CLOUD_COMPLIANCE_CONTROLS
        r = self.post(url, params={"customerGUID": self.selected_tenant_id ,"includeRules" : with_rules} , json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error getting controls. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_cloud_compliance_rules(self,body):
        url = API_CLOUD_COMPLIANCE_RULES
        r = self.post(url, params={"customerGUID": self.selected_tenant_id} , json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error getting rules. Customer: "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

    def get_cloud_compliance_resources(self,rule_hash,body):
        url = API_CLOUD_COMPLIANCE_RESOURCES

        if rule_hash is not None:
            r = self.post(url, params={"customerGUID": self.selected_tenant_id,
                                        "ruleHash": rule_hash} , json=body)
            if not 200 <= r.status_code < 300:
                raise Exception(
                    'Error getting resources. Customer: "%s" (code: %d, message: %s)' % (
                        self.customer, r.status_code, r.text))
            return r.json()
        else:
            r = self.post(url, params={"customerGUID": self.selected_tenant_id} , json=body)
            if not 200 <= r.status_code < 300:
                raise Exception(
                    'Error getting resources. Customer: "%s" (code: %d, message: %s)' % (
                        self.customer, r.status_code, r.text))
            return r.json()

    def create_cspm_exception_req(self, payload:str):
        """
        Add a new CSPM exception policy.
        
        Args:
            payload (str) the body of the create request
        """
        params = {"customerGUID": self.selected_tenant_id}

        r = self.post(API_CLOUD_COMPLIANCE_EXCEPTIONS_NEW, params=params, json=payload)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: add_cspm_exception "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def create_cspm_exception(self, rule_hashes: List[str], accounts: List[str] = None, resource_hashes: List[str] = None, reason: str = ""):
        """
        Create CSPM exceptions with flexible account and resource targeting.
        
        Args:
            rule_hashes (List[str]): List of rule hashes (policy GUIDs) to create exceptions for
            accounts (List[str], optional): List of account IDs. If None, applies to all accounts (*/*).
            resource_hashes (List[str], optional): List of resource hashes. If None, applies to all resources (*/*).
            reason (str, optional): Reason for creating the exception.

        Examples:
            # Exception for all accounts and all resources
            create_cspm_exception(["rule-hash-1"])

            # Exception for specific accounts but all their resources
            create_cspm_exception(["rule-hash-1"], accounts=["account-1", "account-2"])

            # Exception for specific accounts and specific resources
            create_cspm_exception(["rule-hash-1"], accounts=["account-1"], resource_hashes=["resource-1"])
        """

        assert accounts is not None and len(accounts) > 0, "got 0 accounts, cannot open exception on 0 account - need at least 1"

        resources = []
        for account in accounts:
            # If no specific resources, apply to all resources in the account
            if not resource_hashes:
                resources.append({
                    "designatorType": "Attribute",
                    "attributes": {
                        "account": account,
                        "resourceHash": "*/*"
                    }
                })
            # If specific resources, create an entry for each account-resource combination
            else:
                for resource_hash in resource_hashes:
                    resources.append({
                        "designatorType": "Attribute",
                        "attributes": {
                            "account": account,
                            "resourceHash": resource_hash
                        }
                    })

        #build requeest body
        payload = {
            "policyIDs": rule_hashes,
            "resources": resources,
            "reason": reason,
            "policyType": "cspmExceptionPolicy"
        }

        return self.create_cspm_exception_req(payload=payload)

    def delete_cspm_exception(self, exception_guid: str):
        """
        Delete a CSPM exception by its GUID.

        Args:
            exception_guid (str): The GUID of the exception to delete
        """
        url = f"{API_CLOUD_COMPLIANCE_EXCEPTIONS}/{exception_guid}"
        r = self.delete(url, params={"customerGUID": self.selected_tenant_id})

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error deleting CSPM exception. Request: delete_cspm_exception "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r
        
    def update_cspm_exception(self, payload:str):
        """
        Update an existing CSPM exception.
        
        Args:
            exception_guid (str): The GUID of the exception to update
            policy_ids (List[str]): List of policy IDs for the exception
            resources (List[Dict]): List of resources to apply the exception to. Each resource should have:
                                  - designatorType: str (e.g. "Attribute")
                                  - attributes: Dict with account and resourceHash
            reason (str): Reason for the exception (optional)
        """
       
        r = self.put(API_CLOUD_COMPLIANCE_EXCEPTIONS, params={"customerGUID": self.selected_tenant_id}, json=payload)

        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error updating CSPM exception. Request: update_cspm_exception "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def update_cspm_exception_resources(self, exception_guid: str, rule_hash: str, accounts: List[str] = None, resource_hashes: List[str] = None, reason: str = ""):
        """
        Update the resources of an existing CSPM exception with a more user-friendly interface.
        
        Args:
            exception_guid (str): The GUID of the exception to update
            rule_hash (str): The rule hash (policy GUID) for the exception
            accounts (List[str], optional): List of account IDs. If None, applies to all accounts (*/*).
            resource_hashes (List[str], optional): List of resource hashes. If None, applies to all resources (*/*).
            reason (str, optional): Reason for the exception.
            
        Examples:
            # Update to apply to all resources in an account
            update_cspm_exception_resources("exception-guid", "rule-hash", accounts=["account-1"])
            
            # Update to apply to specific resources
            update_cspm_exception_resources(
                "exception-guid",
                "rule-hash",
                accounts=["account-1"],
                resource_hashes=["resource-1", "resource-2"]
            )
            
            # Update to apply to all accounts and resources
            update_cspm_exception_resources("exception-guid", "rule-hash")
        """

        assert accounts is not None and len(accounts) > 0, "got 0 accounts, cannot open exception on 0 account - need at least 1"

        resources = []
        for account in accounts:
            # If no specific resources, apply to all resources in the account
            if not resource_hashes:
                resources.append({
                    "designatorType": "Attribute",
                    "attributes": {
                        "account": account,
                        "resourceHash": "*/*"
                    }
                })
            # If specific resources, create an entry for each account-resource combination
            else:
                for resource_hash in resource_hashes:
                    resources.append({
                        "designatorType": "Attribute",
                        "attributes": {
                            "account": account,
                            "resourceHash": resource_hash
                        }
                    })

        #build requeest body
        payload = {
            "guid": exception_guid,
            "policyIDs": [rule_hash],
            "resources": resources,
            "reason": reason,
            "policyType": "cspmExceptionPolicy"
        }


        return self.update_cspm_exception(
            payload=payload
        )

    def cspm_scan_now(self, cloud_account_guid: str) -> requests.Response:
        """
        Trigger an immediate CSPM scan for a specific cloud account.

        Args:
            cloud_account_guid (str): The GUID of the cloud account to scan

        Returns:
            requests.Response: The response from the API
        """
        params = {"customerGUID": self.selected_tenant_id}
        body = {
            "innerFilters": [
                {
                    "cloudAccountGUID": cloud_account_guid
                }
            ]
        }

        r = self.post(API_CLOUD_COMPLIANCE_SCAN_NOW, params=params, json=body)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error triggering CSPM scan. Request: scan now "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r

    def create_runtime_exception(self, policy_ids: List[str], resources: List[Dict], reason: str = "", advanced_scopes: Optional[List[Dict]] = None) -> dict:
        """
        Create a new runtime exception
        Args:
            policy_ids: List of policy IDs to create exception for
            resources: List of resources to apply the exception to
            reason: Reason for the exception
            advanced_scopes: Optional advanced scopes for the exception
        Returns:
            Response from the API
        Example:
            "resources":[{"designatorType":"Attribute",
            "attributes":{"cluster":"do-fra1-k8s-1-32-1-do-0-fra1-amit-demo",
            "namespace":"systest-ns-mli2","name":"redis-sleep","kind":"Deployment"}}]
            "advancedScopes":[{"entity": "process.name",
            "condition": "in",
            "values": "python, firefox"}]
        """
        payload = {
            "policyIDs": policy_ids,
            "reason": reason,
            "policyType": "runtimeIncidentExceptionPolicy",
            "resources": resources,
            "createdBy": "shanyl@armosec.io"
        }
        if advanced_scopes:
            payload["advancedScopes"] = advanced_scopes
            
        response = self.post(f"{API_RUNTIME_EXCEPTION_NEW}", json=payload)
        assert 200 <= response.status_code < 300, f"Failed to create runtime exception, got {response.status_code}"
        return response.json()

    def delete_runtime_exception(self, exception_id: str) -> requests.Response:
        """
        Delete a runtime exception
        Args:
            exception_id: ID of the exception to delete
        Returns:
            Response from the API
        """
        response = self.delete(f"{API_RUNTIME_EXCEPTION}/{exception_id}")
        assert 200 <= response.status_code < 300, f"Failed to delete runtime exception, got {response.status_code}"
        return response.json()

    def get_runtime_exceptions(self, filters: Dict = None) -> requests.Response:
        """
        Get list of runtime exceptions
        Args:
            filters: Optional filters to apply to the request
        Returns:
            Response from the API containing list of exceptions
        """
        params = {}
        if filters:
            params.update(filters)
        response = self.get(f"{API_RUNTIME_EXCEPTION}", params=params)
        assert 200 <= response.status_code < 300, f"Failed to get runtime exceptions, got {response.status_code}"
        return response.json()

    def list_runtime_exceptions(self, filters: List[Dict] = [{}]) -> requests.Response:
        """
        Get list of runtime exceptions
        Args:
            filters: Optional filters (inner filters) to apply to the request
        Returns:
            Response from the API containing list of exceptions
        """
        payload = {
            "innerFilters": filters
        }

        response = self.post(f"{API_RUNTIME_EXCEPTION_LIST}", json=payload)
        assert 200 <= response.status_code < 300, f"Failed to get list of runtime exceptions, got {response.status_code}"
        return response.json()

    def get_helm(self):

        r = self.get(API_COMMAND_HELM)
        if not 200 <= r.status_code < 300:
            raise Exception(
                'Error accessing dashboard. Request: get helm "%s" (code: %d, message: %s)' % (
                    self.customer, r.status_code, r.text))
        return r.json()

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

class EventReceiver(object):
    def __init__(self,  server: str, customer_guid: str, api_key: str):
        self.server = server
        self.customer_guid = customer_guid
        self.api_key = api_key
    
    def post_cdr_alerts(self, cdr_alerts: dict):
        response = requests.post(f"{self.server}{POST_CDR_ALERTS}", json=cdr_alerts, headers={"X-API-KEY": self.api_key}, params={"customerGUID": self.customer_guid})
        assert 200 <= response.status_code < 300, f"Failed to send cdr alerts, got {response.status_code}"
        return response

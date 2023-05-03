
# BACKEND API OBJECT (ControlPanelAPI)

The [backend api component](/infrastructure/backend_api.py) is used to authenticate and interact with the different backend APIs environments.

## ENVIRONMENTS

The different environments are configured in the [backends object](/configurations/system/backends.py).

Supported environments:

<u>FrontEgg supported</u> - development-egg, staging-egg, production-egg (requires api keys system-tests configurations and full test)

<u>FrontEgg unsupported</u> - development, staging, production

<u>local environment (typcally http://localhost:7666)</u> - local


## AUTHENTICATION

Backend API use the [api login object](/infrastructure/api_login.py) for authentication.

There are 3 authentication methods supported:

1. <u>FrontEgg API keys</u> (Class: FrontEggSecretAPILogin)
   
   Authenticating directly against frontEgg using API client_id and secret (login_method=LOGIN_METHOD_FRONTEGG_SECRET).

   Supported only in frontegg envs

2. <u>KeyCloak</u> (Class: KeycloakAPILogin)
   
   Authenticating using keyclock (login_method=LOGIN_METHOD_KEYCLOAK).

   Supports all enviroments.


3. <u>FrontEgg username and password / customer guid *</u>  
   (Class: FrontEggUsernameAPILogin)

   Authenticating using username and password or customer_guid if configured in AllowedAnyCustomer (login_method=LOGIN_METHOD_FRONTEGG_USERNAME).
   
   <b>*Not fully supported, required further tests.</b>



## API ACCESS CUSTOMERS MANAGEMENT

Backend api object holds information about 2 types of customers: login_customer and selected_customer.

### login customer

This is the customer guid the authentication has been made for on backend API object construction. This customer guid is prefered to have access to [admin apis](#admin-apis) for full utillization of backend api. 

Backend API Attributes associated with login customer:

<u>login_customer_cookie</u> - the login customer cookie.

<u>login_customer_guid</u> - the login customer guid.

### selected customer

This is the selected customer on which all APIs are executed against by default (besides admin apis which are always perfomed using the login_customer). If not actively selected, default values equal to the login customer.

<u>selected_customer_cookie</u> - the selected customer cookie (default: login_customer_cookie).

<u>selected_customer_guid</u> - the selected customer guid (default: login_customer_guid)


## Admin APIs

Admin apis are apis that can be accessed only by a customer guid that is configured in backend AllowedAnyCustomer. Admin apis allow us to perform actions that are not allowed for a regular user. Admin prefix is <i>"/api/v1/admin/"</i>.

When making an API request, the API is checked if it is an admin api and if send the login_customer_cookie.

In case test requires admin apis access, login_customer_guid must be configured in AllowedAnyCustomer in backend config for all the relevant enviroments.

```json
"AllowedAnyCustomer": [ {
        "customerGuid": "CUSTOMER_GUID",
      }],
```


## TENANTS MANAGEMENT

Backend api object supports the creation and running tests against a specific tenant (selected_customer) that is not the login_customer_guid. 

This allows test isolation for a specifc tenant which can be easily deleted once test is concluded.

In order to populate the selected_customer, best practice will be to first create it and then "select" it:

```go
res, test_tenant_id = self.backend.create_tenant(tenantName)
self.backend.select_customer(test_tenant_id)
```

Once the customer is selected, all apis calls will use it's cookie (selected_customer_cookie), unless it is an admin api which uses the login_customer_cookie.

At the end of the test, need to delete the selected customer:

```go
self.backend.delete_tenant(tenant_id)
```

For safety purposes, it is not allowed to delete the login_customer_guid (if attempted, exeption will be raised)



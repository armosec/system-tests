import base64
from slack_sdk import WebClient
import requests
from datetime import datetime
from systest_utils import Logger
import os
import requests
from requests.auth import HTTPBasicAuth
import time






# tests constants
NOTIFICATIONS_SVC_DELAY_FIRST_SCAN = 4 * 60
NOTIFICATIONS_SVC_DELAY = 7 * 60

# severity levels
SEVERITIES_CRITICAL = ["Critical"]
SEVERITIES_HIGH = ["High"]
SEVERITIES_MEDIUM = ["Medium"]

# workflow names
WORKFLOW_NAME = "system_test_workflow"
UPDATED_WORKFLOW_NAME = "system_test_workflow_updated"

SECURITY_RISKS_WORKFLOW_NAME_TEAMS = "security_risks_workflow_teams_"
SECURITY_RISKS_WORKFLOW_NAME_SLACK = "security_risks_workflow_slack_"
SECURITY_RISKS_WORKFLOW_NAME_JIRA = "security_risks_workflow_jira_"

VULNERABILITIES_WORKFLOW_NAME_TEAMS = "vulnerabilities_workflow_teams_"
VULNERABILITIES_WORKFLOW_NAME_SLACK = "vulnerabilities_workflow_slack_"
VULNERABILITIES_WORKFLOW_NAME_JIRA = "vulnerabilities_workflow_jira_"


COMPLIANCE_WORKFLOW_NAME_TEAMS = "compliance_workflow_teams_"
COMPLIANCE_WORKFLOW_NAME_SLACK = "compliance_workflow_slack_"
SYSTEM_HEALTH_WORKFLOW_NAME_SLACK = "system_health_workflow_slack_"

# channel provider names
SLACK_CHANNEL_NAME = "system_tests_slack"
TEAMS_CHANNEL_NAME = "system_tests_teams"
JIRA_PROVIDER_NAME = "jira"


# expected responses
EXPECTED_CREATE_RESPONSE = "Workflow created"
EXPECTED_UPDATE_RESPONSE = "Workflow updated"
EXPECTED_DELETE_RESPONSE = "Workflow deleted"

# categories
SECURITY_RISKS = "SecurityRisks"
VULNERABILITIES = "Vulnerability"
COMPLIANCE = "Compliance"
SYSTEM_HEALTH = "SystemHealth"
SECURITY_RISKS_ID = "R_0007"

# webhooks
WEBHOOK_NAME = "system_test_webhook_"


def get_access_token():
    url = "https://login.microsoftonline.com/50a70646-52e3-4e46-911e-6ca1b46afba3/oauth2/v2.0/token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    body = {
        'grant_type': 'client_credentials',
        'client_id': get_env("MS_TEAMS_CLIENT_ID"),
        'client_secret': get_env("MS_TEAMS_CLIENT_SECRET"),
        'scope': 'https://graph.microsoft.com/.default'
    }
    response = requests.post(url, headers=headers, data=body)
    return response.json().get('access_token')


def get_messages_from_teams_channel(before_test):
    before_test_utc = datetime.utcfromtimestamp(before_test).isoformat() + "Z"
    endpoint = f'https://graph.microsoft.com/v1.0/teams/{get_env("TEAMS_ID")}/channels/{get_env("CHANNEL_ID")}' \
               f'/messages/delta?$filter=lastModifiedDateTime gt {before_test_utc}'
    headers = {
        'Authorization': 'Bearer ' + get_access_token(),
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    messages = []
    while endpoint:
        response = requests.get(endpoint, headers=headers)
        data = response.json()
        messages.extend(data.get('value', []))
        endpoint = data.get('@odata.nextLink')  # Set the endpoint to the next page link if present
    return messages



def get_messages_from_slack_channel(before_test):
    formatted_time = format(before_test, ".6f")
    Logger.logger.info(f'Attempting to read messages from slack before timestamp {formatted_time}')
    
    client = WebClient(token=get_env("SLACK_SYSTEM_TEST_TOKEN"))
    channel_id = get_env("SLACK_CHANNEL_ID")
    
    messages = []
    cursor = None

    while True:
        result = client.conversations_history(
            channel=channel_id, 
            oldest=formatted_time,
            limit=200,  # Adjust based on your needs (max is 200)
            cursor=cursor
        )
        
        if result and isinstance(result.data, dict) and 'messages' in result.data:
            messages.extend(result.data['messages'])

            cursor = result.data.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                break  # No more pages to fetch
        else:
            Logger.logger.info("No 'messages' key found in the result.")
            break  # Stop if response is not as expected

    return messages
    

def get_tickets_from_jira_channel(before_test):

    token = get_env("JIRA_API_TOKEN")
    email = get_env("JIRA_EMAIL")
    project_id = get_env("JIRA_PROJECT_ID")
    server = f"https://{get_env('JIRA_SITE_NAME')}.atlassian.net"


    # Calculate 5 minutes before the given timestamp
    before_test_minus_5 = before_test - (5 * 60)  # Subtract 5 minutes (300 seconds)

    # Format the new timestamp for Jira JQL
    formatted_date = time.strftime('%Y-%m-%d %H:%M', time.gmtime(before_test_minus_5))


    url = f"{server}/rest/api/3/search"

    auth = HTTPBasicAuth(email, token)

    # headers = {
    #     "Accept": "application/json"
    # }

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Basic {base64.b64encode(f'{email}:{token}'.encode()).decode()}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    # JQL to fetch issues updated before the specified time
    jql = f'project = "{project_id}" AND created > "{formatted_date}"'

    params = {
        "jql": jql,
        "maxResults": 100,  # Adjust this to control the number of issues per page
        "fields": "summary,created,description",  # Specify the fields you want to retrieve
        "startAt": 0
    }

    all_issues = []

    while True:
        response = requests.get(url, headers=headers, auth=auth, params=params)

        assert response.status_code == 200, f"Failed to fetch issues from Jira. params: {params}, response: {response.text}, error: {response.status_code}"

        data = response.json()
        all_issues.extend(data.get("issues", []))

        # Check if there are more issues to fetch
        if data.get("startAt", 0) + data.get("maxResults", 0) >= data.get("total", 0):
            break

        # Update startAt for pagination
        params["startAt"] += data["maxResults"]
    
    return all_issues
    
def enrich_slack_alert_channel(data):
    data["channel"]["context"]["channel"]["id"] = get_env("SLACK_CHANNEL_ID")

def enrich_teams_alert_channel(data):
    data["channel"]["context"]["webhook"]["id"] = get_env("CHANNEL_WEBHOOK")


def extract_text_from_adf(adf):
    """ Recursively extract text from Jira's Atlassian Document Format (ADF) """
    if isinstance(adf, str):
        return adf
    elif isinstance(adf, dict):
        if adf.get("text"):  # Direct text
            return adf["text"]
        elif "content" in adf:  # Nested content
            return " ".join(extract_text_from_adf(item) for item in adf["content"] if item)
    elif isinstance(adf, list):
        return " ".join(extract_text_from_adf(item) for item in adf if item)
    return ""

def mask_value(value):
    if len(value) <= 3:
        return "***"
    return value[:3] + '*' * (len(value) - 6) + value[-3:]


def get_env(env_var_name):
    value = os.getenv(env_var_name)
    if value is not None:
        masked_value = mask_value(value)
        Logger.logger.info(f"Environment variable '{env_var_name}' retrieved with value: {masked_value}")
    else:
        Logger.logger.info(f"Environment variable '{env_var_name}' not found.")
    return value
from slack_sdk import WebClient
import requests
from datetime import datetime
from systest_utils import Logger
import os





# tests constants
NOTIFICATIONS_SVC_DELAY_FIRST_SCAN = 7 * 60
NOTIFICATIONS_SVC_DELAY = 7 * 60

# severity levels
SEVERITIES_CRITICAL = ["Critical"]
SEVERITIES_HIGH = ["High"]

# workflow names
WORKFLOW_NAME = "system_test_workflow"
UPDATED_WORKFLOW_NAME = "system_test_workflow_updated"
SECURITY_RISKS_WORKFLOW_NAME_TEAMS = "security_risks_workflow_teams"
SECURITY_RISKS_WORKFLOW_NAME_SLACK = "security_risks_workflow_slack"
SECURITY_RISKS_WORKFLOW_NAME_JIRA = "security_risks_workflow_jira"
VULNERABILITIES_WORKFLOW_NAME_TEAMS = "vulnerabilities_workflow_teams"
VULNERABILITIES_WORKFLOW_NAME_SLACK = "vulnerabilities_workflow_slack"
VULNERABILITIES_WORKFLOW_NAME_JIRA = "vulnerabilities_workflow_jira"
COMPLIANCE_WORKFLOW_NAME_TEAMS = "compliance_workflow_teams"
COMPLIANCE_WORKFLOW_NAME_SLACK = "compliance_workflow_slack"

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
SECURITY_RISKS_ID = "R_0017"


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
    response = requests.get(endpoint, headers=headers)
    return response.json().get('value', [])


def get_messages_from_slack_channel(before_test):
    formatted_time = format(before_test, ".6f")
    Logger.logger.info('Attempting to read messages from slack before timestamp ' + formatted_time)
    client = WebClient(token=get_env("SLACK_SYSTEM_TEST_TOKEN"))
    result = client.conversations_history(channel=f'{get_env("SLACK_CHANNEL_ID")}', oldest=formatted_time)
    if result is not None and isinstance(result.data, dict) and 'messages' in result.data:
        return result.data['messages']
    else:
        Logger.logger.info("No 'messages' key found in the result.")
        return []
    
def enrich_slack_alert_channel(data):
    data["channel"]["context"]["channel"]["id"] = get_env("SLACK_CHANNEL_ID")

def enrich_teams_alert_channel(data):
    data["channel"]["context"]["webhook"]["id"] = get_env("CHANNEL_WEBHOOK")



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
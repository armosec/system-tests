from slack_sdk import WebClient
import requests
from datetime import datetime
from systest_utils import Logger
import os
import requests
from requests.auth import HTTPBasicAuth
from typing import Dict, Any, List, Optional
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
SYSTEM_HEALTH_WORKFLOW_NAME_TEAMS = "system_health_workflow_teams_"

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
    

def get_tickets_from_jira_channel(
    before_test: int,
    cluster: str,
) -> List[Dict[str, Any]]:
    token = get_env("JIRA_API_TOKEN")
    email = get_env("JIRA_EMAIL")
    project_id = get_env("JIRA_PROJECT_ID")
    site_name = get_env("JIRA_SITE_NAME")
    issue_type = get_env("JIRA_ISSUE_TYPE_ID")

    Logger.logger.debug(f"Jira auth/site - Email: {email}, Token: {'***' if token else 'None'}, Site: {site_name}, Project: {project_id}, IssueType: {issue_type}")

    missing = [name for name, val in [("JIRA_API_TOKEN", token), ("JIRA_EMAIL", email), ("JIRA_SITE_NAME", site_name), ("JIRA_PROJECT_ID", project_id), ("JIRA_ISSUE_TYPE_ID", issue_type)] if not val]
    if missing:
        raise Exception(f"Missing required Jira environment variables: {', '.join(missing)}")

    server = f"https://{site_name}.atlassian.net"

    before_test_minus_5 = before_test - 5 * 60
    formatted_date = time.strftime("%Y-%m-%d %H:%M", time.gmtime(before_test_minus_5))

    project_clause = f'project = {project_id}' if str(project_id).isdigit() else f'project = "{project_id}"'
    jql = f'{project_clause} AND issuetype = {issue_type} AND text ~ "{cluster}" AND created > "{formatted_date}" ORDER BY created ASC'

    search_url = f"{server}/rest/api/3/search/jql"
    auth = HTTPBasicAuth(email, token)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    fields = ["summary", "created", "description", "status", "key"]

    payload: Dict[str, Any] = {"jql": jql, "maxResults": 100, "fields": fields}

    all_issues: List[Dict[str, Any]] = []
    next_page_token: Optional[str] = None

    while True:
        if next_page_token:
            payload["nextPageToken"] = next_page_token
        else:
            payload.pop("nextPageToken", None)

        resp = requests.post(search_url, headers=headers, auth=auth, json=payload, timeout=30)

        if resp.status_code == 429:
            retry = int(resp.headers.get("Retry-After", "5"))
            time.sleep(min(max(retry, 1), 60))
            continue

        if not resp.ok:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            error_msg = f"Jira search failed: {resp.status_code}, detail: {detail}"
            Logger.logger.error(error_msg)
            raise Exception(error_msg)

        data = resp.json()
        
        # Check for authentication/authorization errors in response body
        if "errorMessages" in data:
            error_msg = f"Jira API error: {data['errorMessages']}"
            Logger.logger.error(error_msg)
            raise Exception(error_msg)

        if "errors" in data and data["errors"]:
            error_msg = f"Jira API errors: {data['errors']}"
            Logger.logger.error(error_msg)
            raise Exception(error_msg)
        
        issues = data.get("issues", [])
        all_issues.extend(issues)

        Logger.logger.debug(f"Retrieved {len(issues)} issues in this page; total so far: {len(all_issues)}")

        next_page_token = data.get("nextPageToken")
        is_last = data.get("isLast", next_page_token is None)
        if is_last or not next_page_token:
            break

    Logger.logger.info(f"Successfully retrieved {len(all_issues)} issues")
    return all_issues


def get_jira_ticket_by_id(issue_id: str, site_name: str = "cyberarmor-io") -> Dict[str, Any]:
    """Get a specific Jira ticket by its ID using direct Jira API."""
    token = get_env("JIRA_API_TOKEN")
    email = get_env("JIRA_EMAIL")
    
    if not token or not email:
        raise Exception("Missing JIRA_API_TOKEN or JIRA_EMAIL environment variables")
    
    server = f"https://{site_name}.atlassian.net"
    url = f"{server}/rest/api/3/issue/{issue_id}"
    auth = HTTPBasicAuth(email, token)
    headers = {"Accept": "application/json"}
    
    resp = requests.get(url, headers=headers, auth=auth, timeout=30)
    
    if not resp.ok:
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        error_msg = f"Failed to get Jira ticket {issue_id}: {resp.status_code}, detail: {detail}"
        Logger.logger.error(error_msg)
        raise Exception(error_msg)
    
    data = resp.json()
    
    # Check for authentication/authorization errors in response body
    if "errorMessages" in data:
        error_msg = f"Jira API error: {data['errorMessages']}"
        Logger.logger.error(error_msg)
        raise Exception(error_msg)

    if "errors" in data and data["errors"]:
        error_msg = f"Jira API errors: {data['errors']}"
        Logger.logger.error(error_msg)
        raise Exception(error_msg)
    
    return data
    
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
import inspect
from .structures import TestConfiguration
from systest_utils.statics import DEFAULT_WORKFLOWS_DEPLOYMENT_PATH
from os.path import join
from tests_scripts.workflows.utils import get_messages_from_slack_channel, enrich_slack_alert_channel, get_messages_from_teams_channel, enrich_teams_alert_channel, get_tickets_from_jira_channel





class WorkflowsTests(object):
    '''
    NOTE:
    
    '''
    
    @staticmethod
    def slack_notifications_workflows():
        from tests_scripts.workflows.slack_workflows import WorkflowsSlackNotifications
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=WorkflowsSlackNotifications,
            deployments=join(DEFAULT_WORKFLOWS_DEPLOYMENT_PATH, "http1"),
            deployments1=join(DEFAULT_WORKFLOWS_DEPLOYMENT_PATH, "http2"),
            getMessagesFunc=get_messages_from_slack_channel,
            enrichAlertChannelFunc=enrich_slack_alert_channel,
            create_test_tenant = False
        )    
    
    @staticmethod
    def teams_notifications_workflows():
        from tests_scripts.workflows.teams_workflows import WorkflowsTeamsNotifications
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=WorkflowsTeamsNotifications,
            deployments=join(DEFAULT_WORKFLOWS_DEPLOYMENT_PATH, "http1"),
            deployments1=join(DEFAULT_WORKFLOWS_DEPLOYMENT_PATH, "http2"),
            getMessagesFunc=get_messages_from_teams_channel,
            enrichAlertChannelFunc=enrich_teams_alert_channel,
            create_test_tenant = False
        )   
     
    @staticmethod
    def jira_notifications_workflows():
        from tests_scripts.workflows.jira_workflows import WorkflowsJiraNotifications
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=WorkflowsJiraNotifications,
            deployments=join(DEFAULT_WORKFLOWS_DEPLOYMENT_PATH, "http1"),
            getMessagesFunc=get_tickets_from_jira_channel,
            create_test_tenant = False
        )    

    @staticmethod
    def workflows_configurations():
        from tests_scripts.workflows.conf_workflows import WorkflowConfigurations
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=WorkflowConfigurations,
            create_test_tenant = False
        )
   
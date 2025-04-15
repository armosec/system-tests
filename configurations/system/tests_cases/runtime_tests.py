import inspect

from tests_scripts.runtime.alerts import enrich_slack_alert_notifications, enrich_teams_alert_notifications
from tests_scripts.users_notifications.alert_notifications import get_messages_from_slack_channel, get_messages_from_teams_channel
from .structures import KubescapeConfiguration, TestConfiguration
from os.path import join
from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH



class RuntimeTests(object):
    
    @staticmethod
    def basic_incident_presented():
        from tests_scripts.runtime.incidents import Incidents
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Incidents,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            # create_test_tenant=True,
        )
    
    @staticmethod
    def kdr_runtime_policies_configurations():
        from tests_scripts.runtime.policies import RuntimePoliciesConfigurations
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=RuntimePoliciesConfigurations,
            create_test_tenant=True,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
        )
    
    @staticmethod
    def kdr_teams_alerts():
        from tests_scripts.runtime.alerts import IncidentsAlerts
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=IncidentsAlerts,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            getMessagesFunc=get_messages_from_teams_channel,
            enrichAlertChannelFunc=enrich_teams_alert_notifications,

        )

    @staticmethod
    def kdr_slack_alerts():
        from tests_scripts.runtime.alerts import IncidentsAlerts
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=IncidentsAlerts,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            getMessagesFunc=get_messages_from_slack_channel,
            enrichAlertChannelFunc=enrich_slack_alert_notifications,
        )
    
    @staticmethod
    def kdr_response_by_user():
        from tests_scripts.runtime.response import IncidentResponse
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=IncidentResponse,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            tests=["ApplyNetworkPolicy", "ApplySeccompProfile"],
            with_private_node_agent=False,
            # create_test_tenant=True,
        )
    
    # @staticmethod
    # def kdr_webhook_alerts():
    #     from tests_scripts.runtime.alerts import IncidentsAlerts
    #     return TestConfiguration(
    #         name=inspect.currentframe().f_code.co_name,
    #         test_obj=IncidentsAlerts,
    #         deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
    #         getMessagesFunc=get_messages_from_webhook_channel,
    #         enrichAlertChannelFunc=enrich_webhooks_alert_notifications,
    #     )
    
import inspect
from os.path import join

from systest_utils.statics import DEFAULT_NOTIFICATIONS_PATHS, DEFAULT_NOTIFICATIONS_DEPLOYMENT_PATH
from .structures import TestConfiguration



class NotificationSTests(object):
    
    @staticmethod
    def user_email_settings():
        from tests_scripts.users_notifications.email_settings import EmailSettings
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=EmailSettings
    )

    @staticmethod
    def user_alert_channels():
        from tests_scripts.users_notifications.alert_channels import AlertChannels
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=AlertChannels,
            alert_channel_file=join(DEFAULT_NOTIFICATIONS_PATHS, "teams-alert-channel.json")
        )

    @staticmethod
    def teams_alerts():
        from tests_scripts.users_notifications.alert_notifications import AlertNotifications
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=AlertNotifications,
            deployments=join(DEFAULT_NOTIFICATIONS_DEPLOYMENT_PATH, "http"),
            alert_channel_file=join(DEFAULT_NOTIFICATIONS_PATHS, "teams-alert-channel.json")
        )

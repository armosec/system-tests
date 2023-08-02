import inspect
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
            test_obj=AlertChannels
        )
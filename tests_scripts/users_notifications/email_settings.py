
from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger
from .base_notifications import BaseNotifications



class EmailSettings(BaseNotifications):

    '''
        Test user email settings - add/remove email notifications
        
    '''

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(EmailSettings, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)


    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
         # Stage 1: Remove all notification types (weekly and push)
        Logger.logger.info("Stage 1: Remove all notification types (weekly and push)")
        all_notify_types_payload = [
            {"notificationType": "weekly"},
            {"notificationType": "push"}
        ]
        self.backend.remove_notifications_unsubscribed(all_notify_types_payload)
        # Verify if notifications are empty
        get_unsubscribe_response = self.backend.get_notifications_unsubscribed()        
        unsubscribe_list = get_unsubscribe_response.json()
        self.assertEqual(len(unsubscribe_list), 0, "Expected unsubscribed notifications to be empty")
        # Stage 2: Add "push" notification type
        Logger.logger.info("Stage 2: Add 'push' notification type")
        add_push_payload = [
            {"notificationType": "push"}
        ]
        self.backend.add_notifications_unsubscribed(add_push_payload)  
        # Verify if "push" notification type is present
        get_unsubscribe_response = self.backend.get_notifications_unsubscribed()        
        unsubscribe_list = get_unsubscribe_response.json()
        self.assertEqual(len(unsubscribe_list), 1, "Expected unsubscribed notifications to contain 1 item")
        self.assertIn({"notificationType": "push"}, unsubscribe_list, "Expected unsubscribed notifications to contain 'push' item")

        # Stage 3: Add "weekly" notification type
        Logger.logger.info("Stage 3: Add 'weekly' notification type")
        add_weekly_payload = [
            {"notificationType": "weekly"}
        ]
        self.backend.add_notifications_unsubscribed(add_weekly_payload)
        # Verify if "push" and "weekly" notification types are present
        get_unsubscribe_response = self.backend.get_notifications_unsubscribed()
        unsubscribe_list = get_unsubscribe_response.json()
        self.assertEqual(len(unsubscribe_list), 2, "Expected unsubscribed notifications to contain 2 items")
        self.assertIn({"notificationType": "push"}, unsubscribe_list, "Expected unsubscribed notifications to contain 'push' item")
        self.assertIn({"notificationType": "weekly"}, unsubscribe_list, "Expected unsubscribed notifications to contain 'weekly' item")
        # Stage 4: Add "push" and "weekly" notification types (no change expected)
        Logger.logger.info("Stage 4: Add 'push' and 'weekly' notification types (no change expected)")
        add_both_payload = [
            {"notificationType": "push"},
            {"notificationType": "weekly"}
        ]
        self.backend.add_notifications_unsubscribed(add_both_payload)        
        # Stage 5: Clean up - remove all notification types (weekly and push)
        Logger.logger.info("Stage 5: Clean up - remove all notification types (weekly and push)")         
        self.backend.remove_notifications_unsubscribed(all_notify_types_payload)        
   
        return self.cleanup()
    
    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)
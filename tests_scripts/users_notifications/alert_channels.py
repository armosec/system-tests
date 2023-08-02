from systest_utils import Logger
from .base_notifications import BaseNotifications


class AlertChannels(BaseNotifications):
    """
        Test user's alert channels - CRUD APIs

    """

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(AlertChannels, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):
        Logger.logger.info("Stage 1: Get all alert channels")
        get_all_channels_response = self.backend.get_all_alert_channels()
        assert not get_all_channels_response.content, "Expected alert channels to be empty"

        Logger.logger.info("Stage 2: Create new alert channel")
        created_alert_channel_response = self.backend.create_alert_channel()
        assert created_alert_channel_response, "Expected alert channel"
        guid = created_alert_channel_response.json()["channel"]["guid"]
        assert guid, "Expected alert channel's guid"

        Logger.logger.info("Stage 3: Get the created alert channel by guid")
        get_created_alert_channel_json = self.backend.get_alert_channel(guid).json()
        assert get_created_alert_channel_json == created_alert_channel_response.json(), \
            "Expected alert channel to be the same as created"

        Logger.logger.info("Stage 4: Updated the created alert channel")
        get_created_alert_channel_json["channel"]["context"]["webhook"]["id"] = "modified"
        updated_alert_channel_json = self.backend.update_alert_channel(get_created_alert_channel_json).json()
        assert updated_alert_channel_json["channel"]["context"]["webhook"]["id"] == "modified", "Expected updated " \
                                                                                                    "webhook url to " \
                                                                                                    "be equal to be " \
                                                                                                    "modified"

        Logger.logger.info("Stage 4: delete the created alert channel")
        self.backend.remove_alert_channel(guid)
        get_all_channels_response = self.backend.get_all_alert_channels()
        assert not get_all_channels_response.content, "Expected alert channels to be empty"

        return self.cleanup()

    def cleanup(self, **kwargs):
        leftovers = self.backend.get_all_alert_channels().content
        if leftovers:
            for ac in leftovers.json():
                self.backend.remove_alert_channel(ac["channel"]["guid"])
        return super().cleanup(**kwargs)

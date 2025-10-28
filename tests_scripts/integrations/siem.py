import random
from systest_utils import Logger
from tests_scripts.integrations.base_integrations import BaseIntegrations

class Providers:
    SUMO_LOGIC = "sumoLogic"
    SPLUNK = "splunk"
    MICROSOFT_SENTINEL = "microsoftSentinel"
    WEBHOOK = "webhook"
    
class TestMessageStatus:
    SUCCESS = "successful"
    FAILURE = "failed"

class SIEMIntegrations(BaseIntegrations):

    def __init__(self, test_obj=None, backend=None, test_driver=None):
        super().__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)

    def start(self):
        
        self.test_identifier_rand = str(random.randint(10000000, 99999999))
        self.webhook_integration_name = "systest-" + self.test_identifier_rand + "-webhook-integration"
        
        Logger.logger.info('Stage 1: Create Webhook SIEM integration')
        self.create_siem_integration(name=self.webhook_integration_name,
                                     provider=Providers.WEBHOOK,
                                     configuration={
                                         "webhookURL": "https://example.com/webhook"})  # on purpose invalid URL for testing
        Logger.logger.info(f'Successfully created SIEM integration: {self.webhook_integration_name}')

        Logger.logger.info('Stage 2: Get Webhook SIEM integration')
        webhook_integration = self.get_siem_integration_by_name(name=self.webhook_integration_name, provider=Providers.WEBHOOK)
        assert webhook_integration, f"SIEM integration: {self.webhook_integration_name} not found"
        Logger.logger.info(f'Successfully retrieved SIEM integration: {self.webhook_integration_name}')
        
        Logger.logger.info('Stage 3: Validate test message status is failed due to invalid webhook URL')
        self.validate_test_message_status(provider=Providers.WEBHOOK,
                                          guid=webhook_integration["guid"],
                                          expected_status=TestMessageStatus.FAILURE)

        Logger.logger.info('Stage 4: Update Webhook SIEM integration with valid webhook URL')
        self.update_siem_integration(guid=webhook_integration["guid"],
                                     name=self.webhook_integration_name,
                                     provider=Providers.WEBHOOK,
                                     configuration={
                                          "webhookURL": "https://cyberarmorio.webhook.office.com/webhookb2/c26291b4-0240-49e7-a165-1d568d3d1013@50a70646-52e3-4e46-911e-6ca1b46afba3/IncomingWebhook/6d902cfccbc04d9a91f4b7d784ce3663/6bc28457-1839-4890-b633-82cc56c77deb/V2Vo5ro2YapZc7Q6ONj50TQFq3jtTrs_tATypBRI1Vse41"})
        Logger.logger.info(f'Successfully updated SIEM integration: {self.webhook_integration_name}')

        Logger.logger.info('Stage 5: Validate test message status is successful due to valid webhook URL')
        self.validate_test_message_status(provider=Providers.WEBHOOK,
                                          guid=webhook_integration["guid"],
                                          expected_status=TestMessageStatus.SUCCESS)

        Logger.logger.info('Step 6: Delete Webhook SIEM integration')
        self.backend.delete_siem_integration(provider=Providers.WEBHOOK, guid=webhook_integration["guid"])
        Logger.logger.info(f'Successfully deleted SIEM integration: {self.webhook_integration_name}')
        
        return self.cleanup()
    
    def create_siem_integration(self, name: str, provider: Providers, configuration: dict):
        body = {
            "name": name,
            "configuration": configuration
        }
        
        response = self.backend.create_siem_integration(provider, body)
        return response

    def get_siem_integration_by_name(self, name: str, provider: Providers) -> dict:
        integrations = self.backend.get_siem_integrations(provider=provider)
        assert len(integrations) > 0, f"Expected at least one SIEM integration for provider {provider}"
        for integration in integrations:
            if integration["name"] == name:
                return integration
        return {}
    
    def get_siem_integration_by_guid(self, guid: str, provider: Providers) -> dict:
        integrations = self.backend.get_siem_integrations(provider=provider)
        assert len(integrations) > 0, f"Expected at least one SIEM integration for provider {provider}"
        for integration in integrations:
            if integration["guid"] == guid:
                return integration
        return {}
    
    def validate_test_message_status(self, provider: Providers, guid: str, expected_status: TestMessageStatus):
        integration = self.get_siem_integration_by_guid(guid=guid, provider=provider)
        assert integration, f"SIEM integration with guid {guid} not found"
        assert integration.get("testMessageStatus") == expected_status, \
            f"Expected test message status to be {expected_status}, but got {integration.get('testMessageStatus')}"

    def update_siem_integration(self, guid: str, name: str, provider: Providers, configuration: dict, is_enabled: bool = True):
        body = {
            "guid": guid,
            "name": name,
            "configuration": configuration,
            "isEnabled": is_enabled
        }
        
        response = self.backend.update_siem_integration(provider, body)
        return response

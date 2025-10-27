import random
from systest_utils import Logger
from tests_scripts.integrations.base_integrations import BaseIntegrations

class Providers:
    SUMO_LOGIC = "sumoLogic"
    SPLUNK = "splunk"
    MICROSOFT_SENTINEL = "microsoftSentinel"
    WEBHOOK = "webhook"
    

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
        
        Logger.logger.info('Stage 3: Update Webhook SIEM integration with valid webhook URL')
        self.update_siem_integration(guid=webhook_integration["guid"],
                                     name=self.webhook_integration_name,
                                     provider=Providers.WEBHOOK,
                                     configuration={
                                          "webhookURL": "https://example.com/webhook/updated"})  # TODO: change to valid URL
        Logger.logger.info(f'Successfully updated SIEM integration: {self.webhook_integration_name}')
        
        Logger.logger.info('Step 4: delete SIEM integration')
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
    
    def update_siem_integration(self, guid: str, name: str, provider: Providers, configuration: dict):
        body = {
            "guid": guid,
            "name": name,
            "configuration": configuration
        }
        
        response = self.backend.update_siem_integration(provider, body)
        return response

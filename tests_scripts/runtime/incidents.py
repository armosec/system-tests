# test incidents list API
# test single incident API
# Bonus: test alerts overtime + raw alerts
from tests_scripts.helm.base_helm import BaseHelm
from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import statics, Logger, TestUtil

class Incidents(BaseHelm):
    '''
        check incidents page.
    '''
    
    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(Incidents, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)
        self.helm_kwargs = {
            "capabilities.relevancy": "disable",
            "capabilities.configurationScan": "disable",
            "capabilities.continuousScan": "disable",
            "capabilities.nodeScan": "disable",
            "capabilities.vulnerabilityScan": "disable",
            "grypeOfflineDB.enabled": "false",
            # enable application profile, malware and runtime detection
            "capabilities.runtimeObservability": "enable",
            "capabilities.malwareDetection": "enable",
            "capabilities.runtimeDetection": "enable",
            # short learning period
            "nodeAgent.config.maxLearningPeriod": "1m",
            "nodeAgent.config.learningPeriod": "1m",
            "nodeAgent.config.updatePeriod": "1m",
        }
        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)
    
    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        cluster, namespace = self.setup()

        Logger.logger.info("1. Install armo helm-chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.verify_running_pods(
            namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360
        )
        
        # Logger.logger.info("Stage 1: Go to incidents page")
        
        response = self.backend.get_incidents()
        # self.http_status_ok(response.status_code)
        
        # response = self.incident(incident_id=1)
        # self.http_status_ok(response.status_code)
        
        return self.cleanup()
    
    def incidents_list(self):
        '''
            get incidents list
        '''
        return self.backend.incidents_list()
    
    def incident(self, incident_id: int):
        '''
            get single incident
        '''
        return self.backend.incident(incident_id=incident_id)
    
    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)
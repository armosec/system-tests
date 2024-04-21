import inspect

from systest_utils import statics
from .structures import TestConfiguration
from os.path import join



class SecurityRisksTests(object):

    @staticmethod
    # test security risks detection and resolve with kubescape helm chart
    # based on attack chain 5 scenarios.
    def sr_detect_and_resolve_attack_chain():
        from tests_scripts.helm.ks_microservice import ScanSecurityRisksWithKubescapeHelmChart
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanSecurityRisksWithKubescapeHelmChart,
            test_scenario="attack-chain-5",
            test_job=[{"trigger_by": "scan_on_start", "security_risks_ids": ["R_0035"]}],
            fix_object="control",
            relevancy_enabled=False,
            helm_kwargs={
                        statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_DISABLED,
                        statics.HELM_NETWORK_POLICY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED,
                         statics.HELM_NODE_AGENT_LEARNING_PERIOD: '30s',
                         statics.HELM_NODE_AGENT_UPDATE_PERIOD: '10s'
                         }
        )
    
    @staticmethod
    # test security risks detection and resolve with kubescape helm chart
    # based on attack chain 5 scenarios.
    def sr_detect_and_resolve_control():
        from tests_scripts.helm.ks_microservice import ScanSecurityRisksWithKubescapeHelmChart
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanSecurityRisksWithKubescapeHelmChart,
            test_scenario="attack-chain-5",
            test_job=[{"trigger_by": "scan_on_start", "security_risks_ids": ["R_0005"]}],
            fix_object="control",
            relevancy_enabled=False,
            helm_kwargs={
                        statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_DISABLED,
                        statics.HELM_NETWORK_POLICY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED,
                         statics.HELM_NODE_AGENT_LEARNING_PERIOD: '30s',
                         statics.HELM_NODE_AGENT_UPDATE_PERIOD: '10s'
                         }
        )
    
    
    
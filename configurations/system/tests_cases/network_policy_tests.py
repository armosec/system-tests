import inspect

from systest_utils import statics
from .structures import TestConfiguration
from os.path import join

class NetworkPolicyTests(object):

    @staticmethod
    def network_policy():
        from tests_scripts.helm.network_policy import NetworkPolicy

        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            services=join(statics.DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(statics.DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(statics.DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_obj=NetworkPolicy,
            expected_network_neighbors=["configurations/network-policy/expected-network-neighbors/deployment-wikijs.json",
                 "configurations/network-policy/expected-network-neighbors/deployment-mariadb.json",
                "configurations/network-policy/expected-network-neighbors/deployment-nginx.json", 
            ],
            expected_generated_network_policies=["configurations/network-policy/expected-generated-network-policy/deployment-wikijs.json",
                    "configurations/network-policy/expected-generated-network-policy/deployment-mariadb.json",
                    "configurations/network-policy/expected-generated-network-policy/deployment-nginx.json",
                                                 ],
            helm_kwargs={statics.HELM_NETWORK_POLICY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED, statics.HELM_NODE_AGENT_LEARNING_PERIOD: '30s', statics.HELM_NODE_AGENT_UPDATE_PERIOD: '10s'}
        )
    
    @staticmethod
    def network_policy_data_appended():
        from tests_scripts.helm.network_policy import NetworkPolicyDataAppended
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            services=join(statics.DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(statics.DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(statics.DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_obj=NetworkPolicyDataAppended,
            expected_network_neighbors = ["configurations/network-policy/expected-network-neighbors/deployment-wikijs-basic.json",
                 "configurations/network-policy/expected-network-neighbors/deployment-mariadb-basic.json",
                "configurations/network-policy/expected-network-neighbors/deployment-nginx-basic.json", 
            ],
            expected_generated_network_policies = [
                "configurations/network-policy/expected-generated-network-policy/deployment-wikijs-basic.json",
                    "configurations/network-policy/expected-generated-network-policy/deployment-mariadb-basic.json",
                    "configurations/network-policy/expected-generated-network-policy/deployment-nginx-basic.json",
            ],
            expected_updated_network_neighbors=["configurations/network-policy/expected-network-neighbors/deployment-wikijs.json",
                 "configurations/network-policy/expected-network-neighbors/deployment-mariadb.json",
                "configurations/network-policy/expected-network-neighbors/deployment-nginx.json", 
            ],
            expected_updated_generated_network_policies=["configurations/network-policy/expected-generated-network-policy/deployment-wikijs.json",
                    "configurations/network-policy/expected-generated-network-policy/deployment-mariadb.json",
                    "configurations/network-policy/expected-generated-network-policy/deployment-nginx.json",
                                                 ],
            helm_kwargs={statics.HELM_NETWORK_POLICY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED, statics.HELM_NODE_AGENT_LEARNING_PERIOD: '30s', statics.HELM_NODE_AGENT_UPDATE_PERIOD: '10s'}
        )

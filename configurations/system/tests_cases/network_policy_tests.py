import inspect
from os.path import join

from systest_utils import statics
from .structures import TestConfiguration


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
            expected_network_neighborhood=[
                "configurations/network-policy/expected-network-neighborhood/deployment-wikijs.json",
                "configurations/network-policy/expected-network-neighborhood/deployment-mariadb.json",
                "configurations/network-policy/expected-network-neighborhood/deployment-nginx.json",
                ],
            expected_generated_network_policies=[
                "configurations/network-policy/expected-generated-network-policy/deployment-wikijs.json",
                "configurations/network-policy/expected-generated-network-policy/deployment-mariadb.json",
                "configurations/network-policy/expected-generated-network-policy/deployment-nginx.json",
                ],
            helm_kwargs={statics.HELM_NETWORK_POLICY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED,
                         "storage.forceVirtualCrds": "true",
                         statics.HELM_NODE_AGENT_LEARNING_PERIOD: '30s',
                         statics.HELM_NODE_AGENT_MAX_LEARNING_PERIOD: '3m',
                         statics.HELM_NODE_AGENT_UPDATE_PERIOD: '10s'
                         }
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
            expected_network_neighborhood=[
                "configurations/network-policy/expected-network-neighborhood/deployment-wikijs-basic.json",
                "configurations/network-policy/expected-network-neighborhood/deployment-mariadb-basic.json",
                "configurations/network-policy/expected-network-neighborhood/deployment-nginx-basic.json",
                ],
            expected_generated_network_policies=[
                "configurations/network-policy/expected-generated-network-policy/deployment-wikijs-basic.json",
                "configurations/network-policy/expected-generated-network-policy/deployment-mariadb-basic.json",
                "configurations/network-policy/expected-generated-network-policy/deployment-nginx-basic.json",
            ],
            expected_updated_network_neighborhood=[
                "configurations/network-policy/expected-network-neighborhood/deployment-wikijs.json",
                "configurations/network-policy/expected-network-neighborhood/deployment-mariadb.json",
                "configurations/network-policy/expected-network-neighborhood/deployment-nginx.json",
                ],
            expected_updated_generated_network_policies=[
                "configurations/network-policy/expected-generated-network-policy/deployment-wikijs.json",
                "configurations/network-policy/expected-generated-network-policy/deployment-mariadb.json",
                "configurations/network-policy/expected-generated-network-policy/deployment-nginx.json",
                ],
            helm_kwargs={statics.HELM_NETWORK_POLICY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED,
                         "storage.forceVirtualCrds": "true",
                         statics.HELM_NODE_AGENT_LEARNING_PERIOD: '30s',
                         statics.HELM_NODE_AGENT_MAX_LEARNING_PERIOD: '3m',
                         statics.HELM_NODE_AGENT_UPDATE_PERIOD: '10s'
                         }
        )

    @staticmethod
    def network_policy_pod_restarted():
        from tests_scripts.helm.network_policy import NetworkPolicyPodRestarted
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            services=join(statics.DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(statics.DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(statics.DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_obj=NetworkPolicyPodRestarted,
            expected_network_neighborhood=[
                "configurations/network-policy/expected-network-neighborhood/deployment-wikijs-basic.json",
                "configurations/network-policy/expected-network-neighborhood/deployment-mariadb-basic.json",
                "configurations/network-policy/expected-network-neighborhood/deployment-nginx-basic.json",
                ],
            expected_generated_network_policies=[
                "configurations/network-policy/expected-generated-network-policy/deployment-wikijs-basic.json",
                "configurations/network-policy/expected-generated-network-policy/deployment-mariadb-basic.json",
                "configurations/network-policy/expected-generated-network-policy/deployment-nginx-basic.json",
            ],
            helm_kwargs={statics.HELM_NETWORK_POLICY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED,
                         "storage.forceVirtualCrds": "true",
                         statics.HELM_NODE_AGENT_LEARNING_PERIOD: '30s',
                         statics.HELM_NODE_AGENT_MAX_LEARNING_PERIOD: '3m',
                         statics.HELM_NODE_AGENT_UPDATE_PERIOD: '10s'
                         }
        )

    @staticmethod
    def network_policy_multiple_replicas():
        from tests_scripts.helm.network_policy import NetworkPolicyMultipleReplicas
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(statics.DEFAULT_DEPLOYMENT_PATH, "busybox"),
            test_obj=NetworkPolicyMultipleReplicas,
            expected_network_neighborhood=["configurations/network-policy/expected-network-neighborhood/busybox.json",
                                        ],
            expected_generated_network_policies=[
                "configurations/network-policy/expected-generated-network-policy/busybox.json",
            ],
            helm_kwargs={statics.HELM_NETWORK_POLICY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED,
                         "storage.forceVirtualCrds": "true",
                         statics.HELM_NODE_AGENT_LEARNING_PERIOD: '30s',
                         statics.HELM_NODE_AGENT_UPDATE_PERIOD: '10s'
                         }
        )

    @staticmethod
    def network_policy_known_servers():
        from tests_scripts.helm.network_policy import NetworkPolicyKnownServers
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(statics.DEFAULT_DEPLOYMENT_PATH, "busybox"),
            knownservers=join(statics.DEFAULT_KNOWN_SERVERS_PATH, "known-server.json"),
            test_obj=NetworkPolicyKnownServers,
            expected_network_neighborhood=[
                "configurations/network-policy/expected-network-neighborhood/busybox-known-server.json",
                ],
            expected_generated_network_policies=[
                "configurations/network-policy/expected-generated-network-policy/busybox-known-server.json",
            ],
            helm_kwargs={statics.HELM_NETWORK_POLICY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED,
                         "storage.forceVirtualCrds": "true",
                         statics.HELM_NODE_AGENT_LEARNING_PERIOD: '30s',
                         statics.HELM_NODE_AGENT_UPDATE_PERIOD: '10s'
                         }
        )

    @staticmethod
    def network_policy_known_servers_cache():
        from tests_scripts.helm.network_policy import NetworkPolicyKnownServersCache
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=NetworkPolicyKnownServersCache
        )

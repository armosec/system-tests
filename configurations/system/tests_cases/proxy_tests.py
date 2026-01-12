import inspect

from infrastructure import supported_systemsAPI
from .structures import TestConfiguration
from systest_utils import statics
from os.path import join


class ProxyTests(object):

    @staticmethod
    def proxy_integration_test():
        """
        Combined proxy test that verifies:
        1. Synchronizer works through proxy
        2. Vulnerability scanning works through proxy  
        3. Kubescape control scanning works through proxy
        
        This saves time by installing helm chart only once.
        """
        from tests_scripts.helm.proxy_integration import ProxyIntegrationTest
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH, DEFAULT_SYNCHRONIZER_PATH
        
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ProxyIntegrationTest,
            # Synchronizer workloads
            synchronizer_workload_1=join(DEFAULT_SYNCHRONIZER_PATH, "deployment.yaml"),
            synchronizer_workload_2=join(DEFAULT_SYNCHRONIZER_PATH, "replicaset.yaml"),
            synchronizer_workload_3=join(DEFAULT_SYNCHRONIZER_PATH, "statefulset.yaml"),
            # WikiJS workloads (for vuln scan and kubescape tests)
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            database=supported_systemsAPI.WikiJS,
            expected_results="wikijs.json",
            # Kubescape test jobs
            test_job=[
                {"trigger_by": "cronjob", "operation": "create", "framework": ["MITRE"], "hostsensor": False},
                {"trigger_by": "cronjob", "operation": "create", "framework": ["NSA"], "hostsensor": False}
            ],
            # Helm config - merge settings from all three tests
            helm_kwargs={
                statics.HELM_NODE_SBOM_GENERATION: statics.HELM_NODE_SBOM_GENERATION_DISABLED,
            },
            proxy_config={"helm_proxy_url": statics.HELM_PROXY_URL}
        )

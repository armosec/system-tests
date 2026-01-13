import inspect

from .structures import TestConfiguration
from systest_utils import statics
from os.path import join


class ProxyTests(object):

    @staticmethod
    def proxy_integration_test():
        """
        Simplified proxy test that verifies:
        1. Helm chart installation with proxy
        2. Synchronizer resources are reported through proxy
        3. Kubescape report exists through proxy
        
        This is a fast test that only verifies basic proxy functionality.
        """
        from tests_scripts.helm.proxy_integration import ProxyIntegrationTest
        from systest_utils.statics import DEFAULT_SYNCHRONIZER_PATH
        
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ProxyIntegrationTest,
            synchronizer_workload_1=join(DEFAULT_SYNCHRONIZER_PATH, "deployment.yaml"),
            helm_kwargs={
                statics.HELM_NODE_SBOM_GENERATION: statics.HELM_NODE_SBOM_GENERATION_DISABLED,
            },
            proxy_config={"helm_proxy_url": statics.HELM_PROXY_URL}
        )

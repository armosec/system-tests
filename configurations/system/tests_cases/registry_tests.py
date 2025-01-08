import inspect
from os.path import join

from systest_utils.statics import DEFAULT_REGISTRY_PATHS
from .structures import TestConfiguration

class RegistryTests(object):

    @staticmethod
    def test_registry_scanning():
        from tests_scripts.registry.registry_connectors import RegistryChecker
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=RegistryChecker,
            check_payload_file=join(DEFAULT_REGISTRY_PATHS, "check_{}.json"),
            create_payload_file=join(DEFAULT_REGISTRY_PATHS, "create_quay.json") # we do sanity only for one provider
        )
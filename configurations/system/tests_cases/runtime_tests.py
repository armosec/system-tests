import inspect
from .structures import KubescapeConfiguration
from os.path import join
from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH



class RuntimeTests(object):
    
    @staticmethod
    def basic_incident_presented():
        from tests_scripts.runtime.incidents import Incidents
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Incidents,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            # create_test_tenant=True,
        )
    
    @staticmethod
    def kdr_runtime_policies_configurations():
        from tests_scripts.runtime.policies import RuntimePoliciesConfigurations
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=RuntimePoliciesConfigurations,
            create_test_tenant=True,
        )
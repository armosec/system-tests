import inspect

from .structures import TestConfiguration
from systest_utils import statics



class KSMicroserviceTests(object):
    @staticmethod
    def scan_with_kubescape_helm_chart():
        from tests_scripts.helm.ks_microservice import ScanWithKubescapeHelmChart
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithKubescapeHelmChart,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
        )

    @staticmethod
    def scan_for_attack_chains_scenario_1_1():
        """
        install kubescape helm chart, run scan with 'security' framework and check detected attack-chains.
        """
        from tests_scripts.helm.ks_microservice import ScanAttackChainsWithKubescapeHelmChart
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanAttackChainsWithKubescapeHelmChart,
            test_job=[{"trigger_by": "scan_on_start"}],
            test_scenario="attack-chain-1.1"
        )

    @staticmethod
    def ks_microservice_ns_creation():
        from tests_scripts.helm.ks_microservice import ScanWithKubescapeAsServiceTest
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithKubescapeAsServiceTest,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_job=[{"trigger_by": "scan_on_start", "host_sensor": True}]
        )

    @staticmethod
    def ks_microservice_on_demand():
        from tests_scripts.helm.ks_microservice import ScanWithKubescapeAsServiceTest
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithKubescapeAsServiceTest,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_job=[{"trigger_by": "job", "framework": [""], "hostsensor": True}]
        )

    @staticmethod
    def ks_microservice_mitre_framework_on_demand():
        from tests_scripts.helm.ks_microservice import ScanWithKubescapeAsServiceTest
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithKubescapeAsServiceTest,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_job=[{"trigger_by": "job", "framework": ["MITRE"], "hostsensor": False}]
        )

    @staticmethod
    def ks_microservice_nsa_and_mitre_framework_demand():
        from tests_scripts.helm.ks_microservice import ScanWithKubescapeAsServiceTest
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithKubescapeAsServiceTest,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_job=[{"trigger_by": "job", "framework": ["MITRE", "NSA"], "hostsensor": False}]
        )

    @staticmethod
    def ks_microservice_triggering_with_cron_job():
        from tests_scripts.helm.ks_microservice import ScanWithKubescapeAsServiceTest
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithKubescapeAsServiceTest,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_job=[{"trigger_by": "cronjob", "operation": "create", "framework": [""], "hostsensor": True}]
        )

    @staticmethod
    def ks_microservice_update_cronjob_schedule():
        from tests_scripts.helm.ks_microservice import ScanWithKubescapeAsServiceTest
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithKubescapeAsServiceTest,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_job=[{"trigger_by": "cronjob", "operation": "create", "framework": [""], "hostsensor": True},
                      {"trigger_by": "cronjob", "operation": "update", "framework": [""], "hostsensor": True}]
        )

    @staticmethod
    def ks_microservice_delete_cronjob():
        from tests_scripts.helm.ks_microservice import ScanWithKubescapeAsServiceTest
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithKubescapeAsServiceTest,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_job=[{"trigger_by": "cronjob", "operation": "create", "framework": [""], "hostsensor": True},
                      {"trigger_by": "cronjob", "operation": "delete", "framework": [""], "hostsensor": True}]
        )

    @staticmethod
    def ks_microservice_create_2_cronjob_mitre_and_nsa():
        from tests_scripts.helm.ks_microservice import ScanWithKubescapeAsServiceTest
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithKubescapeAsServiceTest,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_job=[{"trigger_by": "cronjob", "operation": "create", "framework": ["MITRE"], "hostsensor": False},
                      {"trigger_by": "cronjob", "operation": "create", "framework": ["NSA"], "hostsensor": False}]
        )


    @staticmethod
    def ks_microservice_create_2_cronjob_mitre_and_nsa_proxy():
        from tests_scripts.helm.ks_microservice import ScanWithKubescapeAsServiceTest
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithKubescapeAsServiceTest,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_job=[{"trigger_by": "cronjob", "operation": "create", "framework": ["MITRE"], "hostsensor": False},
                      {"trigger_by": "cronjob", "operation": "create", "framework": ["NSA"], "hostsensor": False}],
            proxy_config={"helm_proxy_url":statics.HELM_PROXY_URL}
        )

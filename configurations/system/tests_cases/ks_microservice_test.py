import inspect

from .structures import TestConfiguration
from systest_utils import statics
from os.path import join



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
    def sbom_test():
         from tests_scripts.helm.ks_microservice import ScanSBOM

         return TestConfiguration(
                name=inspect.currentframe().f_code.co_name,
                test_obj=ScanSBOM,
                deployments=join(statics.DEFAULT_DEPLOYMENT_PATH, "nginx"),

         )

    @staticmethod
    def attackchains_all():
        """
        check multiple attack chains scenarios.
        once the attack chain has been detected on the backend, fix the attack chain and verify that is has been solved 
        by triggering a new control scan.

        'fix_object' parameter is used to determine which type of fix you want to apply, to test the attack-chain fix functionality.
        fix_object = ["control", "image"]
        """
        from tests_scripts.helm.ks_microservice import ScanAttackChainsWithKubescapeHelmChartMultiple
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanAttackChainsWithKubescapeHelmChartMultiple,
            test_job=[
                {"test_scenario": "attack-chain-8", "fix_object": "control", "attack_track": "external-workload-with-cluster-takeover-roles", "default_namespace":True}, # external workload with cluster takeover, must use default for the role subjects
                {"test_scenario": "attack-chain-9", "fix_object": "control", "attack_track": "workload-unauthenticated-service"}, # unauthenticated service
                {"test_scenario": "alpine", "fix_object": "image", "attack_track": "workload-external-track"}, # alpine workload external track fix image
                {"test_scenario": "alpine", "fix_object": "control", "attack_track": "workload-external-track"}, # alpine workload external track fix control
                ],
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

    @staticmethod
    def control_cluster_from_CLI_config_scan_default():
        from tests_scripts.helm.ks_microservice import ControlClusterFromCLI
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ControlClusterFromCLI,
            cli_args={"scan": True, "trigger": "configurations"},
        )

    @staticmethod
    def control_cluster_from_CLI_config_scan_exclude_namespaces():
        from tests_scripts.helm.ks_microservice import ControlClusterFromCLI
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ControlClusterFromCLI,
            cli_args={"scan": True, "trigger": "configurations", "exclude-namespaces": ["kubescape"]},
        )

    @staticmethod
    def control_cluster_from_CLI_config_scan_include_namespaces():
        from tests_scripts.helm.ks_microservice import ControlClusterFromCLI
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ControlClusterFromCLI,
            cli_args={"scan": True, "trigger": "configurations", "include-namespaces": ["kubescape"]},
        )

    @staticmethod
    def control_cluster_from_CLI_config_scan_host_scanner_enabled():
        from tests_scripts.helm.ks_microservice import ControlClusterFromCLI
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ControlClusterFromCLI,
            cli_args={"scan": True, "trigger": "configurations", "host-scanner-enabled": True},
        )

    @staticmethod
    def control_cluster_from_CLI_config_scan_submit():
        from tests_scripts.helm.ks_microservice import ControlClusterFromCLI
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ControlClusterFromCLI,
            cli_args={"scan": True, "trigger": "configurations", "submit": True},
        )

    @staticmethod
    def control_cluster_from_CLI_config_scan_MITRE_framework():
        from tests_scripts.helm.ks_microservice import ControlClusterFromCLI
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ControlClusterFromCLI,
            cli_args={"scan": True, "trigger": "configurations", "frameworks": ["MITRE"]},
        )

    @staticmethod
    def control_cluster_from_CLI_vulnerabilities_scan_default():
        from tests_scripts.helm.ks_microservice import ControlClusterFromCLI
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ControlClusterFromCLI,
            cli_args={"scan": True, "trigger": "vulnerabilities"},
        )

    @staticmethod
    def control_cluster_from_CLI_vulnerabilities_scan_include_namespaces():
        from tests_scripts.helm.ks_microservice import ControlClusterFromCLI
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ControlClusterFromCLI,
            cli_args={"scan": True, "trigger": "vulnerabilities", "include-namespaces": ["kubescape"]},
        )

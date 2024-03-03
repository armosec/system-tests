import inspect

from infrastructure import supported_systemsAPI
from tests_scripts.helm.vuln_scan import VulnerabilityScanningRegistry
from .structures import TestConfiguration
from systest_utils import statics


class VulnerabilityScanningTests(object):

    @staticmethod
    def vuln_scan_proxy():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanningProxy
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningProxy,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            database=supported_systemsAPI.WikiJS,
            expected_results="wikijs.json",
            proxy_config={"helm_proxy_url": statics.HELM_PROXY_URL}
        )
    
    @staticmethod
    def vuln_v2_views():
        from tests_scripts.helm.vuln_scan import VulnerabilityV2Views
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityV2Views, 
            services=join(DEFAULT_SERVICE_PATH, "viewsv2"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "viewsv2")
        )
     
    @staticmethod
    def vuln_v2_views_kev():
        from tests_scripts.helm.vuln_scan import VulnerabilityV2ViewsKEV
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityV2ViewsKEV,
            services=join(DEFAULT_SERVICE_PATH, "viewsv2kev"),           
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "viewsv2kev"),
            secret="wikijs.yaml"
        )
    
    

    @staticmethod
    def vuln_scan():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanning
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanning,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            database=supported_systemsAPI.WikiJS,
            expected_results="wikijs.json",
            helm_kwargs={statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED},
            create_test_tenant=True
        )

    @staticmethod
    def vuln_scan_trigger_scan_on_new_image():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanningTriggerScanOnNewImage
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningTriggerScanOnNewImage,
            deployment=join("nginx-vuln-scan-new-image.yaml"),
            expected_results="nginx-new-image.json",
            helm_kwargs={"triggerNewImageScan": True}
        )

    @staticmethod
    def vuln_scan_cve_exceptions():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanningCVEExceptions
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningCVEExceptions,
            deployment=join("nginx-vuln-scan-new-image.yaml"),
            expected_results="nginx-new-image.json",
            helm_kwargs={"triggerNewImageScan": True}
        )

    @staticmethod
    def vuln_scan_trigger_scan_public_registry():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanningRegistry
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningRegistry,
            deployment=join(DEFAULT_DEPLOYMENT_PATH, "public-registry.yaml"),
            service=join(DEFAULT_SERVICE_PATH, "public-registry.yaml"),
            properties={'http': True},  # https://hub.armosec.io/docs/registry-vulnerability-scan
            registry='local',  # either local or specify the registry itself
            configmap_data=None,  # https://hub.armosec.io/docs/registry-vulnerability-scan
            expected_results="nginx-new-image.json",
            expected_payloads={"image": "nginx:test"},
            is_https=False
        )

    @staticmethod
    def vuln_scan_trigger_scan_public_registry_excluded():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanningRegistry
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningRegistry,
            deployment=join(DEFAULT_DEPLOYMENT_PATH, "public-registry.yaml"),
            service=join(DEFAULT_SERVICE_PATH, "public-registry.yaml"),
            properties={'http': True},  # https://hub.armosec.io/docs/registry-vulnerability-scan
            registry='local',  # either local or specify the registry itself
            configmap_data={
                "depth": 2,
                "exclude": ["nginx"]
            },  # https://hub.armosec.io/docs/registry-vulnerability-scan
            expected_results="nginx-new-image.json",
            expected_payloads={"image": "nginx:test"}
        )

    @staticmethod
    def vuln_scan_trigger_scan_private_quay_registry():
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningRegistry,
            deployment=join(DEFAULT_DEPLOYMENT_PATH, "public-registry.yaml"),
            service=join(DEFAULT_SERVICE_PATH, "public-registry.yaml"),
            # https://hub.armosec.io/docs/registry-vulnerability-scan
            properties=None,  # https://hub.armosec.io/docs/registry-vulnerability-scan
            registry='quay.io/armosec',  # either local or specify the registry itself
            configmap_data=None,  # https://hub.armosec.io/docs/registry-vulnerability-scan
            expected_results="nginx-new-image.json",
            expected_payloads={"image": "system-test-nginx:latest"}

        )

    @staticmethod
    def vuln_scan_trigger_scan_registry_by_backend():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanningRegistryBackendTrigger
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningRegistryBackendTrigger,
            deployment=join(DEFAULT_DEPLOYMENT_PATH, "public-registry.yaml"),
            service=join(DEFAULT_SERVICE_PATH, "public-registry.yaml"),
            properties={'http': True},  # https://hub.armosec.io/docs/registry-vulnerability-scan
            registry='local',  # either local or specify the registry itself
            configmap_data=None,  # https://hub.armosec.io/docs/registry-vulnerability-scan
            expected_results="nginx-new-image.json",
            expected_payloads={"image": "nginx:test"},
            expected_layers="layers.json"
        )

    @staticmethod
    def vuln_scan_triggering_with_cron_job():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanningTriggeringWithCronJob
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningTriggeringWithCronJob,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            schedule_time="1 2 3 4 5",
            updating_schedule_time="1 * * * *"
        )

    @staticmethod
    def registry_scanning_triggering_with_cron_job():
        from tests_scripts.helm.vuln_scan import RegistryScanningTriggeringWithCronJob
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=RegistryScanningTriggeringWithCronJob,
            deployment=join(DEFAULT_DEPLOYMENT_PATH, "public-registry.yaml"),
            service=join(DEFAULT_SERVICE_PATH, "public-registry.yaml"),
            properties={'http': True},  # https://hub.armosec.io/docs/registry-vulnerability-scan
            registry='local',  # either local or specify the registry itself
            configmap_data=None,  # https://hub.armosec.io/docs/registry-vulnerability-scan
            expected_results="nginx-new-image.json",
            expected_payloads={"image": "nginx:test"},
            schedule_time="1 2 3 4 5",
            updating_schedule_time="2 2 2 2 2",
            expected_layers="layers.json",
            depth=3,
        )

    @staticmethod
    def vuln_scan_test_public_registry_connectivity_by_backend():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanningTestRegistryConnectivity
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningTestRegistryConnectivity,
        )

    @staticmethod
    def vuln_scan_test_public_registry_connectivity_excluded_by_backend():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanningTestRegistryConnectivity
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningTestRegistryConnectivity,
            excluded_repositories=["notification-server", "action-trigger"]
        )

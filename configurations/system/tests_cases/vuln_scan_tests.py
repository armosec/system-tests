import inspect

from infrastructure import supported_systemsAPI
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
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "viewsv2"),
            database=supported_systemsAPI.WikiJS,
            helm_kwargs={"triggerNewImageScan": True}
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
    def vuln_scan_cve_global_container_name_exceptions():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanningCVEExceptions
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningCVEExceptions,
            deployment=join("nginx-vuln-scan-new-image.yaml"),
            expected_results="nginx-new-image.json",
            exceptions_parameters={"container_name": "*/*"},
            helm_kwargs={"triggerNewImageScan": True},
        )

    @staticmethod
    def vuln_scan_cve_global_namespace_exceptions():
        from tests_scripts.helm.vuln_scan import VulnerabilityScanningCVEExceptions
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=VulnerabilityScanningCVEExceptions,
            deployment=join("nginx-vuln-scan-new-image.yaml"),
            expected_results="nginx-new-image.json",
            exceptions_parameters={"namespace": "*/*"},
            helm_kwargs={"triggerNewImageScan": True},
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

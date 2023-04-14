import inspect

from infrastructure import supported_systemsAPI
from tests_scripts.helm.vulnerability_scanning import VulnerabilityScanningRegistry
from .structures import TestConfiguration


class RelevantVulnerabilityScanningTests(object):
    @staticmethod
    def relevantCVEs():
        from tests_scripts.helm.relevant_cve import RelevantCVEs
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_obj=RelevantCVEs,
            expected_SBOMs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/SBOM/nginx_SBOM.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/SBOM/mariadb_SBOM.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/SBOM/wikijs_SBOM.json")],
            expected_CVEs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/CVEs/nginx.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/CVEs/mariadb.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/CVEs/wikijs.json")],
            expected_filtered_SBOMs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/CVEs/nginx.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/CVEs/mariadb.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/CVEs/wikijs.json")],
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: True}
        )
        
    @staticmethod
    def relevancy_disabled_installation():
        from tests_scripts.helm.relevant_cve import RelevancyDisabled
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_obj=RelevancyDisabled,
            expected_SBOMs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/SBOM/nginx_SBOM.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/SBOM/mariadb_SBOM.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/SBOM/wikijs_SBOM.json")],
            expected_CVEs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/CVEs/nginx.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/CVEs/mariadb.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/CVEs/wikijs.json")],
            expected_filtered_SBOMs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/CVEs/nginx.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/CVEs/mariadb.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/CVEs/wikijs.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/wikijs.json",
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: False}
        )
    
    @staticmethod
    def relevancy_enabled_stop_sniffing():
        from tests_scripts.helm.relevant_cve import RelevancyEnabledStopSniffingAfterTime
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "nginx_modified_entrypoint"),
            test_obj=RelevancyEnabledStopSniffingAfterTime,
            expected_SBOMs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/SBOM/nginx_SBOM.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/SBOM/mariadb_SBOM.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/SBOM/wikijs_SBOM.json")],
            expected_CVEs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/CVEs/nginx.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/CVEs/mariadb.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/CVEs/wikijs.json")],
            expected_filtered_SBOMs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/nginx_entrypoint.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/wikijs.json",
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: False}
        )
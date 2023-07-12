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
            expected_filtered_SBOMs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/nginx.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/mariadb.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/wikijs.json")],
            expected_filtered_CVEs = [("nginx", "configurations/relevant_cves/expected-result/wikijs/filteredCVEs/nginx.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/filteredCVEs/mariadb.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/filteredCVEs/wikijs.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/wikijs.json",
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
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
            expected_filtered_SBOMs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/nginx.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/mariadb.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/wikijs.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/wikijs.json",
            helm_kwargs={statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_DISABLED},
            relevancy_enabled=False
        )
    
    @staticmethod
    def relevancy_enabled_stop_sniffing():
        from tests_scripts.helm.relevant_cve import RelevancyEnabledStopSniffingAfterTime
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            test_obj=RelevancyEnabledStopSniffingAfterTime,
            expected_SBOMs=[("redis-sleep", "configurations/relevant_cves/expected-result/wikijs/SBOM/redis_entrypoint_SBOM.json")],
            expected_filtered_SBOMs=[("redis-sleep", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/redis_sleep_long.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/redis-sleep.json",
            expected_filtered_CVEs = [("redis-sleep" ,"configurations/relevant_cves/expected-result/wikijs/filteredCVEs/redis_sleep_long.json")],
            expected_CVEs = [("redis-sleep", "configurations/relevant_cves/expected-result/wikijs/CVEs/redis_sleep_long.json")],
            helm_kwargs={statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}

        )
    
    @staticmethod
    def relevant_data_is_appended():
        from tests_scripts.helm.relevant_cve import RelevantDataIsAppended
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis-sleep"),
            test_obj=RelevantDataIsAppended,
            expected_SBOMs=[("redis-sleep", "configurations/relevant_cves/expected-result/wikijs/SBOM/redis_entrypoint_SBOM.json")],
            expected_filtered_SBOMs=[("redis-sleep", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/redis_sleep_long.json")],
            expected_updated_filtered_SBOMs=[("redis-sleep", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/redis_sleep.json")],
            expected_filtered_CVEs = [("redis-sleep" ,"configurations/relevant_cves/expected-result/wikijs/filteredCVEs/redis_sleep.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/redis-sleep.json",
            expected_CVEs = [("redis-sleep", "configurations/relevant_cves/expected-result/wikijs/CVEs/redis_sleep_long.json")],
            helm_kwargs={"nodeAgent.config.learningPeriod": "2m", statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
        )

    @staticmethod
    def relevancy_enabled_deleted_image():
        from tests_scripts.helm.relevant_cve import RelevancyEnabledDeletedImage
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "nginx_modified_entrypoint"),
            test_obj=RelevancyEnabledDeletedImage,
            expected_SBOMs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/SBOM/nginx_SBOM.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/SBOM/mariadb_SBOM.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/SBOM/wikijs_SBOM.json")],
            expected_CVEs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/CVEs/nginx.json"), ("mariadb", "configurations/relevant_cves/expected-result/wikijs/CVEs/mariadb.json"), ("wikijs", "configurations/relevant_cves/expected-result/wikijs/CVEs/wikijs.json")],
            expected_filtered_SBOMs=[("nginx", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/nginx_entrypoint.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/wikijs.json",
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_DISABLED}
        )
    

    @staticmethod
    def relevancy_large_image():
        from tests_scripts.helm.relevant_cve import RelevancyEnabledLargeImage
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            test_obj=RelevancyEnabledLargeImage,
            expected_SBOMs=[("redis", "configurations/relevant_cves/expected-result/wikijs/SBOM/redis_incomplete_SBOM.json")],
            expected_filtered_SBOMs=[("redis", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/incomplete.json")],
            helm_kwargs={statics.HELM_MAX_IMAGE_SIZE: 5, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
        )

    @staticmethod
    def relevancy_extra_large_image():
        from tests_scripts.helm.relevant_cve import RelevancyEnabledExtraLargeImage
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            test_obj=RelevancyEnabledExtraLargeImage,
            expected_SBOMs=[("redis", "configurations/relevant_cves/expected-result/wikijs/SBOM/redis_incomplete_SBOM.json")],
             expected_filtered_SBOMs=[("redis", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/incomplete.json")],
            helm_kwargs={statics.HELM_SCAN_TIMEOUT: "1ms", statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
        )
    
    @staticmethod
    def relevancy_storage_disabled():
        from tests_scripts.helm.relevant_cve import RelevancyStorageDisabled
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            test_obj=RelevancyStorageDisabled,
            helm_kwargs={statics.HELM_STORAGE_FEATURE: False, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_DISABLED}
        )
    
    @staticmethod
    def relevancy_fix_vuln():
        from tests_scripts.helm.relevant_cve import RelevancyFixVuln
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis"),
            expected_SBOMs=[("redis", "configurations/relevant_cves/expected-result/wikijs/SBOM/redis.json"), ("redis-fixed", "configurations/relevant_cves/expected-result/wikijs/SBOM/redis-fixed.json")],
            expected_CVEs=[("redis", "configurations/relevant_cves/expected-result/wikijs/CVEs/redis.json"), ("redis-fixed", "configurations/relevant_cves/expected-result/wikijs/CVEs/redis-fixed.json")],
            expected_filtered_SBOMs=[("redis", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/redis.json"), ("redis-fixed", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/redis-fixed.json")],
            expected_filtered_CVEs = [("redis" ,"configurations/relevant_cves/expected-result/wikijs/filteredCVEs/redis.json"), ("redis-fixed", "configurations/relevant_cves/expected-result/wikijs/filteredCVEs/redis-fixed.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/redis-fixed.json",
            test_obj=RelevancyFixVuln, 
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
        )


    @staticmethod
    def relevancy_python():
        from tests_scripts.helm.relevant_cve import RelevantCVEs
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "python-simple"),
            expected_SBOMs=[("python", "configurations/relevant_cves/expected-result/wikijs/SBOM/python-simple.json")],
            expected_CVEs= [("python", "configurations/relevant_cves/expected-result/wikijs/CVEs/python-simple.json")],
            expected_filtered_SBOMs=[("python", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/python-simple.json")],
            expected_filtered_CVEs =[("python", "configurations/relevant_cves/expected-result/wikijs/filteredCVEs/python-simple.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/python-simple.json",
            test_obj=RelevantCVEs,
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
        )
    
    @staticmethod
    def relevancy_golang():
        from tests_scripts.helm.relevant_cve import RelevantCVEs
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "golang-simple"),
            expected_SBOMs=[("golang", "configurations/relevant_cves/expected-result/wikijs/SBOM/golang-simple.json")],
            expected_CVEs=[("golang", "configurations/relevant_cves/expected-result/wikijs/CVEs/golang-simple.json")],
            expected_filtered_SBOMs=[("golang", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/golang-simple.json")],
            expected_filtered_CVEs = [("golang", "configurations/relevant_cves/expected-result/wikijs/filteredCVEs/golang-simple.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/golang-simple.json",
            test_obj=RelevantCVEs,
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
        )
    
    @staticmethod
    def relevancy_java():
        from tests_scripts.helm.relevant_cve import RelevantCVEs
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "java-simple"),
            expected_SBOMs=[("java", "configurations/relevant_cves/expected-result/wikijs/SBOM/java-simple.json")],
            expected_CVEs=[("java", "configurations/relevant_cves/expected-result/wikijs/CVEs/java-simple.json")],
            expected_filtered_SBOMs=[("java", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/java-simple.json")],
            expected_filtered_CVEs = [("java", "configurations/relevant_cves/expected-result/wikijs/filteredCVEs/java-simple.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/java-simple.json",
            test_obj=RelevantCVEs,
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
        )
    
    @staticmethod
    def relevancy_java_and_python():
        from tests_scripts.helm.relevant_cve import RelevantCVEs
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "java-and-python"),
            services=join(DEFAULT_SERVICE_PATH, "java-server"),
            expected_SBOMs=[("python", "configurations/relevant_cves/expected-result/wikijs/SBOM/python-simple.json"), ("java", "configurations/relevant_cves/expected-result/wikijs/SBOM/java-simple.json")],
            expected_CVEs= [("python", "configurations/relevant_cves/expected-result/wikijs/CVEs/python-simple.json"), ("java", "configurations/relevant_cves/expected-result/wikijs/CVEs/java-simple.json")],
            expected_filtered_SBOMs=[("python", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/python-client-to-java.json"), ("java", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/java-simple.json")],
            expected_filtered_CVEs =[("python", "configurations/relevant_cves/expected-result/wikijs/filteredCVEs/python-client-to-java.json"), ("java", "configurations/relevant_cves/expected-result/wikijs/filteredCVEs/java-simple.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/java-and-python.json",
            test_obj=RelevantCVEs,
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
        )
    
    @staticmethod
    def relevancy_golang_dynamic():
        from tests_scripts.helm.relevant_cve import RelevantCVEs
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "golang-simple-dynamic"),
            expected_SBOMs=[("golang", "configurations/relevant_cves/expected-result/wikijs/SBOM/golang-dynamic-simple.json")],
            expected_CVEs= [("golang", "configurations/relevant_cves/expected-result/wikijs/CVEs/golang-dynamic-simple.json")],
            expected_filtered_SBOMs=[("golang", "configurations/relevant_cves/expected-result/wikijs/filteredSBOM/golang-dynamic-simple.json")],
            expected_filtered_CVEs =[("golang", "configurations/relevant_cves/expected-result/wikijs/filteredCVEs/golang-dynamic-simple.json")],
            expected_results= "configurations/relevant_cves/expected-result/wikijs/BE_CVEs/golang-dynamic.json",
            test_obj=RelevantCVEs,
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True, statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
        )
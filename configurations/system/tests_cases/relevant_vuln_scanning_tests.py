import inspect

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
            expected_SBOMs=[("nginx", "configurations/expected-result/SBOM/nginx.json"),
                            ("mariadb", "configurations/expected-result/SBOM/mariadb.json"),
                            ("wikijs", "configurations/expected-result/SBOM/wikijs.json")],
            expected_CVEs=[("nginx", "configurations/expected-result/CVEs/nginx.json"),
                           ("mariadb", "configurations/expected-result/CVEs/mariadb.json"),
                           ("wikijs", "configurations/expected-result/CVEs/wikijs.json")],
            expected_filtered_CVEs=[
                ("nginx", "configurations/expected-result/filteredCVEs/nginx.json"),
                ("mariadb", "configurations/expected-result/filteredCVEs/mariadb.json"),
                ("wikijs", "configurations/expected-result/filteredCVEs/wikijs.json")],
            expected_results="configurations/expected-result/BE_CVEs/wikijs.json",
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
        )

    @staticmethod
    def relevancy_multiple_containers():
        from tests_scripts.helm.relevant_cve import RelevantCVEs
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "collection"),
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "collection"),
            services=join(DEFAULT_SERVICE_PATH, "collection"),
            test_obj=RelevantCVEs,
            expected_SBOMs=[("alpine-container", "configurations/expected-result/SBOM/alpine.json"),
                            ("redis", "configurations/expected-result/SBOM/redis.json"),
                            ("wordpress", "configurations/expected-result/SBOM/wordpress.json"),
                            ("busybox", "configurations/expected-result/SBOM/busybox.json"),
                            ("alpine", "configurations/expected-result/SBOM/alpine.json")],
            expected_CVEs=[("alpine-container", "configurations/expected-result/CVEs/alpine.json"),
                           ("redis", "configurations/expected-result/CVEs/redis.json"),
                           ("wordpress", "configurations/expected-result/CVEs/wordpress.json"),
                           ("busybox", "configurations/expected-result/CVEs/busybox.json"),
                           ("alpine", "configurations/expected-result/CVEs/alpine.json")],
            expected_filtered_CVEs=[("alpine-container", "configurations/expected-result/filteredCVEs/alpine.json"),
                                    ("redis", "configurations/expected-result/filteredCVEs/redis-collection.json"),
                                    ("wordpress", "configurations/expected-result/filteredCVEs/wordpress.json")],
            helm_kwargs={statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED,
                         "nodeAgent.config.learningPeriod": "2m",
                         "nodeAgent.config.updatePeriod": "0.5m"
                         }
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
            expected_SBOMs=[("nginx", "configurations/expected-result/SBOM/nginx.json"),
                            ("mariadb", "configurations/expected-result/SBOM/mariadb.json"),
                            ("wikijs", "configurations/expected-result/SBOM/wikijs.json")],
            expected_CVEs=[("nginx", "configurations/expected-result/CVEs/nginx.json"),
                           ("mariadb", "configurations/expected-result/CVEs/mariadb.json"),
                           ("wikijs", "configurations/expected-result/CVEs/wikijs.json")],
            expected_results="configurations/expected-result/BE_CVEs/wikijs.json",
            helm_kwargs={statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_DISABLED},
            relevancy_enabled=False
        )

    @staticmethod
    def relevancy_enabled_stop_sniffing():
        from tests_scripts.helm.relevant_cve import RelevantDataIsAppended
        from systest_utils import statics
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis-sleep"),
            test_obj=RelevantDataIsAppended,
            expected_SBOMs=[
                ("redis-sleep", "configurations/expected-result/SBOM/redis_sleep.json")],
            expected_CVEs=[
                ("redis-sleep", "configurations/expected-result/CVEs/redis_sleep.json")],
            expected_filtered_CVEs=[
                ("redis-sleep", "configurations/expected-result/filteredCVEs/redis_sleep.json")],
            expected_updated_filtered_CVEs=[("redis-sleep",
                                             "configurations/expected-result/filteredCVEs/redis_sleep.json")],
            helm_kwargs={statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED,
                         "nodeAgent.config.learningPeriod": "0.5m",
                         "nodeAgent.config.updatePeriod": "0.5m",
                         "nodeAgent.config.maxLearningPeriod": "2m"}

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
            expected_SBOMs=[
                ("redis-sleep", "configurations/expected-result/SBOM/redis_sleep.json")],
            expected_CVEs=[
                ("redis-sleep", "configurations/expected-result/CVEs/redis_sleep.json")],
            expected_filtered_CVEs=[
                ("redis-sleep", "configurations/expected-result/filteredCVEs/redis_sleep.json")],
            expected_updated_filtered_CVEs=[("redis-sleep",
                                             "configurations/expected-result/filteredCVEs/redis_sleep_updated.json")],
            helm_kwargs={"nodeAgent.config.learningPeriod": "0.5m",
                         "nodeAgent.config.updatePeriod": "0.5m",
                         statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
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
            expected_SBOMs=[("nginx", "configurations/expected-result/SBOM/nginx.json"),
                            ("mariadb", "configurations/expected-result/SBOM/mariadb.json"),
                            ("wikijs", "configurations/expected-result/SBOM/wikijs.json")],
            expected_CVEs=[("nginx", "configurations/expected-result/CVEs/nginx.json"),
                           ("mariadb", "configurations/expected-result/CVEs/mariadb.json"),
                           ("wikijs", "configurations/expected-result/CVEs/wikijs.json")],
            expected_results="configurations/expected-result/BE_CVEs/wikijs.json",
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_DISABLED}
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
            expected_SBOMs=[
                ("redis", "configurations/expected-result/SBOM/redis_incomplete.json")],
            helm_kwargs={statics.HELM_MAX_IMAGE_SIZE: 5, statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
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
            expected_SBOMs=[
                ("redis", "configurations/expected-result/SBOM/redis_incomplete.json")],
            helm_kwargs={statics.HELM_SCAN_TIMEOUT: "1ms", statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
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
            helm_kwargs={statics.HELM_STORAGE_FEATURE: False,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_DISABLED}
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
            expected_SBOMs=[("redis", "configurations/expected-result/SBOM/redis.json"), (
                "redis-fixed", "configurations/expected-result/SBOM/redis-fixed.json")],
            expected_CVEs=[("redis", "configurations/expected-result/CVEs/redis.json"), (
                "redis-fixed", "configurations/expected-result/CVEs/redis-fixed.json")],
            expected_filtered_CVEs=[
                ("redis", "configurations/expected-result/filteredCVEs/redis.json"),
                ("redis-fixed", "configurations/expected-result/filteredCVEs/redis-fixed.json")],
            expected_results="configurations/expected-result/BE_CVEs/redis-fixed.json",
            test_obj=RelevancyFixVuln,
            helm_kwargs={statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
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
            expected_SBOMs=[("python", "configurations/expected-result/SBOM/python-simple.json")],
            expected_CVEs=[("python", "configurations/expected-result/CVEs/python-simple.json")],
            expected_filtered_CVEs=[
                ("python", "configurations/expected-result/filteredCVEs/python-simple.json")],
            expected_results="configurations/expected-result/BE_CVEs/python-simple.json",
            test_obj=RelevantCVEs,
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
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
            expected_SBOMs=[("golang", "configurations/expected-result/SBOM/golang-simple.json")],
            expected_CVEs=[("golang", "configurations/expected-result/CVEs/golang-simple.json")],
            expected_filtered_CVEs=[
                ("golang", "configurations/expected-result/filteredCVEs/golang-simple.json")],
            expected_results="configurations/expected-result/BE_CVEs/golang-simple.json",
            test_obj=RelevantCVEs,
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
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
            expected_SBOMs=[("java", "configurations/expected-result/SBOM/java-simple.json")],
            expected_CVEs=[("java", "configurations/expected-result/CVEs/java-simple.json")],
            expected_filtered_CVEs=[
                ("java", "configurations/expected-result/filteredCVEs/java-simple.json")],
            expected_results="configurations/expected-result/BE_CVEs/java-simple.json",
            test_obj=RelevantCVEs,
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
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
            expected_SBOMs=[("python", "configurations/expected-result/SBOM/python-simple.json"),
                            ("java", "configurations/expected-result/SBOM/java-simple.json")],
            expected_CVEs=[("python", "configurations/expected-result/CVEs/python-simple.json"),
                           ("java", "configurations/expected-result/CVEs/java-simple.json")],
            expected_filtered_CVEs=[("python",
                                     "configurations/expected-result/filteredCVEs/python-client-to-java.json"),
                                    ("java",
                                     "configurations/expected-result/filteredCVEs/java-simple.json")],
            expected_results="configurations/expected-result/BE_CVEs/java-and-python.json",
            test_obj=RelevantCVEs,
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
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
            expected_SBOMs=[
                ("golang", "configurations/expected-result/SBOM/golang-dynamic-simple.json")],
            expected_CVEs=[
                ("golang", "configurations/expected-result/CVEs/golang-dynamic-simple.json")],
            expected_filtered_CVEs=[("golang",
                                     "configurations/expected-result/filteredCVEs/golang-dynamic-simple.json")],
            expected_results="configurations/expected-result/BE_CVEs/golang-dynamic.json",
            test_obj=RelevantCVEs,
            helm_kwargs={"triggerNewImageScan": True, statics.HELM_STORAGE_FEATURE: True,
                         statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED}
        )

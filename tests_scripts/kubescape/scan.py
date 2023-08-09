import copy
import os
import subprocess
from time import perf_counter
import time
import json

from configurations.system.git_repository import GitRepository
from systest_utils import Logger, TestUtil, statics
from .base_kubescape import (
    _CLI_SKIPPED_RESOURCES_FIELD,
    BaseKubescape,
    _CLI_RESULTS_FIELD,
    _CLI_PASSED_RESOURCES_FIELD,
    _CLI_FAILED_RESOURCES_FIELD,
    _CLI_EXCLUDED_RESOURCES_FIELD,
    _CLI_SUMMARY_DETAILS_FIELD,
    _CLI_RESOURCE_COUNTERS_FIELD,
    _CLI_RESOURCES_FIELD,
    _CLI_FRAMEWORKS_FIELD,
    _CLI_NAME_FIELD
)


class Scan(BaseKubescape):

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(Scan, self).__init__(test_obj=test_obj, backend=backend,
                                   kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        Logger.logger.info("Installing kubescape")
        # Logger.logger.info(self.install())
        self.install(branch=self.ks_branch)

        Logger.logger.info("Scanning kubescape")
        result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name)

        Logger.logger.info("Testing results")
        self.test_counters(framework_report=result)

        return self.cleanup()


class ScanUrl(BaseKubescape):

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanUrl, self).__init__(test_obj=test_obj, backend=backend,
                                      kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        Logger.logger.info("Installing kubescape")
        # Logger.logger.info(self.install())
        self.install(branch=self.ks_branch)

        Logger.logger.info("Scanning kubescape")
        result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                                   url=self.test_obj.get_arg("url"))

        TestUtil.sleep(25, "wait for kubescape scan to report", "info")
        
        Logger.logger.info("Testing results")
        self.test_counters(framework_report=result)

        return self.cleanup()


class ScanWithExceptions(BaseKubescape):

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanWithExceptions, self).__init__(test_obj=test_obj, backend=backend,
                                                 kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        Logger.logger.info("Installing kubescape")
        # Logger.logger.info(self.install())
        self.install(branch=self.ks_branch)

        Logger.logger.info("Scanning kubescape")
        exception_file = BaseKubescape.get_abs_path(statics.DEFAULT_EXCEPTIONS_PATH,
                                                    [self.test_obj.get_arg("exceptions")])
        self.override_exceptions_file(exception_file=exception_file)
        result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                                   exceptions=''.join(exception_file))
        control_test = self.test_obj.get_arg("controls_tested")
        Logger.logger.info("Testing results")
        self.test_exception_result(framework_report=result, controls_with_exception=control_test)

        return self.cleanup()

    def override_exceptions_file(self, exception_file):
        # Kubescape supports input from a single source, so, when artifacts and exceptions are the input, we must override the exceptions file in theartifacts directory.
        # This is a patch, the correct solution is to combine both file.
        # The real solution is for Kubescape to support such cases
        if self.artifacts:
            import shutil
            shutil.copy(exception_file[0], os.path.join(self.artifacts, "exceptions.json"))


class ScanComplianceScore(BaseKubescape):

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanComplianceScore, self).__init__(test_obj=test_obj, backend=backend,
                                                 kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        # test Agenda:
        # 1. run kubescape scan
        # 2. check the compliance score per control matches the resource counters
        # 3. check the framework compliance score is the average of its controls
        # 4. check controls compliance score from backend api /api/v1/posture/controls
        # 5. check the framework compliance score from backend api /api/v1/posture/frameworks
        # 6. check the framework compliance score from backend api /api/v1/posture/clustersOvertime
        
        Logger.logger.info("Installing kubescape")
        # Logger.logger.info(self.install())
        self.install(branch=self.ks_branch)

        Logger.logger.info("Scanning kubescape")
        result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                                   submit=self.test_obj.get_arg("submit"), account=self.test_obj.get_arg("account"))

        Logger.logger.info("Testing results")

        Logger.logger.info("Testing results in controls")
        self.test_controls_compliance_score(report=result)

        Logger.logger.info("Testing results in frameworks")
        self.test_frameworks_compliance_score(report=result)

        TestUtil.sleep(25, "wait for kubescape scan to report", "info")

        Logger.logger.info("Testing data in backend")
        # get first framework name from policy_name, until first ','
        framework_name = self.test_obj.get_arg("policy_name").split(',')[0].upper()
        report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(), wait_to_result=True,
                                               framework_name=framework_name)
        assert report_guid != "", "report guid is empty"

        for framework_report in result[_CLI_SUMMARY_DETAILS_FIELD][_CLI_FRAMEWORKS_FIELD]:
            Logger.logger.info("Testing results from backend in controls")
            self.test_controls_compliance_score_from_backend(framework_name=framework_report[_CLI_NAME_FIELD], report_guid=report_guid,
                                                             framework_report=framework_report)

            Logger.logger.info("Testing results from backend in frameworks")
            self.test_frameworks_compliance_score_from_backend(framework_report=framework_report, report_guid=report_guid, framework_name=framework_report[_CLI_NAME_FIELD])

            Logger.logger.info("Testing results in clusters overtime")
            self.test_compliance_score_in_clusters_overtime(cluster_name=self.kubernetes_obj.get_cluster_name(),
                                                            framework_name=framework_report[_CLI_NAME_FIELD],framework_report=framework_report)
        

        return self.cleanup()


class ScanLocalFile(BaseKubescape):

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanLocalFile, self).__init__(test_obj=test_obj, backend=backend,
                                            kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        Logger.logger.info("Installing kubescape")
        # Logger.logger.info(self.install())
        self.install(branch=self.ks_branch)

        Logger.logger.info("Scanning kubescape")
        files = BaseKubescape.get_abs_path(statics.DEFAULT_INPUT_YAML_PATH, self.test_obj.get_arg("yamls"))
        result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                                   yamls=files)

        Logger.logger.info("Testing results")
        self.number_of_resources(framework_report=result, resources=self.test_obj.get_arg("resources"))

        return self.cleanup()


class ScanAndSubmitToBackend(BaseKubescape):

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanAndSubmitToBackend, self).__init__(test_obj=test_obj, backend=backend,
                                                     kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        Logger.logger.info("Installing kubescape")
        # Logger.logger.info(self.install())

        self.install(branch=self.ks_branch)

        Logger.logger.info('Stage 1.1: apply namespace "system-test" to cluster')
        namespace = self.create_namespace(name=self.test_obj.get_arg("namespace"), auto_attach=False,
                                          auto_protect=False)
        Logger.logger.info('Stage 1.2: apply deployment "apache" to cluster')
        self.apply_yaml_file(yaml_file=self.test_obj.get_arg("yaml"), namespace=namespace)
        TestUtil.sleep(30, "wait for report guid", "info")

        old_report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(), wait_to_result=False,
                                               framework_name=self.test_obj.get_arg("policy_name"))

        Logger.logger.info("Scanning kubescape")
        cli_result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                                       submit=self.test_obj.get_arg("submit"), account=self.test_obj.get_arg("account"))

        TestUtil.sleep(60, "wait for kubescape scan to report", "info")

        Logger.logger.info("Testing data in backend")
        self.test_data_in_be(cli_result=cli_result, cluster_name=self.kubernetes_obj.get_cluster_name(),
                             framework_name=(self.test_obj.get_arg("policy_name")),
                             old_report_guid=old_report_guid)

        return self.cleanup()


class ScanWithExceptionToBackend(BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanWithExceptionToBackend, self).__init__(test_obj=test_obj, backend=backend,
                                                         kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        # test Agenda:
        # 1. Apply namespace "system-test" and Deployment "apache" to cluster
        # 2. Scanning kubescape without exception and test result with backend
        # 3. Add exception to backend and test with backend
        # 4. Scanning kubescape with exception and test result with backend
        # 5. Delete exception object from backend and test with backend
        # 6. Scanning kubescape after deleting the exception and test result with backend

        resource = 'apache'
        control_id = "C-0016"
        control_name = "Allow privilege escalation"
        #second resource exception (by resource ID)
        resource_1 = 'default'
        control_id_1 = "C-0034"
        control_name_1 = "Allow privilege escalation"
        
        exceptionFiles = self.test_obj.get_arg("exceptions").split(',')

        Logger.logger.info("Installing kubescape")
        # Logger.logger.info(self.install())
        self.install()

        Logger.logger.info("Delete all exception from backend")
        self.backend.delete_all_posture_exceptions(cluster_name=self.kubernetes_obj.get_cluster_name())

        old_report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(), wait_to_result=False,
                                               framework_name=self.test_obj.get_arg("policy_name").upper())
        TestUtil.sleep(30, "wait for report guid", "info")

        Logger.logger.info('Stage 1: Apply namespace "system-test" and Deployment "apache" to cluster')
        Logger.logger.info('Stage 1.1: apply namespace "system-test" to cluster')
        namespace = self.create_namespace(name='system-test', auto_attach=False, auto_protect=False)
        Logger.logger.info('Stage 1.2: apply deployment "apache" to cluster')
        self.apply_yaml_file(yaml_file=self.test_obj.get_arg("yaml"), namespace=namespace)

        Logger.logger.info("Stage 2: Scanning kubescape without exception and test result with backend")
        Logger.logger.info("Stage 2.1: Scanning kubescape without exception")
        self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                          submit=self.test_obj.get_arg("submit"), account=self.test_obj.get_arg("account"))

        TestUtil.sleep(60, "wait for kubescape scan to report", "info")

        first_report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(),
                                                 framework_name=self.test_obj.get_arg("policy_name").upper(),
                                                 old_report_guid=old_report_guid)

        Logger.logger.info("Stage 2.2: Check if exception-applied empty and exception-related empty")
        self.test_related_applied_in_be(control_name=control_name, control_id=control_id, resource_name=resource,
                                        report_guid=first_report_guid, has_related=False, has_applied=False,
                                        framework_name=self.test_obj.get_arg("policy_name").upper())
        Logger.logger.info("Stage 2.2.1: Check 2nd control if exception-applied empty and exception-related empty")
        self.test_related_applied_in_be(control_name=control_name_1, control_id=control_id_1, resource_name=resource_1,
                                        report_guid=first_report_guid, has_related=False, has_applied=False,
                                        framework_name=self.test_obj.get_arg("policy_name").upper(),namespace="system-test")

        Logger.logger.info("Stage 2.3: Verify download of controls and resources")
        self.get_posture_controls_CSV(framework_name=self.test_obj.get_arg("policy_name").upper(),
                                      report_guid=first_report_guid)
        self.get_posture_resources_CSV(framework_name=self.test_obj.get_arg("policy_name").upper(),
                                       report_guid=first_report_guid)

        Logger.logger.info("Stage 3: Add exception to backend and test with backend")
        Logger.logger.info("Stage 3.1: Add exception to backend")
        policy_guid = self.post_posture_exception(exceptions_file=exceptionFiles[0],
                                                  cluster_name=self.kubernetes_obj.get_cluster_name())
        Logger.logger.info("Stage 3.1.1: Add 2nd exception to backend")
        policy_guid_1 = self.post_posture_exception(exceptions_file=exceptionFiles[1],
                                                  cluster_name=self.kubernetes_obj.get_cluster_name())

        Logger.logger.info("Stage 3.2: Check if exception-applied empty and exception-deployed not empty")
        self.test_related_applied_in_be(control_name=control_name, control_id=control_id, resource_name=resource,
                                        report_guid=first_report_guid, has_related=True, has_applied=False,
                                        framework_name=self.test_obj.get_arg("policy_name").upper())
        Logger.logger.info("Stage 3.2.1: Check 2nd control if exception-applied empty and exception-deployed not empty")
        self.test_related_applied_in_be(control_name=control_name_1, control_id=control_id_1, resource_name=resource_1,
                                        report_guid=first_report_guid, has_related=True, has_applied=False,
                                        framework_name=self.test_obj.get_arg("policy_name").upper(),namespace="system-test")

        Logger.logger.info("Stage 4: Scanning kubescape with exception and test result with backend")
        Logger.logger.info("Stage 4.1: Scanning kubescape with exception")
        self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                          submit=self.test_obj.get_arg("submit"), account=self.test_obj.get_arg("account"))
        
        TestUtil.sleep(60, "wait for kubescape scan to report", "info")
        
        second_report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(),
                                                  framework_name=self.test_obj.get_arg("policy_name").upper(),
                                                  old_report_guid=first_report_guid)

        Logger.logger.info("Stage 4.2: Check if exception-applied not empty and exception-deployed not empty")
        self.test_related_applied_in_be(control_name=control_name, control_id=control_id, resource_name=resource,
                                        report_guid=second_report_guid, has_related=True, has_applied=True,
                                        framework_name=self.test_obj.get_arg("policy_name").upper())
        Logger.logger.info("Stage 4.2.1: Check for 2nd control if exception-applied not empty and exception-deployed not empty")
        self.test_related_applied_in_be(control_name=control_name_1, control_id=control_id_1, resource_name=resource_1,
                                        report_guid=second_report_guid, has_related=True, has_applied=True,
                                        framework_name=self.test_obj.get_arg("policy_name").upper(),namespace="system-test")
        # Test for cli-result
        # TODO self.test_exception_result(framework_report=cli_result)
        # Test for backend-result
        Logger.logger.info("Stage 4.3: Test data from controls-api, from backend")
        self.test_exception_in_controls(framework_name=(self.test_obj.get_arg("policy_name")).upper(),
                                        report_guid=second_report_guid, control_id=control_id)
        Logger.logger.info("Stage 4.3.1: Test data of 2nd from controls-api, from backend")
        self.test_exception_in_controls(framework_name=(self.test_obj.get_arg("policy_name")).upper(),
                                        report_guid=second_report_guid, control_id=control_id_1)

        Logger.logger.info("Stage 5: Delete exception object from backend and test with backend")
        Logger.logger.info("Stage 5.1: Delete exception object from backend")
        self.delete_posture_exception(policy_guid=policy_guid)
        Logger.logger.info("Stage 5.1: Delete 2nd exception object from backend")
        self.delete_posture_exception(policy_guid=policy_guid_1)

        Logger.logger.info("Stage 5.2: Check if exception-applied not empty and exception-deployed empty")
        self.test_related_applied_in_be(control_name=control_name, control_id=control_id, resource_name=resource,
                                        report_guid=second_report_guid, has_related=False, has_applied=True,
                                        framework_name=self.test_obj.get_arg("policy_name").upper())
        Logger.logger.info("Stage 5.2.1: Check if 2nd exception-applied not empty and exception-deployed empty")
        self.test_related_applied_in_be(control_name=control_name_1, control_id=control_id_1, resource_name=resource_1,
                                        report_guid=second_report_guid, has_related=False, has_applied=True,
                                        framework_name=self.test_obj.get_arg("policy_name").upper(),namespace="system-test")

        Logger.logger.info("Stage 6: Scanning kubescape after deleting the exception and test result with backend")
        Logger.logger.info("Stage 6.1: Scanning kubescape after deleting the exception")
        self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                          submit=self.test_obj.get_arg("submit"), account=self.test_obj.get_arg("account"))

        TestUtil.sleep(60, "wait for kubescape scan to report", "info")
        
        third_report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(),
                                                 framework_name=self.test_obj.get_arg("policy_name").upper(),
                                                 old_report_guid=second_report_guid)

        Logger.logger.info("Stage 6.2: Check if exception-applied empty and exception-deployed empty")
        self.test_related_applied_in_be(control_name=control_name, control_id=control_id, resource_name=resource,
                                        report_guid=third_report_guid, has_related=False, has_applied=False,
                                        framework_name=self.test_obj.get_arg("policy_name").upper())
        Logger.logger.info("Stage 6.2.1: Check if 2nd exception-applied empty and exception-deployed empty")
        self.test_related_applied_in_be(control_name=control_name_1, control_id=control_id_1, resource_name=resource_1,
                                        report_guid=third_report_guid, has_related=False, has_applied=False,
                                        framework_name=self.test_obj.get_arg("policy_name").upper(),namespace="system-test")


        return self.cleanup()

    def cleanup(self):
        Logger.logger.info("Delete all exception from backend")
        self.backend.delete_all_posture_exceptions(cluster_name=self.kubernetes_obj.get_cluster_name())

        return super().cleanup()


class ScanWithCustomFramework(BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanWithCustomFramework, self).__init__(test_obj=test_obj, backend=backend,
                                                      kubernetes_obj=kubernetes_obj, test_driver=test_driver)
        self.report_fw = None

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        # test Agenda:
        # 1. Add custom framework to backend and check if success
        # 2. Scanning kubescape with custom framework and test result
        # 3. Delete custom-framework from backend and check if success

        Logger.logger.info("Installing kubescape")
        # Logger.logger.info(self.install())
        self.install()

        Logger.logger.info("Stage 1: Add custom framework to backend and check if success")
        Logger.logger.info("Stage 1.1: Add custom framework to backend")
        fw_object, self.report_fw = self.post_custom_framework(framework_file=self.test_obj.get_arg("framework_file"),
                                                               cluster_name=self.kubernetes_obj.get_cluster_name())
        Logger.logger.info("Stage 1.2: Get old report-guid")
        old_report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(), wait_to_result=False,
                                               framework_name=self.report_fw['name'])

        Logger.logger.info("Stage 1.3: Check if framework created")
        self.test_framework_created(fw_object=fw_object, report_fw=self.report_fw)

        Logger.logger.info("Stage 2: Scanning kubescape with custom framework and test result")
        Logger.logger.info("Stage 2.1: Scanning kubescape with custom-fw")
        cli_result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.report_fw['name'],
                                       submit=self.test_obj.get_arg("submit"), account=self.test_obj.get_arg("account"))
        
        TestUtil.sleep(25, "wait for kubescape scan to report", "info")
        Logger.logger.info("Stage 2.2: Get report-guid")
        report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(),
                                           framework_name=self.report_fw['name'], old_report_guid=old_report_guid)

        Logger.logger.info("Stage 2.3: Test cli result vs backend result")
        self.test_scan_custom_fw_result(cli_result=cli_result, fw_object=fw_object, report_guid=report_guid)

        Logger.logger.info("Stage 3: Delete custom-framework from backend and check if success")
        Logger.logger.info("Stage 3.1: Delete custom-fw object from backend")
        self.delete_custom_framework(ks_custom_fw=self.report_fw)
        fw_name = self.report_fw['name']
        self.report_fw = None
        Logger.logger.info("Stage 3.2: Test custom framework deleted")
        self.test_scan_custom_fw_deleted(fw_name)

        return self.cleanup()

    def cleanup(self):
        try:
            if self.report_fw:
                Logger.logger.info("Delete custom-fw object from backend")
                self.delete_custom_framework(ks_custom_fw=self.report_fw)
        except:
            Logger.logger.warning("Failed to delete custom-framework from backend")

        return super().cleanup()


class CustomerConfiguration(BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(CustomerConfiguration, self).__init__(test_obj=test_obj, backend=backend,
                                                    kubernetes_obj=kubernetes_obj, test_driver=test_driver)
        self.original_customer_configuration = None

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        # test Agenda:
        # 1. scan yaml file and check expected result that control X without configuration Y passed
        # 2. apply control configuration to backend
        # 3.1. download from kubescape control-input and checks if it has been updated
        # 3.2. scan yaml file and check expected result that control X without configuration Y failed
        # 4. delete control configuration from backend
        # 5. download from kubescape control-input and checks if it has been updated

        Logger.logger.info("Installing kubescape")
        # Logger.logger.info(self.install())

        self.install(branch=self.ks_branch)
        files = BaseKubescape.get_abs_path(statics.DEFAULT_INPUT_YAML_PATH, self.test_obj.get_arg("yaml"))

        Logger.logger.info("Stage 1.1: Scan yaml file")
        result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                                   submit=self.test_obj.get_arg("submit"), account=self.test_obj.get_arg("account"),
                                   yamls=files)
        TestUtil.sleep(25, "wait for kubescape scan to report", "info")    
        Logger.logger.info("Stage 1.2: Test expected result that control X without configuration Y skipped")
        self.test_customer_configuration_result(cli_result=result, expected_result='skipped',
                                                c_id=self.test_obj.policy_name)

        Logger.logger.info("Stage 2: Apply control configuration to backend")
        self.original_customer_configuration = self.get_customer_configuration()
        self.original_customer_configuration['name'] = 'CustomerConfig'
        self.original_customer_configuration['attributes'] = {}
        self.add_to_customer_configuration(customer_configuration=copy.deepcopy(self.original_customer_configuration),
                                           input_kind=self.test_obj.get_arg('input_kind'),
                                           input_name=self.test_obj.get_arg('input_name'))

        Logger.logger.info("Stage 3.1: Test control input in kubescape")
        self.test_control_input_in_kubescape(input_kind=self.test_obj.get_arg('input_kind'), input_name=self.test_obj.
                                             get_arg('input_name'), included=True)

        Logger.logger.info("Stage 3.2: Test expected result that control X with configuration Y failed")
        result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                                   submit=self.test_obj.get_arg("submit"), account=self.test_obj.get_arg("account"),
                                   yamls=files)
        
        TestUtil.sleep(25, "wait for kubescape scan to report", "info")
        
        self.test_customer_configuration_result(cli_result=result, expected_result='failed',
                                                c_id=self.test_obj.policy_name)

        Logger.logger.info("Stage 4: delete control configuration to backend")
        self.update_customer_configuration(customer_config=self.original_customer_configuration)

        Logger.logger.info("Stage 5: Test control input in kubescape")
        self.test_control_input_in_kubescape(input_kind=self.test_obj.get_arg('input_kind'), input_name=self.test_obj.
                                             get_arg('input_name'), included=False)

        return self.cleanup()

    def cleanup(self):
        if self.original_customer_configuration:
            try:
                self.update_customer_configuration(customer_config=self.original_customer_configuration)
            except:
                Logger.logger.warning("Failed to return to first customer_config")

        return super().cleanup()


class OfflineSupport(BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(OfflineSupport, self).__init__(test_obj=test_obj, backend=backend,
                                             kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        # test Agenda:
        # 1. apply deployment apache to namespace system-test
        # 2. download artifact
        # 3. run kubescape using artifact (without submit)
        # 4. test result against expected results

        Logger.logger.info("Installing kubescape")
        self.install(branch=self.ks_branch)

        Logger.logger.info('Stage 1.1: apply namespace "system-test" to cluster')
        namespace = self.create_namespace(name=self.test_obj.get_arg("namespace"), auto_attach=False,
                                          auto_protect=False)
        Logger.logger.info('Stage 1.2: apply deployment "apache" to cluster')
        self.apply_yaml_file(yaml_file=self.test_obj.get_arg("yaml"), namespace=namespace)

        Logger.logger.info('Stage 2: download artifact')
        artifact = self.download_artifact()

        Logger.logger.info('Stage 3: run kubescape using artifact (without submit)')
        result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                                   use_artifacts=artifact, include_namespaces=namespace)

        Logger.logger.info('test result against expected results')
        self.test_expected_result_against_cli_result(cli_result=result,
                                                     expected_result_name=self.test_obj.get_arg('expected_results'))
        return self.cleanup()


class HostScanner(BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(HostScanner, self).__init__(test_obj=test_obj, backend=backend,
                                          kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        Logger.logger.info("Installing kubescape")
        self.install(branch=self.ks_branch)

        Logger.logger.info("Scanning kubescape")
        result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.policy_name,
                                   enable_host_scan=True)

        Logger.logger.info("Test cli_result containing status = skipped")
        self.test_host_scanner_results(cli_results=result)

        return self.cleanup()


class ScanGitRepositoryAndSubmit(BaseKubescape):
    def __init__(
            self,
            test_obj=None,
            backend=None,
            kubernetes_obj=None,
            test_driver=None,
    ):
        super(ScanGitRepositoryAndSubmit, self).__init__(
            test_obj=test_obj,

            backend=backend,
            kubernetes_obj=kubernetes_obj,
            test_driver=test_driver,
        )

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        Logger.logger.info("Installing kubescape")

        self.install(branch=self.ks_branch)

        should_clone_before = self.test_obj.get_arg("clone_before")
        git_repository = self.test_obj.get_arg("git_repository")
        if not isinstance(git_repository, GitRepository):
            raise Exception("test expected git_repository arg to be a GitRepository instance")

        # Check for existing previous report
        old_report_guid, repo_hash = self.get_report_guid_and_repo_hash_for_git_repository(git_repository,
                                                                                               wait_to_result=False)
        if repo_hash is not None:
            Logger.logger.info(f"Running test cleanup - deleting repository ({repo_hash})")
            self.backend.delete_repository(repository_hash=repo_hash)

        Logger.logger.info("Scanning with kubescape")

        if should_clone_before:
            # Local Git Folder
            temp_dir = os.path.abspath(
                os.path.join(self.test_driver.temp_dir, "repo_clone")
            )
            os.system(f'git clone -b {git_repository.branch} {git_repository.url} "{temp_dir}"')
            kubescape_report = self.default_scan(
                policy_scope=self.test_obj.policy_scope,
                policy_name=self.test_obj.policy_name,
                submit=self.test_obj.get_arg("submit"),
                account=self.test_obj.get_arg("account"),
                path=temp_dir,
            )
        else:
            # Remote URL
            kubescape_report = self.default_scan(
                policy_scope=self.test_obj.policy_scope,
                policy_name=self.test_obj.policy_name,
                submit=self.test_obj.get_arg("submit"),
                account=self.test_obj.get_arg("account"),
                url=git_repository.url,
            )
            
        TestUtil.sleep(25, "wait for kubescape scan to report", "info")
        Logger.logger.info("Testing kubescape results")
        self.test_counters(framework_report=kubescape_report)

        # Check that all relevant resources have a source
        relevant_resources = [resource for resource in kubescape_report[_CLI_RESOURCES_FIELD]
                              if
                              not 'rbac.authorization' in resource['resourceID'] and 'apiVersion' in resource['object']]
        relevant_resources_without_source = [resource['resourceID'] for resource in relevant_resources if
                                             'source' not in resource]
        assert len(
            relevant_resources_without_source) == 0, f"The following resources are missing source: {','.join(relevant_resources_without_source)}"

        Logger.logger.info("Fetching repo posture report from backend")
        new_report_guid, repo_hash = self.get_report_guid_and_repo_hash_for_git_repository(git_repository,
                                                                                               wait_to_result=True)
        Logger.logger.info("Testing repository summary")
        repo_summary = None
        for _ in range(5):
            repo_summaries = self.backend.get_repository_posture_repositories_by_report_guid(new_report_guid)
            if len(repo_summaries) != 0:
                repo_summary = repo_summaries[0]
                break
            else:
                time.sleep(5)

        assert repo_summary, f"ReportGUID was found ({new_report_guid}) but repository summary API returned an empty result"

        designators_attributes = repo_summary["designators"]["attributes"]
        assert designators_attributes[
                   "repoName"] == git_repository.name, f"Expected repo name '{git_repository.name}', but got {designators_attributes['repoName']}"
        assert designators_attributes[
                   "branch"] == git_repository.branch, f"Expected branch name '{git_repository.branch}', but got {designators_attributes['branch']}"
        assert designators_attributes[
                   "repoOwner"] == git_repository.owner, f"Expected repo owner '{git_repository.owner}', but got {designators_attributes['repoOwner']}"
        assert designators_attributes[
                   "remoteURL"] == git_repository.url, f"Expected remote URL '{git_repository.url}', but got {designators_attributes['remoteURL']}"
        assert designators_attributes[
                   "repoHash"] != "", f"Expected to find a non-empty value for repoHash, but got {designators_attributes['repoHash']}"
        assert repo_summary["statusText"] == kubescape_report[_CLI_SUMMARY_DETAILS_FIELD][
            "status"], "Repository summary status is different between BE and KS"

        kubescape_status_to_control_id = dict(passed=[], failed=[], skipped=[])
        for c_id, control in kubescape_report.get(_CLI_SUMMARY_DETAILS_FIELD, {}).get(statics.CONTROLS_FIELD,
                                                                                      {}).items():
            if control["status"] not in kubescape_status_to_control_id:
                kubescape_status_to_control_id[control["status"]] = []
            kubescape_status_to_control_id[control["status"]].append(c_id)

        # Check controlsStats counters in Repo Summary
        assert repo_summary["controlsStats"]["passed"] == len(kubescape_status_to_control_id["passed"])
        assert repo_summary["controlsStats"]["failed"] == len(kubescape_status_to_control_id["failed"])
        assert repo_summary["controlsStats"]["skipped"] == len(kubescape_status_to_control_id["skipped"])

        # Check controlsInfo in Repo Summary
        assert sorted([c["id"] for c in repo_summary["controlsInfo"]["failed"]]) == sorted(
            kubescape_status_to_control_id["failed"])
        assert sorted([c["id"] for c in repo_summary["controlsInfo"]["passed"]]) == sorted(
            kubescape_status_to_control_id["passed"])
        if "skipped" in repo_summary["controlsInfo"].keys():
            assert sorted([c["id"] for c in repo_summary["controlsInfo"]["skipped"]]) == sorted(
                kubescape_status_to_control_id["skipped"])
        else:
            assert len(kubescape_status_to_control_id["skipped"]) == 0

        Logger.logger.info("Testing file summary")
        file_summary = None
        for _ in range(12):
            file_summary = self.backend.get_repository_posture_files(new_report_guid)
            if len(file_summary) == repo_summary["childCount"]:
                break
            else:
                time.sleep(5)

        # Compare Files
        assert repo_summary["childCount"] == len(file_summary), \
            f"expected {len(file_summary)} files to be the value of childCount, but got {repo_summary['childCount']}"

        kubescape_scanned_files = set(
            [
                resource["source"]["relativePath"]
                for resource in kubescape_report[_CLI_RESOURCES_FIELD]
                if resource.get("source")
            ]
        )
        be_file_paths = set(
            [file["designators"]["attributes"]["filePath"] for file in file_summary]
        )
        if len(kubescape_scanned_files) != len(be_file_paths):
            for file in kubescape_scanned_files:
                assert file in be_file_paths, f"Expected to find {file} in file summary, but it wasn't found"
            for file in be_file_paths:
                assert file in kubescape_scanned_files, f"Expected to find {file} in kubescape report, but it wasn't found"
        
        expected_helm_files = self.test_obj.get_arg("expected_helm_files")
        be_helm_files = [file for file in file_summary if file["designators"]["attributes"]["fileType"] == "Helm Chart"]
        if expected_helm_files and len(expected_helm_files) > 0:
            Logger.logger.info("Testing helm chart scanning")
            be_helm_file_paths = [f["designators"]["attributes"]["filePath"] for f in be_helm_files]
            assert len(expected_helm_files) <= len(
                be_helm_file_paths), f"Expected {len(expected_helm_files)} files to be with type 'Helm Chart' in file summary: {expected_helm_files}, " \
                                     f"but there are {len(be_helm_file_paths)}: {be_helm_file_paths}"
            for helm_chart in expected_helm_files:
                assert helm_chart in be_helm_file_paths, f"Expected to find {helm_chart} in file summary, but it wasn't found"
            assert "0" not in [str(f["childCount"]) for f in
                               be_helm_files], f"Helm charts expected to have at least 1 resource, but some have 0"
        else:
            assert len(be_helm_files) == 0

        Logger.logger.info("Testing resources summary")
        be_resources = self.backend.get_repository_posture_resources(new_report_guid)

        cli_resources = kubescape_report[_CLI_RESOURCES_FIELD]
        # Check Total # of Resources
        if len(be_resources) != len(cli_resources):
            l = [i["resourceID"] for i in be_resources if any(i["resourceID"] != j["resourceID"] for j in cli_resources)]
            li = [i["resourceID"] for i in cli_resources if any(i["resourceID"] != j["resourceID"] for j in be_resources)]
            raise Exception(f"Number of failed resources reported to BE: {len(be_resources)}, Number of failed resources counted by the CLI: {len(cli_resources)}."\
                f"Diff: Resources in be_resources and not in cli_resources:{l}, Resources in cli_resources and not in be_resources:{li}")

        # Check amount of resources per status
        ks_resource_counters = kubescape_report.get(_CLI_SUMMARY_DETAILS_FIELD, {}).get(
            _CLI_RESOURCE_COUNTERS_FIELD, {}
        )

        failed = len([r["statusText"] for r in be_resources if r["statusText"] == "failed"])
        skipped = len([r["statusText"] for r in be_resources if r["statusText"] == "skipped"])
        excluded = len([r["statusText"] for r in be_resources if (r["statusText"] == "excluded" or r["statusText"] == "warning")])
        passed = len([r["statusText"] for r in be_resources if r["statusText"] == "passed"])

        assert ks_resource_counters.get(_CLI_FAILED_RESOURCES_FIELD, 0) == failed, f'CLI - number of failed resources: {ks_resource_counters.get(_CLI_FAILED_RESOURCES_FIELD, 0)}. BE - number of failed resources: {failed}'
        assert ks_resource_counters.get(_CLI_SKIPPED_RESOURCES_FIELD, 0) == skipped, f'CLI - number of skipped resources: {ks_resource_counters.get(_CLI_SKIPPED_RESOURCES_FIELD, 0)}. BE - number of skipped resources: {skipped}'
        assert ks_resource_counters.get(_CLI_EXCLUDED_RESOURCES_FIELD, 0) == excluded, f'CLI - number of excluded resources: {ks_resource_counters.get(_CLI_EXCLUDED_RESOURCES_FIELD, 0)}. BE - number of excluded resources: {excluded}'
        assert ks_resource_counters.get(_CLI_PASSED_RESOURCES_FIELD, 0) == passed, f'CLI - number of passed resources: {ks_resource_counters.get(_CLI_PASSED_RESOURCES_FIELD, 0)}. BE - number of passed resources: {passed}'

        Logger.logger.info("Testing repository registration in portal")
        repoHash = designators_attributes['repoHash']
        customer_repos = self.backend.get_repositories()
        repository_info = next((r for r in customer_repos if r['name'] == repoHash), None)

        assert repository_info, f"Expected to find repository in portal with repoHash {repoHash}"
        expected = new_report_guid
        actual = repository_info['attributes']['lastPostureReportGUID']
        assert actual == expected, f"last report GUID of repository was not updated in portal expected: {expected} actual: {actual}"
        
        Logger.logger.info(f"Running test cleanup - deleting repository ({repoHash})")
        self.backend.delete_repository(repository_hash=repoHash)
        return statics.SUCCESS, ""

class TestScanningScope(BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(TestScanningScope, self).__init__(test_obj=test_obj, backend=backend,
                                                      kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        # test Agenda:
        # 1. Scanning kubescape with custom framework and test result

        Logger.logger.info("Stage 1: Installing kubescape")
        self.install()

        Logger.logger.info("Stage 2: Scanning kubescape with custom-fw")
        cli_result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.get_arg("policy_name"),
                                       keep_local=self.test_obj.get_arg("keep_local"), use_from=self.test_obj.get_arg("framework_file"))

        Logger.logger.info("Stage 3: Testing result")
        self.test_result(cli_result=cli_result, scope_control_counter=self.test_obj.get_arg("scope_control_counter"))
        return self.cleanup()
    
    def test_result(self, cli_result, scope_control_counter):
        assert len(cli_result['summaryDetails']['controls']) == scope_control_counter, f"cli result: number of controls: {len(cli_result['summaryDetails']['controls'])} should be equal to {scope_control_counter}"

    def cleanup(self):
        return super().cleanup()


class TestScanningFileScope(BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(TestScanningFileScope, self).__init__(test_obj=test_obj, backend=backend,
                                                      kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        # test Agenda:
        # 1. Scanning kubescape with custom framework and test result

        Logger.logger.info("Stage 1: Installing kubescape")
        self.install()

        Logger.logger.info("Stage 2: Scanning kubescape with custom-fw")
        cli_result = self.default_scan(policy_scope=self.test_obj.policy_scope, policy_name=self.test_obj.get_arg("policy_name"),
                                       keep_local=self.test_obj.get_arg("keep_local"), use_from=self.test_obj.get_arg("framework_file"), yamls=self.test_obj.get_arg("yamls"))

        Logger.logger.info("Stage 3: Testing result")
        self.test_result(cli_result=cli_result, scope_control_counter=self.test_obj.get_arg("scope_control_counter"))
        return self.cleanup()
    
    def test_result(self, cli_result, scope_control_counter):
        assert len(cli_result['summaryDetails']['controls']) == scope_control_counter, f"cli result: number of controls: {len(cli_result['summaryDetails']['controls'])} should be equal to {scope_control_counter}"

    def cleanup(self):
        return super().cleanup()

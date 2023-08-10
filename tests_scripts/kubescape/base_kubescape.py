from datetime import datetime
import json
import os
import stat
import shutil
import time
import platform
from typing import Optional, Tuple
from dateutil import parser
import kubernetes.client.models.v1_config_map
import requests
from kubernetes.client import ApiException
from configurations.system.git_repository import GitRepository
from tests_scripts.kubernetes.base_k8s import BaseK8S

from infrastructure import KubectlWrapper
from systest_utils import TestUtil, statics, Logger

DEFAULT_ORG = "kubescape"
DEFAULT_BRANCH = "release"
DEFAULT_RELEASE = "latest"
DEFAULT_RESULTS = "results.json"

_CLI_STATUS_FILED = 'status'
_CLI_STATUS_INFO_FIELD = 'statusInfo'
_CLI_SUB_STATUS_FIELD = 'subStatus'
_CLI_SUB_STATUS_EXCEPTIONS = 'w/exceptions'
_CLI_STATUS_FAILED = 'failed'
_CLI_STATUS_PASSED = 'passed'
_CLI_SUMMARY_DETAILS_FIELD = 'summaryDetails'
_CLI_RESOURCE_COUNTERS_FIELD = 'ResourceCounters'
_CLI_EXCLUDED_RESOURCES_FIELD = 'excludedResources'
_CLI_PASSED_RESOURCES_FIELD = 'passedResources'
_CLI_SKIPPED_RESOURCES_FIELD = 'skippedResources'
_CLI_FAILED_RESOURCES_FIELD = 'failedResources'
_CLI_WARNING_RESOURCES_FIELD = "warningResources"
_CLI_RESOURCE_ID_FIELD = 'resourceID'
_CLI_CONTROL_ID_FIELD = 'controlID'
_CLI_RULES_ID_FIELD = 'rules'
_CLI_RESOURCES_FIELD = 'resources'
_CLI_RESULTS_FIELD = 'results'
_CLI_FRAMEWORKS_FIELD = "frameworks"
_CLI_SCORE_FIELD = "score"
_COMPLIANCE_SCORE_FIELD = "complianceScore"
_COMPLIANCE_SCORE_FIELDV1 = "complianceScorev1"

_ALL_RESOURCES_COUNT_FIELD = "totalResources"
_WARN_RESOURCES_COUNT_FIELD = "warningResources"
_FAILED_RESOURCES_COUNT_FIELD = "failedResources"

_FRAMEWORK_REPORTS_FIELD = "frameworkReports"
_CONTROLS_FIELD = "controls"
_RULE_REPORTS_FIELD = "ruleReports"
_RULE_RESPONSE_FIELD = "ruleResponse"

_BE_FAILED_RESOURCES_COUNT_FIELD = "failedResourcesCount"
_BE_WARNING_RESOURCES_COUNT_FIELD = "warningResourcesCount"
_BE_CORDS_FIELD = "cords"
_BE_REPORT_GUID_FIELD = "reportGUID"
_BE_REPORT_TIMESTAMP_FIELD = "timestamp"
_CLI_CONTROL_REPORT_FIELD = "controlReports"
_CLI_NAME_FIELD = "name"

_POSTURE_CONTROL_INPUT_FILED = 'postureControlInputs'
_SETTINGS_FILED = 'settings'

_VULN_SCAN_RESOURCE_API_VERSION = 'result.vulnscan.com/v1'


class BaseKubescape(BaseK8S):
    """
    Attach deployment by adding the inject annotation
    """

    def __init__(self, test_obj=None, backend=None, test_driver=None, kubernetes_obj=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                         kubernetes_obj=kubernetes_obj)

        self.ks_branch = self.test_driver.kwargs.get("ks_branch", DEFAULT_BRANCH)
        self.artifacts = self.test_driver.kwargs.get("use_artifacts", None)
        self.policies = self.test_driver.kwargs.get("use_from", None)
        self.kubescape_exec = self.test_driver.kwargs.get("kubescape", None)
        self.environment = '' if self.test_driver.backend_obj == None or self.test_driver.backend_obj.get_name() == "production" else self.test_driver.backend_obj.get_name()
        self.host_scan_yaml = self.test_driver.kwargs.get("host_scan_yaml", None)
        self.remove_cluster_from_backend = False

    def default_scan(self, **kwargs):
        self.delete_kubescape_config_file(**kwargs)
        res_file = self.get_default_results_file()
        self.scan(output_format="json", output=res_file, **kwargs)
        return self.load_results(results_file=res_file)

    def is_kubescape_config_file_exist(self):
        return os.path.exists(self.get_kubescape_config_file())

    def create_kubescape_config_file(self):
        config_file_data = {
            statics.CLOUD_API_URL_KEY: "any_value"
        }
        with open(file=self.get_kubescape_config_file(), mode="w") as outfile:
            json.dump(config_file_data, outfile)

    def default_config(self, **kwargs):
        if self.is_kubescape_config_file_exist() == False:
            self.create_kubescape_config_file()
        res_file = self.get_default_results_file()
        with open(res_file, "w") as f:
            return self.config(stdout=f,**kwargs)

    def cleanup(self, **kwargs):
        self.delete_kubescape_config_file(**kwargs)
        if self.remove_cluster_from_backend and not self.cluster_deleted:
            TestUtil.sleep(150, "Waiting for aggregation to end")
            self.cluster_deleted = self.delete_cluster_from_backend()
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""

    def get_default_results_file(self):
        return os.path.join(self.test_driver.temp_dir, "results.json")
    
    def get_kubescape_config_file(self):
        return os.path.join(os.path.expanduser('~'), ".kubescape", "config.json")

    def download_control_input(self):
        output_file = os.path.join(self.test_driver.temp_dir, 'controls-inputs.json')
        self.download_policy(output_file=output_file, policy="controls-inputs", account=True)
        return self.load_results(results_file=output_file)

    def download_artifact(self):
        output_file = os.path.join(self.test_driver.temp_dir, 'artifacts')
        self.download_policy(output_file=output_file, policy="artifacts")
        return output_file

    def download_policy(self, output_file: str, policy: str, policy_name: str = None, **kwargs):
        command = [self.kubescape_exec, 'download', policy]

        if policy_name:
            command.append(policy_name)

        command.extend(['--output', output_file])
        if "account" in kwargs:
            command.extend(["--account", self.backend.get_customer_guid()])
        if self.environment == "dev" or self.environment == "development":
            command.extend(["--env", "dev"])
        if self.environment == "staging" or self.environment == "stage":
            command.extend(["--env", "report-ks.eustage2.cyberarmorsoft.com,api-stage.armosec.io,"
                                     "cloud-stage.armosec.io,eggauth-stage.armosec.io"])

        Logger.logger.info(" ".join(command))
        status_code, res = TestUtil.run_command(command_args=command, timeout=360,
                                                stderr=TestUtil.get_arg_from_dict(kwargs, "stderr", None),
                                                stdout=TestUtil.get_arg_from_dict(kwargs, "stdout", None))
        assert status_code == 0, res
        return res
    
    def delete_kubescape_config_file(self, **kwargs):
        if self.kubescape_exec is None:
            return "kubescape_exec not found"
        command = [self.kubescape_exec, "config", "delete"]
        status_code, res = TestUtil.run_command(command_args=command, timeout=360,
                                                stderr=TestUtil.get_arg_from_dict(kwargs, "stderr", None),
                                                stdout=TestUtil.get_arg_from_dict(kwargs, "stdout", None))
        assert status_code == 0, res
        return res

    
    def view_kubescape_config_file(self, **kwargs):
        command = [self.kubescape_exec, "config", "view"]
        status_code, res = TestUtil.run_command(command_args=command, timeout=360,
                                                stderr=TestUtil.get_arg_from_dict(kwargs, "stderr", None),
                                                stdout=TestUtil.get_arg_from_dict(kwargs, "stdout", None))
        assert status_code == 0, res
        return res

    def config(self, **kwargs):
        command = [self.kubescape_exec, "config"]
        if "view" in kwargs:
            command.append(kwargs["view"])
        elif "set" in kwargs:
            command.append(kwargs["set"])
            command.append(kwargs["data"][0])
            command.append(kwargs["data"][1])
        elif "delete" in kwargs:
            command.append(kwargs["delete"])

        Logger.logger.info(" ".join(command))
        status_code, res = TestUtil.run_command(command_args=command, timeout=360,
                                                stderr=TestUtil.get_arg_from_dict(kwargs, "stderr", None),
                                                stdout=TestUtil.get_arg_from_dict(kwargs, "stdout", None))
        assert status_code == 0, res
        return res



    def scan(self, policy_scope: str = None, policy_name: str = None, output_format: str = None, output: str = None,
             **kwargs):

        command = [self.kubescape_exec, "scan", "--format-version", "v2"]

        if policy_scope:
            command.append(policy_scope)
        if policy_name:
            command.append(policy_name)
        if "path" in kwargs:
            command.append(kwargs["path"])
        if "url" in kwargs:
            command.append(kwargs["url"])
        if "yamls" in kwargs:
            command.extend(kwargs["yamls"])
        if output_format:
            command.extend(["--format", output_format])
        if output:
            command.extend(["--output", output])
        if "exceptions" in kwargs:
            command.extend(["--exceptions", kwargs['exceptions']])
        if "keep_local" in kwargs:
            command.append("--keep-local")
        if "submit" in kwargs:
            command.append("--submit")
            self.remove_cluster_from_backend = True
            account_id = kwargs["account"] if "account" in kwargs else self.backend.get_customer_guid()
            assert account_id, "missing account ID, the report will not be submitted"
            command.extend(["--account", self.backend.get_customer_guid()])

        if self.environment == "staging" or self.environment == "stage":
            command.extend(["--env", "report-ks.eustage2.cyberarmorsoft.com,api-stage.armosec.io,"
                                     "cloud-stage.armosec.io,eggauth-stage.armosec.io"])

        if self.environment == "dev" or self.environment == "development":
            command.extend(["--env", "dev"])

        # first check if artifacts are passed to function
        if "use_artifacts" in kwargs and kwargs['use_artifacts'] != "":
            command.extend(['--use-artifacts-from', kwargs['use_artifacts']])
        elif self.artifacts:  # otherwise, load default artifacts (if passed by the command line)
            command.extend(['--use-artifacts-from', self.artifacts])

        # used to include rego rules not yet merged in master branch.
        if "use_from" in kwargs and kwargs['use_from'] != "":
            command.extend(['--use-from', kwargs['use_from']])
        elif self.policies:  # otherwise, load default policies (if passed by the command line)
            command.extend(['--use-from', self.policies])

        if "include_namespaces" in kwargs:
            command.extend(["--include-namespaces", kwargs['include_namespaces']])
        if "enable_host_scan" in kwargs:
            command.append("--enable-host-scan")
        if "client_id" in kwargs:
            command.append(f"--client-id={self.backend.get_client_id()}")
        if "secret_key" in kwargs:
            command.append(f"--secret-key={self.backend.get_secret_key()}")

        if "host_scan_yaml" in kwargs and kwargs['host_scan_yaml'] != "":
            command.append(f"--host-scan-yaml={kwargs['host_scan_yaml']}")
        elif self.host_scan_yaml:
            command.append(f"--host-scan-yaml={self.host_scan_yaml}")

        # command.append("--use-default")

        Logger.logger.info(" ".join(command))

        status_code, res = TestUtil.run_command(command_args=command, timeout=360,
                                                stderr=TestUtil.get_arg_from_dict(kwargs, "stderr", None),
                                                stdout=TestUtil.get_arg_from_dict(kwargs, "stdout", None))
        assert status_code == 0, res
        return res

    def get_repository_posture_repositories(self, repository_owner: str, repository_name: str, repository_branch: str):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_repository_posture_repositories_by_name,
                                               repository_owner=repository_owner,
                                               repository_name=repository_name,
                                               repository_branch=repository_branch)
        return c_panel_info

    def get_posture_frameworks(self, report_guid, framework_name: str = ""):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_posture_frameworks,
                                               framework_name=framework_name, report_guid=report_guid)
        return c_panel_info

    def get_framework(self, framework_name: str = ''):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_framework,
                                               framework_name=framework_name)
        return c_panel_info

    def get_posture_controls(self, framework_name: str, report_guid):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_posture_controls,
                                               framework_name=framework_name, report_guid=report_guid)
        return c_panel_info

    def get_posture_controls_CSV(self, framework_name: str, report_guid):
        ws = self.backend.ws_export_open("/ws/v1/posture/controls")
        message = {"innerFilters": [{"frameworkName": framework_name, "reportGUID": report_guid}]}
        self.backend.ws_send(ws, json.dumps(message))
        result = self.backend.ws_extract_receive(ws)
        return result

    def get_posture_resources(self, framework_name: str, report_guid: str, resource_name: str = "", related_exceptions="false", namespace=None):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_posture_resources,
                                               framework_name=framework_name, report_guid=report_guid,
                                               resource_name=resource_name, related_exceptions=related_exceptions,namespace=namespace)
        return c_panel_info

    def get_top_controls_results(self, cluster_name):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_top_controls_results,
                                               cluster_name=cluster_name)
        return c_panel_info

    def get_posture_resources_CSV(self, framework_name: str, report_guid):
        ws = self.backend.ws_export_open("/ws/v1/posture/resources")
        message = {"innerFilters": [{"frameworkName": framework_name, "reportGUID": report_guid}]}
        self.backend.ws_send(ws, json.dumps(message))
        result = self.backend.ws_extract_receive(ws)
        return result

    def get_posture_resources_by_control(self, related_exceptions: str, control_name: str, control_id: str,
                                         report_guid: str, framework_name: str):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_posture_resources_by_control,
                                               framework_name=framework_name, report_guid=report_guid,
                                               control_name=control_name, control_id=control_id,
                                               related_exceptions=related_exceptions)
        return c_panel_info

    def get_version_info(self, cluster_name: str):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_cluster, cluster_name=cluster_name)
        assert isinstance(c_panel_info,
                          dict), f"Expecting cluster data to be a dict, but got the following: {json.dumps(c_panel_info)}"
        return c_panel_info['apiServerInfo']

    def get_customer_configuration(self):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_customer_configuration)
        return c_panel_info

    def update_customer_configuration(self, customer_config: dict):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.update_customer_configuration,
                                               customer_config=customer_config)
        return c_panel_info

    # @staticmethod
    def install(self, org: str = DEFAULT_ORG, branch: str = DEFAULT_BRANCH):
        if self.kubescape_exec:  # run local kubescape
            # print("kubescape path: ", self.kubescape_exec)
            # os.system(self.kubescape_exec + " version")
            return

        if branch != DEFAULT_BRANCH:
            self.download_from_branch(org, branch)
        else:
            self.download_release(org=org)

        Logger.logger.debug("kubescape path: {}".format(self.kubescape_exec))

    # def download_docker(self):
    #     os.system('git clone -b dev https://github.com/armosec/kubescape.git kubescape && cd "$_"')
    #     os.system('docker build -t kubescape -f build/Dockerfile .')
    #
    #     kubescape_exec = 'docker run kubescape'
    #
    #     # st = os.stat(kubescape_exec)
    #     # os.chmod(kubescape_exec, st.st_mode | stat.S_IEXEC)
    #     os.system(kubescape_exec + " version")
    #     self.kubescape_exec = kubescape_exec

    def download_release(self, org: str = DEFAULT_ORG, release: str = DEFAULT_RELEASE):
        Logger.logger.debug("downloading kubescape from release")

        if platform.system() == "Darwin":
            os_name = "macos"
        else:
            os_name = "ubuntu"

        download_url = f"https://github.com/{org}/kubescape/releases/{release}/download/kubescape-{os_name}-latest"

        kubescape_exec = os.path.join(self.test_driver.temp_dir, "kubescape")
        res = requests.get(download_url)

        with open(kubescape_exec, 'wb') as f:
            f.write(res.content)
        # update permission
        st = os.stat(kubescape_exec)
        os.chmod(kubescape_exec, st.st_mode | stat.S_IEXEC)
        os.system(kubescape_exec + " version")
        self.kubescape_exec = kubescape_exec

    def download_from_branch(self, org: str, branch: str):
        Logger.logger.debug(f"downloading kubescape from branch {branch} (org {org})")
        download_url = f"https://github.com/{org}/kubescape"
        kubescape_exec = os.path.join(self.test_driver.temp_dir, "ks")

        os.system('go env -w GO111MODULE=on')

        # clone kubescape from branch to dir tempks_branch
        return_code, return_obj = TestUtil.run_command(command_args=["git", "clone", download_url, "-b", branch],
                                                       cwd=self.test_driver.temp_dir, timeout=360)
        assert not return_code, f"Failed to clone kubescape from branch {branch} : {return_obj.stderr}"

        ks_path = os.path.join(self.test_driver.temp_dir, "kubescape")

        # build kubescape (make file) for non-windows machines
        if platform.system() != "Windows" and os.path.exists(os.path.join(ks_path, "Makefile")):
            return_code, return_obj = TestUtil.run_command(command_args=["make"], cwd=ks_path, timeout=360)
            assert not return_code, f"Failed to build kubescape (make) from branch {branch} : {return_obj.stderr}"
            shutil.move(os.path.join(ks_path, "kubescape"), kubescape_exec)
        else:
            # build kubescape using go build
            return_code, return_obj = TestUtil.run_command(command_args=["go", "build", "-o", kubescape_exec],
                                                           cwd=ks_path, timeout=360)
            assert not return_code, f"Failed to build kubescape (go build) from branch {branch} : {return_obj.stderr}"

        self.kubescape_exec = kubescape_exec

        # update permission
        st = os.stat(kubescape_exec)
        os.chmod(kubescape_exec, st.st_mode | stat.S_IEXEC)
        self.kubescape_exec = kubescape_exec

    @staticmethod
    def get_abs_path(relative_path: str = "", files_name: list = []):
        files = []
        for file in files_name:
            files.append(os.path.abspath(os.path.join(relative_path, file)))
        return files

    @staticmethod
    def load_results(results_file):
        with open(results_file, 'r') as f:
            res = json.loads(f.read())
        Logger.logger.debug("results: {}".format(res))
        return res

    @staticmethod
    def load_bytes_results(data, results_file):
        with open(results_file, 'r') as f:
            res = json.loads(data)
        Logger.logger.debug("results: {}".format(res))
        return res

    @staticmethod
    def run_kubescape_command(command, timeout=120):
        return

    @staticmethod
    def test_counters(framework_report: dict):
        BaseKubescape.test_negative_numbers_in_result(framework_report)
        BaseKubescape.test_resources_number_counter_in_result(framework_report)
        # BaseKubescape.test_zero_numbers_in_framework_result(framework_report)

    @staticmethod
    def test_zero_numbers_in_framework_result(framework_report: dict):
        """
        Make sure there are no zero in the report counters at the framework level
        """
        message = "found zero counter in resource: {resource_name}, counter: {counter}"
        assert framework_report[statics.ALL_RESOURCES_COUNT_FIELD] != 0, message.format(
            resource_name=framework_report["name"],
            counter=statics.ALL_RESOURCES_COUNT_FIELD)
        assert framework_report[statics.FAILED_RESOURCES_COUNT_FIELD] != 0, message.format(
            resource_name=framework_report["name"],
            counter=statics.FAILED_RESOURCES_COUNT_FIELD)

    @staticmethod
    def test_negative_numbers_in_result(framework_report: dict):
        """
        Make sure there are no negative numbers in the report counters
        """
        BaseKubescape.is_negative(result=framework_report[_CLI_SUMMARY_DETAILS_FIELD][_CLI_RESOURCE_COUNTERS_FIELD],
                                  name='global')
        for c_id, control in framework_report[_CLI_SUMMARY_DETAILS_FIELD][statics.CONTROLS_FIELD].items():
            BaseKubescape.is_negative(result=control[_CLI_RESOURCE_COUNTERS_FIELD], name=c_id)

    @staticmethod
    def is_negative(result: dict, name: str):
        message = "found negative counter in: {resource_name}, counter: {counter}"
        assert result[_CLI_PASSED_RESOURCES_FIELD] >= 0, message.format(resource_name=name,
                                                                        counter=_CLI_PASSED_RESOURCES_FIELD)
        assert result[_CLI_FAILED_RESOURCES_FIELD] >= 0, message.format(resource_name=name,
                                                                        counter=_CLI_FAILED_RESOURCES_FIELD)
        # assert result[_CLI_EXCLUDED_RESOURCES_FIELD] >= 0, message.format(resource_name=name,
        #                                                                   counter=_CLI_EXCLUDED_RESOURCES_FIELD)

        assert result.get(_CLI_SKIPPED_RESOURCES_FIELD, 0) >= 0, message.format(resource_name=name,
                                                                                counter=_CLI_SKIPPED_RESOURCES_FIELD)

    @staticmethod
    def is_failed_passed_and_skipped_less_than_all(total_resources: int, resource_counters: dict, name: str):
        message = "in {name}, {all} < {passed}+{failed}+{skipped} (all<passed+failed+skipped)"
        failed = resource_counters[_CLI_FAILED_RESOURCES_FIELD]
        passed = resource_counters[_CLI_PASSED_RESOURCES_FIELD]
        skipped = resource_counters.get(_CLI_SKIPPED_RESOURCES_FIELD, 0)
        # skipped = resource_counters[_CLI_SKIPPED_RESOURCES_FIELD]
        assert total_resources >= passed + failed + skipped, message.format(
            name=name, all=total_resources, failed=failed, passed=passed, skipped=skipped)

    @staticmethod
    def test_resources_number_counter_in_result(framework_report: dict):
        """
        Check if the number in "all resources" >= "passed" + "failed" + "skipped"
        """
        all_resources = len(framework_report[_CLI_RESULTS_FIELD])
        BaseKubescape.is_failed_passed_and_skipped_less_than_all(
            total_resources=all_resources,
            resource_counters=framework_report[_CLI_SUMMARY_DETAILS_FIELD][_CLI_RESOURCE_COUNTERS_FIELD], name='global')
        for c_id, control in framework_report[_CLI_SUMMARY_DETAILS_FIELD][statics.CONTROLS_FIELD].items():
            BaseKubescape.is_failed_passed_and_skipped_less_than_all(
                total_resources=all_resources, resource_counters=control[_CLI_RESOURCE_COUNTERS_FIELD], name=c_id)

    @staticmethod
    def test_exception_result(framework_report: dict, controls_with_exception: list):
        for c_id in controls_with_exception:
            sub_status = \
                framework_report[_CLI_SUMMARY_DETAILS_FIELD][statics.CONTROLS_FIELD][c_id][_CLI_STATUS_INFO_FIELD][
                    _CLI_SUB_STATUS_FIELD]
            assert sub_status == _CLI_SUB_STATUS_EXCEPTIONS, \
                "control {x} supposed to be {w}, but it is {y}".format(x=c_id, y=sub_status,
                                                                       w=_CLI_SUB_STATUS_EXCEPTIONS)

    # @staticmethod
    # def test_results(framework_report: dict):
    #     BaseKubescape.number_of_resources(framework_report)

    @staticmethod
    def number_of_resources(framework_report: dict, resources: int):
        message = "expected to receive {x} resources, and received {y} resources"
        assert len(framework_report[_CLI_RESULTS_FIELD]) == resources, \
            message.format(x=resources, y=len(framework_report[_CLI_RESULTS_FIELD]))

    @staticmethod
    def test_frameworks_from_backend(cli_result: dict, be_frameworks: dict):
        pass

    @staticmethod
    def test_number_of_controls_in_be(cli_controls: dict, be_controls: list):
        message = "Kubescape runs {x} controls, but the backend receive {y} controls"
        assert len(be_controls) == len(cli_controls), \
            message.format(x=len(cli_controls), y=len(be_controls))

    @staticmethod
    def test_status_text(result_count: dict, skipped_controls: int, failed_count: int, status_txt: str,
                         control_name: str):
        if failed_count > 0:
            result_count['failed_controls'] += 1
            assert status_txt == "failed", \
                "control {x} supposed to be failed, but it is {y}".format(x=control_name, y=status_txt)
        elif skipped_controls > 0:
            result_count['skipped_controls'] += 1
            assert status_txt == "skipped", \
                "control {x} supposed to be warning, but it is {y}".format(x=control_name, y=status_txt)
        else:
            # TODO: kept for backward compatibility the line below should be changed to "assert status_txt == "passed", \" 
            # after the statuses merged to kubescape"
            assert status_txt == "passed" or status_txt == "skipped" or status_txt == "warning" or status_txt == "irrelevant", \
                "control {x} supposed to be passed or skipped, but it is {y}".format(x=control_name, y=status_txt)
        result_count['total_controls'] += 1
        return result_count

    @staticmethod
    def test_controls_result_count(be_frameworks: dict, result_count: dict):
        assert be_frameworks[statics.BE_TOTAL_CONTROLS_FILED] == result_count['total_controls'], \
            "Total-control from controls_api is {x}, but total-controls from framework_api is {y}.". \
                format(x=result_count['total_controls'], y=be_frameworks[statics.BE_TOTAL_CONTROLS_FILED])
        assert be_frameworks[statics.BE_FAILED_CONTROLS_FILED] == result_count['failed_controls'], \
            "Failed-control from controls_api is {x}, but failed-controls from framework_api is {y}.". \
                format(x=result_count['failed_controls'], y=be_frameworks[statics.BE_FAILED_CONTROLS_FILED])
        assert be_frameworks[statics.BE_WARNING_CONTROLS_FILED] == result_count['warning_controls'], \
            "Warning-control from controls_api is {x}, but warning-controls from framework_api is {y}.". \
                format(x=result_count['warning_controls'], y=be_frameworks[statics.BE_WARNING_CONTROLS_FILED])

    @staticmethod
    def test_controls_from_backend(cli_controls: dict, be_frameworks: dict, be_controls: list):
        BaseKubescape.test_number_of_controls_in_be(cli_controls=cli_controls, be_controls=be_controls)

        result_count = {'total_controls': 0, 'failed_controls': 0, 'skipped_controls': 0}
        for be_control in be_controls:
            c_id = be_control['id']
            assert c_id in cli_controls.keys(), "control {x} found in be_results, but not in cli_results".format(x=c_id)
            assert be_control[statics.BE_FAILED_RESOURCES_COUNT_FIELD] == \
                   cli_controls[c_id][_CLI_RESOURCE_COUNTERS_FIELD][_CLI_FAILED_RESOURCES_FIELD], \
                "control {x} - {w}: the cli result is {y} failed, backend result is {z} failed". \
                    format(x=c_id, w=be_control[statics.BE_NAME_FILED],
                           y=cli_controls[c_id][_CLI_RESOURCE_COUNTERS_FIELD][_CLI_FAILED_RESOURCES_FIELD],
                           z=be_control[statics.BE_FAILED_RESOURCES_COUNT_FIELD])

            assert be_control.get(statics.BE_SKIPPED_RESOURCES_COUNT_FIELD, 0) == cli_controls[c_id][
                _CLI_RESOURCE_COUNTERS_FIELD].get(_CLI_SKIPPED_RESOURCES_FIELD, 0), \
                "control {x} - {w}: the cli result is {y} skipped, backend result is {z} skipped". \
                    format(x=c_id, w=be_control[statics.BE_NAME_FILED],
                           y=cli_controls[c_id][_CLI_RESOURCE_COUNTERS_FIELD][_CLI_SKIPPED_RESOURCES_FIELD],
                           z=be_control[statics.BE_SKIPPED_RESOURCES_COUNT_FIELD])

            result_count = BaseKubescape.test_status_text(
                result_count=result_count,
                skipped_controls=be_control.get(statics.BE_SKIPPED_RESOURCES_COUNT_FIELD, 0),
                failed_count=be_control[statics.BE_FAILED_RESOURCES_COUNT_FIELD],
                status_txt=be_control[statics.BE_STATUS_TEXT_FILED],
                control_name=be_control[statics.BE_NAME_FILED])

        # BaseKubescape.test_controls_result_count(result_count=result_count, be_frameworks=be_frameworks)

    @staticmethod
    def test_number_of_resources_in_be(cli_result: dict, be_resources: list):
        message = "Kubescape failed {x} resources, but the backend failed {y} resources"
        assert len(be_resources) == cli_result[_CLI_FAILED_RESOURCES_FIELD], \
            message.format(x=cli_result[_CLI_FAILED_RESOURCES_FIELD], y=len(be_resources))

    @staticmethod
    def get_attributes_from_be_resources(be_resources: list, cluster: str, kind: str, name: str, namespace: str):
        for resource in be_resources:
            attributes = resource['designators']['attributes']
            if attributes['cluster'] == cluster and attributes['kind'] == kind and name in attributes['name'] and \
                    (len(namespace) == 0 or attributes['namespace'] == namespace):
                return [control for x in resource['statusToControls'].values() for control in x]
        return None

    @staticmethod
    def resource_in_filed_control(rule_responses: list, kind: str, name: str, namespace: str):
        for response in rule_responses:
            k8s_obj = response['alertObject']['k8sApiObjects'][0]
            if k8s_obj['kind'] == kind and name in k8s_obj['metadata']['name'] and \
                    (len(namespace) == 0 or k8s_obj['metadata']['namespace'] == namespace):
                return True
        return False

    @staticmethod
    def get_alert_object_from_cli_result_by_id(cli_result: dict, control_id: str):
        for control in cli_result['controlReports']:
            if control['id'] == control_id:
                # TODO - support list of controls
                return control['ruleReports'][0]['ruleResponses']

    def test_failed_controls_in_resource(self, cli_result: dict, be_resources: list, cluster: str, kind: str, name: str,
                                        namespace: str, api_version: str):
        be_affected_controls = BaseKubescape.get_attributes_from_be_resources(be_resources=be_resources, kind=kind,
                                                                              cluster=cluster, name=name,
                                                                              namespace=namespace)
        if not be_affected_controls:
            raise Exception(
                "no failed controls found for- cluster: {cluster}, kind: {kind}, name: {name}, namespace: {namespace}".
                    format(cluster=cluster, kind=kind, name=name, namespace=namespace))

        resource_id, cli_affected_controls = self.get_affected_controls_from_cli_result(cli_result=cli_result,
                                                                                        kind=kind, name=name,
                                                                                        namespace=namespace,
                                                                                        api_version=api_version)

        assert sorted(be_affected_controls) == sorted(cli_affected_controls), \
            "For resource: {resource_id}, the affected controls from cli is {x}, the affected controls from be is {y}" \
                .format(resource_id=resource_id, x=sorted(cli_affected_controls), y=sorted(be_affected_controls))

    @staticmethod
    def get_resource_id_from_cli_result(cli_result: dict, kind: str, name: str, namespace: str, api_version: str):
        resource_id = ''
        for resource in cli_result[_CLI_RESOURCES_FIELD]:
            # if resource['resourceID'].endswith("/" + namespace + "/" + kind + "/" + name):
            if KubectlWrapper.get_kind_from_wl(resource['object']) == kind \
                    and KubectlWrapper.get_name_from_wl(resource['object']) == name \
                    and KubectlWrapper.get_namespace_from_wl(resource['object']) == namespace \
                    and KubectlWrapper.get_api_version_from_wl(resource['object']) == api_version:
                resource_id = resource['resourceID']
                break
        return resource_id

    @staticmethod
    def get_resource_result_from_cli_result(cli_result: dict, resource_id: str):
        resource_result = {}
        for result in cli_result[_CLI_RESULTS_FIELD]:
            if result["resourceID"] == resource_id:
                resource_result = result
                break
        return resource_result

    # @staticmethod
    def get_failed_controls_from_cli_result(self, cli_result: dict, kind: str, name: str, namespace: str,
                                            api_version: str):
        # not support rbac
        if kind == 'Pod':
            name = self.kubernetes_obj.get_pod_full_name(namespace=namespace, partial_name=name)
        resource_id = BaseKubescape.get_resource_id_from_cli_result(cli_result=cli_result, kind=kind, name=name,
                                                                    namespace=namespace, api_version=api_version)

        assert resource_id, \
            "No resource was found whose kind={kind}, name={name}, namespace={namespace} in in cli_result->resources". \
                format(kind=kind, name=name, namespace=namespace)

        resource_result = BaseKubescape.get_resource_result_from_cli_result(cli_result=cli_result,
                                                                            resource_id=resource_id)
        assert resource_result, "No result found whose resourceID={resource_id} in cli_result->results". \
            format(resource_id=resource_id)

        return resource_id, [control['controlID'] for control in resource_result[_CONTROLS_FIELD]
                             if BaseKubescape.cli_resource_failed_in_control(resource_result=resource_result,
                                                                             c_id=control['controlID'])]

    def get_affected_controls_from_cli_result(self, cli_result: dict, kind: str, name: str, namespace: str,
                                              api_version: str):
        # not support rbac
        if kind == 'Pod':
            name = self.kubernetes_obj.get_pod_full_name(namespace=namespace, partial_name=name)
        resource_id = BaseKubescape.get_resource_id_from_cli_result(cli_result=cli_result, kind=kind, name=name,
                                                                    namespace=namespace, api_version=api_version)

        assert resource_id, \
            "No resource was found whose kind={kind}, name={name}, namespace={namespace} in in cli_result->resources". \
                format(kind=kind, name=name, namespace=namespace)

        resource_result = BaseKubescape.get_resource_result_from_cli_result(cli_result=cli_result,
                                                                            resource_id=resource_id)
        assert resource_result, "No result found whose resourceID={resource_id} in cli_result->results". \
            format(resource_id=resource_id)

        return resource_id, list(map(lambda control: control['controlID'], resource_result[statics.CONTROLS_FIELD]))

    @staticmethod
    def cli_resource_failed_in_control(resource_result: dict, c_id: str):
        for control in resource_result[_CONTROLS_FIELD]:
            if control[_CLI_CONTROL_ID_FIELD] == c_id:
                for rule in control[_CLI_RULES_ID_FIELD]:
                    if rule[_CLI_STATUS_FILED] == _CLI_STATUS_FAILED:
                        return True
                break
        return False

    def test_top_controls_from_backend(self, cli_result: dict, be_results: list, report_guid: str, framework_name: str):
        be_ctrl_ids = [be_ctrl["id"] for be_ctrl in be_results]
        assert len(be_ctrl_ids) > 0 and len(
            be_ctrl_ids) <= 5, "Top controls count should be between 1 to 5 but was {count}".format(
            count=len(be_ctrl_ids))
        for be_ctrl in be_results:
            for id, control in cli_result["summaryDetails"]["controls"].items():
                # check that there is no control with higher failed resources that is not in top 5 controls response
                if be_ctrl['clusters'][0]['resourcesCount'] < control['ResourceCounters'][
                    "failedResources"] and id not in be_ctrl_ids:
                    assert False, "Control {ctrl} should be in top controls".format(ctrl=id)

                # check control data and failed resources
                if be_ctrl["id"] == id:
                    assert be_ctrl['clusters'][0]['reportGUID'] == report_guid, "reportGUID should be {guid}".format(
                        guid=report_guid)
                    assert be_ctrl['clusters'][0][
                               'topFailedFramework'] == framework_name, "framework name should be {name}".format(
                        name=framework_name)
                    assert be_ctrl['clusters'][0]['resourcesCount'] == control['ResourceCounters']["failedResources"], \
                        "Control {ctrl} should have {count} failed resources".format(ctrl=id,
                                                                                     count=control['ResourceCounters'][
                                                                                         "failedResources"])
                    assert be_ctrl['name'] == control['name'], "Control {ctrl} should have name {name}".format(ctrl=id,
                                                                                                               name=
                                                                                                               control[
                                                                                                                   'name'])
                    assert be_ctrl['baseScore'] == control[
                        'scoreFactor'], "Control {ctrl} should have scored {scored}".format(ctrl=id,
                                                                                            scored=control['scored'])

    def test_resources_from_backend(self, cli_result: dict, be_resources: list):
        resources_obj = self.test_obj[("resources_for_test", [])]
        for resource_obj in resources_obj:
            self.test_failed_controls_in_resource(cli_result=cli_result, be_resources=be_resources,
                                                 kind=resource_obj['kind'], api_version=resource_obj['apiVersion'],
                                                 cluster=self.kubernetes_obj.get_cluster_name(),
                                                 name=resource_obj['name'], namespace=resource_obj['namespace'])

    def test_api_version_info(self):
        cli_info = self.kubernetes_obj.get_info_version().to_dict()
        be_info = self.get_version_info(cluster_name=self.kubernetes_obj.get_cluster_name())
        assert cli_info['git_version'] == be_info['gitVersion'].split(';')[0] and \
               cli_info['git_commit'] == be_info['gitCommit'], \
            "cluster {name}: from backend the git-version is {x1}, and git-commit is {y1}." \
            "from k8s-api the git-version is {x2}, and git-commit is {y2}.".format(
                name=self.kubernetes_obj.get_cluster_name(), x1=be_info['gitVersion'].split(';')[0],
                y1=be_info['gitCommit'], x2=cli_info['git_version'], y2=cli_info['git_commit']
            )

    @staticmethod
    def get_resource_from_be_resources(be_resources: list, resource_name: str):
        for resource in be_resources:
            if resource['name'][len(resource['name']) - len(resource_name):] == resource_name:
                return resource
        raise Exception(
            f'resource "{resource_name}" not found in backend, resources found: {[resource["name"] for resource in be_resources]}')

    def test_related_applied_in_be(self, control_name: str, control_id: str, report_guid: str, framework_name: str,
                                   resource_name: str, has_related: bool, has_applied: bool, namespace=None):
        be_resources = self.get_posture_resources(framework_name=framework_name, report_guid=report_guid, 
                                                  resource_name=resource_name,related_exceptions="true",namespace=namespace)
        # be_resources = self.get_posture_resources_by_control(related_exceptions="true", control_name=control_name,
        #                                                      control_id=control_id, report_guid=report_guid,
        #                                                      framework_name=framework_name)
        resource = BaseKubescape.get_resource_from_be_resources(be_resources=be_resources, resource_name=resource_name)
        assert has_applied and len(resource["exceptionApplied"]) > 0 or not has_applied and \
               len(resource["exceptionApplied"]) == 0, "Applied-exception was received, " \
                                                       "even though it was not supposed to be received"
        assert has_related and len(resource["relatedExceptions"]) > 0 or not has_related and \
               len(resource["relatedExceptions"]) == 0, "relatedExceptions was received, " \
                                                        "even though it was not supposed to be received"
        assert has_related and len(resource["ignoreRulesSummary"]) > 0 or not has_related and \
               resource["ignoreRulesSummary"] == None, "ignoreRulesSummary was received, " \
                                                       "even though it was not supposed to be received"

    def test_data_in_be(self, cli_result, cluster_name: str, framework_name: str, old_report_guid: str):
        report_guid = self.get_report_guid(cluster_name=cluster_name, framework_name=framework_name,
                                           old_report_guid=old_report_guid)

        # "security" framework is excluded from postureClusters report, therefore skipping tests using APIS that depends on this report.
        if framework_name not in statics.SECURITY_FRAMEWORKS:
            self.test_api_version_info()
            self.compare_top_controls_data(cli_result=cli_result, cluster_name=cluster_name, report_guid=report_guid,
                                        framework_name=framework_name)
            
        # self.compare_framework_data(cli_result, framework_name, report_guid)
        self.compare_controls_data(cli_result, framework_name, report_guid)
        self.compare_resources_data(cli_result, framework_name, report_guid)

    def get_posture_control_by_id(self, framework_name: str, report_guid: str, control_id: str):
        be_controls = self.get_posture_controls(framework_name=framework_name, report_guid=report_guid)
        for control in be_controls:
            if control["id"] == control_id:
                return control
        raise Exception(f'Failed to get control "{control_id}" from backend')

    def test_exception_in_controls(self, framework_name: str, report_guid: str, control_id: str):
        control = self.get_posture_control_by_id(framework_name=framework_name, report_guid=report_guid,
                                                 control_id=control_id)
        message = "Expect to reduce the failed-controls. received from backend: previousFailedResourcesCount = {x1}" \
                  " and failedResourcesCount = {x2}"
        assert control['previousFailedResourcesCount'] - control['failedResourcesCount'] > 0, message.format(
            x1=control['previousFailedResourcesCount'], x2=control['failedResourcesCount']
        )

    def get_report_guid_and_repo_hash_for_git_repository(self, git_repository: GitRepository, old_report_guid: str = "",
                                                         wait_to_result: bool = False) -> Tuple[
        Optional[str], Optional[str]]:
        check_intervals = 30
        sleep_sec = 12

        for _ in range(check_intervals):
            try:
                repository_scans = self.get_repository_posture_repositories(repository_name=git_repository.name,
                                                                            repository_branch=git_repository.branch,
                                                                            repository_owner=git_repository.owner)
            except Exception:
                Logger.logger.exception("get_repository_posture_repositories returned with error")
                repository_scans = []

            scan = next((scan for scan in repository_scans if scan[statics.BE_REPORT_GUID_FIELD] != old_report_guid),
                        None)
            if scan:
                return scan[statics.BE_REPORT_GUID_FIELD], scan['designators']['attributes']['repoHash']
            elif not wait_to_result:
                return None, None
            time.sleep(sleep_sec)

        raise Exception(
            f'Failed to get the report guid from last repository scan after {check_intervals * sleep_sec} seconds')

    def compare_framework_data(self, cli_result, framework_name, report_guid):
        be_frameworks = self.get_posture_frameworks(framework_name=framework_name, report_guid=report_guid)
        self.test_frameworks_from_backend(be_frameworks=be_frameworks, cli_result=cli_result)

    def compare_controls_data(self, cli_result, framework_name, report_guid):
        be_frameworks = self.get_posture_frameworks(framework_name=framework_name, report_guid=report_guid)[0]
        be_controls = self.get_posture_controls(framework_name=framework_name, report_guid=report_guid)
        cli_controls = cli_result[_CLI_SUMMARY_DETAILS_FIELD][statics.CONTROLS_FIELD]
        self.test_controls_from_backend(be_controls=be_controls, be_frameworks=be_frameworks, cli_controls=cli_controls)

    def compare_resources_data(self, cli_result, framework_name, report_guid):
        be_resources = self.get_posture_resources(framework_name=framework_name, report_guid=report_guid)
        self.test_resources_from_backend(be_resources=be_resources, cli_result=cli_result)

    def compare_top_controls_data(self, cli_result, cluster_name, report_guid, framework_name):
        be_results = self.get_top_controls_results(cluster_name)
        self.test_top_controls_from_backend(cli_result=cli_result, be_results=be_results, report_guid=report_guid,
                                            framework_name=framework_name)

    def post_posture_exception(self, exceptions_file, cluster_name: str):
        ks_exceptions = self.create_ks_exceptions(cluster_name=cluster_name, exceptions_file=exceptions_file)
        if isinstance(ks_exceptions, list):
            return [self.post_posture_exception(exceptions_file=i, cluster_name=cluster_name) for i in exceptions_file]
        elif isinstance(ks_exceptions, dict):
            return self.backend.post_posture_exception(exception_object=ks_exceptions)
        else:
            raise Exception("in post_posture_exception, ks_exceptions is wrong type")

    def delete_posture_exception(self, policy_guid):
        if isinstance(policy_guid, list):
            return [self.delete_posture_exception(policy_guid=i) for i in policy_guid]
        self.wait_for_report(report_type=self.backend.delete_posture_exception, policy_guid=policy_guid['guid'])

    def post_custom_framework(self, framework_file, cluster_name: str):
        framework_name, ks_custom_fw = self.create_ks_custom_fw(cluster_name=cluster_name,
                                                                framework_file=framework_file)
        if isinstance(ks_custom_fw, list):
            return [self.post_custom_framework(framework_file=i, cluster_name=cluster_name) for i in ks_custom_fw]
        elif isinstance(ks_custom_fw, dict):
            report_fw, _ = self.wait_for_report(report_type=self.backend.post_custom_framework, fw_object=ks_custom_fw)
            return ks_custom_fw, report_fw
        else:
            raise Exception("in post_custom_framework, framework_file is wrong type")

    def delete_custom_framework(self, ks_custom_fw):
        if isinstance(ks_custom_fw, list):
            return [self.delete_custom_framework(ks_custom_fw=i) for i in ks_custom_fw]
        self.wait_for_report(report_type=self.backend.delete_custom_framework, framework_name=ks_custom_fw['name'])

    def delete_kubescape_config_map(self, namespace: str = 'default', name: str = 'kubescape'):
        try:
            self.kubernetes_obj.delete_config_map(namespace=namespace, name=name)
        except ApiException as api_ex:
            if api_ex.status != 404:
                raise api_ex
        except Exception as ex:
            raise ex

    @staticmethod
    def test_framework_created(fw_object: dict, report_fw: dict):
        message = 'Create framework with {x} controls, backend receive framework with {y} controls'
        assert len(report_fw['controls']) == len(fw_object['controls']), message.format(
            x=len(fw_object['controls']), y=len(report_fw['controls']))

    @staticmethod
    def test_controls_count_of_custom_fw(fw_object: dict, ks_custom_fw: dict, be_result: dict):
        message = 'Create custom-fw with {x} controls, but backend in framework return {y} controls'
        assert len(fw_object['controls']) == len(ks_custom_fw['controlsIDs']), message.format(
            x=len(fw_object['controls']), y=len(ks_custom_fw['controlsIDs']))
        message = 'Create custom-fw with {x} controls, but backend in scan-framework result return {y} controls'
        assert len(fw_object['controls']) == be_result['totalControls'], message.format(
            x=len(fw_object['controls']), y=be_result['totalControls'])

    @staticmethod
    def test_result_of_custom_fw(cli_controls: dict, be_result: list):
        be_controls = sorted(be_result, key=lambda control: control['id'])
        message = 'cli-result return {x} controls, but backend-controls result return {y} controls'
        assert len(cli_controls) == len(be_controls), message.format(x=len(cli_controls), y=len(be_controls))
        for be_control in be_controls:
            c_id = be_control['id']
            message = 'In control {i} cli-result return {x} failedResources and be-result return {y}' \
                      ' failedResourcesCount'
            assert cli_controls[c_id][_CLI_RESOURCE_COUNTERS_FIELD][_CLI_FAILED_RESOURCES_FIELD] == \
                   be_control[statics.BE_FAILED_RESOURCES_COUNT_FIELD], message.format(
                i=c_id, x=cli_controls[c_id][_CLI_RESOURCE_COUNTERS_FIELD][_CLI_FAILED_RESOURCES_FIELD],
                y=be_control[statics.BE_FAILED_RESOURCES_COUNT_FIELD])

    def test_scan_custom_fw_result(self, cli_result: dict, fw_object: dict, report_guid: str):
        ks_custom_fw = self.get_framework(framework_name=fw_object['name'])
        be_fw_result = self.get_posture_frameworks(framework_name=fw_object['name'], report_guid=report_guid)[0]
        self.test_controls_count_of_custom_fw(fw_object=fw_object, ks_custom_fw=ks_custom_fw, be_result=be_fw_result)
        be_controls_result = self.get_posture_controls(framework_name=fw_object['name'], report_guid=report_guid)
        self.test_result_of_custom_fw(cli_controls=cli_result[_CLI_SUMMARY_DETAILS_FIELD][statics.CONTROLS_FIELD],
                                      be_result=be_controls_result)

    def test_scan_custom_fw_deleted(self, fw_name: str):
        frameworks = self.get_framework()
        frameworks_name = list(map(lambda fw: fw['name'], frameworks))
        assert fw_name not in frameworks_name, 'Backend return framework {x} after deleted'.format(x=fw_name)

    @staticmethod
    def test_customer_configuration_result(cli_result: dict, expected_result: str, c_id: str):
        assert c_id in cli_result[_CLI_SUMMARY_DETAILS_FIELD][statics.CONTROLS_FIELD].keys(), \
            'Not found control {c_id} in cli_results->summaryDetails'.format(c_id=c_id)
        assert cli_result[_CLI_SUMMARY_DETAILS_FIELD][statics.CONTROLS_FIELD][c_id][
                   _CLI_STATUS_FILED] == expected_result, \
            'Received from cli_results for control {c_id} status {x}, but expected to be {y}'. \
                format(c_id=c_id,
                       x=cli_result[_CLI_SUMMARY_DETAILS_FIELD][statics.CONTROLS_FIELD][c_id][_CLI_STATUS_FILED],
                       y=expected_result)

    def test_control_input_in_kubescape(self, input_kind: str, input_name: str, included: bool):
        controls_input = self.download_control_input()
        if included:
            assert input_name in controls_input[input_kind], \
                f'Expect to find {input_name} in the controls input -> {input_kind} list'
        else:
            assert input_name not in controls_input[input_kind], \
                f'Expect not to find {input_name} in the controls input -> {input_kind} list'

    def add_to_customer_configuration(self, customer_configuration: dict, input_kind: str, input_name: str):
        customer_configuration[_SETTINGS_FILED][_POSTURE_CONTROL_INPUT_FILED][input_kind].append(input_name)
        self.update_customer_configuration(customer_config=customer_configuration)

    def test_expected_result_against_cli_result(self, cli_result: dict, expected_result_name: str):
        expected_r = self.create_kubescape_expected_results(expected_results=expected_result_name)
        cli_r = cli_result[_CLI_SUMMARY_DETAILS_FIELD]
        fail_path = self.expected_results_contained_in_cli_results(er=expected_r, cr=cli_r, failed_path='')
        assert not fail_path, 'Expected that all the fields in expected-results will be in cli-results. ' \
                              f'The following fields are not found in cli-results: {fail_path}'

    @staticmethod
    def expected_results_contained_in_cli_results(er: dict, cr: dict, failed_path: str):
        """
        Checks whether any key found in er, its value is in cr.
        Support in value for str, int, float, dict. If the value is dict sent in recursion.

        :param er: expected_results
        :param cr: cli_results
        :param failed_path: path until this iteration

        Return Value: list of failed path
        """
        result = []
        for k in er.keys():
            if isinstance(er[k], str):
                if k not in cr.keys() or cr[k] != er[k]:
                    result.append(failed_path + k)
            elif isinstance(er[k], (int, float)):
                if k not in cr.keys() or cr[k] < er[k]:
                    result.append(failed_path + k)
            elif isinstance(er[k], dict):
                if k not in cr.keys():
                    result.append(failed_path + k)
                else:
                    result.extend(BaseKubescape.expected_results_contained_in_cli_results(er=er[k], cr=cr[k],
                                                                                          failed_path=failed_path + k))
            else:
                raise Exception(f"value in Expected-result could be only str, int, float, dict. received {type(er[k])}")
        return result

    @staticmethod
    def get_total_and_failed_controls(kube_controlls):
        tc = len(kube_controlls)
        fc = 0
        for kc in kube_controlls:
            if kube_controlls[kc]["status"] == "failed":
                fc = fc + 1
        return tc, fc

    def comapare_backend_vs_kubescape_frameworks(self, kbs_frameworks_r, be_frameworks):
        failed_ks_frameworks = []
        failed_backend_frameworks = []
        for bf in be_frameworks:
            for kf in kbs_frameworks_r:
                if bf["name"] == kf["name"]:
                    total_kube_c, failed_kube_c = self.get_total_and_failed_controls(kf["controls"])
                    if bf["totalControls"] != total_kube_c:
                        failed_backend_frameworks.append(bf)
                        failed_ks_frameworks.append(kf)
                    if bf["failedControls"] != failed_kube_c:
                        failed_backend_frameworks.append(bf)
                        failed_ks_frameworks.append(kf)
                    break
        return failed_backend_frameworks, failed_ks_frameworks

    def results_ready(self, cluster_name, port, report_guid=''):
        url = f"http://0.0.0.0:{port}/v1/status"
        if report_guid and len(report_guid) > 0:
            url = f"{url}?id={report_guid}"

        for i in range(1, 15):
            try:
                Logger.logger.debug(f"results_ready - url: {url}")
                res = requests.get(url=url)
                if res.status_code >= 200 and res.status_code < 300:
                    res = res.json()
                    if "type" not in res:
                        Logger.logger.warning("response from kubescape is missing 'type'")
                    elif res["type"] == "notBusy":
                        Logger.logger.info(f"kubescape results ready. res: {res}")
                        return True
            except:
                pass
            time.sleep(20)
        raise Exception('the last scan results are not ready in {} seconds'.format(10 * 20))

    def get_kubescape_as_server_last_result(self, cluster_name, port, report_guid=''):
        if self.results_ready(cluster_name, port=port, report_guid=report_guid):
            url = f"http://0.0.0.0:{port}/v1/results?keep=true"
            if report_guid and len(report_guid) > 0:
                url += f"&id={report_guid}"

            Logger.logger.debug(f"get_kubescape_as_server_last_result - url: {url}")
            res = requests.get(url=url)
            if res.status_code >= 200 and res.status_code < 300:
                return res.json()["response"]
            raise Exception('failed to get the last kubescape scan results http code {}'.format(res.status_code))

    def test_backend_vs_kubescape_result(self, report_guid, kubescape_result):
        be_frameworks = self.get_posture_frameworks(report_guid=report_guid)

        # check if there are also security fw scanned for report_guid
        if self.enable_security:
            for sf in statics.SECURITY_FRAMEWORKS:
                be_current_security_framework = self.get_posture_frameworks(report_guid=report_guid, framework_name=sf)
                if be_current_security_framework:
                    Logger.logger.debug(f"test_backend_vs_kubescape_result - found security framework: {sf} in backend")
                    be_frameworks.extend(be_current_security_framework)

        assert _CLI_SUMMARY_DETAILS_FIELD in kubescape_result, "expected key {} is not in kubescape result,kubescape_result: {}".format(
            _CLI_SUMMARY_DETAILS_FIELD, kubescape_result)
        kbs_r = kubescape_result[_CLI_SUMMARY_DETAILS_FIELD]

        assert _CLI_FRAMEWORKS_FIELD in kbs_r, "expected key {} is not in kubescape result,kubescape_result[{}]: {}".format(
            _CLI_SUMMARY_DETAILS_FIELD, _CLI_SUMMARY_DETAILS_FIELD, kbs_r)
        kbs_frameworks_r = kbs_r[_CLI_FRAMEWORKS_FIELD]

        fail_backend_frameworks, fail_kubescape_frameworks = self.comapare_backend_vs_kubescape_frameworks(
            kbs_frameworks_r, be_frameworks)
        assert not fail_backend_frameworks and not fail_kubescape_frameworks, 'Expected that all the fields in expected-results will be in cli-results. ' \
                                                                              f'The following fields are not matched in kubescape-results: {fail_kubescape_frameworks} and in backend results {fail_backend_frameworks}'

    def get_report_guid(self, cluster_name: str, framework_name: str = "", old_report_guid: str = "",
                        wait_to_result: bool = False):
        found = False
        Logger.logger.info("cluster_name: {}, framework_name: {}, old_report_guid: {}, wait_to_result: {}".format(
            cluster_name, framework_name, old_report_guid, wait_to_result))
        for i in range(25):
            be_cluster_overtime = self.get_posture_clusters_overtime(cluster_name=cluster_name,
                                                                     framework_name=framework_name)
            if not wait_to_result and len(be_cluster_overtime) == 0:
                return ""
            if len(be_cluster_overtime) > 0 and (old_report_guid == "" or
                                                 be_cluster_overtime[statics.BE_CORDS_FIELD][
                                                     statics.BE_REPORT_GUID_FIELD] != old_report_guid):
                if found:
                    Logger.logger.info("get_report_guid - returning found report_guid: {}".format(
                        be_cluster_overtime[statics.BE_CORDS_FIELD][statics.BE_REPORT_GUID_FIELD]))
                    return be_cluster_overtime[statics.BE_CORDS_FIELD][statics.BE_REPORT_GUID_FIELD]
                Logger.logger.info("get_report_guid - found report_guid: {}".format(
                        be_cluster_overtime[statics.BE_CORDS_FIELD][statics.BE_REPORT_GUID_FIELD]))
                found = True
                # results where found, this means the backend started the aggregation, we will wait a little for the backend to complete the aggregation
                time.sleep(20)

            time.sleep(5)
        raise Exception('Failed to get the report-guid for the last scan.')
    
    def test_controls_compliance_score(self, report: dict):
        # for each control check that compliance score is the percentage of passed resources/total resources
        for _, control in report[_CLI_SUMMARY_DETAILS_FIELD][_CONTROLS_FIELD].items():
            total_resources = 0
            passed_resources = 0
            for resource_group, amount in control[_CLI_RESOURCE_COUNTERS_FIELD].items():
                total_resources += amount
                # excluded resources are considered to have passed status
                if resource_group == _CLI_PASSED_RESOURCES_FIELD or resource_group == _CLI_EXCLUDED_RESOURCES_FIELD:
                    passed_resources += amount
            if total_resources == 0:
                if control[_CLI_STATUS_INFO_FIELD][_CLI_STATUS_FILED] == _CLI_STATUS_PASSED:
                    assert control[_COMPLIANCE_SCORE_FIELD] == 100, "expected passed control to have compliance score of 100, but it is {}".format(control[_COMPLIANCE_SCORE_FIELD])
                else:
                    assert control[_COMPLIANCE_SCORE_FIELD] == 0, "expected compliance score to be 0, but it is {}".format(control[_COMPLIANCE_SCORE_FIELD])
            else:
                assert round(control[_COMPLIANCE_SCORE_FIELD], 2) == round((passed_resources / total_resources) * 100, 2), \
                    "expected compliance score to be {}, but it is {}".format(round((passed_resources / total_resources) * 100, 2), round(control[_COMPLIANCE_SCORE_FIELD]), 2)
    
    def test_frameworks_compliance_score(self, report: dict):
        #  for each framework check that compliance score is the average of controls scores
        for framework in report[_CLI_SUMMARY_DETAILS_FIELD][_CLI_FRAMEWORKS_FIELD]:
            sum_scores = 0
            for c_id, control in framework[_CONTROLS_FIELD].items():
                sum_scores += control[_COMPLIANCE_SCORE_FIELD]
            assert round(framework[_COMPLIANCE_SCORE_FIELD], 2) == round(sum_scores / len(framework[_CONTROLS_FIELD]), 2), \
                "expected compliance score to be {}, but it is {}".format(round(sum_scores / len(framework[_CONTROLS_FIELD]), 2), round(framework[_COMPLIANCE_SCORE_FIELD]), 2)


    def test_controls_compliance_score_from_backend(self, framework_report, report_guid, framework_name: str = ""):
        controls = self.get_posture_controls(framework_name=framework_name, report_guid=report_guid)
        for control in controls:
          c_id = control['id']
          assert control[_COMPLIANCE_SCORE_FIELD] == framework_report[_CONTROLS_FIELD][c_id][_COMPLIANCE_SCORE_FIELD], \
            "in framework {}, expected compliance score in be of control: {} to be {}, but it is {}".format(
              framework_name, c_id, framework_report[_CONTROLS_FIELD][c_id][_COMPLIANCE_SCORE_FIELD], control[_COMPLIANCE_SCORE_FIELD])

    def test_frameworks_compliance_score_from_backend(self, framework_report, report_guid, framework_name: str = ""):
        be_frameworks = self.get_posture_frameworks(framework_name=framework_name, report_guid=report_guid)
        assert framework_report[_COMPLIANCE_SCORE_FIELD] == be_frameworks[0][_COMPLIANCE_SCORE_FIELDV1], \
            "expected framework: {} compliance score in be to be {}, but it is".format(
            framework_name, framework_report[_COMPLIANCE_SCORE_FIELD], be_frameworks[0][_COMPLIANCE_SCORE_FIELDV1])


    def test_compliance_score_in_clusters_overtime(self, cluster_name: str, framework_report: dict, framework_name: str = ""):
        be_cluster_overtime = self.get_posture_clusters_overtime(cluster_name=cluster_name, framework_name=framework_name)
        assert len(be_cluster_overtime) > 0 , "expected to get response from clustersOvertime for framework {} in cluster {}".format(framework_name, cluster_name)
        # check that framework score from be_cluster_overtime matches the score from framework_report from kubescape
        assert be_cluster_overtime[statics.BE_CORDS_FIELD][_COMPLIANCE_SCORE_FIELD] == framework_report[_COMPLIANCE_SCORE_FIELD], \
            "expected framework: {} compliance score in be to be {}, but it is".format(  
            framework_name, framework_report[_COMPLIANCE_SCORE_FIELD], be_cluster_overtime[statics.BE_CORDS_FIELD][_COMPLIANCE_SCORE_FIELD])



    def get_job_report_info(self, report_guid, cluster_wlid: str = ""):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_job_report_info,
                                               report_guid=report_guid, cluster_wlid=cluster_wlid)
        return c_panel_info

    def is_ks_cronjob_created(self, framework_name, timeout=60):
        start = time.time()
        err = ""
        while time.time() - start < timeout:
            if self.kubernetes_obj.is_ks_cronjob_created(framework_name=framework_name):
                return True
            time.sleep(10)
        return False

    def is_hostsensor_triggered(self, timeout=180):
        start = time.time()
        err = ""
        while time.time() - start < timeout:
            if self.kubernetes_obj.is_hostsensor_triggered():
                return True
            time.sleep(5)
        return False

    @staticmethod
    def test_host_scanner_results(cli_results: dict):
        for control_id, control_value in cli_results[_CLI_SUMMARY_DETAILS_FIELD][statics.CONTROLS_FIELD].items():
            assert control_value[_CLI_STATUS_FILED] != 'skipped', \
                f'Expected not to get skipped status as a result of the controls, ' \
                f'when the flag enable-host-scan is added, the status of control {control_id} is skipped'

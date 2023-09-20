import copy
import json
import os
import shutil
import time

import test_driver as driver
from configurations.system.network_policy import NetworkPolicy, NetworkPolicyIngress
from configurations.system.posture_exception_policy import PostureExceptionPolicy
from configurations.system.secret_policy import SecretPolicy
from infrastructure import backend_api
from systest_utils import TestUtil, Logger, statics
from systest_utils.wlid import Wlid
from datetime import datetime, timezone

from http import client

AGENT_REPORT_RETIES: int = 10
AGENT_REPORT_RETIES_WAIT: int = 20

DEFAULT_TIMEOUT_IS_ATTACHED = 60 * 10
DEFAULT_TIMEOUT_IS_SIGNED = 60 * 10
DEFAULT_TIMEOUT_IS_SECRET_PROTECTED = 60 * 10


DELETE_TEST_TENANT_ALWAYS = "ALWAYS"
DELETE_TEST_TENANT_TEST_PASSED = "TEST_PASSED"
DELETE_TEST_TENANT_NEVER = "NEVER"

DELETE_TEST_TENANT_DEFAULT = DELETE_TEST_TENANT_ALWAYS


class BaseTest(object):
    def __init__(self, test_driver: driver.TestDriver, test_obj, backend: backend_api.ControlPanelAPI = None,
                 **kwargs):
        
        self.test_started_at = datetime.now(timezone.utc).astimezone().isoformat()
        self.cluster_deleted = False

        # objects
        self.test_driver = test_driver
        self.test_obj = test_obj
        self.backend: backend_api.ControlPanelAPI = backend
        self.kwargs = kwargs

        # stored for cleanup
        self.wlids: list = list()
        self.encryption_configurations: list = list()
        self.network_policies: list = list()
        self.ingress_network_policies: list = list()
        self.secret_policies: list = list()

        self.ignore_agent: bool = TestUtil.get_arg_from_dict(self.test_driver.kwargs, "load_without_agent", False)
        self.leave_redis_data: bool = TestUtil.get_arg_from_dict(self.test_driver.kwargs, "leave_redis_data", False)
        self.test_summery_data = {}

        self.test_tenant_id = ""

        # defines when to delete tenant. Only applied if self.create_test_tenant is True
        self.delete_test_tenant = TestUtil.get_arg_from_dict(self.test_driver.kwargs, "delete_test_tenant", DELETE_TEST_TENANT_DEFAULT)

        # defines if to create a new  test tenant for the test
        self.create_test_tenant = test_obj[("create_test_tenant", False)]

        if self.create_test_tenant:
            Logger.logger.info(f"create_test_tenant is True")
            self.test_tenant_id = self.create_new_tenant()

        self.test_failed = False



    def __del__(self):
        Logger.logger.info(f"test summarize: {json.dumps(self.test_summery_data, indent=4)}")

    def failed(self):
        self.test_failed = True

    def create_tenant_name(self, prefix: str) -> str:
        epoch = time.time()
        prefix = "auto_systest_" + prefix
        name = "%s_%d" % (prefix, epoch)
        return name

    def create_new_tenant(self, prefix=None) -> int:
        Logger.logger.info(f"creating new test tenant")
        # prefix = self.__class__.__name__ if prefix is None else prefix + self.__class__.__name__
        prefix = prefix if prefix is not None else ""
        tenantName = self.create_tenant_name(prefix)
        res, test_tenant_id = self.backend.create_tenant(tenantName)
        Logger.logger.info(f"created tenant name '{tenantName}' with tenant id {test_tenant_id}")
        self.backend.select_tenant(test_tenant_id)
        return test_tenant_id


    def delete_tenants(self):

        if self.test_tenant_id == "":
            Logger.logger.info(f"test_tenant_id is empty or was deleted, not deleting")
            return

        # skip delete if delete_test_tenant is NEVER
        if self.delete_test_tenant == DELETE_TEST_TENANT_NEVER:
            Logger.logger.info(f"'delete_test_tenant' arg is '{DELETE_TEST_TENANT_NEVER}', not deleting")
            Logger.logger.info(f"test_tenant_id is '{self.test_tenant_id}'")
            return 
    
        # skip delete if delete_test_tenant is TEST_PASSED and test failed
        if self.delete_test_tenant == DELETE_TEST_TENANT_TEST_PASSED and self.test_failed:
            Logger.logger.info(f"'delete_test_tenant' arg is '{DELETE_TEST_TENANT_TEST_PASSED}' and test failed, not deleting")
            Logger.logger.info(f"test_tenant_id is '{self.test_tenant_id}'")
            return
        
   
        response = self.backend.delete_tenant(self.test_tenant_id)
        if response.status_code != client.OK:
            Logger.logger.error(f"delete tenant failed {self.test_tenant_id}")
        else:
            Logger.logger.info(f"deleted tenant {self.test_tenant_id}")
            self.test_tenant_id = ""


    
    def create_ks_exceptions(self, cluster_name: str, exceptions_file):
        if not exceptions_file:
            return {}
        if isinstance(exceptions_file, list):
            return [self.create_ks_exceptions(cluster_name=cluster_name, exceptions_file=i) for i in exceptions_file]
        elif isinstance(exceptions_file, str):
            ke_path = self.get_ks_exceptions_path(ke=exceptions_file)
            with open(ke_path, "r") as f:
                ks_exception = json.loads(f.read())
            ks_exception['name'] += cluster_name
            resources = ks_exception['resources']
            for resource in resources:
                resource['attributes']['cluster'] = cluster_name
            ks_exception['resources'] = resources
            return ks_exception
        else:
            raise Exception("in create_ks_exceptions, exception_file is wrong type")

    def create_ks_custom_fw(self, cluster_name: str, framework_file, framework_guid=""):
        if not framework_file:
            return {}
        if isinstance(framework_file, list):
            return [self.create_ks_custom_fw(cluster_name=cluster_name, framework_file=i) for i in framework_file]
        elif isinstance(framework_file, str):
            ke_path = self.get_ks_custom_fw_path(cf=framework_file)
            with open(ke_path, "r") as f:
                ks_custom_fw = json.loads(f.read())
            ks_custom_fw['name'] += cluster_name
            ks_custom_fw['description'] += cluster_name
            if framework_guid != "":
                ks_custom_fw['guid'] = framework_guid
            return ks_custom_fw['name'], ks_custom_fw
        else:
            raise Exception("in create_ks_custom_fw, framework_file is wrong type")

    def create_vulnerabilities_expected_results(self, expected_results):
        if not expected_results:
            return []
        er_path = self.get_vulnerabilities_expected_results(er=expected_results)
        with open(er_path, "r") as f:
            vulnerabilities_expected_results = json.loads(f.read())
        return vulnerabilities_expected_results

    def create_kubescape_expected_results(self, expected_results):
        if not expected_results:
            return []
        er_path = self.get_kubescape_expected_results(er=expected_results)
        with open(er_path, "r") as f:
            kubescape_expected_results = json.loads(f.read())
        return kubescape_expected_results

    def is_unattached_n_running(self, wlid: list, replicas=None):
        total_running_instances = 0
        c_panel_infos = {}
        for i in wlid:
            c_panel_info = self.backend.get_info_from_wlid(wlid)
            assert c_panel_info[
                       "armoIntegrityStatus"] == "Unattached", f"wrong armoIntegrityStatus for unattached workload: {c_panel_info['armoIntegrityStatus']}; {c_panel_info['caLastUpdate']}"
            assert "Running" in c_panel_info[
                "instancesStatus"], f"wrong instancesStatus for unattached workload:{c_panel_info['instancesStatus']} ; {c_panel_info['caLastUpdate']}"
            assert c_panel_info["instancesStatus"][
                       "Running"] > 0, f"no running instances for unattached workload:{c_panel_info['instancesStatus']} ; {c_panel_info['caLastUpdate']}"
            total_running_instances += c_panel_info["instancesStatus"]["Running"]
            c_panel_infos[i] = copy.deepcopy(c_panel_info)
        if replicas:
            assert total_running_instances == replicas, f"wrong running instances num for unattached workloads: expected {replicas} running instances; found {c_panel_infos}"
        return c_panel_infos[wlid[0]] if len(wlid) == 1 and wlid[0] in c_panel_infos else c_panel_infos

    def is_running(self, wlid: list, replicas=None):
        total_running_instances = 0
        c_panel_infos = {}
        for i in wlid:
            c_panel_info = self.backend.get_info_from_wlid(wlid)
            assert "Running" in c_panel_info[
                "instancesStatus"], f"wrong instancesStatus for running workload:{c_panel_info['instancesStatus']} ; {c_panel_info['caLastUpdate']}"
            assert c_panel_info["instancesStatus"][
                       "Running"] > 0, f"no running instances for running workload:{c_panel_info['instancesStatus']} ; {c_panel_info['caLastUpdate']}"
            total_running_instances += c_panel_info["instancesStatus"]["Running"]
            c_panel_infos[i] = copy.deepcopy(c_panel_info)
        if replicas:
            assert total_running_instances == replicas, f"wrong number of running instances: expected {replicas}, found {c_panel_infos}"
        return c_panel_infos[wlid[0]] if len(wlid) == 1 and wlid[0] in c_panel_infos else c_panel_infos

    def is_unattached_reported(self, wlid, timeout=120, replicas=None):
        if self.ignore_agent:
            return

        Logger.logger.debug('waiting for in-cluster collector to report in dashboard')
        if isinstance(wlid, str):
            wlid = [wlid]
        c_panel_info, t = self.wait_for_report(wlid=wlid, report_type=self.is_unattached_n_running,
                                               ignore_agent=self.ignore_agent, timeout=timeout, replicas=replicas)
        Logger.logger.debug('in-cluster collector successfully reported.\nwlid: {}\ntime: {}\ndata:\n{}'.format(
            wlid, t, json.dumps(c_panel_info, indent=4)))

    def is_reported(self, wlid, timeout=120, replicas=None):
        if self.ignore_agent:
            return

        Logger.logger.debug('waiting for in-cluster collector to report in dashboard')
        if isinstance(wlid, str):
            wlid = [wlid]
        c_panel_info, t = self.wait_for_report(wlid=wlid, report_type=self.is_running,
                                               ignore_agent=self.ignore_agent, timeout=timeout, replicas=replicas)
        Logger.logger.debug('in-cluster collector successfully reported.\nwlid: {}\ntime: {}\ndata:\n{}'.format(
            wlid, t, json.dumps(c_panel_info, indent=4)))

    def get_microservice_instances(self, wlid: str = None, instance_id: str = None):
        return self.backend.get_microservice_instances(wlid, instance_id)

    @staticmethod
    def wait_for_report(report_type, timeout=120, sleep_interval=30, ignore_agent: bool = False, **kwargs):
        """Given a input function, repeats its execution for an interval of time 
        and returns its result if no exceptions happened.

        :param report_type: Input function we want to run.
        :param timeout: Timeout time.
        :param sleep_interval: Interval of time we want to wait before the next run.
        :param ignore_agent: <parameter not in use>
        :param **kwargs: Parameters needed for the input function.
        :return: Result of input function - Time passed since the first run.
        """
        start = time.time()
        err = ""
        while time.time() - start < timeout:
            try:
                report_info = report_type(**kwargs)
                return report_info, TestUtil.get_time(start, time.time())
            except Exception as e:
                if str(e).find("502 Bad Gateway") > 0:
                    raise e
                err = e
                Logger.logger.warning(f"{report_type.__func__.__name__}, error: '{e}', kwargs: '{kwargs}'")
            time.sleep(sleep_interval)
        raise Exception(
            f"{report_type.__func__.__name__}, timeout: {timeout // 60} minutes, error: {err}. kwargs: '{kwargs}'")

    def cleanup(self, wlid: str = None, display_wt: bool = False):
        self.delete_tenants()
        return "", ""

    def validate_microservice_is_inactive(self, wlid, tries_num=5):
        for i in range(tries_num):
            waiting_time = 30 * (i + 1)
            time.sleep(waiting_time)
            try:
                ms_info = self.backend.get_info_from_wlid(wlid=wlid)
                assert ms_info['isActive'], "still active"
                assert ms_info['numOfProcesses'] == 0, "processes reported"
                break
            except Exception as ex:
                Logger.logger.warning(
                    "Microservice is still active!!! ({}/{}) {}".format(i + 1, tries_num, ex))
            if i == (tries_num - 1):
                Logger.logger.warning("make sure the agent had send bye packet (report type 0x1)")

    def validate_microservice_is_deleted(self, wlid):
        try:
            Logger.logger.info("Validating microservices is deleted")
            self.backend.get_info_from_wlid(wlid=wlid)
        except:
            return
        raise Exception("microservice not deleted. wlid: {}".format(wlid))

    @staticmethod
    def get_workload_templates_paths(wt):
        if isinstance(wt, str):
            return TestUtil.get_abs_path(relative_path=statics.DEFAULT_WT_PATH, file_name=wt)
        if isinstance(wt, list):
            return [TestUtil.get_abs_path(relative_path=statics.DEFAULT_WT_PATH,
                                          file_name=i if isinstance(wt, str) else i.name) for i in wt]
        return TestUtil.get_abs_path(relative_path=statics.DEFAULT_WT_PATH, file_name=wt.name)

    @staticmethod
    def get_signing_profiles_path(sp):
        return TestUtil.get_abs_path(relative_path=statics.DEFAULT_SP_PATH, file_name=sp)

    @staticmethod
    def get_ks_exceptions_path(ke):
        return TestUtil.get_abs_path(relative_path=statics.DEFAULT_KS_EXCEPTIONS_PATH, file_name=ke)

    @staticmethod
    def get_ks_custom_fw_path(cf):
        return TestUtil.get_abs_path(relative_path=statics.DEFAULT_KS_CUSTOM_FW_PATH, file_name=cf)

    @staticmethod
    def get_vulnerabilities_expected_results(er):
        return TestUtil.get_abs_path(relative_path=statics.DEFAULT_VULNERABILITY_EXPECTED_RESULTS, file_name=er)

    @staticmethod
    def get_kubescape_expected_results(er):
        return TestUtil.get_abs_path(relative_path=statics.DEFAULT_KUBESCAPE_EXPECTED_RESULTS, file_name=er)

    def replicate_wt_containers(self):
        if not hasattr(self.test_obj, "workload_templates") or not self.test_obj.workload_templates:
            return
        for i in self.test_obj.workload_templates:
            for j in i.containers:
                if j.replicas > 1:
                    containers = []
                    n = j.name
                    j.name = n + "0"
                    containers.append(copy.deepcopy(j))
                    for k in range(1, j.replicas):
                        temp_con = copy.deepcopy(j)
                        temp_con.name = n + str(k)
                        containers.append(temp_con)
                    i.containers = containers

    def get_configuration(self, config: str, default=None):
        """
        get configuration from command line or test config
        :param config: config key
        :param default: if not found in command line args or in test config
        :return:
        """
        return TestUtil.get_arg_from_dict(self.test_driver.kwargs, config,
                                          default=TestUtil.get_arg_from_dict(self.test_obj.kwargs, config,
                                                                             default=default))

    @staticmethod
    def assertEqual(firts, second, msg):
        assert firts == second, msg
        
    @staticmethod
    def assertIn(member, container, msg):
        assert member in container, msg

    def get_all_alert_channels_for_cluster(self, cluster):
        ret = []
        channels = self.backend.get_all_alert_channels().content
        if channels:
            for ac in json.loads(channels.decode("utf-8")):
                for scope in ac["scope"]:
                    if scope["cluster"] == "" or scope["cluster"] == cluster:
                        ret.append(ac)
                        break
        return ret

    def delete_all_alert_channels_for_cluster(self, cluster):
        leftovers = self.get_all_alert_channels_for_cluster(cluster)
        for ac in leftovers:
            self.backend.remove_alert_channel(ac["channel"]["guid"])

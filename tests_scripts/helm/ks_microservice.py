from datetime import datetime,timezone
import os
import time
from tests_scripts.helm.base_helm import BaseHelm
from tests_scripts.kubescape.base_kubescape import BaseKubescape
from systest_utils import Logger, TestUtil, statics
#from struct_diff import Comparator,JSONFormatter
import json

DEFAULT_BRANCH = "release"

class ScanAttackChainsWithKubescapeHelmChart(BaseHelm, BaseKubescape):
    """
    ScanWithKubescapeHelmChartWithoutManifests install the kubescape operator and run the scan to check attack-chains.
    """

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanAttackChainsWithKubescapeHelmChart, self).__init__(test_obj=test_obj, backend=backend,
                                                         kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'

        attack_chain_scenarios_path = "./configurations/attack-chains-test-env"
        attack_chain_expected_values = "./configurations/attack_chains_expected_values"

        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info("Installing attack-chain-scenario")

        Logger.logger.info("Applying scenario manifests")
        test_scenario = self.test_obj[("test_scenario", None)]
        deploy_cmd = os.path.join(attack_chain_scenarios_path, 'deploy_scenario') + ' ' + os.path.join(attack_chain_scenarios_path , test_scenario)
        TestUtil.run_command(command_args=deploy_cmd, display_stdout=True, timeout=300)
        time.sleep(5)

        Logger.logger.info("Installing kubescape with helm-chart")
        # 2.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 2.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))
        current_datetime = datetime.now(timezone.utc)

        # 2.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        time.sleep(10)

        Logger.logger.info("wait for response from BE")
        r, t = self.wait_for_report(
            self.backend.get_active_attack_chains, 
            timeout=1200,
            current_datetime=current_datetime,
            cluster_name=cluster
            )

        Logger.logger.info('loading attack chain scenario to validate it')
        f = open(os.path.join(attack_chain_expected_values, test_scenario+'.json'))
        expected = json.load(f) 
        response = json.loads(r.text)

        Logger.logger.info('comparing attack-chains result with expected ones')
        #cmp = Comparator()
        #d = cmp.diff(expected, response)
        #difference = JSONFormatter(d, {'max_elisions': 1})
        #Logger.logger.info('diff: %s', difference)
        assert self.check_attack_chains_results(response, expected), f"Attack chain response differs from the expected one. Response: {response}, Expected: {expected}"


        # Fixing phase
        Logger.logger.info("attack chains detected, applying fix command")
        self.fix_attack_chain(attack_chain_scenarios_path, test_scenario)
        time.sleep(20)
        current_datetime = datetime.now(timezone.utc)
        Logger.logger.info("triggering a new scan")
        trigger = self.test_obj["test_job"][0]["trigger_by"]
        self.trigger_scan(cluster, trigger)

        Logger.logger.info("wait for response from BE")
        # we set the timeout to 1000s because image scan 
        # cat take more than 15m to get the updated result
        active_attack_chains, t = self.wait_for_report(
            self.backend.has_active_attack_chains, 
            timeout=1000, 
            cluster_name=cluster
            )

        Logger.logger.info('attack-chain fixed properly')
        return self.cleanup()

    def fix_attack_chain(self, attack_chain_scenarios_path, test_scenario):
        fix_type = self.test_obj[("fix_object", "control")]
        fix_command= os.path.join(attack_chain_scenarios_path, test_scenario, 'fix_' + fix_type)
        TestUtil.run_command(command_args=fix_command, display_stdout=True, timeout=300)
        time.sleep(5)

    def trigger_scan(self, cluster_name, trigger_by) -> None:
        """trigger_scan create a new scan action from the backend

        :param cluster_name: name of the cluster you want to scan
        :param trigger_by: the kind of event that trigger the scan ("cronjob", "scan_on_start")
        """
        if trigger_by == "cronjob":
            self.backend.create_kubescape_job_request(
                cluster_name=cluster_name,
                trigger_by=trigger_by,
                framework_list=["security"],
                with_host_sensor="true"
            )
        else:
            self.backend.trigger_posture_scan(
                cluster_name=cluster_name,
                framework_list=["security"],
                with_host_sensor="true"
                )

    def compare_nodes(self, obj1, obj2) -> bool:
        """Walk 2 dictionary object to compare their values.

        :param obj1: dictionary one to be compared.
        :param obj2: dictionary two to be compared.
        :return: True if all checks passed, False otherwise.
        """
        # check at first if we are managin dictionaries
        if isinstance(obj1, dict) and isinstance(obj2, dict):
            # check if key 'nextNodes' is present in the dictionaries
            if 'nextNodes' in obj1 and 'nextNodes' in obj2:
                # check if length of the items is the same
                if len(obj1['nextNodes']) != len(obj2['nextNodes']):
                    return False
                # loop over the new nextNodes
                for node1, node2 in zip(obj1['nextNodes'], obj2['nextNodes']):
                    if not self.compare_nodes(node1, node2):
                        return False
                return True
            else:
                if 'name' in obj1 and 'name' in obj2:
                    return obj1['name'] == obj2['name']
                return all(self.compare_nodes(obj1[key], obj2[key]) for key in obj1.keys())
        return False

    def check_attack_chains_results(self, result, expected) -> bool:
        """Validate the input content with the expected one.
        
        :param result: content retrieved from backend.
        :return: True if all the controls passed, False otherwise.
        """
        # Some example of assertion needed to recognize attack chain scenarios
        for acid, ac in enumerate(result['response']['attackChains']):
            ac_node_result = result['response']['attackChains'][acid]['attackChainNodes']
            ac_node_expected = expected['response']['attackChains'][acid]['attackChainNodes']
            if ac_node_result['name'] != ac_node_expected['name']:
                return False
            if not self.compare_nodes(ac_node_result, ac_node_expected):
                return False
        return True


class ScanWithKubescapeHelmChart(BaseHelm, BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanWithKubescapeHelmChart, self).__init__(test_obj=test_obj, backend=backend,
                                                         kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        # test Agenda:

        # P1 Install Wikijs
        # 1.1 install Wikijs
        # 1.2 verify installation
        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)

        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)

        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        Logger.logger.info("Stage 1.2: Get old report-guid")
        old_report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(), wait_to_result=True)

        Logger.logger.info("Installing kubescape with helm-chart")
        # 2.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 2.2 install armo helm-chart
        self.install_armo_helm_chart()

        # 2.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        Logger.logger.info("Stage 2.2: Get report-guid")
        report_guid = self.get_report_guid(cluster_name=self.kubernetes_obj.get_cluster_name(),
                                           old_report_guid=old_report_guid)

        self.test_helm_chart_results(report_guid=report_guid)

        return self.cleanup()


class ScanWithKubescapeAsServiceTest(BaseHelm, BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanWithKubescapeAsServiceTest, self).__init__(test_obj=test_obj, backend=backend,
                                                             kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        # test Agenda:

        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)

        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        Logger.logger.info("Installing kubescape with helm-chart")
        # 2.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 2.2 install armo helm-chart
        self.install_armo_helm_chart()

        # 2.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=240)

        self.test_scan_jobs(port=statics.KS_PORT_FORWARD)

        return self.cleanup()

    def test_scan_jobs(self, port):

        cluster_name = self.kubernetes_obj.get_cluster_name()
        Logger.logger.info("Get old report-guid")
        old_report_guid = self.get_report_guid(cluster_name=cluster_name, wait_to_result=True)
        TestUtil.sleep(120, "wait for namespace creation to finished")
        pod_name = self.kubernetes_obj.get_kubescape_pod(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        self.port_forward_proc = self.kubernetes_obj.portforward(cluster_name, statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                                 pod_name, 8080)

        for job in self.test_obj["test_job"]:
            job_type = job["trigger_by"]
            if job_type == "scan_on_start":
                self.check_result_in_namespace_creation(job, cluster_name, "", port=port)
            elif job_type == "job":
                self.check_result_with_backend_demand(job, cluster_name, old_report_guid, port=port)
            elif job_type == "cronjob":
                self.check_result_with_backend_cronjob(job, cluster_name, old_report_guid, port=port)

    def check_result_in_namespace_creation(self, job, cluster_name, old_report_guid, port):
        Logger.logger.info('check result in namespace creation')
        report_guid = self.get_report_guid(cluster_name=cluster_name,
                                           old_report_guid=old_report_guid)

        Logger.logger.info('get result from kubescape in cluster')
        kubescape_result = self.get_kubescape_as_server_last_result(cluster_name, port=port, report_guid=report_guid)

        Logger.logger.info('test result against backend results')
        self.test_backend_vs_kubescape_result(report_guid=report_guid, kubescape_result=kubescape_result)      

        return report_guid

    def check_result_with_backend_demand(self, job, cluster_name, old_report_guid, port):
        trigger_by = job["trigger_by"]
        framework_list = None
        if "framework" in job.keys():
            framework_list = job["framework"]
        with_host_sensor = "false"
        if "hostsensor" in job.keys():
            if job["hostsensor"]:
                with_host_sensor = "true"

        Logger.logger.info("create scan by backend trigger")

        self.backend.create_kubescape_job_request(cluster_name=cluster_name, trigger_by=trigger_by,
                                                  framework_list=framework_list, with_host_sensor=with_host_sensor)

        if with_host_sensor == "true":
            Logger.logger.info('check hostsensor trigger')
            assert self.is_hostsensor_triggered(), "host sensor has not triggered"

        Logger.logger.info("Get report-guid")
        report_guid = self.get_report_guid(cluster_name=cluster_name,
                                           old_report_guid=old_report_guid,
                                           framework_name=framework_list[0])

        Logger.logger.info('get result from kubescape in cluster')
        kubescape_result = self.get_kubescape_as_server_last_result(cluster_name, port, report_guid)

        Logger.logger.info('test result against backend results')
        self.test_backend_vs_kubescape_result(report_guid=report_guid, kubescape_result=kubescape_result)

    def check_result_with_backend_cronjob(self, job, cluster_name, old_report_guid, port):
        sleep_time = 120

        trigger_by = job["trigger_by"]
        framework_list = None
        if "framework" in job.keys():
            framework_list = job["framework"]
        with_host_sensor = "false"
        if "hostsensor" in job.keys():
            if job["hostsensor"]:
                with_host_sensor = "true"

        if job["operation"] == "create":
            self.backend.create_kubescape_job_request(cluster_name=cluster_name, trigger_by=trigger_by,
                                                      framework_list=framework_list, with_host_sensor=with_host_sensor)

            Logger.logger.info("check if kubescape cronjob created")
            assert self.is_ks_cronjob_created(framework_list[0]), "kubescape cronjob failed to create"

            Logger.logger.info("check if kubescape cronjob created in backend")
            assert self.backend.is_ks_cronjob_created_in_backend(cluster_name,
                framework_list[0]), "kubescape cronjob failed to create in backend"

            Logger.logger.info("check if backend returns only kubescape cronjobs for api")
            self.backend.is__backend_returning_only_ks_cronjob(cluster_name), "kubescape cronjob failed to create in backend"


            sleep_time += 30
            TestUtil.sleep(sleep_time, "wait till data will arrive to backend")
            Logger.logger.info("Get report-guid")
            report_guid = self.get_report_guid(cluster_name=cluster_name,
                                               old_report_guid=old_report_guid,
                                               framework_name=framework_list[0])

            Logger.logger.info('get result from kubescape in cluster')
            kubescape_result = self.get_kubescape_as_server_last_result(cluster_name, port=port)

            Logger.logger.info('test result against backend results, report_guid: {}'.format(report_guid))
            self.test_backend_vs_kubescape_result(report_guid=report_guid, kubescape_result=kubescape_result)

        if job["operation"] == "update":
            Logger.logger.info("update kubescape cronjob")

            Logger.logger.info("check if kubescape cronjob created")
            assert self.is_ks_cronjob_created(framework_list[0]), "kubescape cronjob failed to create"
            cron_job_schedule = self.kubernetes_obj.get_ks_cronjob_schedule(statics.CA_NAMESPACE_FROM_HELM_NAME)

            Logger.logger.info("update kubescape cronjob created")
            cronjobs_name = self.kubernetes_obj.get_ks_cronjob_name(statics.CA_NAMESPACE_FROM_HELM_NAME)
            self.backend.update_kubescape_job_request(cluster_name=cluster_name, cronjobs_name=cronjobs_name)

            TestUtil.sleep(sleep_time, "wait till update will from backend to finish")
            Logger.logger.info("check if kubescape update succeeded")
            assert self.is_ks_cronjob_created(framework_list[0]), "kubescape cronjob failed to create"
            new_cron_job_schedule = self.kubernetes_obj.get_ks_cronjob_schedule(statics.CA_NAMESPACE_FROM_HELM_NAME)
            assert cron_job_schedule != new_cron_job_schedule, "kubescape schedule string is not changed new {} old {}".format(
                new_cron_job_schedule, cron_job_schedule)

        if job["operation"] == "delete":
            Logger.logger.info("delete kubescape cronjob")

            Logger.logger.info("check if kubescape cronjob exist")
            assert self.is_ks_cronjob_created(framework_list[0]), "kubescape cronjob is not exist"

            Logger.logger.info("delete kubescape cronjob created")
            cron_job_schedule = self.kubernetes_obj.get_ks_cronjob_schedule(statics.CA_NAMESPACE_FROM_HELM_NAME)
            cronjobs_name = self.kubernetes_obj.get_ks_cronjob_name(statics.CA_NAMESPACE_FROM_HELM_NAME)
            self.backend.delete_kubescape_job_request(cluster_name=cluster_name, schedule=cron_job_schedule,
                                                      cronjobs_name=cronjobs_name)

            TestUtil.sleep(sleep_time, "wait till delete cronjob will from backend to finish")
            Logger.logger.info("check if kubescape cronjob deleted")
            assert not self.is_ks_cronjob_created(framework_list[0]), "kubescape cronjob failed to deleted"

class ControlClusterFromCLI(BaseHelm, BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ControlClusterFromCLI, self).__init__(test_obj=test_obj, backend=backend,
                                                             kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        # test check in cluster workloads and kubescape CLI 
        # assert self.backend == None; f'the test {self.test_driver.test_name} must run without backend'

        # 1 install kubescape in cluster workloads
        Logger.logger.info("Installing kubescape with helm-chart")
        # 1.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 1.2 install armo helm-chart
        # self.install_armo_helm_chart()
        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=240)

        # 2 install kubescape CLI
        Logger.logger.info("Installing kubescape CLI")
        # 2.1 Installing kubescape CLI
        self.install(branch=self.ks_branch)

        # 3 trigger in cluster components
        Logger.logger.info("Triggering in cluster components")
        # 3.1 trigger in cluster components
        self.trigger_in_cluster_components(cli_args=self.parse_cli_args(args=self.test_obj["cli_args"]))

        # 4 validate cluster trigger 
        Logger.logger.info("Validate triggering in cluster components")
        # 4.1 validate cluster trigger
        self.validate_cluster_trigger_as_expected(cluster_name=self.get_cluster_name(), args=self.test_obj["cli_args"])

        return self.cleanup()

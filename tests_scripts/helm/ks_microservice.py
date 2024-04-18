import time
from tests_scripts.helm.base_helm import BaseHelm
from tests_scripts.kubescape.base_kubescape import BaseKubescape
from systest_utils import Logger, TestUtil, statics
from systest_utils.scenarios_manager import SecurityRisksScenarioManager, AttackChainsScenarioManager

DEFAULT_BRANCH = "release"


class ScanSecurityRisksWithKubescapeHelmChart(BaseHelm, BaseKubescape):
    """
    ScanAttackChainsWithKubescapeHelmChart install the kubescape operator and run the scan to check attack-chains.
    """

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanSecurityRisksWithKubescapeHelmChart, self).__init__(test_obj=test_obj, backend=backend,
                                                         kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        """
        Agenda:
        1. Install attack-chains scenario manifests in the cluster
        2. Install kubescape with helm-chart
        3. Verify scenario on backend
        4. Verify security risks categories
        5. Verify security risks severities
        6. Verify security risks unique values
        7. Verify security risks resources
        8. Apply attack chain fix
        9. trigger scan after fix
        10. verify fix
        TODO: validate security risks trends

        """
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'

        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('1. Install attack-chains scenario manifests in the cluster')
        Logger.logger.info(f"1.1 construct AttackChainsScenarioManager with test_scenario: {self.test_obj[('test_scenario', None)]} and cluster {cluster}")
        scenarios_manager = SecurityRisksScenarioManager(test_scenario=self.test_obj[("test_scenario", None)], 
                                                            backend= self.backend, cluster=cluster)
               
        Logger.logger.info("1.2 apply attack chains scenario manifests")
        scenarios_manager.apply_scenario()

        Logger.logger.info("2. Install kubescape with helm-chart")
        Logger.logger.info("2.1 Installing kubescape with helm-chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        Logger.logger.info("2.2 verify installation")
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        time.sleep(10)

        Logger.logger.info("3. Verify scenario on backend")
        scenarios_manager.verify_scenario()
                
        Logger.logger.info("4. validating security risks categories")
        scenarios_manager.verify_security_risks_categories()
        
        Logger.logger.info("5. validating security risks severities")
        scenarios_manager.verify_security_risks_severities()

        # verify unique values - no need to wait.
        Logger.logger.info("6. validating security risks unique values")
        uniqueValuesAllFilters = {"clusterShortName":self.cluster,
                                  "namespace":"default",
                                  "severity":"Medium",
                                  "category":"Workload configuration",
                                  "smartRemediation":"1"}
        scenarios_manager.verify_security_risks_list_uniquevalues(uniqueValuesAllFilters)

        # verify resources side panel - no need to wait.
        Logger.logger.info("7. validating security risks resources")
        scenarios_manager.verify_security_risks_resources()

        Logger.logger.info("8. Apply attack chain fix")
        scenarios_manager.apply_fix(self.test_obj[("fix_object", "control")])

        Logger.logger.info("9. trigger scan after fix")
        scenarios_manager.trigger_scan(self.test_obj["test_job"][0]["trigger_by"])

        Logger.logger.info("10. verify fix")
        scenarios_manager.verify_fix()
        
        Logger.logger.info('attack-chain fixed properly')
        return self.cleanup()

class ScanAttackChainsWithKubescapeHelmChart(BaseHelm, BaseKubescape):
    """
    ScanAttackChainsWithKubescapeHelmChart install the kubescape operator and run the scan to check attack-chains.
    """

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanAttackChainsWithKubescapeHelmChart, self).__init__(test_obj=test_obj, backend=backend,
                                                         kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        """
        Agenda:
        1. Install attack-chains scenario manifests in the cluster
        2. Install kubescape with helm-chart
        3. Verify scenario on backend
        4. Apply attack chain fix
        5. trigger scan after fix
        6. verify fix

        """
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'

        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('1. Install attack-chains scenario manifests in the cluster')
        Logger.logger.info(f"1.1 construct AttackChainsScenarioManager with test_scenario: {self.test_obj[('test_scenario', None)]} and cluster {cluster}")
        scenarios_manager = AttackChainsScenarioManager(test_scenario=self.test_obj[("test_scenario", None)], 
                                                            backend= self.backend, cluster=cluster)

        Logger.logger.info("1.2 apply attack chains scenario manifests")
        scenarios_manager.apply_scenario()

        Logger.logger.info("2. Install kubescape with helm-chart")
        Logger.logger.info("2.1 Installing kubescape with helm-chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        Logger.logger.info("2.2 verify installation")
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        time.sleep(10)

        Logger.logger.info("3. Verify scenario on backend")
        scenarios_manager.verify_scenario()
        Logger.logger.info("attack chains detected, applying fix command")

        Logger.logger.info("4. Apply attack chain fix")
        scenarios_manager.apply_fix(self.test_obj[("fix_object", "control")])

        Logger.logger.info("5. trigger scan after fix")
        scenarios_manager.trigger_scan(self.test_obj["test_job"][0]["trigger_by"])

        Logger.logger.info("6. verify fix")
        scenarios_manager.verify_fix()
        
        Logger.logger.info('attack-chain fixed properly')
        return self.cleanup()


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

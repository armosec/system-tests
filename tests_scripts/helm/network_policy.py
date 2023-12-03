from systest_utils.systests_utilities import TestUtil
from tests_scripts.helm.base_network_policy import BaseNetworkPolicy
from systest_utils import statics, Logger


class NetworkPolicy(BaseNetworkPolicy):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(NetworkPolicy, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                    kubernetes_obj=kubernetes_obj)

    def start(self):
        """
        Test plan:
        1. Install Armo helm-chart
        2. Apply workloads
        3. Generate traffic
        4. Validate network neighbors
        5. Validate generated network policies
        6. TODO: Check BE APIs
        7. Uninstall Armo helm-chart
        """

        cluster, namespace = self.setup(apply_services=False)

        helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)
        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)
        Logger.logger.info('apply secrets')
        self.apply_directory(path=self.test_obj[("secrets", None)], namespace=namespace)
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        duration_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_LEARNING_PERIOD][:-1]
        TestUtil.sleep(2 * int(duration_in_seconds), "wait for node-agent learning period", "info")

        pod = self.wait_for_report(report_type=self.get_pod_if_ready, namespace=namespace, name="wikijs", timeout=180)
        pod_name = pod[0].metadata.name

        Logger.logger.info(f"pod {pod_name} is ready. Triggering exec commands")
        self.wait_for_report(timeout=180, report_type=self.run_exec_cmd, namespace=namespace, pod_name=pod_name, cmd="curl https://google.com")
        self.wait_for_report(timeout=180, report_type=self.run_exec_cmd, namespace=namespace, pod_name=pod_name, cmd="curl https://wikipedia.org")
        
        update_period_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_UPDATE_PERIOD][:-1]
        TestUtil.sleep(2 * int(update_period_in_seconds), "wait for node-agent update period", "info")

        expected_network_neighbors_list = TestUtil.load_objs_from_json_files( self.test_obj["expected_network_neighbors"])

        Logger.logger.info("validating expected network neighbors")
        self.validate_expected_network_neighbors_list(namespace=namespace, expected_network_neighbors_list=expected_network_neighbors_list)

        expected_generated_network_policy_list = TestUtil.load_objs_from_json_files( self.test_obj["expected_generated_network_policies"])

        Logger.logger.info("validating expected generated network policies")
        self.validate_expected_generated_network_policy_list(namespace=namespace, expected_generated_network_policy_list=expected_generated_network_policy_list)

        
        #TODO: check BE APIs

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()

        return self.cleanup()

class NetworkPolicyDataAppended(BaseNetworkPolicy):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(BaseNetworkPolicy, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                    kubernetes_obj=kubernetes_obj)

    def start(self):
        """
        Test plan:
        1. Install Armo helm-chart
        2. Apply workloads
        3. Check first generate network neighbors
        4. Check first generated network policies
        5. Generate traffic
        6. Check second generate network neighbors
        7. Check second generated network policies
        8. TODO: Check BE APIs
        9. Uninstall Armo helm-chart
        """

        cluster, namespace = self.setup(apply_services=False)

        helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)
        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)
        Logger.logger.info('apply secrets')
        self.apply_directory(path=self.test_obj[("secrets", None)], namespace=namespace)
        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        duration_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_LEARNING_PERIOD][:-1]
        TestUtil.sleep(2 * int(duration_in_seconds), "wait for node-agent learning period", "info")

        expected_network_neighbors_list = TestUtil.load_objs_from_json_files( self.test_obj["expected_network_neighbors"])

        Logger.logger.info("validating expected network neighbors")
        self.validate_expected_network_neighbors_list(namespace, expected_network_neighbors_list)

        expected_generated_network_policy_list = TestUtil.load_objs_from_json_files(self.test_obj["expected_generated_network_policies"])

        Logger.logger.info("validating expected generated network policies")
        self.validate_expected_generated_network_policy_list(namespace, expected_generated_network_policy_list)

        pod = self.wait_for_report(report_type=self.get_pod_if_ready, namespace=namespace, name="wikijs", timeout=180)
        pod_name = pod[0].metadata.name

        Logger.logger.info(f"pod {pod_name} is ready. Triggering exec commands")
        self.wait_for_report(timeout=180, report_type=self.run_exec_cmd, namespace=namespace, pod_name=pod_name, cmd="curl https://google.com")
        self.wait_for_report(timeout=180, report_type=self.run_exec_cmd, namespace=namespace, pod_name=pod_name, cmd="curl https://wikipedia.org")

        update_period_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_UPDATE_PERIOD][:-1]
        TestUtil.sleep(2 * int(update_period_in_seconds), "wait for node-agent update period", "info")

        Logger.logger.info("validating updated expected network neighbors")
        expected_updated_network_neighbors_list = TestUtil.load_objs_from_json_files( self.test_obj["expected_updated_network_neighbors"])
        self.validate_expected_network_neighbors_list(namespace=namespace, expected_network_neighbors_list=expected_updated_network_neighbors_list)

        Logger.logger.info("validating updated expected generated network policies")
        expected_updated_generated_network_policy_list = TestUtil.load_objs_from_json_files( self.test_obj["expected_updated_generated_network_policies"])
        self.validate_expected_generated_network_policy_list(namespace=namespace, expected_generated_network_policy_list=expected_updated_generated_network_policy_list)

        #TODO: check BE APIs

        Logger.logger.info('delete armo namespace')
        self.uninstall_armo_helm_chart()

        return self.cleanup()

    





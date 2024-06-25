from systest_utils.systests_utilities import TestUtil
from tests_scripts.helm.base_network_policy import BaseNetworkPolicy
from systest_utils import statics, Logger
import json
from tests_scripts import base_test


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
        4. Validating in-cluster expected network neighbors and generated network policies
        5. Validating backend expected network neighbors and generated network policies
        6. Check deletion flow
        """

        cluster, namespace = self.setup(apply_services=False)

        helm_kwargs = self.test_obj.get_arg("helm_kwargs")

        Logger.logger.info('1. Install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)
        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)
        Logger.logger.info('apply secrets')
        self.apply_directory(path=self.test_obj[("secrets", None)], namespace=namespace)

        Logger.logger.info('2. Apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        duration_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_LEARNING_PERIOD][:-1]
        TestUtil.sleep(7 * int(duration_in_seconds), "wait for node-agent learning period", "info")

        pod = self.wait_for_report(report_type=self.get_pod_if_ready, namespace=namespace, name="wikijs", timeout=180)
        pod_name = pod[0].metadata.name

        Logger.logger.info(f"3. pod {pod_name} is ready. Triggering exec commands to generate traffic")
        self.run_exec_cmd(namespace=namespace, pod_name=pod_name, cmd="curl https://google.com", repeat=10)
        self.run_exec_cmd(namespace=namespace, pod_name=pod_name, cmd="curl https://wikipedia.org", repeat=10)

        update_period_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_UPDATE_PERIOD][:-1]
        TestUtil.sleep(6 * int(update_period_in_seconds), "wait for node-agent update period", "info")

        expected_network_neighbors_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_network_neighbors"])

        expected_generated_network_policy_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_generated_network_policies"])

        Logger.logger.info("4. Validating in-cluster expected network neighbors and generated network policies")
        self.validate_expected_network_neighbors_and_generated_network_policies_lists(namespace=namespace,
                                                                                      expected_network_neighbors_list=expected_network_neighbors_list,
                                                                                      expected_generated_network_policy_list=expected_generated_network_policy_list)

        Logger.logger.info("5. Validating backend expected network neighbors and generated network policies")
        self.wait_for_report(timeout=120,
                             sleep_interval=5,
                             report_type=self.validate_expected_backend_results,
                             cluster=cluster,
                             namespace=namespace,
                             expected_workloads_list=workload_objs,
                             expected_network_neighbors_list=expected_network_neighbors_list,
                             expected_generated_network_policy_list=expected_generated_network_policy_list
                             )

        Logger.logger.info('6. Check deletion flow')
        deleted_workload_name = workload_objs[0]['metadata']['name']
        Logger.logger.info(f"deleting workload {deleted_workload_name} from kubernetes")
        self.kubernetes_obj.delete_workload(namespace=namespace, application=workload_objs[0])
        TestUtil.sleep(120, "wait for workload deletion", "info")

        deleted_workload_nn = expected_network_neighbors_list.pop(0)
        deleted_workload_np = expected_generated_network_policy_list.pop(0)

        Logger.logger.info(f"validating workload {deleted_workload_name} was deleted")
        self.validate_workload_deleted_from_backend(cluster=cluster, namespace=namespace,
                                                    workload_name=deleted_workload_name)
        Logger.logger.info(f"validated workload {deleted_workload_name} was deleted")

        return self.cleanup()


class NetworkPolicyDataAppended(BaseNetworkPolicy):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(NetworkPolicyDataAppended, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                        kubernetes_obj=kubernetes_obj)

    def start(self):
        """
        Test plan:
        1. Install Armo helm-chart
        2. Apply workloads
        3. Validating in-cluster expected network neighbors and generated network policies before generating traffic
        4. Generate traffic
        5. Validating in-cluster expected network neighbors and generated network policies after generating traffic
        6. Validating backend expected network neighbors and generated network policies after generating traffic
        """

        cluster, namespace = self.setup(apply_services=False)

        helm_kwargs = self.test_obj.get_arg("helm_kwargs")

        Logger.logger.info('1. Install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)
        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)
        Logger.logger.info('apply secrets')
        self.apply_directory(path=self.test_obj[("secrets", None)], namespace=namespace)

        Logger.logger.info('2. Apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        duration_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_LEARNING_PERIOD][:-1]
        TestUtil.sleep(6 * int(duration_in_seconds), "wait for node-agent learning period", "info")

        expected_network_neighbors_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_network_neighbors"])
        expected_generated_network_policy_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_generated_network_policies"])

        Logger.logger.info(
            "3. Validating in-cluster expected network neighbors and generated network policies before generating traffic")
        self.validate_expected_network_neighbors_and_generated_network_policies_lists(namespace=namespace,
                                                                                      expected_network_neighbors_list=expected_network_neighbors_list,
                                                                                      expected_generated_network_policy_list=expected_generated_network_policy_list)

        pod = self.wait_for_report(report_type=self.get_pod_if_ready, namespace=namespace, name="wikijs", timeout=180)
        pod_name = pod[0].metadata.name

        Logger.logger.info(f"4. pod {pod_name} is ready. Triggering exec commands to generate traffic")
        self.run_exec_cmd(namespace=namespace, pod_name=pod_name, cmd="curl https://google.com", repeat=10)
        self.run_exec_cmd(namespace=namespace, pod_name=pod_name, cmd="curl https://wikipedia.org", repeat=10)

        update_period_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_UPDATE_PERIOD][:-1]
        TestUtil.sleep(5 * int(update_period_in_seconds), "wait for node-agent update period", "info")

        Logger.logger.info(
            "5. Validating in-cluster expected network neighbors and generated network policies after generating traffic")

        expected_updated_network_neighbors_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_updated_network_neighbors"])
        expected_updated_generated_network_policy_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_updated_generated_network_policies"])

        self.validate_expected_generated_network_policy_list(namespace=namespace,
                                                             expected_generated_network_policy_list=expected_updated_generated_network_policy_list)
        Logger.logger.info("validated updated expected generated network policies")

        self.validate_expected_network_neighbors_and_generated_network_policies_lists(namespace=namespace,
                                                                                      expected_network_neighbors_list=expected_updated_network_neighbors_list,
                                                                                      expected_generated_network_policy_list=expected_updated_generated_network_policy_list)

        Logger.logger.info(
            "6. Validating backend expected network neighbors and generated network policies after generating traffic")
        self.wait_for_report(timeout=120,
                             sleep_interval=5,
                             report_type=self.validate_expected_backend_results,
                             cluster=cluster,
                             namespace=namespace,
                             expected_workloads_list=workload_objs,
                             expected_network_neighbors_list=expected_updated_network_neighbors_list,
                             expected_generated_network_policy_list=expected_updated_generated_network_policy_list
                             )

        return self.cleanup()


class NetworkPolicyPodRestarted(BaseNetworkPolicy):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(NetworkPolicyPodRestarted, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                        kubernetes_obj=kubernetes_obj)

    def start(self):
        """
        Test plan:
        1. Apply workloads
        2. Install Armo helm-chart
        3. Restart workloads
        4. Validating in-cluster expected network neighbors and generated network policies
        5. Validating bakcned expected network neighbors and generated network policies
        """

        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)
        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)
        Logger.logger.info('apply secrets')
        self.apply_directory(path=self.test_obj[("secrets", None)], namespace=namespace)
        Logger.logger.info('1. Apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        Logger.logger.info('2. Install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)
        
        TestUtil.sleep(40, "wait for 40 seconds before restarting pods", "info")

        pods_list = list(map(lambda obj: obj['metadata']['name'], workload_objs))
        Logger.logger.info(f"3. Restarting pods: {pods_list}")
        for pod in pods_list:
            pod = self.wait_for_report(report_type=self.get_pod_if_ready, namespace=namespace, name=pod, timeout=180)
            pod_name = pod[0].metadata.name
            self.restart_pods(namespace=namespace, name=pod_name)
        Logger.logger.info(f"restarted pods successfully")

        duration_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_LEARNING_PERIOD][:-1]
        TestUtil.sleep(10 * int(duration_in_seconds), "wait for node-agent learning period", "info")

        expected_network_neighbors_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_network_neighbors"])
        expected_generated_network_policy_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_generated_network_policies"])

        Logger.logger.info("4. Validating in-cluster expected network neighbors and generated network policies")
        self.validate_expected_network_neighbors_and_generated_network_policies_lists(namespace=namespace,
                                                                                      expected_network_neighbors_list=expected_network_neighbors_list,
                                                                                      expected_generated_network_policy_list=expected_generated_network_policy_list)

        Logger.logger.info("5. Validating backend expected network neighbors and generated network policies")
        self.wait_for_report(timeout=240,
                             sleep_interval=5,
                             report_type=self.validate_expected_backend_results,
                             cluster=cluster,
                             namespace=namespace,
                             expected_workloads_list=workload_objs,
                             expected_network_neighbors_list=expected_network_neighbors_list,
                             expected_generated_network_policy_list=expected_generated_network_policy_list
                             )

        return self.cleanup()


class NetworkPolicyMultipleReplicas(BaseNetworkPolicy):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(NetworkPolicyMultipleReplicas, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                            kubernetes_obj=kubernetes_obj)

    def start(self):
        """
        Test plan:
        1. Install Armo helm-chart
        2. Apply workloads
        3. Generate different traffic for one pod
        4. Validating in-cluster expected network neighbors and generated network policies
        5. Validating backend expected network neighbors and generated network policies
        """

        cluster, namespace = self.setup(apply_services=False)

        helm_kwargs = self.test_obj.get_arg("helm_kwargs")

        Logger.logger.info('1. Install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        Logger.logger.info('2. Apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        pods_list = list(map(lambda obj: obj['metadata']['name'], workload_objs))
        pods = self.get_ready_pods(namespace=namespace, name=pods_list[0])
        pod_name = pods[0].metadata.name

        duration_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_LEARNING_PERIOD][:-1]
        TestUtil.sleep(int(duration_in_seconds) + 5, "wait for node-agent learning period", "info")

        Logger.logger.info(f"3. pod {pod_name} is ready. Triggering exec command to generate traffic")
        self.run_exec_cmd(namespace=namespace, pod_name=pod_name, cmd="wget http://google.com", repeat=10)
        self.run_exec_cmd(namespace=namespace, pod_name=pod_name, cmd="wget http://www.google.com", repeat=10)

        duration_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_LEARNING_PERIOD][:-1]
        TestUtil.sleep(6 * int(duration_in_seconds), "wait for node-agent learning period", "info")

        expected_network_neighbors_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_network_neighbors"])
        expected_generated_network_policy_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_generated_network_policies"])

        Logger.logger.info("4. Validating in-cluster expected network neighbors and generated network policies")
        self.validate_expected_network_neighbors_and_generated_network_policies_lists(namespace=namespace,
                                                                                      expected_network_neighbors_list=expected_network_neighbors_list,
                                                                                      expected_generated_network_policy_list=expected_generated_network_policy_list)

        Logger.logger.info("5. Validating backend expected network neighbors and generated network policies")
        self.wait_for_report(timeout=120,
                             sleep_interval=5,
                             report_type=self.validate_expected_backend_results,
                             cluster=cluster,
                             namespace=namespace,
                             expected_workloads_list=workload_objs,
                             expected_network_neighbors_list=expected_network_neighbors_list,
                             expected_generated_network_policy_list=expected_generated_network_policy_list
                             )

        return self.cleanup()


class NetworkPolicyKnownServers(BaseNetworkPolicy):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(NetworkPolicyKnownServers, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                        kubernetes_obj=kubernetes_obj)

    def start(self):
        """
        Test plan:
        1. Install Armo helm-chart
        2. Apply workloads
        3. Send request from within Pod
        4. Apply Known Servers
        5. Validating in-cluster expected network neighbors and generated network policies
        6. Validating backend expected network neighbors and generated network policies
        """

        cluster, namespace = self.setup(apply_services=False)

        helm_kwargs = self.test_obj.get_arg("helm_kwargs")

        Logger.logger.info('1. Install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        Logger.logger.info('2. Apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        pods_list = list(map(lambda obj: obj['metadata']['name'], workload_objs))
        pods = self.get_ready_pods(namespace=namespace, name=pods_list[0])
        pod_name = pods[0].metadata.name

        Logger.logger.info(f"3. pod {pod_name} is ready. Triggering exec command to send request from within Pod")
        self.run_exec_cmd(namespace=namespace, pod_name=pod_name, cmd="wget 185.199.108.153", repeat=10)
        self.run_exec_cmd(namespace=namespace, pod_name=pod_name, cmd="wget http://www.google.com", repeat=10)

        Logger.logger.info('4. Apply Known Servers')
        known_servers_file = self.test_obj.get_arg("knownservers")
        known_servers_body = TestUtil.load_objs_from_json_files([known_servers_file])
        self.create_known_servers(body=known_servers_body[0])

        duration_in_seconds = helm_kwargs[statics.HELM_NODE_AGENT_LEARNING_PERIOD][:-1]
        TestUtil.sleep(5 * int(duration_in_seconds), "wait for node-agent learning period", "info")

        expected_network_neighbors_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_network_neighbors"])
        expected_generated_network_policy_list = TestUtil.load_objs_from_json_files(
            self.test_obj["expected_generated_network_policies"])

        Logger.logger.info("5. Validating in-cluster expected network neighbors and generated network policies")
        self.validate_expected_network_neighbors_and_generated_network_policies_lists(namespace=namespace,
                                                                                      expected_network_neighbors_list=expected_network_neighbors_list,
                                                                                      expected_generated_network_policy_list=expected_generated_network_policy_list)

        Logger.logger.info("6. Validating backend expected network neighbors and generated network policies")
        self.wait_for_report(timeout=120,
                             sleep_interval=5,
                             report_type=self.validate_expected_backend_results,
                             cluster=cluster,
                             namespace=namespace,
                             expected_workloads_list=workload_objs,
                             expected_network_neighbors_list=expected_network_neighbors_list,
                             expected_generated_network_policy_list=expected_generated_network_policy_list
                             )

        return self.cleanup()


class NetworkPolicyKnownServersCache(base_test.BaseTest):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(NetworkPolicyKnownServersCache, self).__init__(test_driver=test_driver, test_obj=test_obj,
                                                             backend=backend,
                                                             kubernetes_obj=kubernetes_obj)

    def start(self):
        # TODO: add test to check the data in the known servers cache
        """
        Checks that known servers cache returns values
        """

        res = self.backend.get_known_servers_cache()
        assert res.status_code == 200, f"Failed to get known servers cache. status code: {res.status_code}"

        res_json = json.loads(res.text)
        assert len(res_json) > 0, f"Known servers cache is empty"

        return statics.SUCCESS, ""

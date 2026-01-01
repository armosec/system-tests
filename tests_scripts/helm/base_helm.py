import os
import re
from typing import Optional

from infrastructure.helm_wrapper import HelmWrapper
from systest_utils import TestUtil, Logger, statics
from tests_scripts.kubernetes.base_k8s import BaseK8S
import signal
import psutil
from kubernetes.dynamic import ResourceField
import json



DEFAULT_BRANCH = "release"

HTTPD_PROXY_CRT_PATH = os.path.join(statics.DEFAULT_HELM_PROXY_PATH, "httpd-proxy.crt")
HTTPD_PROXY_KEY_PATH = os.path.join(statics.DEFAULT_HELM_PROXY_PATH, "httpd-proxy.key")


class ResourceFieldEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ResourceField):
            return obj.__dict__
        return json.JSONEncoder.default(self, obj)


class BaseHelm(BaseK8S):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None, with_proxy=False):
        super(BaseHelm, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                       kubernetes_obj=kubernetes_obj)

        self.helm_armo_repo = self.test_driver.kwargs.get("helm_repo", statics.HELM_REPO)
        self.helm_branch = self.test_driver.kwargs.get("helm_branch", DEFAULT_BRANCH)
        self.local_helm_chart = self.test_driver.kwargs.get("local_helm_chart", None)
        self.print_kubescape_chart_logs: bool = TestUtil.get_arg_from_dict(self.test_driver.kwargs,
                                                                           "print_kubescape_chart_logs", True)
        self.port_forward_proc = None
        self.proxy_config = test_obj[("proxy_config", None)]
        self.enable_security = self.test_obj[("enable_security", True)]

        self.node_agent_learning_period = self.test_driver.kwargs.get("node_agent_learning_period", "2m")
        self.node_agent_update_period = self.test_driver.kwargs.get("node_agent_update_period", "2m")

    @staticmethod
    def kill_child_processes(parent_pid, sig=signal.SIGTERM):
        try:
            parent = psutil.Process(parent_pid)
        except psutil.NoSuchProcess:
            return
        children = parent.children(recursive=True)
        for process in children:
            process.send_signal(sig)

    def cleanup(self, **kwargs):
        if self.port_forward_proc:
            self.kill_child_processes(self.port_forward_proc.pid)
            self.port_forward_proc.terminate()

        if self.print_kubescape_chart_logs:
            self.display_armo_system_logs()

        if self.remove_kubescape_namespace:
            self.namespaces.append(statics.CA_NAMESPACE_FROM_HELM_NAME)
            try:
                Logger.logger.info('uninstall armo helm-chart')
                self.uninstall_kubescape_chart()
                self.remove_armo_from_repo()
            except:
                pass
            if self.backend:
                if not hasattr(self, "wait_for_agg_to_end") or self.wait_for_agg_to_end:
                    TestUtil.sleep(50, "Waiting for aggregation to end")
                self.cluster_deleted = self.delete_cluster_from_backend()

        return super().cleanup(**kwargs)

    def display_armo_system_logs(self, level=Logger.logger.debug):
        pods = self.get_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        for pod in pods:
            # if "storage" in pod.metadata.name:
            #     continue
            try:
                level(self.get_pod_logs(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                        pod_name=pod.metadata.name,
                                        containers=list(map(lambda container: container.name, pod.spec.containers)),
                                        previous=False))
            except Exception as e:
                Logger.logger.error("cant print webhook logs. reason: {}".format(e))
            try:
                level(self.get_pod_logs(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                        pod_name=pod.metadata.name,
                                        containers=list(map(lambda container: container.name, pod.spec.containers)),
                                        previous=True))
            except:
                pass

    def get_private_node_agent_params(self):
        helm_kwargs = {}
        helm = self.backend.get_helm()

        repository = extract_set_param(helm["installCommand"], "nodeAgent.image.repository")
        assert repository is not None, f"Failed to extract nodeAgent.image.repository from helm command: {helm['installCommand']}"
        tag = extract_set_param(helm["installCommand"], "nodeAgent.image.tag")
        assert tag is not None, f"Failed to extract nodeAgent.image.tag from helm command: {helm['installCommand']}"
        secret_password = extract_set_param(helm["installCommand"], "imagePullSecret.password")
        assert secret_password is not None, f"Failed to extract imagePullSecret.password from helm command: {helm['installCommand']}"
        secret_server = extract_set_param(helm["installCommand"], "imagePullSecret.server")
        assert secret_server is not None, f"Failed to extract imagePullSecret.server from helm command: {helm['installCommand']}"
        secret_username = extract_set_param(helm["installCommand"], "imagePullSecret.username")
        assert secret_username is not None, f"Failed to extract imagePullSecret.username from helm command: {helm['installCommand']}"
        pull_secrets = extract_set_param(helm["installCommand"], "imagePullSecrets")
        assert pull_secrets is not None, f"Failed to extract imagePullSecrets from helm command: {helm['installCommand']}"

        helm_kwargs["nodeAgent.image.repository"] = repository
        helm_kwargs["nodeAgent.image.tag"] = tag
        helm_kwargs["imagePullSecret.password"] = secret_password
        helm_kwargs["imagePullSecret.server"] = secret_server
        helm_kwargs["imagePullSecret.username"] = secret_username
        helm_kwargs["imagePullSecrets"] = pull_secrets

        return helm_kwargs

    def install_armo_helm_chart(self, namespace: str = statics.CA_NAMESPACE_FROM_HELM_NAME, helm_kwargs: dict = None, use_offline_db: bool = True, private_node_agent: bool = False):
        if helm_kwargs is None:
            helm_kwargs = {}

        if private_node_agent:
            helm_kwargs.update(self.get_private_node_agent_params())

        if self.local_helm_chart:
            self.helm_armo_repo = self.local_helm_chart

        if self.helm_branch != DEFAULT_BRANCH:
            self.download_armo_helm_chart_from_branch(branch=self.helm_branch)
            self.helm_dependency_update(repo=self.helm_armo_repo)

        helm_kwargs.update(self.get_in_cluster_tags())

        # if there is proxy configuration, configure and get the proxy helm params
        if self.proxy_config is not None:
            helm_proxy_url = self.proxy_config.get("helm_proxy_url", None)
            if helm_proxy_url is None:
                helm_proxy_url = statics.HELM_PROXY_URL
                Logger.logger.warning(
                    f"helm_proxy_url is not defined in proxy_config, using default {statics.HELM_PROXY_URL}")
            else:
                Logger.logger.info(f"helm_proxy_url is defined in proxy_config, using {helm_proxy_url}")

            helm_proxy_params = HelmWrapper.configure_helm_proxy(helm_proxy_url=helm_proxy_url,
                                                                 namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

            helm_kwargs.update(helm_proxy_params)

        if not self.enable_security:
            security_params = {"operator.triggerSecurityFramework": "false"}
            helm_kwargs.update(security_params)

        if "nodeAgent.config.learningPeriod" not in helm_kwargs:
            helm_kwargs.update({"nodeAgent.config.learningPeriod": self.node_agent_learning_period})

        if "nodeAgent.config.updatePeriod" not in helm_kwargs:
            helm_kwargs.update({"nodeAgent.config.updatePeriod": self.node_agent_update_period})

        helm_kwargs.update({"operator.podScanGuardTime": "5s"})

        # Remove flags that shouldn't be set for multi-prod environments
        server = self.test_driver.backend_obj.get_api_url()
        if server and "r7.armo-cadr.com" in server:
            # These flags are not needed/supported for multi-prod environments
            helm_kwargs.pop("alertCRD.installDefault", None)
            helm_kwargs.pop("alertCRD.scopeClustered", None)
            helm_kwargs.pop("nodeAgent.image.repository", None)
            helm_kwargs.pop("nodeAgent.image.tag", None)

        create_namespace = True
        if self.docker_default_secret:
            self.create_namespace(unique_name=False, name=namespace)
            create_namespace = False

        HelmWrapper.install_armo_helm_chart(customer=self.backend.get_customer_guid() if self.backend != None else "",
                                            access_key=self.backend.get_access_key() if self.backend != None else "",
                                            server=self.test_driver.backend_obj.get_api_url(),
                                            cluster_name=self.kubernetes_obj.get_cluster_name(),
                                            namespace=namespace,
                                            repo=self.helm_armo_repo, create_namespace=create_namespace,
                                            helm_kwargs=helm_kwargs, use_offline_db=use_offline_db)

    def get_in_cluster_tags(self):
        component_tag = {}
        component_tag.update(self.extract_tag_from_kwargs(component_name=statics.KUBESCAPE_COMPONENT_NAME,
                                                          component_tag=statics.KUBESCAPE_COMPONENT_TAG))
        component_tag.update(self.extract_tag_from_kwargs(component_name=statics.KUBEVULN_COMPONENT_NAME,
                                                          component_tag=statics.KUBEVULN_COMPONENT_TAG))
        component_tag.update(self.extract_tag_from_kwargs(component_name=statics.OPERATOR_COMPONENT_NAME,
                                                          component_tag=statics.OPERATOR_COMPONENT_TAG))
        component_tag.update(self.extract_tag_from_kwargs(component_name=statics.KOLLECTOR_COMPONENT_NAME,
                                                          component_tag=statics.KOLLECTOR_COMPONENT_TAG))
        component_tag.update(self.extract_tag_from_kwargs(component_name=statics.GATEWAY_COMPONENT_NAME,
                                                          component_tag=statics.GATEWAY_COMPONENT_TAG))
        component_tag.update(self.extract_tag_from_kwargs(component_name=statics.STORAGE_COMPONENT_NAME,
                                                          component_tag=statics.STORAGE_COMPONENT_TAG))
        component_tag.update(self.extract_tag_from_kwargs(component_name=statics.NODE_AGENT_COMPONENT_NAME,
                                                          component_tag=statics.NODE_AGENT_COMPONENT_TAG))

        return component_tag

    def extract_tag_from_kwargs(self, component_name, component_tag):
        # component_tag can be either tag or bla0/bla1:bla2 → this contains the image name(repo) and tag
        tag = self.test_driver.kwargs.get(component_tag, '')
        if not tag:
            return {}
        return {f'{component_name}.image.tag': tag.split(':')[-1]}

    def download_armo_helm_chart_from_branch(self, branch: str):
        # git clone branch dev
        command_args = ["git", "clone", "-b", branch, "https://github.com/kubescape/helm-charts.git",
                        self.test_driver.temp_dir]

        TestUtil.run_command(command_args=command_args, timeout=360)
        self.helm_armo_repo = os.path.join(self.test_driver.temp_dir, statics.HELM_REPO_FROM_LOCAL)

    def test_helm_chart_results(self, report_guid: str):
        be_frameworks = self.get_posture_frameworks(report_guid=report_guid)

        assert len(be_frameworks) >= 4, \
            'Expect to have at least 4 frameworks in backend, and there is only {x}'.format(x=len(be_frameworks))

        for fw in be_frameworks:
            assert fw['failedControls'] > 0, 'In framework {x} there are no failed controls'.format(x=fw['name'])

        # TODO add test results when kubescape from helm-chart return results

    def get_posture_frameworks(self, report_guid, framework_name: str = ""):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_posture_frameworks,
                                               framework_name=framework_name, report_guid=report_guid)
        return c_panel_info


    def verify_application_profiles(self, wlids: list, namespace):
        Logger.logger.info("Get application profiles")
        if "r7.armo-cadr.com" in self.backend.server:
            k8s_data = self.backend.get_application_profiles(cluster=self.kubernetes_obj.get_cluster_name(), namespace=namespace)
            assert k8s_data != [], "Failed to get application profiles"
            assert len(k8s_data) >= len(wlids), f"Failed to get all application profiles {len(k8s_data)}"
            Logger.logger.info(f"Application profiles are presented {len(k8s_data)}")
            ap_wlids = [i['metadata']['annotations']['kubescape.io/wlid'] for i in k8s_data]
            for i in wlids:
                assert i in ap_wlids, f"Failed to get application profile for {i}"
            not_complete_application_profiles = [i for i in k8s_data if
                                                i['metadata']['annotations']['kubescape.io/status'] != 'completed']

            assert len(
                not_complete_application_profiles) == 0, f"Application profiles are not complete {json.dumps([i['metadata'] for i in not_complete_application_profiles], cls=ResourceFieldEncoder)}"

        else:
            k8s_data = self.kubernetes_obj.get_dynamic_client("spdx.softwarecomposition.kubescape.io/v1beta1",
                                                            "ApplicationProfile").get(namespace=namespace).items
            assert k8s_data != None, "Failed to get application profiles"
            assert len(k8s_data) >= len(wlids), f"Failed to get all application profiles {len(k8s_data)}"
            Logger.logger.info(f"Application profiles are presented {len(k8s_data)}")
            ap_wlids = [i.metadata.annotations['kubescape.io/wlid'] for i in k8s_data]
            for i in wlids:
                assert i in ap_wlids, f"Failed to get application profile for {i}"
            # kubescape.io/status: completed, kubescape.io/completion: complete
            # i.metadata.annotations['kubescape.io/completion'] != 'complete' or
            not_complete_application_profiles = [i for i in k8s_data if
                                                i.metadata.annotations['kubescape.io/status'] != 'completed']

            assert len(
                not_complete_application_profiles) == 0, f"Application profiles are not complete {json.dumps([i.metadata for i in not_complete_application_profiles], cls=ResourceFieldEncoder)}"

    # ---------------------- helm ------------------------
    @staticmethod
    def add_and_upgrade_armo_to_repo():
        HelmWrapper.add_armo_to_repo()
        HelmWrapper.upgrade_armo_in_repo()

    def uninstall_kubescape_chart(self):
        # Determine release name based on environment
        # For multi-prod environments, use 'rapid7', otherwise use default 'kubescape'
        release_name = statics.CA_HELM_NAME  # default
        if self.backend and hasattr(self.backend, 'get_api_url'):
            try:
                server = self.backend.get_api_url()
                if server and "r7.armo-cadr.com" in server:
                    release_name = "rapid7"
            except:
                pass  # If we can't get server URL, use default
        HelmWrapper.uninstall_kubescape_chart(release_name=release_name)

    @staticmethod
    def remove_armo_from_repo():
        HelmWrapper.remove_armo_from_repo()

    @staticmethod
    def helm_dependency_update(repo):
        HelmWrapper.helm_dependency_update(repo)



def extract_set_param(command: str, param_name: str) -> Optional[str]:
    """
    Extracts the value of a given --set parameter from a Helm command string.

    Args:
        command (str): The Helm install or upgrade command string.
        param_name (str): The parameter name to extract (e.g., "nodeAgent.image.repository").

    Returns:
        Optional[str]: The value of the parameter, or None if not found.
    """
    # Escape dots for regex and build pattern
    pattern = rf'--set {re.escape(param_name)}=([^\s]+)'
    match = re.search(pattern, command)

    return match.group(1) if match else None
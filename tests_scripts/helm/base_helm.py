import os

from infrastructure.helm_wrapper import HelmWrapper
from systest_utils import TestUtil, Logger, statics
from tests_scripts.kubernetes.base_k8s import BaseK8S
import signal
import psutil

DEFAULT_BRANCH = "release"


HTTPD_PROXY_CRT_PATH = os.path.join(statics.DEFAULT_HELM_PROXY_PATH, "httpd-proxy.crt")
HTTPD_PROXY_KEY_PATH = os.path.join(statics.DEFAULT_HELM_PROXY_PATH, "httpd-proxy.key")


class BaseHelm(BaseK8S):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None, with_proxy=False):
        super(BaseHelm, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                       kubernetes_obj=kubernetes_obj)

        self.helm_armo_repo = self.test_driver.kwargs.get("helm_repo", statics.HELM_REPO)
        self.helm_branch = self.test_driver.kwargs.get("helm_branch", DEFAULT_BRANCH)
        self.local_helm_chart = self.test_driver.kwargs.get("local_helm_chart", None)
        self.remove_armo_system_namespace = False
        self.remove_cyberarmor_namespace = False
        self.ignore_as_logs: bool = TestUtil.get_arg_from_dict(self.test_driver.kwargs,
                                                               "ignore_armo_system_logs", False)
        self.remove_cluster_from_backend = False
        self.port_forward_proc = None
        self.proxy_config = test_obj[("proxy_config", None)]
        self.enable_security = self.test_obj[("enable_security", True)]

        self.filtered_sbom_init_time = self.test_driver.kwargs.get("filtered_sbom_init_time", "2m")
        self.filtered_sbom_update_time = self.test_driver.kwargs.get("filtered_sbom_update_time", "2m")
    

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
        if self.port_forward_proc != None:
            self.kill_child_processes(self.port_forward_proc.pid)
            self.port_forward_proc.terminate()

        if not self.ignore_as_logs:
            self.display_armo_system_logs()

        if self.remove_armo_system_namespace:
            self.namespaces.append(statics.CA_NAMESPACE_FROM_HELM_NAME)
            try:
                if self.remove_cyberarmor_namespace:
                    Logger.logger.info('uninstall armo helm-chart')
                    self.uninstall_armo_helm_chart()
                    self.remove_armo_from_repo()
            except:
                pass

        if self.remove_cluster_from_backend and not self.cluster_deleted and self.backend != None:
            TestUtil.sleep(150, "Waiting for aggregation to end")
            self.cluster_deleted = self.delete_cluster_from_backend()

        return super().cleanup(**kwargs)

    def display_armo_system_logs(self, level=Logger.logger.debug):
        pods = self.get_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        for pod in pods:
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

    def install_armo_helm_chart(self, helm_kwargs: dict = {}):
        if self.local_helm_chart:
            self.helm_armo_repo = self.local_helm_chart

        if self.helm_branch != DEFAULT_BRANCH:
            self.download_armo_helm_chart_from_branch(branch=self.helm_branch)

        helm_kwargs.update(self.get_in_cluster_tags())

        # if there is proxy configuration, configure and get the proxy helm params
        if self.proxy_config is not None:
            helm_proxy_url = self.proxy_config.get("helm_proxy_url", None)
            if helm_proxy_url is None:
                helm_proxy_url = statics.HELM_PROXY_URL
                Logger.logger.warning(f"helm_proxy_url is not defined in proxy_config, using default {statics.HELM_PROXY_URL}")
            else:
                Logger.logger.info(f"helm_proxy_url is defined in proxy_config, using {helm_proxy_url}")

            helm_proxy_params = HelmWrapper.configure_helm_proxy(helm_proxy_url=helm_proxy_url, namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
            
            helm_kwargs.update(helm_proxy_params)

        if self.enable_security == False:
            security_params = {"operator.triggerSecurityFramework": "false"}
            helm_kwargs.update(security_params)

        helm_kwargs.update({"nodeAgent.config.learningPeriod": self.filtered_sbom_init_time, 
                            "nodeAgent.config.updatePeriod": self.filtered_sbom_update_time})
        
        HelmWrapper.install_armo_helm_chart(customer=self.backend.get_customer_guid() if self.backend != None else "",
                                            environment=self.test_driver.backend_obj.get_name() if self.backend != None else "",
                                            cluster_name=self.kubernetes_obj.get_cluster_name(),
                                            repo=self.helm_armo_repo, helm_kwargs=helm_kwargs)
        self.remove_armo_system_namespace = True
        self.remove_cluster_from_backend = True

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
                                                          component_tag=statics.STORAGE_COMPONENT_TAG))

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

    def test_helm_chart_tesults(self, report_guid: str):
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

    # ---------------------- helm ------------------------
    @staticmethod
    def add_and_upgrade_armo_to_repo():
        HelmWrapper.add_armo_to_repo()
        HelmWrapper.upgrade_armo_in_repo()

    @staticmethod
    def uninstall_armo_helm_chart():
        HelmWrapper.uninstall_armo_helm_chart()

    @staticmethod
    def remove_armo_from_repo():
        HelmWrapper.remove_armo_from_repo()


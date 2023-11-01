import os
import json
from tests_scripts.helm.base_helm import BaseHelm
from tests_scripts.kubescape.base_kubescape import BaseKubescape
from systest_utils import Logger, statics


class ConfigView(BaseHelm, BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ConfigView, self).__init__(test_obj=test_obj, backend=backend,
                                   kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        return self.cleanup()

        # 1 install kubescape helm
        Logger.logger.info("Installing kubescape with helm-chart")
        # 1.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 1.2 install armo helm-chart
        self.install_armo_helm_chart()

        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=240)

        # 2 install kubescape CLI
        Logger.logger.info("Installing kubescape")
        self.install(branch=self.ks_branch)

        # 3 run config view
        self.default_config(view="view")

        # 4 check results
        self.compare_view_result()

        return self.cleanup()

    def compare_view_result(self):
        ks_cm_obj = self.kubernetes_obj.get_config_map(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, name=statics.KS_CONFIG)
        cm_data = ks_cm_obj.data["config.json"]
        cm_dict = json.loads(cm_data)

        # kubescape reads its URLs from the cloud configmap, so we merge the dict from the cloud configmap with the dict from the kubescape configmap
        ks_cloud_cm_obj = self.kubernetes_obj.get_config_map(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, name=statics.CA_CONFIG)
        if statics.CA_CONFIGMAP_SERVICE_DISCOVERY_KEY in ks_cloud_cm_obj.data:
            ks_cloud_cm_dict = json.loads(ks_cloud_cm_obj.data[statics.CA_CONFIGMAP_SERVICE_DISCOVERY_KEY])
            cm_dict[statics.CLOUD_REPORT_URL_KEY] = ks_cloud_cm_dict["response"]["event-receiver-http"]
            cm_dict[statics.CLOUD_API_URL_KEY] = ks_cloud_cm_dict["response"]["api-server"]

        with open(self.get_default_results_file()) as f:
            res_dict = json.load(f)
        with open(self.get_kubescape_config_file()) as f:
            file_dict = json.load(f)
        expected_keys = []
        for fkey, _ in file_dict.items():
            if fkey not in cm_dict.keys():
                expected_keys.append(fkey)
        for key in expected_keys:
            assert key not in res_dict.keys(), f'key {key} should exist in the config view result: {res_dict}'
                 
class ConfigSet(BaseHelm, BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ConfigSet, self).__init__(test_obj=test_obj, backend=backend,
                                   kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        return self.cleanup()

        # 1 install kubescape helm
        Logger.logger.info("Installing kubescape with helm-chart")
        # 1.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 1.2 install armo helm-chart
        self.install_armo_helm_chart()

        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=240)

        # 2 install kubescape CLI
        Logger.logger.info("Installing kubescape")
        self.install(branch=self.ks_branch)

        # 3 run config view
        self.default_config(set="set", data=(self.test_obj.kwargs["set_key"], self.test_obj.kwargs["set_value"]))

        # 4 check results
        self.compare_set_result()

        return self.cleanup()

    def compare_set_result(self):
        with open(self.get_kubescape_config_file()) as f:
            file_dict = json.load(f)
        assert self.test_obj.kwargs["set_key"] in file_dict.keys(), f'key {self.test_obj.kwargs["set_key"]} should exist in the file {self.get_kubescape_config_file()}'
        cm_obj = self.kubernetes_obj.get_config_map(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, name=statics.KS_CONFIG)
        cm_data = cm_obj.data["config.json"]
        cm_dict = json.loads(cm_data)
        assert self.test_obj.kwargs["set_key"] not in cm_dict.keys() or self.test_obj.kwargs["set_key"] in cm_dict.keys() and cm_dict[self.test_obj.kwargs["set_key"]] != self.test_obj.kwargs["set_value"], f'key {self.test_obj.kwargs["set_key"]} should mot exist in the kubescape configmap:{cm_dict}'

class ConfigDelete(BaseHelm, BaseKubescape):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ConfigDelete, self).__init__(test_obj=test_obj, backend=backend,
                                   kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        return self.cleanup()

        # 1 install kubescape helm
        Logger.logger.info("Installing kubescape with helm-chart")
        # 1.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 1.2 install armo helm-chart
        self.install_armo_helm_chart()

        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=240)

        # 2 install kubescape CLI
        Logger.logger.info("Installing kubescape")
        self.install(branch=self.ks_branch)

        # 3 run config view
        self.default_config(delete="delete")

        # 4 check results
        self.compare_view_result()

        return self.cleanup()

    def compare_view_result(self):
        kubescape_config_file_path=self.get_kubescape_config_file()
        cm_obj = self.kubernetes_obj.get_config_map(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, name=statics.KS_CONFIG)
        assert not(cm_obj) == False, f'the kubescape configmap should not be deleted'
        assert os.path.exists(kubescape_config_file_path) == False, f'kubescape config file in path: {kubescape_config_file_path} should be deleted'
                 
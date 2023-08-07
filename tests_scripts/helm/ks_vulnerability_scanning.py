from datetime import datetime, timezone

from systest_utils import Logger, statics
from .base_helm import BaseHelm
from ..kubescape.base_kubescape import (
    BaseKubescape
)


class ScanImageControls(BaseKubescape, BaseHelm):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(ScanImageControls, self).__init__(test_obj=test_obj, backend=backend,
                                                kubernetes_obj=kubernetes_obj, test_driver=test_driver)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'
        # P1 Install Wikijs
        # 1.1 install Wikijs
        # 1.2 verify installation
        # P2 install armo-helm-chart
        # P3 install kubescape
        # P4 run kubescape with api-token
        # P5 test result against expected result
        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)

        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        since_time = datetime.now(timezone.utc).astimezone().isoformat()

        Logger.logger.info("Installing helm-chart")
        # 2.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 2.2 install armo helm-chart
        self.install_armo_helm_chart()

        # 2.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=180)

        Logger.logger.info('Verify all pods not in pending')
        expected_number_of_pods = self.get_expected_number_of_pods(namespace=namespace)
        _, _ = self.wait_for_report(timeout=600, report_type=self.backend.get_scan_results_sum_summary,
                                    namespace=namespace, since_time=since_time,
                                    expected_results=expected_number_of_pods)

        Logger.logger.info("Installing kubescape")
        # Logger.logger.info(self.install())

        self.install(branch=self.ks_branch)

        result = self.default_scan(submit=self.test_obj.get_arg("submit"), account=self.test_obj.get_arg("account"),
                                   client_id=self.test_obj.get_arg("client_id"),
                                   secret_key=self.test_obj.get_arg("secret_key"))

        Logger.logger.info("Testing data against expected results")
        self.test_image_scan_related_expected_results(result=result, namespace=namespace)

        return self.cleanup()

    def test_image_scan_related_expected_results(self, result: dict, namespace: str):
        resources_for_test = self.test_obj.get_arg("resources_for_test")
        for resource in resources_for_test:
            kind = resource['kind']
            name = resource['name']
            expected_failed_c = resource['failed_controls']
            resource_id, failed_controls = self.get_failed_controls_from_cli_result(result, kind=kind, name=name,
                                                                                    namespace=namespace,
                                                                                    api_version=statics.CA_VULN_SCAN_RESOURCE_API_VERSION)
            for control in expected_failed_c:
                assert control in failed_controls, \
                    f'Control {control} from expected failed_controls, not fail in resource {resource_id}'
            pass

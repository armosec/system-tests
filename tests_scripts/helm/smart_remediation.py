from .base_helm import BaseHelm
from ..kubescape.base_kubescape import BaseKubescape
from systest_utils import statics, Logger, TestUtil


class SmartRemediation(BaseKubescape, BaseHelm):
    def __init__(
            self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None
    ):
        super(SmartRemediation, self).__init__(
            test_driver=test_driver,
            test_obj=test_obj,
            backend=backend,
            kubernetes_obj=kubernetes_obj,
        )

        self.helm_kwargs = {
            "capabilities.relevancy": "enable",
            "capabilities.configurationScan": "enable",
            "capabilities.continuousScan": "disable",
            "capabilities.nodeScan": "disable",
            "capabilities.vulnerabilityScan": "disable",
            "capabilities.runtimeObservability": "enable",
            "grypeOfflineDB.enabled": "false",
        }

        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)

    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""

    def check_smart_remediation(self, body, want=True, retries=0):
        hl = {}
        for _ in range(retries):
            hl = self.backend.get_posture_resources_highlights(body)
            if len(hl["response"]) > 0 and (want == ("smartRemediations" in hl["response"][0])):
                return True
            TestUtil.sleep(10, "wait for smart remediation")
        Logger.logger.error("timed out waiting for smart remediation: {}".format(hl))
        return False

    def start(self):
        """
        Test plan:
        1. Install Helm chart
        2. Apply workload
        ...
        """
        assert (
                self.backend is not None
        ), f"the test {self.test_driver.test_name} must run with backend"

        cluster, namespace = self.setup(apply_services=False)
        print("Debug: cluster: ", cluster)

        Logger.logger.info(f"1. Install Helm Chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.verify_running_pods(
            namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360
        )

        Logger.logger.info(f"2. Apply workload")
        workload = self.apply_yaml_file(
            yaml_file=self.test_obj["workload"], namespace=namespace
        )
        self.verify_all_pods_are_running(
            namespace=namespace, workload=workload, timeout=300
        )

        Logger.logger.info(f"3. Trigger a scan")
        self.backend.trigger_posture_scan(
            cluster_name=cluster,
            framework_list=["AllControls"],
            with_host_sensor="false",
        )

        Logger.logger.info(f"3.1. Get report guid")
        report_guid = self.get_report_guid(
            cluster_name=cluster, wait_to_result=True, framework_name="AllControls"
        )
        assert report_guid != "", "report guid is empty"

        Logger.logger.info(f"4. Check smart remediation is available")
        body = {"pageNum": 1, "pageSize": 1, "cursor": "", "orderBy": "", "innerFilters": [{
            "resourceID": "apps/v1/" + namespace + "/Deployment/" + workload["metadata"]["name"],
            "controlID": self.test_obj["control"],
            "reportGUID": report_guid,
            "frameworkName": "AllControls"
        }]}
        assert self.check_smart_remediation(body, retries=30), "smartRemediations is not found"

        Logger.logger.info(f"5. Correct the issue")
        workload_fix = self.apply_yaml_file(
            yaml_file=self.test_obj["workload_fix"], namespace=namespace, replace=True
        )
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_fix, timeout=60)

        Logger.logger.info(f"6. Trigger another scan")
        self.backend.trigger_posture_scan(
            cluster_name=cluster,
            framework_list=["AllControls"],
            with_host_sensor="false",
        )

        Logger.logger.info(f"6.1. Get report guid")
        report_guid = self.get_report_guid(
            cluster_name=cluster, wait_to_result=True, framework_name="AllControls"
        )
        assert report_guid != "", "report guid is empty"

        Logger.logger.info(f"7. Check the issue is resolved")
        body = {"pageNum": 1, "pageSize": 1, "cursor": "", "orderBy": "", "innerFilters": [{
            "resourceID": "apps/v1/" + namespace + "/Deployment/" + workload["metadata"]["name"],
            "controlID": self.test_obj["control"],
            "reportGUID": report_guid,
            "frameworkName": "AllControls"
        }]}
        assert self.check_smart_remediation(body, want=False, retries=30), "smartRemediations should be empty"

        return self.cleanup()

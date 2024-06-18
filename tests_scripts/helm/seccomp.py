from systest_utils import statics, Logger
from .base_helm import BaseHelm
from ..kubescape.base_kubescape import BaseKubescape


class SeccompProfile(BaseKubescape, BaseHelm):
    def __init__(
            self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None
    ):
        super(SeccompProfile, self).__init__(
            test_driver=test_driver,
            test_obj=test_obj,
            backend=backend,
            kubernetes_obj=kubernetes_obj,
        )

        self.helm_kwargs = {
            "capabilities.relevancy": "enable",
            "capabilities.seccompProfileService": "enable",
        }

        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)

    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""

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

        Logger.logger.info(f"2. Apply seccomp profile")
        self.apply_yaml_file(
            yaml_file=self.test_obj["seccomp"], namespace=namespace
        )

        Logger.logger.info(f"3. Apply workload")
        workload = self.apply_yaml_file(
            yaml_file=self.test_obj["workload"], namespace=namespace
        )
        self.verify_all_pods_are_running(
            namespace=namespace, workload=workload, timeout=300
        )

        Logger.logger.info(f"4. Wait for application profiles")
        applicationProfiles, _ = self.wait_for_report(timeout=360,
                                                      report_type=self.get_application_profiles_from_storage,
                                                      namespace=namespace,
                                                      label_selector="app=nginx")

        Logger.logger.info(f"5. Verify seccomp profile")
        path = applicationProfiles[0]['spec']['containers'][0]["seccompProfile"]["path"]
        assert path == self.test_obj["want_path"], \
            f"Expected seccomp profile path: {self.test_obj['want_path']}, got: {path}"

        return self.cleanup()

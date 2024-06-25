from systest_utils import statics, Logger
from .base_helm import BaseHelm
from ..kubescape.base_kubescape import BaseKubescape
import json
import time




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
        }

        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)
        
        self.wait_for_agg_to_end = False

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


class SeccompProfileList(SeccompProfile):
    def __init__(
            self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None
    ):
        super(SeccompProfileList, self).__init__(
            test_obj=test_obj,
            backend=backend,
            kubernetes_obj=kubernetes_obj,
            test_driver=test_driver,
        )

    def start(self):
        """
        Test plan:
        1. Install Helm chart
        2. Apply seccomp profiles - overly_permissive, optimized
        3. Apply workloads - missing_seccomp, overly_permissive, optimized
        4. validate backend seccomp workloads list
        
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

        Logger.logger.info(f"2. Apply seccomp profiles")
        Logger.logger.info(f"2.1 Apply overly_permissive seccomp profile")
        self.apply_yaml_file(
            yaml_file=self.test_obj["seccomp_overly_permissive"], namespace=namespace
        )


        Logger.logger.info(f"2.2 Apply optimized seccomp profile")
        self.apply_yaml_file(
            yaml_file=self.test_obj["seccomp_optimized"], namespace=namespace
        )

        Logger.logger.info(f"3. Apply workloads")
        Logger.logger.info(f"3.1 Apply workload missing")
        workload = self.apply_yaml_file(
            yaml_file=self.test_obj["workload_missing"], namespace=namespace
        )

        self.verify_all_pods_are_running(
            namespace=namespace, workload=workload, timeout=300
        )

        Logger.logger.info(f"3.2 Apply workload overly_permissive")
        workload = self.apply_yaml_file(
            yaml_file=self.test_obj["workload_overly_permissive"], namespace=namespace
        )
        self.verify_all_pods_are_running(
            namespace=namespace, workload=workload, timeout=300
        )


        # TODO: add an explicit test for optimized seccomp profile. Currently, it is expected to be also overly permissive because blocked syscalls 
        # are being recorded as well.
        # no need to verify the pods are running, as it might fail due to the seccomp profile
        Logger.logger.info(f"3.3 Apply workload optimized")
        workload = self.apply_yaml_file(
            yaml_file=self.test_obj["workload_optimized"], namespace=namespace
        )

        Logger.logger.info("4. validate backend seccomp workloads list")

        excepted = self.test_obj["expected"]

        try:
            res = self.wait_for_report(
            self.verify_seccomp_workloads_list, 
            timeout=180,
            sleep_interval=10,
            cluster=cluster,
            namespace=namespace,
            expected=excepted
            )
        except Exception as e:
            Logger.logger.info(f"latest seccomp workloads list: {res}")
            self.log_on_failure(cluster, namespace, excepted)
            raise e

        return self.cleanup()

    
    def verify_seccomp_workloads_list(self, cluster, namespace, expected: dict):
        """
        verify_seccomp_workloads_list verifies the seccomp workloads list
        """
        Logger.logger.info(f"get seccomp workloads list for cluster: {cluster}, namespace: {namespace}")
        seccomp_list_body = {
            "innerFilters": [
                {
                    "cluster": cluster,
                    "namespace": namespace,
                }
            ],
            "pageNum": 1,
            "pageSize": 50,
        }
        res = self.backend.get_seccomp_workloads_list(seccomp_list_body)
        response = json.loads(res.text)

        assert "total" in response, "total key not found in response"
        assert "response" in response, "response key not found in response"
        assert response["total"]["value"] == len(expected), f"expected total value: {len(expected)}, got: {response['total']['value']}"
        assert len(response["response"]) == len(expected), f"expected response items: {len(expected)}, got: {len(response['response'])}"

        for item in expected:
            found = False
            for res_item in response["response"]:
                if res_item["name"] == item:
                    assert res_item["profileStatus"] in expected[item]["profileStatuses"], f"expected for item: {item} profileStatus: {expected[item]['profileStatuses']}, got: {res_item['profileStatus']}"
                    found = True
                  
            assert found, f"expected workload: {item} not found in response"
        
        return response
        

    

    def log_on_failure(self, cluster, namespace, expected: dict):
        """
        log_on_failure logs additional information in case of failure
        """
        Logger.logger.info("Log application profiles:")

        for item in expected:
            Logger.logger.info(f"get and log application profiles for item: {item}")
            try:
                applicationProfiles, _ = self.wait_for_report(timeout=180,
                                                            report_type=self.get_application_profiles_from_storage,
                                                            namespace=namespace,
                                                            label_selector=f"app={item}")
                Logger.logger.info(f"label_selector:app={item}, applicationProfiles: {applicationProfiles}")
            except Exception as e:
                Logger.logger.error(f"failed to get application profiles for item: {item}, error: {e}")
                continue


       
        
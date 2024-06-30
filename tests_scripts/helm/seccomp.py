from systest_utils import statics, Logger
from .base_helm import BaseHelm
from ..kubescape.base_kubescape import BaseKubescape
import json
import time
import os
import yaml


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
        assert response["total"]["value"] == len(
            expected), f"expected total value: {len(expected)}, got: {response['total']['value']}"
        assert len(response["response"]) == len(
            expected), f"expected response items: {len(expected)}, got: {len(response['response'])}"

        for item in expected:
            found = False
            for res_item in response["response"]:
                if res_item["name"] == item:
                    assert res_item["profileStatus"] in expected[item][
                        "profileStatuses"], f"expected for item: {item} profileStatus: {expected[item]['profileStatuses']}, got: {res_item['profileStatus']}"
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


class SeccompProfileGenerate(SeccompProfileList):
    def start(self):
        """
        Generate seccomp profile test plan:
        1. Install Helm chart
        2. Apply seccomp profiles - overly_permissive
        3. Apply workload - overly_permissive
        4. Validate backend seccomp workloads list
        5. Generate seccomp profile and validate response
        6. Apply seccomp profile and verify workload is running
        """
        # Call the original start method from SeccompProfileList and get the response
        cluster, namespace = self.setup(apply_services=False)
        print("Debug: cluster: ", cluster)

        Logger.logger.info(f"1. Install Helm Chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.verify_running_pods(
            namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360
        )

        Logger.logger.info(f"2 Apply overly_permissive seccomp profile")
        self.apply_yaml_file(
            yaml_file=self.test_obj["seccomp_overly_permissive"], namespace=namespace
        )

        Logger.logger.info(f"3 Apply workload overly_permissive")
        workload = self.apply_yaml_file(
            yaml_file=self.test_obj["workload_overly_permissive"], namespace=namespace
        )
        self.verify_all_pods_are_running(
            namespace=namespace, workload=workload, timeout=300
        )

        Logger.logger.info("4. Validate backend seccomp workloads list")
        expected = self.test_obj["expected"]
        try:
            response = self.wait_for_report(
                self.verify_seccomp_workloads_list,
                timeout=180,
                sleep_interval=10,
                cluster=cluster,
                namespace=namespace,
                expected=expected
            )
        except Exception as e:

            Logger.logger.info(f"latest seccomp workloads list: {response}")
            self.log_on_failure(cluster, namespace, expected)
            raise e

        Logger.logger.info("5. Generate seccomp profile")

        # Generate seccomp profile and validate response
        response = self.generate_seccomp(response)

        Logger.logger.info(f"6 Apply optimized seccomp profile, verify that workload runs and all good")

        # Remove the resourceVersion field from the new suggested workload so apply will work
        suggested_workload = response["suggestedWorkload"]["new"]
        if "metadata" in suggested_workload and "resourceVersion" in suggested_workload["metadata"]:
            del suggested_workload["metadata"]["resourceVersion"]

        self.apply_yaml_file(
            yaml_file=suggested_workload, namespace=namespace
        )
        self.verify_all_pods_are_running(
            namespace=namespace, workload=workload, timeout=300
        )
        return self.cleanup()

    def generate_seccomp(self, response):
        """
        Generate seccomp profile with BE API and verify response
        """
        Logger.logger.info("Generating seccomp profile")

        res_item = response[0]["response"][0]
        assert len(res_item) > 0, f"expected non empty response items, got: {len(response['response'])}"

        generate_seccomp_body = {
            "innerFilters": [
                {
                    "k8sResourceHash": res_item["k8sResourceHash"]
                }
            ]
        }

        res = self.backend.generate_seccomp_profile(generate_seccomp_body)
        response = json.loads(res.text)

        assert response["name"] == res_item["name"], f"expected name: {res_item['name']}, got: {response['name']}"
        assert response["kind"] == res_item["kind"], f"expected kind: {res_item['kind']}, got: {response['kind']}"
        assert response["namespace"] == res_item[
            "namespace"], f"expected namespace: {res_item['namespace']}, got: {response['namespace']}"
        assert response["k8sResourceHash"] == res_item[
            "k8sResourceHash"], f"expected k8sResourceHash: {res_item['k8sResourceHash']}, got: {response['k8sResourceHash']}"

        # Extract the securityContext from both old and new suggestedWorkload
        old_security_context = response["suggestedWorkload"]["old"]["spec"]["template"]["spec"]["containers"][0][
            "securityContext"]
        new_security_context = response["suggestedWorkload"]["new"]["spec"]["template"]["spec"]["containers"][0][
            "securityContext"]

        # Load the expected YAML content and convert to JSON
        workload_overly_permissive_path = self.test_obj["workload_overly_permissive"]
        assert os.path.isfile(workload_overly_permissive_path), f"File not found: {workload_overly_permissive_path}"

        with open(workload_overly_permissive_path, 'r') as f:
            file_content = f.read().strip()
            assert file_content, f"File is empty: {workload_overly_permissive_path}"
            try:
                expected_yaml_content = yaml.safe_load(file_content)
                expected_json_content = json.loads(json.dumps(expected_yaml_content))
            except (yaml.YAMLError, json.JSONDecodeError) as e:
                raise ValueError(f"Error parsing YAML/JSON from file {workload_overly_permissive_path}: {e}")

        expected_security_context = expected_json_content["spec"]["template"]["spec"]["containers"][0][
            "securityContext"]
        container_name = expected_json_content["spec"]["template"]["spec"]["containers"][0]["name"]
        namespace = response["namespace"]
        workload_name = response["name"]
        workload_kind = response["kind"]
        # Compare security contexts
        assert old_security_context == expected_security_context, f"expected securityContext: {expected_security_context}, got: {old_security_context}"
        assert new_security_context["seccompProfile"][
                   "type"] == "Localhost", f"expected securityContext type: Localhost, got:{new_security_context['seccompProfile']['type']}"
        expected_localhost_profile_path = f"{namespace}/{workload_kind}-{workload_name}-{container_name}.json"
        assert new_security_context["seccompProfile"][
                   "localhostProfile"] == expected_localhost_profile_path, f"expected securityContext localhostProfile : {expected_localhost_profile_path}, got: {new_security_context['seccompProfile']['localhostProfile']}"

        # check seccompCRD
        seccomp_crd = response["seccompCRD"]
        assert seccomp_crd["metadata"][
                   "name"] == workload_name, f"expected seccompCRD metadata name: {res_item['name']}, got: {seccomp_crd['metadata']['name']}"
        assert seccomp_crd["metadata"]["namespace"] == res_item[
            "namespace"], f"expected seccompCRD metadata namespace: {namespace}, got: {seccomp_crd['metadata']['namespace']}"
        seccomp_crd_container = seccomp_crd["spec"]["containers"][0]
        seccomp_crd_container_spec = seccomp_crd_container["spec"]
        expected_path = f"{namespace}/{workload_kind}-{workload_name}-{container_name}.json"
        assert seccomp_crd_container[
                   "path"] == expected_path, f"expected seccompCRD container path: {expected_path}, got: {seccomp_crd_container['path']}"
        assert seccomp_crd_container[
                   "name"] == container_name, f"expected seccompCRD container name: {container_name}, got: {seccomp_crd_container['name']}"
        assert seccomp_crd_container_spec[
                   "defaultAction"] == "SCMP_ACT_ERRNO", f"expected defaultAction: SCMP_ACT_ERRNO, got: {seccomp_crd_container_spec['defaultAction']}"
        assert seccomp_crd_container_spec["architectures"] == ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86",
                                                               "SCMP_ARCH_X32"], f"expected architectures: ['SCMP_ARCH_X86_64', 'SCMP_ARCH_X86', 'SCMP_ARCH_X32'], got: {seccomp_crd_container_spec['architectures']}"
        assert seccomp_crd_container_spec["syscalls"][0][
                   "action"] == "SCMP_ACT_ALLOW", f"expected syscalls action :SCMP_ACT_ALLOW, got: {seccomp_crd_container_spec['syscalls'][0]['action']}"
        return response

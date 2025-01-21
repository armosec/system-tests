import base64
import json
import os
from typing import List, Dict

from systest_utils import Logger, TestUtil, statics
from tests_scripts.helm.base_helm import BaseHelm

REGISTRY_PROVIDERS: List[Dict[str, any]] = [
    {
        "provider": "quay",
        "secret_field_name": "robotAccountToken",
        "secret_value_env_var": "QUAY_REGISTRY_ACCESS_TOKEN",
    },
    {
        "provider": "aws",
        "secret_field_name": "secretAccessKey",
        "secret_value_env_var": "AWS_REGISTRY_SECRET_KEY",
    },
    {
        "provider": "azure",
        "secret_field_name": "accessToken",
        "secret_value_env_var": "AZURE_REGISTRY_ACCESS_TOKEN",
    },
    # {
    #     "provider": "google",
    #     "secret_field_name": "key",
    #     "secret_value_env_var": "GOOGLE_REGISTRY_KEY",
    # },
]

class RegistryChecker(BaseHelm):

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RegistryChecker, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                              kubernetes_obj=kubernetes_obj)
        self.cluster = None

    def start(self):
        Logger.logger.info('Stage 1: Install kubescape with helm-chart')
        self.cluster, _ = self.setup(apply_services=False)
        self.install_kubescape()
        TestUtil.sleep(10)
        Logger.logger.info('Stage 2: Check registries connection')
        self.check_registries_connection(self.cluster)
        Logger.logger.info('Stage 3: Check quay.io registry CRUD operations')
        self.check_registry_crud(self.cluster)
        return self.cleanup()

    def check_registry_crud(self, cluster):
        quay_config = REGISTRY_PROVIDERS[0]
        provider = quay_config["provider"]

        Logger.logger.info("Loading creation payload file")
        file_path = self.test_obj["create_payload_file"]
        with open(file_path, 'r') as file:
            data = json.load(file)
        data["clusterName"] = cluster
        Logger.logger.info("Loading creation secret from env var")
        secret = os.getenv(quay_config["secret_value_env_var"])
        data[quay_config["secret_field_name"]] = secret

        Logger.logger.info("Calling creation API")
        created = self.backend.create_registry(data, provider)
        assert created, "Expected created registry"
        guid = created.json()["guid"]

        Logger.logger.info("Checking if registry scan is completed")
        self.assert_registry_scan_completed(provider, guid)

        registry = self.backend.get_registry(provider, guid)
        assert registry, "Expected to get registry"
        update_payload = registry.json()
        update_payload["scanFrequency"] = "30 * * 5 *"
        Logger.logger.info("Updating registry with new scan scanFrequency")
        updated = self.backend.update_registry(update_payload, provider, guid)
        assert updated, "Expected updated registry"
        assert updated.json()["scanFrequency"] == "30 * * 5 *", "Expected scanFrequency to be updated"

        Logger.logger.info("Deleting registry")
        self.backend.delete_registry(provider, guid)
        registries = self.get_all_quay_registries_for_cluster(cluster)
        assert len(registries) == 0, "Expected to have no registries"

    def check_registries_connection(self, cluster):
        for provider_config in REGISTRY_PROVIDERS:
            provider = provider_config["provider"]
            Logger.logger.info(f'{provider}: Loading payload file')
            file_path = self.test_obj["check_payload_file"].format(provider)
            with open(file_path, 'r') as file:
                data = json.load(file)
            data["clusterName"] = cluster
            Logger.logger.info(f'{provider}: Loading secrets from env var')
            secret = os.getenv(provider_config["secret_value_env_var"])
            if provider == "google":
                secret = json.loads(base64.b64decode(secret).decode('utf-8'))
            data[provider_config["secret_field_name"]] = secret
            Logger.logger.info(f'{provider}: Calling repositories API')
            repositories_response = self.backend.check_registry(data, provider)
            assert repositories_response, "Expected repositories"
            assert any("systemtests/webgoat" in item for item in repositories_response.json()), \
                f"'systemtests/webgoat' not found in any item of {repositories_response.json()}"

    def cleanup(self, **kwargs):
        self.delete_all_quay_registries_for_cluster(self.cluster)
        return super().cleanup()

    def install_kubescape(self, helm_kwargs: dict = None):
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

    def assert_registry_scan_completed(self, provider, guid):
        TestUtil.sleep(30, "waiting for registry scan to complete")
        for i in range(60):
            try:
                registry = self.backend.get_registry(provider, guid)
                assert registry, "Expected registry"
                assert registry.json()["scanStatus"] == "Completed"
                break
            except AssertionError:
                if i == 59:
                    raise
                TestUtil.sleep(2, "waiting for registry scan to complete")

    def delete_all_quay_registries_for_cluster(self, cluster):
        leftovers = self.get_all_quay_registries_for_cluster(cluster)
        for r in leftovers:
            self.backend.delete_registry(r["provider"], r["guid"])

    def get_all_quay_registries_for_cluster(self, cluster):
        ret = []
        resp = self.backend.get_all_registries("quay").json()
        if resp['total']['value'] == 0:
            return ret
        for r in resp['response']:
            if r["clusterName"] == cluster:
                ret.append(r)
        return ret
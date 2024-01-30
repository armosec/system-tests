import inspect
from configurations.system.git_repository import GitRepository

# from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
from infrastructure import supported_systemsAPI
from .structures import TestConfiguration, K8SConnection


class KsVulnerabilityScanningTests(object):
    @staticmethod
    def scan_image_controls():
        from tests_scripts.helm.ks_vuln_scan import ScanImageControls
        from configurations.system.network_policy import NetworkPolicy
        from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_SERVICE_PATH, DEFAULT_CONFIGMAP_PATH
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanImageControls,
            services=join(DEFAULT_SERVICE_PATH, "wikijs"),
            secret="wikijs.yaml",
            config_maps=join(DEFAULT_CONFIGMAP_PATH, "wikijs"),
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "wikijs"),
            database=supported_systemsAPI.WikiJS,
            ingress=K8SConnection(workload_name="nginx", port=80, scheme="http"),
            neighbors_map={  # map of neighbors {<client>: [<server>]},
                "nginx": ["wikijs"],
                "wikijs": ["mariadb"]},
            network_policy=NetworkPolicy(
                name="wikijs",
                policy_type="basic",
                server_attributes={"namespace": ""},
                client_attributes={"namespace": ""},
                service_ip=["0.0.0.0/0"],
                port_ranges=[{"start": 1024, "end": 65535}]
            ),
            secret_key=True,
            client_id=True,
            submit=True,
            account=True,
            resources_for_test=[{'kind': 'Pod', 'name': 'nginx', 'failed_controls': ['C-0083', 'C-0084', 'C-0085']}]

        )

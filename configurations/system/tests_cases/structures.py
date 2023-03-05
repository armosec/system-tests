import requests

from systest_utils import TestUtil, statics, IteratorSetup


# TODO: remove IteratorSetup
class Container(IteratorSetup):
    def __init__(self, name: str, **kwargs):
        self.name: str = name
        self.kwargs = kwargs

        # docker container
        self.image_tag: str = self.get_arg("image_tag")
        self.dockerfile: str = TestUtil.get_abs_path(statics.DEFAULT_DOCKER_FILE_PATH, self.get_arg("dockerfile"))
        self.docker_args = self.get_arg("docker_args")
        self.signing_profile = self.get_arg("signing_profile")
        self.port = self.get_arg("port")

        self.replicas = self.get_arg("replicas", default=1)
        self.load_time = self.get_arg("load_time", default=0)
        self.type = self.get_arg("type")

        # caa
        self.processes = self.get_processes("process", "processes")

    def get_arg(self, arg, default=None):
        return self.kwargs[arg] if arg in self.kwargs else default

    def get_processes(self, *p):
        for i in p:
            processes = self.get_arg(i)
            if processes:
                return TestUtil.is_abs_paths(processes)
        return None


class WorkloadTemplate(IteratorSetup):
    def __init__(self, name: str, **kwargs):
        self.name: str = name
        self.kwargs = kwargs

        self.type = self.get_arg("type")
        self.containers = self.get_containers("containers", "container")
        self.encryption_config = self.get_arg("encryption_config")
        self.wlid: str = ""

    def get_arg(self, arg):
        return self.kwargs[arg] if arg in self.kwargs else None

    def get_path(self):
        return TestUtil.get_abs_path(statics.DEFAULT_WT_PATH, self.name)

    def containers_images(self):
        return {i.image_tag: i.dockerfile for i in self.containers.values()}

    def get_containers_names(self):
        return list(self.containers.keys())

    def get_containers(self, *con_config):
        for i in con_config:
            containers = self.get_arg(i)
            if isinstance(containers, Container):
                return containers
            if isinstance(containers, list):
                return {i.name: i for i in containers}
        return None

    def get_containers_name(self):
        if isinstance(self.containers, list):
            return "-".join([i.name for i in self.containers])
        return self.containers.name


class TestConfiguration(object):
    K8S_KINDS = {
        "Service": "service",
        "Secret": "secret",
        "Deployment": "yaml",
        "ReplicaSet": "yaml",
        "CustomResourceDefinition": "custom_resource_definition",
        "ServiceAccount": "service_account",
        "ConfigMap": "config_map",
        "Role": "role",
        "RoleBinding": "role_binding",
        "ClusterRole": "cluster_role",
        "ClusterRoleBinding": "cluster_role_binding",
        "StatefulSet": "yaml",
        "NetworkPolicy": "kubernetes_network_policy",
    }

    def __init__(self, name: str,
                 test_obj,
                 **kwargs):
        # basic
        self.name: str = name
        self.test_obj = test_obj
        self.kwargs: dict = kwargs

        # workload template
        self.workload_templates = self.get_multi("workload_template", "workload_templates")

        # network policy
        self.network_policy = self.get_arg("network_policy")

        # encryption
        self.db = self.get_arg("database")
        self.db_args: dict = self.get_arg("database_args", default={})
        self.entropy: float = self.get_arg("entropy", 6.5)

        # url handler
        url = self.get_arg("url")
        if url:
            self.load_from_url(url=url)

        # windows

    def load_from_url(self, url: str):
        # download from url
        yamls = []
        if isinstance(url, str):
            url = [url]

        for u in url:
            response = requests.get(u)  #
            yamls.extend([i for i in TestUtil.yaml_file_to_dict(response.text)])

        self.init_from_yamls(yamls=yamls)

    def init_from_yamls(self, yamls: list):
        # for each yaml, place yaml in class
        for y in yamls:
            kind = y["kind"]
            assert kind in self.K8S_KINDS, f"kind {kind} unknown, yaml file: {y}"

            if self.K8S_KINDS[kind] not in self.kwargs:
                self.kwargs[self.K8S_KINDS[kind]] = []
            self.kwargs[self.K8S_KINDS[kind]].append(y)


    def get_arg(self, arg, default=None):
        return self.kwargs[arg] if arg in self.kwargs else default

    def get_name(self):
        return self.name

    def get_test_obj(self):
        return self.test_obj

    def get_multi(self, *wts):
        for i in wts:
            wt = self.get_arg(i)
            if wt:
                return wt
        return None

    def __getitem__(self, item):
        """
        usage:
        A(kwargs={"a": 0})
        A["a"] -> 0
        A[("a", 1)] -> 0
        A["b"] -> raise exception
        A[("b", 1)] -> 1
        :param item: single item or tuple (item, default)
        :return:
        """
        return self.kwargs[item[0]] if item[0] in self.kwargs else item[1] if len(item) == 2 else self.kwargs[item]


class K8SConnection(object):
    def __init__(self, workload_name: str = None, service_name: str = None, ip: str = None, port: int = 80,
                 scheme: str = "http", path: str = None, query: dict = None, verify: bool = False):
        self.workload_name: str = workload_name
        self.service_name: str = service_name
        self.ip: str = ip
        self.port: int = port
        self.scheme: str = scheme
        self.path: str = path
        self.query: dict = query
        self.verify: bool = verify

    def get_url(self):
        final_url = f"{self.scheme}://"
        final_url += self.ip
        if self.port:
            final_url += f":{self.port}"
        if self.path:
            final_url += self.path
        if self.query:
            final_url += f"?{'&'.join([f'{k}={v}' for k, v in self.query.items()])}"
        return final_url


def get_args_dict(kwargs, arg):
    if arg not in kwargs:
        return None

    if isinstance(kwargs[arg], dict):
        return kwargs[arg]

    return {i.name: i for i in kwargs[arg]}


class KubescapeConfiguration(object):

    def __init__(self, name: str,
                 test_obj,
                 **kwargs):
        # basic
        self.name: str = name
        self.test_obj = test_obj
        self.kwargs: dict = kwargs

        # scan information
        self.policy_scope = self.get_arg("policy_scope")
        self.policy_name = self.get_arg("policy_name")

        # output
        self.output_file = self.get_arg("output")
        self.output_format = self.get_arg("format")

        # features
        self.exceptions = self.get_arg("exceptions")

    def get_arg(self, arg, default=None):
        return self.kwargs[arg] if arg in self.kwargs else default

    def get_name(self):
        return self.name

    def get_test_obj(self):
        return self.test_obj

    def __getitem__(self, item):
        """
        usage:
        A(kwargs={"a": 0})
        A["a"] -> 0
        A[("a", 1)] -> 0
        A["b"] -> raise exception
        A[("b", 1)] -> 1
        :param item: single item or tuple (item, default)
        :return:
        """
        return self.kwargs[item[0]] if item[0] in self.kwargs else item[1] if len(item) == 2 else self.kwargs[item]


class PaymentConfiguration(object):

    def __init__(self, name: str,
                test_obj,
                **kwargs):
        # basic
        self.name: str = name
        self.test_obj = test_obj
        self.kwargs: dict = kwargs

    def get_arg(self, arg, default=None):
        return self.kwargs[arg] if arg in self.kwargs else default

    def get_name(self):
        return self.name

    def get_test_obj(self):
        return self.test_obj

    def __getitem__(self, item):
        """
        usage:
        A(kwargs={"a": 0})
        A["a"] -> 0
        A[("a", 1)] -> 0
        A["b"] -> raise exception
        A[("b", 1)] -> 1
        :param item: single item or tuple (item, default)
        :return:
        """
        return self.kwargs[item[0]] if item[0] in self.kwargs else item[1] if len(item) == 2 else self.kwargs[item]

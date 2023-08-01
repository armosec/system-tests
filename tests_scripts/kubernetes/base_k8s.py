from __future__ import print_function

import json
import operator
import os
import tempfile
import time

# allow support for python 3.10
try:
    from collections.abc import Iterable
except ImportError:
    from collections import Iterable
# 
from datetime import datetime
from threading import Thread

import requests
import hashlib


from infrastructure import KubectlWrapper
from infrastructure.helm_wrapper import HelmWrapper
from infrastructure.thread_wrapper import WebsocketWrapper
from systest_utils import Logger, TestUtil, statics
from systest_utils.data_structures import DataStructuresUtils
from systest_utils.sid import SID
from systest_utils.statics import Statistics
from systest_utils.wlid import Wlid
from tests_scripts.dockerize import BaseDockerizeTest
from kubernetes import config, client, dynamic

class BaseK8S(BaseDockerizeTest):

    def __init__(self, test_driver, test_obj, backend, agent_crash_report=True, **kwrags):

        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend)
        self.namespaces: list = list()
        self.cluster_resources: list = list()  # cluster scoped resources -> remove after test
        self.cluster: str = ""
        self.kubernetes_obj = KubectlWrapper(
            cluster_name=TestUtil.get_arg_from_dict(self.test_driver.kwargs, "cluster", "minikube"))

        self.service_obj = None
        self.remove_cyberarmor_namespace = not test_driver.kwargs["leave_cyberarmor_namespace"]

        self.env = {"ARMO_TEST_NAME": self.test_obj.get_name()}
        # agent_crash_report = False
        if agent_crash_report:
            self.env["CAA_ENABLE_CRASH_REPORTER"] = "1"

        self.env.update(self.test_obj.get_arg("env", {}))

        # oracle_agent_logs_envs = {"CAA_ORACLE_UPDATES_INFO": "1", "CAA_ORACLE_UPDATES_INFO_DATA": "1"}
        # self.env.update(oracle_agent_logs_envs)

        # oracle_agent_logs_envs = {"CAA_SIGNATURE_DEBUG_PROCESS": "1", "CAA_SIGNATURE_DEBUG_DEEP": "1"}
        # self.env.update(oracle_agent_logs_envs)

        self.enable_connect_oci_image = self.test_obj.get_arg("enable_oci_image", False)
        if not self.enable_connect_oci_image:
            self.enable_connect_oci_image = self.get_configuration(config="enable_oci_image", default=False)

        self.signer_debug = self.test_obj.get_arg("signer_debug", False)
        if not self.signer_debug:
            self.signer_debug = self.get_configuration(config="signer_debug", default=False)

        self.websocket_wrapper = WebsocketWrapper()
        self.safe_mode_logs = []

        self.display_kube_system_container_logs: bool = TestUtil.get_arg_from_dict(self.test_driver.kwargs,
                                                                                   "display_kube_system_logs", False)

        self.ignore_ca_logs: bool = TestUtil.get_arg_from_dict(self.test_driver.kwargs, "ignore_ca_system_logs", False)

    # setup kubernetes
    def setup(self, cluster: str = None, namespace: str = None, auto_attach: bool = False, auto_protect: bool = False,
              apply_secrets: bool = True, apply_services: bool = True,
              apply_service_account: bool = False, apply_cluster_role: bool = False,
              apply_cluster_role_binding: bool = False, apply_custom_resource_definition: bool = False,
              apply_role: bool = False, apply_role_binding: bool = False, apply_config_map: bool = False,
              apply_kubernetes_network_policy: bool = False):
        """
        # 1. register cyberarmorsecret_encrypt
        # 2. apply cyberarmor namespace
        # 3. apply test namesapce
        # 4. apply cyberarmor secret and rest of saecrets
        # 5. apply services

        :param cluster: cluster name
        :param namespace: test namespace
        :param ignore_agent: run without cyberarmor
        :param apply_services:
        :param apply_secrets:
        :param auto_attach: inject auto attach label to namespace
        :param enable_oci_image: webhook and websocket will use oci image and not docker
        :return: cluster name and namespace
        """

        namespace = self.create_namespace(name=namespace, auto_attach=auto_attach, auto_protect=auto_protect)

        if apply_kubernetes_network_policy:
            self.apply_kubernetes_network_policy(namespace=namespace,
                                                 yaml_file=self.test_obj.get_arg("kubernetes_network_policy"))

        # apply secretes
        if apply_secrets:
            # apply ca secret
            self.apply_secret(namespace=namespace, yaml_file=self.test_obj.get_arg("secret"))

        # apply services
        if apply_services:
            self.apply_service(namespace=namespace, yaml_file=self.test_obj.get_arg("service"))

        if apply_service_account:
            self.apply_service_account(namespace=namespace, yaml_file=self.test_obj.get_arg("service_account"))

        if apply_cluster_role:
            self.apply_cluster_role(namespace=namespace, yaml_file=self.test_obj.get_arg("cluster_role"))

        if apply_cluster_role_binding:
            self.apply_cluster_role_binding(namespace=namespace,
                                            yaml_file=self.test_obj.get_arg("cluster_role_binding"))

        if apply_custom_resource_definition:
            self.apply_custom_resource_definition(namespace=namespace,
                                                  yaml_file=self.test_obj.get_arg("custom_resource_definition"))

        if apply_role:
            self.apply_role(namespace=namespace, yaml_file=self.test_obj.get_arg("role"))

        if apply_role_binding:
            self.apply_role_binding(namespace=namespace, yaml_file=self.test_obj.get_arg("role_binding"))

        if apply_config_map:
            self.apply_config_map(namespace=namespace, yaml_file=self.test_obj.get_arg("config_map"))

        return self.get_cluster_name(), namespace

    def __del__(self):

        try:
            self.websocket_wrapper.close()
        except:
            pass

        try:
            for ns in self.namespaces:
                wlids = list(self.backend.get_all_namespace_wlids(cluster=self.cluster, namespace=ns).keys())
                wlids.extend(self.wlids)
                self.wlids = list(set(wlids))
        except:
            pass

        try:
            self.remove_all_namespaces(remove_cyberarmor_namespace=self.remove_cyberarmor_namespace)
        except:
            pass

        super(BaseK8S, self).__del__()

    @staticmethod
    def get_cluster_name():
        clusters, active_cluster = config.list_kube_config_contexts()

        return active_cluster['name']

    def remove_all_namespaces(self, remove_cyberarmor_namespace: bool = True):
        for ns in self.namespaces[:]:
            try:
                self.delete_namespace(namespace=ns)
                self.namespaces.remove(ns)
            except:
                pass

    # ---------------------- cleanup ------------------------
    def cleanup(self, display_ca_logs: bool = True, **kwargs):
        self.websocket_wrapper.close()

        for ns in self.namespaces[:]:
            self.update_containers_list(namespace=ns)

        if self.display_kube_system_container_logs:
            self.display_kube_system_logs()

        super().cleanup(**kwargs)
        return statics.SUCCESS, ""

    def delete_namespace(self, namespace: str):
        try:
            Logger.logger.debug(f"namespace {namespace}")
            TestUtil.run_command(command_args=f"kubectl -n {namespace} get pods".split(" "))
            Logger.logger.debug("remove {} namespace".format(namespace))
            self.kubernetes_obj.delete_namespace(namespace=namespace)
        except Exception as e:
            Logger.logger.error(e)

    def delete_cluster_from_backend(self, confirm_deletion: bool = True) -> bool:
        if self.cluster_deleted:
            Logger.logger.info("Cluster '{}' was confirmed as already deleted from backend".format(cluster_name))
            return True
        
        try:
            cluster_name = self.kubernetes_obj.get_cluster_name()
            try:
                self.backend.get_cluster(cluster_name=cluster_name, expected_status_code=200)
            except Exception as ex:
                if str(ex).find('received "404"') > -1:
                    Logger.logger.info("Cluster '{}' was confirmed as already deleted from backend".format(cluster_name))
                    return True
                Logger.logger.info("Cluster '{}' wasn't confirmed as already deleted from backend. Error: {}".format(cluster_name, ex))
            Logger.logger.info("Deleting cluster '{}' from backend".format(cluster_name))
            self.backend.delete_cluster(cluster_name=cluster_name)
        except requests.ReadTimeout as e:
            return False
        except Exception as e:
            raise e

        if confirm_deletion:
            # verify cluster was deleted from backend
            cluster_result, _ = self.wait_for_report(report_type=self.backend.get_cluster, timeout=300,
                                                    cluster_name=self.kubernetes_obj.get_cluster_name(),
                                                    expected_status_code=404)
            assert cluster_result, 'Failed to verify deleting cluster {x} from backend'. \
                format(x=self.kubernetes_obj.get_cluster_name())
            
            Logger.logger.info("Cluster was deleted successfully '{}'".format(self.kubernetes_obj.get_cluster_name()))
        
            self.cluster_deleted = True
        return True

    def apply_secret(self, **kwargs):
        return self.apply_yaml_file(path=statics.DEFAULT_SECRETE_PATH, **kwargs)

    def apply_service(self, expose_port: int = None, **kwargs):
        # TODO: update port
        return self.apply_yaml_file(path=statics.DEFAULT_SERVICE_PATH, **kwargs)

    def apply_service_account(self, **kwargs):
        # TODO: update port
        return self.apply_yaml_file(path=statics.DEFAULT_SERVICE_ACCOUNT_PATH, **kwargs)

    def apply_role(self, **kwargs):
        return self.apply_yaml_file(path=statics.DEFAULT_ROLE_PATH, **kwargs)

    def apply_role_binding(self, **kwargs):
        return self.apply_yaml_file(path=statics.DEFAULT_ROLE_BINDING_PATH, **kwargs)

    def apply_config_map(self, **kwargs):
        return self.apply_yaml_file(path=statics.DEFAULT_CONFIGMAP_PATH, **kwargs)

    def apply_kubernetes_network_policy(self, **kwargs):
        return self.apply_yaml_file(path=statics.DEFAULT_NETWORK_POLICY_PATH, **kwargs)

    def apply_cluster_role(self, yaml_file: str, **kwargs):
        if not yaml_file:
            return
        workload = self.apply_yaml_file(path=statics.DEFAULT_CLUSTER_ROLE_PATH, yaml_file=yaml_file, **kwargs)

        if isinstance(workload, dict):
            workload = [workload]
        [self.cluster_resources.append(i) for i in workload]

        return workload

    def apply_cluster_role_binding(self, yaml_file: str, namespace: str, **kwargs):
        if not yaml_file:
            return

        workload = self.load_yaml(yaml_file=yaml_file, path=statics.DEFAULT_CLUSTER_ROLE_BINDING_PATH)
        self.update_cluster_role_subject(workload=workload, namespace=namespace)

        if isinstance(workload, dict):
            workload = [workload]
        [self.cluster_resources.append(i) for i in workload]
        return self.apply_workload(workload=workload, namespace=namespace, **kwargs)

    def update_cluster_role_subject(self, workload: dict, namespace: str):
        if isinstance(workload, list):
            for i in workload:
                self.update_cluster_role_subject(workload=i, namespace=namespace)
        # loop update namespace
        else:
            for subject in workload["subjects"]:
                subject["namespace"] = namespace

    def apply_custom_resource_definition(self, yaml_file: str, namespace: str, **kwargs):
        if not yaml_file:
            return
        workload = self.apply_yaml_file(path=statics.DEFAULT_CLUSTER_ROLE_PATH, namespace=namespace,
                                        yaml_file=yaml_file, **kwargs)
        if isinstance(workload, dict):
            workload = [workload]
        [self.cluster_resources.append(i) for i in workload]
        return workload

    def apply_directory(self, path: str, **kwargs):
        """
        apply a project - apply all yamls in a directory

        :param path: directory of project
        :param kwargs-
            namespace: namespace for all yamls
            unique_name: if to provide each one of the workloads a unique name
        :return:
        """
        if not path or not os.path.isdir(path):
            return
        yaml_files = TestUtil.get_files_in_dir(file_path=path)
        if not yaml_files:
            return None
        Logger.logger.debug("applying {} files from dir {}".format(len(yaml_files), path))
        return self.apply_yaml_file(yaml_file=yaml_files, path=path, **kwargs)

    def apply_yaml_file(self, yaml_file, namespace: str, path: str = statics.DEFAULT_DEPLOYMENT_PATH,
                        unique_name: bool = False, name: str = None, wlid: str = None, auto_attach: bool = False,
                        auto_protect: bool = False, **kwargs):
        """
        currently supports yaml with *one* workload
        for applying more than one workload the yaml_file should be a list of files

        :param yaml_file: file or list of files
        :param path: path to file/s
        :param namespace:
        :param unique_name: generate unique name
        :param wlid: if workload has wlid we will change the workload name to be as the name in wlid
        :param auto_attach: if auto attach, inject the ca label
        :return:
        """
        if not yaml_file:
            return None
        workload = self.load_yaml(yaml_file=yaml_file, path=path)
        if unique_name:
            self.update_workload_metadata_name(workload=workload)
        if name:
            self.update_workload_metadata_name(workload=workload, name=name)
        if wlid:
            self.update_workload_metadata_name(workload=workload, name=Wlid.get_name(wlid))
            self.update_workload_metadata_by_wlid(workload=workload, wlid=wlid)
        if auto_attach:
            self.update_workload_metadata_labels(workload=workload, labels={statics.AUTO_ATTACH_LABEL: "true"})
        if auto_protect:
            self.update_workload_metadata_labels(workload=workload, labels={statics.AUTO_ATTACH_SECRET_LABEL:
                                                                                statics.AUTO_ATTACH_SECRET_VALUE})

        self.update_workload_metadata_env(workload=workload, env=self.env)
        self.apply_workload(workload=workload, namespace=namespace, **kwargs)
        return workload

    def apply_workload(self, workload, namespace: str, wait: int = 0):
        try:
            if isinstance(workload, dict):
                Logger.logger.debug("applying {}, name: {}, namespace: {}".format(
                    self.get_workload_kind(workload), self.get_workload_metadata_name(workload), namespace))
                return self.kubernetes_obj.apply_workload(application=workload, namespace=namespace)
            else:
                for i in workload:
                    TestUtil.sleep(t=wait, m="sleep between apply")
                    self.apply_workload(workload=i, namespace=namespace)
        except Exception as e:
            raise Exception("apply_workload: {}".format(e))

    @staticmethod
    def load_yaml(yaml_file, path: str):
        """
        :param yaml_file: file or list of files
        :param path: path to file or to list of files
        :return: the workloads in dict format
        """
        if isinstance(yaml_file, dict):
            return yaml_file
        return TestUtil.load_yaml_file(path=path, file=yaml_file) if isinstance(yaml_file, str) else [
            TestUtil.load_yaml_file(path=path, file=i) for i in yaml_file]

    @staticmethod
    def update_workload_metadata_name(workload, name: str = None):
        if isinstance(workload, dict):
            generate_function = TestUtil.generate_k8s_random_name if BaseK8S.restricted_k8s_name(
                BaseK8S.get_workload_kind(workload)) else TestUtil.generate_random_name
            workload['metadata']['name'] = name if name else generate_function(workload['metadata']['name'])
            return workload['metadata']['name']
        if isinstance(workload, Iterable):
            return [BaseK8S.update_workload_metadata_name(workload=i, name=name) for i in workload]
        raise Exception("workload should be of type dict/list/generator, type: {}".format(type(workload)))

    @staticmethod
    def update_workload_metadata_labels(workload, labels: dict):
        if isinstance(workload, dict):
            if not 'labels' in workload['metadata']:
                workload['metadata']['labels'] = {}
            for k, v in labels.items():
                workload['metadata']['labels'][k] = v
            return workload['metadata']['labels']
        if isinstance(workload, Iterable):
            return [BaseK8S.update_workload_metadata_labels(workload=i, labels=labels) for i in workload]
        raise Exception("workload should be of type dict/list/generator, type: {}".format(type(workload)))

    @staticmethod
    def update_workload_metadata_env(workload, env: dict):
        if isinstance(workload, dict):
            kind = BaseK8S.get_workload_kind(workload=workload)
            if kind not in KubectlWrapper.none_abstract_kinds:
                return workload

            containers = BaseK8S.get_containers_names_from_workload_yaml(workload=workload)
            # workload
            for container in containers:
                if "env" not in container or not isinstance(container["env"], list):
                    container["env"] = []
                container["env"].extend([{"name": k, "value": v} for k, v in env.items()])
            return workload
        if isinstance(workload, Iterable):
            return [BaseK8S.update_workload_metadata_env(workload=i, env=env) for i in workload]
        raise Exception("workload should be of type dict/list/generator, type: {}".format(type(workload)))

    @staticmethod
    def get_workload_metadata_name(workload):
        if not workload:
            return
        if isinstance(workload, dict):
            return workload['metadata']['name']
        if isinstance(workload, Iterable):
            return [BaseK8S.get_workload_metadata_name(workload=i) for i in workload]
        raise Exception("workload should be of type dict/list/generator, type: {}".format(type(workload)))

    @staticmethod
    def get_workload_kind(workload):
        if not workload:
            return
        return workload["kind"]

    @staticmethod
    def get_containers_names_from_workload_yaml(workload):
        if not workload:
            return
        assert isinstance(workload, dict), f"expecting type dict, not {type(workload)}"

        if "spec" in workload:
            if "containers" in workload["spec"]:
                return workload["spec"]["containers"]
            if "template" in workload["spec"]:
                if "spec" in workload["spec"]["template"] and "containers" in workload["spec"]["template"]["spec"]:
                    return workload["spec"]["template"]["spec"]["containers"]
            if "jobTemplate" in workload["spec"]:
                if "spec" in workload["spec"]["jobTemplate"] and "containers" in \
                        workload["spec"]["jobTemplate"]["spec"]:
                    return workload["spec"]["jobTemplate"]["spec"]["containers"]
        return []

    @staticmethod
    def get_none_abstract_workloads(workloads):
        """
        return the none abstract workloads from a list of workloads
        """
        if not isinstance(workloads, list):
            workloads = [workloads]
        wl = [i for i in workloads if BaseK8S.get_workload_kind(i) in KubectlWrapper.none_abstract_kinds]
        return wl[0] if len(wl) == 1 else wl

    def webserver_action(self, duration: int, connection_obj=None, **kwargs):
        if connection_obj:
            self.test_connection(duration=duration, connection_obj=connection_obj, **kwargs)
        else:
            TestUtil.sleep(duration, f"test duration, state: {kwargs.get('state')}", "info")

    def get_pod_name(self, namespace: str = "", subname: str = "", wlid: str = ""):
        """
        get pod/s name/s
        :return:
        """
        if wlid:
            namespace = Wlid.get_namespace(wlid=wlid)
            subname = Wlid.get_name(wlid=wlid)
        names = [pod.metadata.name for pod in self.get_running_pods(namespace=namespace, name=subname)]
        return names[0] if len(names) == 1 else names
    
    @staticmethod
    def get_image_ids(pod):
        return [(container_status.name, container_status.image_id)  for container_status in pod.status.container_statuses]
    
    @staticmethod
    def get_image_tags(pod):
        return [(container_spec.name, container_spec.image)  for container_spec in pod.spec.containers]

    def get_pod_data(self, get_data_of_pod_call_back, namespace: str = "", subname: str = "", wlid: str = ""):
        """
        get pod/s name/s
        :return:
        """
        if get_data_of_pod_call_back is None:
            raise Exception('empty call back get pod data function')
        if wlid:
            namespace = Wlid.get_namespace(wlid=wlid)
            subname = Wlid.get_name(wlid=wlid)
        image_ids = [get_data_of_pod_call_back(pod) for pod in self.get_running_pods(namespace=namespace, name=subname)]
        return image_ids[0] if len(image_ids) == 1 else image_ids

    @staticmethod
    def update_workload_metadata_by_wlid(workload: dict, wlid: str):
        workload['metadata']['labels']['cyberarmor'] = "attached"  # TODO - inject label only
        if not 'annotations' in workload['spec']['template']['metadata']:
            workload['spec']['template']['metadata']['annotations'] = {}
        workload['spec']['template']['metadata']['annotations']['wlid'] = wlid

    @staticmethod
    def calculate_wlid(cluster, namespace, workload):
        # Get Test WLID
        wlid = Wlid(cluster=cluster,
                    namespace=namespace,
                    kind=workload['kind'],
                    name=workload['metadata']['name'])
        return wlid.get_wlid()

    def get_workload(self, api_version, name, kind, namespace):
        dyn_client = self.kubernetes_obj.get_dynamic_client(api_version=api_version, kind=kind)
        return dyn_client.get(name=name, namespace=namespace)

    def get_first_owner_reference(self, workload, namespace):
        p_workload = self.get_workload(api_version=workload['apiVersion'] ,name=workload['metadata']['name'], kind=workload['kind'], namespace=namespace)
        if 'ownerReferences' not in p_workload['metadata'].keys():
            return p_workload
        return self.get_workload(name=p_workload['metadata']['name'], kind=p_workload['kind'], namespace=namespace)

    def get_owner_reference(self, pod, namespace):
        if len(pod.metadata.owner_references) == 0:
            return self.get_workload(api_version=pod.api_version ,name=pod.metadata.name, kind=pod.kind, namespace=namespace)
        return self.get_workload(api_version=pod.metadata.owner_references[0].api_version ,name=pod.metadata.owner_references[0].name, kind=pod.metadata.owner_references[0].kind, namespace=namespace)
        
    def get_api_version_from_instance_ID(self, instance_ID: str):
        return instance_ID.split("/")[0].split("-")[1]
    
    def get_namespace_from_instance_ID(self, instance_ID: str):
        namespace_list = instance_ID.split("-")
        return "-".join(namespace_list[:3])
    
    def get_kind_from_instance_ID(self, instance_ID: str):
        data = instance_ID.split("-")
        return "-".join(data[3:4]) 

    def get_workload_name_from_instance_ID(self, instance_ID: str):
        data = instance_ID.split("-")
        return "-".join(data[4:5])

    # apiVersion-<>/namespace-<>/kind-<>/name-<>/containerName-<>
    def calculate_instance_ID(self, pod, namespace):
        p_workload=self.get_owner_reference(pod, namespace)

        instanceIDs = list()
        for container in p_workload['spec']['template']['spec']['containers']:
            instanceIDs.append("apiVersion-" + p_workload["apiVersion"] + "/namespace-" + namespace + "/kind-" + p_workload['kind'] + "/name-" + p_workload['metadata']['name'] + "/containerName-" + container["name"])
        return instanceIDs
    
       
    @staticmethod
    def calculate_sid(secret, **kwargs):
        sid = SID(name=secret['metadata']['name'], **kwargs)
        return sid.get_sid()

    @staticmethod
    def restricted_k8s_name(kind: str):
        # TODO: find all kinds and change to global method
        restricted_kinds = ["namespace"]
        return kind.lower() in restricted_kinds

    def get_workload_active_pods_from_ca_control_panel(self, wlid, timeout=60):
        now = datetime.now()
        delta_t = 0
        list_of_pods = list()
        while delta_t < timeout:
            try:
                c_panel_info = self.backend.get_execution_info_from_wlid(wlid=wlid)
                list_of_pods = list()
                cp_containers = c_panel_info['containers']
                for container in cp_containers:
                    for i in cp_containers[container]['containerInstances']:
                        list_of_pods.append(i)

                return list_of_pods
            except Exception as e:
                Logger.logger.test("caught an exception: {0}".format(e))

            time.sleep(5)
            later = datetime.now()
            delta_t = (later - now).total_seconds()

        return list_of_pods

    def get_nodes(self):
        """
        :return: list of running pods
        """
        nodes = self.kubernetes_obj.client_CoreV1Api.list_node()
        return list(nodes.items)

    def get_all_pods(self):
        return self.kubernetes_obj.client_CoreV1Api.list_pod_for_all_namespaces()

    def get_pods(self, namespace: str = None, name: str = None, include_terminating: bool = True, wlid: str = None):
        """
        :return: list of running pods
        """
        if wlid:
            namespace = Wlid.get_namespace(wlid=wlid)
            name = Wlid.get_name(wlid=wlid)
        assert namespace is not None, "namespace is None"
        pods = self.kubernetes_obj.get_namespaced_workloads(kind='Pod', namespace=namespace)
        pods = list(filter(lambda x: name in x.metadata.name if isinstance(name, str) else list(
            filter(lambda n: n in x.metadata.name, name)), pods)) if name else pods
        return pods if include_terminating else list(filter(lambda x: x.status.phase != "Terminating", pods))

    def get_all_cluster_images(self, namespace: str = None, name: str = None, include_terminating: bool = True,
                               wlid: str = None):
        """
        :return: list of running pods
        """
        pods = self.get_all_pods()
        images = {}
        for pod in pods.items:
            if pod.status is None:
                continue
            if pod.status.container_statuses is None:
                continue
            for container_status in pod.status.container_statuses:
                if pod.metadata.namespace not in images.keys():
                    images[pod.metadata.namespace] = []
                images[pod.metadata.namespace].append(container_status.image)
        return images

    def get_expected_number_of_pods(self, namespace, workload: str = None, kinds: list = None):
        replicas = 0
        if kinds:
            if isinstance(kinds, str):
                kinds = [kinds]
        else:
            kinds = ['Deployment', "ReplicationController", 'StatefulSet', 'DaemonSet']
        nodes_num = len(self.get_nodes())
        for kind in kinds:
            w = self.kubernetes_obj.get_namespaced_workloads(kind=kind, namespace=namespace)
            for i in w:
                if workload and workload != i.metadata.name:
                    continue
                if kind == 'DaemonSet':
                    replicas += nodes_num
                else:
                    replicas += i.spec.replicas
        return replicas

    def get_running_pods(self, namespace, name: str = None):
        """
        :return: list of running pods with status true
        """
        return list(filter(lambda x: x.status.phase == "Running", self.get_pods(namespace=namespace, name=name)))

    def restart_pods(self, wlid=None, namespace: str = None, name: str = None):
        """
        restart pods of workload
        """
        if isinstance(wlid, list):
            for i in wlid:
                self.restart_pods(wlid=i)
        if wlid:
            name = Wlid.get_name(wlid=wlid)
            namespace = Wlid.get_namespace(wlid=wlid)

        for j in self.get_running_pods(namespace=namespace):
            if name in j.metadata.name:
                self.kubernetes_obj.delete_pod(namespace=namespace, name=j.metadata.name)

    @staticmethod
    def get_workload_name(workload: dict):
        if isinstance(workload, list):
            return [BaseK8S.get_workload_name(workload=i) for i in workload]
        return workload["metadata"]["name"]

    def get_number_of_replicas(self, workload):
        kind = workload['kind']
        number_of_replicas = 1
        if kind in ['Deployment', 'ReplicaSet', 'ReplicationController', 'StatefulSet']:
            if 'replicas' in workload['spec'].keys():
                number_of_replicas = int(workload['spec']['replicas'])
        elif kind in ['DaemonSet']:
            number_of_replicas = len(self.get_nodes())
        elif kind not in ['Job', 'CronJob', "Pod"]:
            raise Exception('unsupported kind: {}'.format(kind))
        return number_of_replicas

    def verify_all_pods_are_running(self, workload, namespace: str, timeout=180):
        """
        compare number of expected running pods with actually running pods
        """
        replicas = sum([self.get_number_of_replicas(i) for i in workload]) if isinstance(workload, list) else \
            self.get_number_of_replicas(workload)
        self.verify_running_pods(namespace=namespace, replicas=replicas, name=self.get_workload_name(workload),
                                 timeout=timeout)
        return replicas

    def verify_running_pods(self, namespace: str, replicas: int = None, name: str = None, timeout=180,
                            comp_operator=operator.eq):
        """
        compare number of expected running pods with actually running pods
        """
        if not replicas:
            replicas = self.get_expected_number_of_pods(namespace=namespace, workload=name)

        Logger.logger.debug("verifying {} pods are running in namespace {} {}".format(
            replicas, namespace, "with substring {}".format(name) if name else ""))
        delta_t = 0
        start = datetime.now()
        running_pods = {}
        total_pods = {}
        while delta_t <= timeout:
            running_pods = self.get_running_pods(namespace=namespace, name=name)
            # total_pods = self.get_pods(namespace=namespace, name=name, include_terminating=False)
            if comp_operator(len(running_pods), replicas):  # and len(running_pods) == len(total_pods):
                Logger.logger.info(f"all pods are running after {timeout - delta_t} seconds")
                return
            delta_t = (datetime.now() - start).total_seconds()
            time.sleep(10)
        Logger.logger.error("wrong number of pods are running, timeout: {} seconds. running_pods: {}".
                            format(timeout,
                                   KubectlWrapper.convert_workload_to_dict(running_pods, f_json=True, indent=2)))
        # KubectlWrapper.convert_workload_to_dict(total_pods, f_json=True, indent=2)))
        raise Exception("wrong number of pods are running after {} seconds. expected: {}, running: {}"
                        .format(timeout, replicas, len(running_pods)))  # , len(total_pods)))

    def is_namespace_running(self, namespace):
        for ns in self.kubernetes_obj.client_CoreV1Api.list_namespace().items:
            if namespace in ns.metadata.name:
                return True
        return False

    def verify_apply_complete(self, workload, namespace, wlid, timeout: int = 360):
        """
        verify the workload is running and reported in cpanel as running but unattached
        :param workload:
        :param namespace:
        :param wlid:
        :return:
        """
        replicas = self.verify_all_pods_are_running(workload, namespace, timeout=timeout)
        self.is_reported(wlid=wlid, timeout=timeout, replicas=replicas)

    def get_wlid(self, workload, **kwargs):
        if isinstance(workload, list):
            wlids: list = [self.get_wlid(workload=i, **kwargs) for i in workload]
            return wlids[0] if len(wlids) == 1 else wlids
        wlid = self.calculate_wlid(workload=workload, **kwargs)
        self.wlids.append(wlid)
        set(self.wlids)
        return wlid

    def get_instance_IDs(self, pods, namespace, **kwargs):
        instanceIDs = []
        for pod in pods:
            instanceIDs_for_pod = self.calculate_instance_ID(pod=pod, namespace=namespace)
            instanceIDs.append(instanceIDs_for_pod)
        return instanceIDs

    def create_namespace(self, yaml_file=statics.BASIC_NAMESPACE_YAML, path=statics.DEFAULT_NAMESPACE_PATH,
                         unique_name=True, **kwargs):
        namespace_obj = self.apply_yaml_file(
            yaml_file=yaml_file, path=path, namespace='', unique_name=unique_name, **kwargs)
        self.namespaces.append(self.get_workload_metadata_name(namespace_obj))
        TestUtil.sleep(t=10, m="loading namespace")
        return self.get_workload_metadata_name(namespace_obj)

    def display_kube_system_logs(self):
        self.display_apiserver_logs()
        self.display_etcd_logs()

    def get_pod_logs(self, namespace: str, pod_name: str, containers, previous: bool):
        logs = ""
        if not containers:
            return logs
        if isinstance(containers, str):
            containers = [containers]
        for container in containers:
            logs = "\n{sep} start {n} logs {sep}\n".format(sep="-" * 80, n=container)
            for i in self.kubernetes_obj.get_pod_logs(pod_name=pod_name, namespace=namespace,
                                                      container=container, previous=previous).split('\n'):
                logs += i + "\n"
            logs += "\n{sep} end {n} logs {sep}\n".format(sep="-" * 80, n=container)
        return logs

    def find_string_in_log(self, namespace: str, pod_name: str, containers, previous: bool, string_in_log: str):
        logs = ""
        if not containers:
            return logs
        if isinstance(containers, str):
            containers = [containers]
        for container in containers:
            logs = "\n{sep} start {n} logs {sep}\n".format(sep="-" * 80, n=container)
            for i in self.kubernetes_obj.get_pod_logs(pod_name=pod_name, namespace=namespace,
                                                      container=container, previous=previous).split('\n'):
                logs += i + "\n"
            logs += "\n{sep} end {n} logs {sep}\n".format(sep="-" * 80, n=container)
        assert string_in_log in logs

    def update_containers_list(self, namespace: str):
        self.containers.extend(self.get_running_containers(namespace=namespace))
        self.containers = list(set(self.containers))

    def get_workload_containers(self, namespace: str, workload_name: str):
        """
        Return list of workloads running containers names
        :return: ["container name"]
        """
        if self.docker.docker_client is None:
            return []
        containers = [i for i in self.docker.docker_client.containers.list()]
        return [i.name for i in containers if
                f"_{workload_name}-" in i.name and f"_{namespace}_" in i.name and "_POD_" not in i.name]

    def get_running_containers(self, namespace: str):
        if self.docker.docker_client is None:
            return []
        pods = self.get_running_pods(namespace=namespace)
        containers = [i for i in self.docker.docker_client.containers.list()]
        return [j for i in pods for j in containers if i.metadata.name in j.name and "_POD_" not in j.name]

    # def open_local_port_forward_to_wlid(self,wlid):
    #     pod_name = self.get_pod_name(wlid=wlid)
    #     assert pod_name != "", f"pod name for wlid '{wlid}' is empty"
    #     self.kubernetes_obj.port

    def get_pod_ip(self, wlid: str):
        ips = [pod.status.pod_ip for pod in self.get_running_pods(namespace=Wlid.get_namespace(wlid=wlid)) if
               Wlid.get_name(wlid=wlid) in pod.metadata.name]
        return ips[0] if len(ips) > 0 else ""

    def get_service_ip(self, namespace: str, service: str):
        services = self.kubernetes_obj.get_namespaced_workloads(kind="Service", namespace=namespace)
        tmp_service = [i for i in services if i.metadata.name == service]
        if len(tmp_service) == 0:
            raise Exception(f"service {service} not found in namespace {namespace}")
        return tmp_service[0].spec.cluster_ip

    def get_image_tag(self, wlid: str):
        containers = [container for pod in self.get_running_pods(namespace=Wlid.get_namespace(wlid=wlid)) for container
                      in pod.spec.containers if Wlid.get_name(wlid=wlid) in pod.metadata.name]
        image_tags = [container.image.split(':')[-1] for container in containers]
        return image_tags[0]

    def exec_pod(self, wlid: str, command: str, splitCmd=True):
        pods = self.get_pod_name(wlid=wlid)
        for pod_name in [pods] if isinstance(pods, str) else pods:
            self.kubernetes_obj.exec_pod(namespace=Wlid.get_namespace(wlid), name=pod_name, command=command,
                                         splitCmd=splitCmd)
            # self.kubernetes_obj.exec_pod(namespace=Wlid.get_namespace(wlid), name=pod_name,
            #                              command=command if isinstance(command, list) else command.split(" "))

    def get_posture_clusters_overtime(self, framework_name: str, cluster_name):
        c_panel_info, t = self.wait_for_report(report_type=self.backend.get_posture_clusters_overtime,
                                               framework_name=framework_name, cluster_name=cluster_name)
        return c_panel_info

    def test_connection(self, connection_obj, wlids: list, duration: int = 60, state: str = Statistics.testing_state):
        if not connection_obj:
            return
        if isinstance(wlids, str):
            wlids = [wlids]

        # setup ip by workload name
        if connection_obj.workload_name:
            wlid = TestUtil.get_wlid_from_workload_name(wlids=wlids, workload_name=connection_obj.workload_name)
            connection_obj.ip = self.get_pod_ip(wlid=wlid)

        # setup ip by workload name
        if connection_obj.service_name:
            connection_obj.ip = self.get_service_ip(
                namespace=Wlid.get_namespace(wlid=wlids[0]), service=connection_obj.service_name)
        # final url
        Logger.logger.info(f"running wget {connection_obj.get_url()} repeatedly for {duration} seconds")

        start = time.time()

        thread, thread_signal = self.start_workloads_statistics(self.get_dict_workloads_and_containers(wlids=wlids),
                                                                state=state)
        while True:
            if not TestUtil.simple_get_request(url=connection_obj.get_url(), verify=connection_obj.verify):
                self.end_workloads_statistics(thread, thread_signal=thread_signal)
                raise Exception(f"cant connect ingress server: {connection_obj.get_url()}")
            if time.time() - start > duration:
                self.end_workloads_statistics(thread, thread_signal=thread_signal)
                break

    def get_dict_workloads_and_containers(self, wlids: list):
        """
        :param wlids: single or list of wlids
        :return: {"workload name": ["container name"]}
        """
        if isinstance(wlids, str):
            wlids = [wlids]
        return {Wlid.get_name(wlid): self.get_workload_containers(
            namespace=Wlid.get_namespace(wlid), workload_name=Wlid.get_name(wlid)) for wlid in wlids}

    def display_etcd_logs(self, level=Logger.logger.debug):
        try:
            level(self.get_pod_logs(namespace=statics.K8S_NAMESPACE_NAME,
                                    pod_name=self.get_pod_name(namespace=statics.K8S_NAMESPACE_NAME,
                                                               subname=statics.K8S_ETCD_POD_NAME),
                                    containers=statics.K8S_ETCD_CONTAINER_NAME, previous=False))
            level(self.get_pod_logs(namespace=statics.K8S_NAMESPACE_NAME,
                                    pod_name=self.get_pod_name(namespace=statics.K8S_NAMESPACE_NAME,
                                                               subname=statics.K8S_ETCD_POD_NAME),
                                    containers=statics.K8S_ETCD_CONTAINER_NAME, previous=True))
        except Exception as e:
            Logger.logger.error("cant print apiserver logs. reason: {}".format(e))

    def display_apiserver_logs(self, level=Logger.logger.debug):
        try:
            level(self.get_pod_logs(namespace=statics.K8S_NAMESPACE_NAME,
                                    pod_name=self.get_pod_name(namespace=statics.K8S_NAMESPACE_NAME,
                                                               subname=statics.K8S_API_SERVER_POD_NAME),
                                    containers=statics.K8S_API_SERVER_CONTAINER_NAME, previous=False))
        except Exception as e:
            Logger.logger.error("cant print apiserver logs. reason: {}".format(e))
        try:
            level(self.get_pod_logs(namespace=statics.K8S_NAMESPACE_NAME,
                                    pod_name=self.get_pod_name(namespace=statics.K8S_NAMESPACE_NAME,
                                                               subname=statics.K8S_API_SERVER_POD_NAME),
                                    containers=statics.K8S_API_SERVER_CONTAINER_NAME, previous=True))
        except:
            pass

    def get_errors_in_armo_system_logs(self):
        error_log = ''
        pods = self.get_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        for pod in pods:
            error_log += self.get_pod_error_logs(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                 pod_name=pod.metadata.name,
                                                 containers=list(map(lambda container: container.name,
                                                                     pod.spec.containers)),
                                                 previous=False)
        return error_log

    def get_pod_error_logs(self, namespace: str, pod_name: str, containers, previous: bool):
        error_logs = ''
        logs = self.get_pod_logs(namespace=namespace, pod_name=pod_name,
                                 containers=containers, previous=previous).split('\n')
        for log in logs:
            if 'error' in log or 'Error' in log:
                error_logs += log + '\n'

        return str(containers) + '\n' + error_logs + '\n' if error_logs else error_logs

    #
    # def start_safe_mode_logs(self):
    #     notification_server_ip = self.get_service_ip(statics.CA_NAMESPACE_NAME,
    #                                                  statics.CA_NOTIFICATION_SERVER_DEPLOYMENT_NAME)
    #     notification_server_port = 8001
    #     notification_server_path = "v1/waitfornotification?clusterComponent=Logger"
    #     notification_server_host = f"ws://{notification_server_ip}:{notification_server_port}/{notification_server_path}"
    #
    #     thread = Thread(target=self.collect_safe_mode_logs, kwargs={"host": notification_server_host})
    #     thread.start()

    def collect_safe_mode_logs(self, host: str):
        while self.websocket_wrapper.reconnect():
            try:
                self.websocket_wrapper.connect(host=host)
                while self.websocket_wrapper.is_connected():
                    notification = self.websocket_wrapper.recv()
                    log = json.loads(notification)['notification']
                    Logger.logger.info(f"safe mode log received: {log}")
                    self.safe_mode_logs.append(log)
            except KeyboardInterrupt:
                break
            except Exception as e:
                if "Expecting value: line 1 column 1 (char 0)" in f'{e}':  # connection closed
                    break
                Logger.logger.warning(e)
                time.sleep(1)
        Logger.logger.info("exiting websocket thread")
    
    def get_SBOM_from_storage(self, SBOMKeys):
        SBOMs = []
        if isinstance(SBOMKeys, str):
            SBOM_data = self.kubernetes_obj.client_CustomObjectsApi.get_namespaced_custom_object(
                group=statics.STORAGE_AGGREGATED_API_GROUP,
                version=statics.STORAGE_AGGREGATED_API_VERSION,
                name=SBOMKeys,
                namespace=statics.STORAGE_AGGREGATED_API_NAMESPACE,
                plural=statics.STORAGE_SBOM_PLURAL,
            )
            SBOMs.append((SBOMKeys, SBOM_data))
        elif isinstance(SBOMKeys, list):
            for key in SBOMKeys:
              SBOM_data = self.kubernetes_obj.client_CustomObjectsApi.get_namespaced_custom_object(
                group=statics.STORAGE_AGGREGATED_API_GROUP,
                version=statics.STORAGE_AGGREGATED_API_VERSION,
                name=key,
                namespace=statics.STORAGE_AGGREGATED_API_NAMESPACE,
                plural=statics.STORAGE_SBOM_PLURAL,
            )
              SBOMs.append((key, SBOM_data))
        return SBOMs

    def get_CVEs_from_storage(self, CVEsKeys):
        CVEs = []
        if isinstance(CVEsKeys, str):
            CVE_data = self.kubernetes_obj.client_CustomObjectsApi.get_namespaced_custom_object(
                group=statics.STORAGE_AGGREGATED_API_GROUP,
                version=statics.STORAGE_AGGREGATED_API_VERSION,
                name=CVEsKeys,
                namespace=statics.STORAGE_AGGREGATED_API_NAMESPACE,
                plural=statics.STORAGE_CVES_PLURAL,
            )
            CVEs.append((CVEsKeys, CVE_data))
        elif isinstance(CVEsKeys, list):
            for key in CVEsKeys:
                CVE_data = self.kubernetes_obj.client_CustomObjectsApi.get_namespaced_custom_object(
                group=statics.STORAGE_AGGREGATED_API_GROUP,
                version=statics.STORAGE_AGGREGATED_API_VERSION,
                name=key,
                namespace=statics.STORAGE_AGGREGATED_API_NAMESPACE,
                plural=statics.STORAGE_CVES_PLURAL,
            )
                CVEs.append((key, CVE_data))
        return CVEs

    def get_filtered_SBOM_from_storage(self, filteredSBOMKeys):
        filteredSBOMs = []
        if any(isinstance(i, list) for i in filteredSBOMKeys):
            for keys in filteredSBOMKeys:
                for key in keys:
                    filtered_SBOM_data = self.kubernetes_obj.client_CustomObjectsApi.get_namespaced_custom_object(
                        group=statics.STORAGE_AGGREGATED_API_GROUP,
                        version=statics.STORAGE_AGGREGATED_API_VERSION,
                        name=key,
                        namespace=statics.STORAGE_AGGREGATED_API_NAMESPACE,
                        plural=statics.STORAGE_FILTERED_SBOM_PLURAL,
                    )
                    filteredSBOMs.append((key, filtered_SBOM_data))
        elif isinstance(filteredSBOMKeys, list):
            for key in filteredSBOMKeys:
              filtered_SBOM_data = self.kubernetes_obj.client_CustomObjectsApi.get_namespaced_custom_object(
                group=statics.STORAGE_AGGREGATED_API_GROUP,
                version=statics.STORAGE_AGGREGATED_API_VERSION,
                name=key,
                namespace=statics.STORAGE_AGGREGATED_API_NAMESPACE,
                plural=statics.STORAGE_FILTERED_SBOM_PLURAL,
            )
              filteredSBOMs.append((key, filtered_SBOM_data))
        return filteredSBOMs

    def get_filtered_CVEs_from_storage(self, filteredCVEsKEys):
        filteredCVEs = []
        if any(isinstance(i, list) for i in filteredCVEsKEys):
            for keys in filteredCVEsKEys:
                for key in keys:
                    cve_data = self.kubernetes_obj.client_CustomObjectsApi.get_namespaced_custom_object(
                        group=statics.STORAGE_AGGREGATED_API_GROUP,
                        version=statics.STORAGE_AGGREGATED_API_VERSION,
                        name=key,
                        namespace=statics.STORAGE_AGGREGATED_API_NAMESPACE,
                        plural=statics.STORAGE_CVES_PLURAL,
                    )
                    filteredCVEs.append((key, cve_data))
        elif isinstance(filteredCVEsKEys, list):
            for key in filteredCVEsKEys:
              cve_data = self.kubernetes_obj.client_CustomObjectsApi.get_namespaced_custom_object(
                group=statics.STORAGE_AGGREGATED_API_GROUP,
                version=statics.STORAGE_AGGREGATED_API_VERSION,
                name=key,
                namespace=statics.STORAGE_AGGREGATED_API_NAMESPACE,
                plural=statics.STORAGE_CVES_PLURAL,
            )
              filteredCVEs.append((key, cve_data))
        return filteredCVEs
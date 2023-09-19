# encoding: utf-8
import datetime
from http.client import FOUND
import time
from crypt import methods

from kubernetes.client import api_client
from kubernetes import client, config, dynamic
from kubernetes.client.exceptions import ApiException
import requests
from systest_utils import Logger, TestUtil, statics
import subprocess

class KubectlWrapper(object):
    """ CaKube provides kubernetes wrapper and helper functions"""

    all_kinds = ["ComponentStatus", "ConfigMap", "ControllerRevision", "CronJob",
                 "CustomResourceDefinition", "DaemonSet", "Deployment", "Endpoints", "Event", "HorizontalPodAutoscaler",
                 "Ingress", "Job", "Lease", "LimitRange", "LocalSubjectAccessReview", "MutatingWebhookConfiguration",
                 "Namespace", "NetworkPolicy", "Node", "PersistentVolume", "PersistentVolumeClaim", "Pod",
                 "PodDisruptionBudget", "PodSecurityPolicy", "PodTemplate", "PriorityClass", "ReplicaSet",
                 "ReplicationController", "ResourceQuota", "Role", "RoleBinding", "Secret", "SelfSubjectAccessReview",
                 "SelfSubjectRulesReview", "Service", "ServiceAccount", "StatefulSet", "StorageClass",
                 "SubjectAccessReview", "TokenReview", "ValidatingWebhookConfiguration", "VolumeAttachment"]
    none_abstract_kinds: list = ["CronJob", "DaemonSet", "Deployment", "Job", "Pod", "PodTemplate", "ReplicaSet",
                                 "StatefulSet"]

    def __init__(self, cluster_name='', client_configuration_file=None):

        self.cluster_name = cluster_name
        self.client_configuration_file = client_configuration_file
        self.context = None
        self.client_CoreV1Api = None
        self.client_AppsV1Api = None
        self.client_AppsV1beta1Api = None
        self.client_RbacAuthorizationV1Api = None
        self.client_NetworkingV1Api = None
        self.client_ApiextensionsV1Api = None
        self.client = None

        self.kubernetes_login()

    def run(self, method, retry=0, _request_timeout=360, **kwargs):
        try:
            status = method(**kwargs)
            return status
        except ApiException as e:
            if retry < 3 and (
                    "failed calling webhook" in e.body or "timed out" in e.body or "Connection refused" in e.body
                    or "request did not complete" in e.body or "transport is closing" in e.body):
                time.sleep(3)
                return self.run(method=method, retry=retry + 1, _request_timeout=_request_timeout, **kwargs)
            if "not found" in e.body or "already exists" in e.body:
                Logger.logger.warning(f"k8s-api response: {e.body}, returning empty object")
                return {}
            raise Exception(f"Error: {e.body}, retries: {retry}")

    @staticmethod
    def get_current_context():
        _, current_context = config.list_kube_config_contexts()
        assert current_context, "Fail To get current-context from kube_config"
        return current_context

    def get_cluster_name(self):
        current_context = self.get_current_context()
        assert 'name' in current_context, "Fail To get Cluster-Name from kube_config"
        return current_context['name']

    def get_info_version(self):
        contexts, active_context = config.list_kube_config_contexts()
        api = client.VersionApi(api_client=config.new_client_from_config(context=active_context['name']))
        method = api.get_code
        status = self.run(method=method)
        return status

    def kubernetes_login(self):
        contexts, active_context = config.list_kube_config_contexts()
        assert contexts, "Fail To Login Cluster {0}".format(self.cluster_name)

        if active_context is not None and 'name' in active_context:
            self.context = active_context
            self.client = client
            self.client_CoreV1Api = client.CoreV1Api(api_client=config.new_client_from_config(
                context=active_context['name']))
            self.client_AppsV1Api = client.AppsV1Api(api_client=config.new_client_from_config(
                context=active_context['name']))
            self.client_RbacAuthorizationV1Api = client.RbacAuthorizationV1Api(
                api_client=config.new_client_from_config(context=active_context['name']))
            self.client_NetworkingV1Api = client.NetworkingV1Api(api_client=config.new_client_from_config(
                context=active_context['name']))
            self.client_AppsV1beta1Api = \
                client.AppsV1beta1Api(api_client=config.new_client_from_config(
                    context=active_context['name']))
            self.client_ApiextensionsV1Api = client.ApiextensionsV1Api(api_client=config.new_client_from_config(
                context=active_context['name']))
            self.client_BatchV1beta1Api = client.BatchV1beta1Api(api_client=config.new_client_from_config(
                context=active_context['name']))
            self.client_CustomObjectsApi = client.CustomObjectsApi(api_client=config.new_client_from_config(context=active_context['name']))

            self.client_dynamic = dynamic.DynamicClient(api_client.ApiClient(configuration=config.load_kube_config())
    )    
            # self.client_ = client.CustomObjectsApi(api_client=config.new_client_from_config(context=active_context['name']))
            

        else:
            for context in contexts:
                if self.cluster_name in context['name']:
                    self.context = context
                    self.client = client
                    self.client_CoreV1Api = client.CoreV1Api(api_client=config.new_client_from_config(
                        context=context['name']))
                    self.client_AppsV1Api = client.AppsV1Api(api_client=config.new_client_from_config(
                        context=active_context['name']))
                    break

        # dummy call to check connection is up
        try:
            Logger.logger.debug("confirming kubernetes cluster is running")
            self.run(method=self.get_namespaced_pods_information, namespace="kube-system")
        except:
            raise Exception("system test framework cant connect to kubernetes cluster")

    def get_workload_api(self, api_ver='apps/v1'):
        if api_ver in 'apps/v1':
            method = client.AppsV1Api
        elif api_ver in 'apps/v1beta1':
            method = client.AppsV1beta1Api
        elif api_ver in 'extensions/v1beta1':
            method = client.ExtensionsV1beta1Api
        else:
            raise Exception('Unsupported ApiVersion  = %s' % api_ver)
        return self.run(method=method, api_client=config.new_client_from_config(context=self.context['name']))

    def get_pod_full_name(self, namespace, partial_name):
        pods = self.client_CoreV1Api.list_namespaced_pod(namespace=namespace)
        for pod in pods.items:
            if partial_name in pod.metadata.name:
                return pod.metadata.name

    def get_kubescape_pod(self, namespace):
        pods = self.client_CoreV1Api.list_namespaced_pod(namespace=namespace)
        for pod in pods.items:
            if 'app' in pod.metadata.labels and pod.metadata.labels['app'] == 'kubescape':
                return pod.metadata.name

    def delete_namespace(self, namespace=str()):
        try:
            return self.client_CoreV1Api.delete_namespace(name=namespace)
        except requests.exceptions.SSLError as ex:
            self.kubernetes_login()
            return self.client_CoreV1Api.delete_namespace(name=namespace)
        except Exception as ex:
            raise ex

    def delete_config_map(self, namespace=str(), name=str()):
        try:
            return self.client_CoreV1Api.delete_namespaced_config_map(namespace=namespace, name=name)
        except requests.exceptions.SSLError as ex:
            self.kubernetes_login()
            return self.client_CoreV1Api.delete_namespaced_config_map(namespace=namespace, name=name)
        except Exception as ex:
            raise ex

    def delete_secret(self, namespace=str(), name=str()):
        try:
            return self.client_CoreV1Api.delete_namespaced_secret(namespace=namespace, name=name)
        except requests.exceptions.SSLError as ex:
            self.kubernetes_login()
            return self.client_CoreV1Api.delete_namespaced_secret(namespace=namespace, name=name)
        except Exception as ex:
            raise ex

    def get_pod_events(self, podname: str, namespace: str = "default"):
        events = self.client_CoreV1Api.list_namespaced_event(namespace).items
        pod_events = []
        for event in events:
            if event.involved_object.name == podname:
                pod_events.append(event)

        return pod_events

    def get_namespaced_workloads(self, kind='Deployment', namespace='Default'):
        if 'Deployment' in kind:
            method = self.client_AppsV1Api.list_namespaced_deployment
        elif "ReplicationController" in kind:
            method = self.client_CoreV1Api.list_namespaced_replication_controller
        elif 'ReplicaSet' in kind:
            method = self.client_AppsV1Api.list_namespaced_replica_set
        elif 'StatefulSet' in kind:
            method = self.client_AppsV1Api.list_namespaced_stateful_set
        elif 'DaemonSet' in kind:
            method = self.client_AppsV1Api.list_namespaced_daemon_set
        elif 'Pod' in kind:
            method = self.client_CoreV1Api.list_namespaced_pod
        elif 'Secret' in kind:

            method = self.client_CoreV1Api.list_namespaced_secret
        elif 'Service' == kind:
            method = self.client_CoreV1Api.list_namespaced_service
        else:
            raise Exception('Unsupported Kind ,{0}, deploy application failed'.format(kind))
        status = self.run(method=method, namespace=namespace)
        return status.items

    # apply kubernetes command
    def apply_workload(self, namespace='default', application=None, timeout=360):
        # 1. get application kind - to select proper api
        # 2. get list of applications in name space
        # 3. check if application exists
        # 4. deploy application

        kind = application['kind']
        if 'Deployment' == kind:
            method = self.client_AppsV1Api.create_namespaced_deployment
        elif 'Service' == kind:
            method = self.client_CoreV1Api.create_namespaced_service
        elif 'ServiceAccount' == kind:
            method = self.client_CoreV1Api.create_namespaced_service_account
        elif 'ClusterRole' == kind:
            method = self.client_RbacAuthorizationV1Api.create_cluster_role
            status = self.run(method=method, body=application, _request_timeout=timeout)
            return status
        elif 'ClusterRoleBinding' == kind:
            method = self.client_RbacAuthorizationV1Api.create_cluster_role_binding
            status = self.run(method=method, body=application, _request_timeout=timeout)
            return status
        elif "CustomResourceDefinition" == kind:
            method = self.client_ApiextensionsV1Api.create_custom_resource_definition
            status = self.run(method=method, body=application, _request_timeout=timeout)
            # self.custom_resource.append(application['spec']['names']['kind'])
            return status
        elif 'Role' == kind:
            method = self.client_RbacAuthorizationV1Api.create_namespaced_role
        elif 'RoleBinding' == kind:
            method = self.client_RbacAuthorizationV1Api.create_namespaced_role_binding
        elif 'ReplicaSet' == kind:
            method = self.client_AppsV1Api.create_namespaced_replica_set
        elif 'StatefulSet' == kind:
            method = self.client_AppsV1Api.create_namespaced_stateful_set
        elif 'DaemonSet' == kind:
            method = self.client_AppsV1Api.create_namespaced_daemon_set
        elif 'Secret' == kind:
            method = self.client_CoreV1Api.create_namespaced_secret
        elif 'ConfigMap' == kind:
            method = self.client_CoreV1Api.create_namespaced_config_map
        elif 'NetworkPolicy' == kind:
            method = self.client_NetworkingV1Api.create_namespaced_network_policy
        elif 'Pod' == kind:
            try:  # when creating a single pod, we must check the failure- if its k8s or our webhook
                status = self.run(method=self.client_CoreV1Api.create_namespaced_pod, namespace=namespace,
                                  body=application, _request_timeout=timeout)
            except ApiException as e:
                if "webhook is processing the workload" in e.body:
                    return e
                raise Exception(e)
            return status
        elif 'Namespace' == kind:
            return self.run(method=self.client_CoreV1Api.create_namespace, body=application, _request_timeout=timeout)
        else:
            raise Exception('Unsupported Kind ,{0}, deploy application failed'.format(kind))
        status = self.run(method=method, namespace=namespace, body=application, _request_timeout=timeout)
        return status

    # apply kubernetes command
    def patch_workload(self, namespace: str, application: dict, kind: str, name: str = None):

        if 'Namespace' in kind:
            return self.run(method=self.client_CoreV1Api.patch_namespace, name=name, body=application)
        elif 'Deployment' in kind:
            method = self.client_AppsV1Api.patch_namespaced_deployment
        elif 'Service' in kind:
            method = self.client_CoreV1Api.patch_namespaced_service
        # elif 'ReplicaSet' in kind:
        #     status = self.client_AppsV1Api.create_namespaced_replica_set(namespace=namespace, body=application)
        # elif 'StatefulSet' in kind:
        #     status = self.client_AppsV1Api.patch_namespaced_stateful_set(namespace=namespace, body=application)
        # elif 'DaemonSet' in kind:
        #     status = self.client_AppsV1Api.patch_namespaced_daemon_set(namespace=namespace, body=application)
        # elif 'Secret' in kind:
        #     status = self.client_CoreV1Api.create_namespaced_secret(namespace=namespace, body=application)
        else:
            raise Exception('Unsupported Kind ,{0}, patching workload failed'.format(kind))
        return self.run(method=method, namespace=namespace, name=name, body=application)

        # apply kubernetes command

    @staticmethod
    def exec_pod(namespace: str, name: str, command: str, splitCmd=True):
        if splitCmd:
            return TestUtil.run_command(
                'kubectl exec -it {pod} -n {ns} -- {command}'.format(ns=namespace, pod=name, command=command).split(
                    " "),
                timeout=None)
        else:
            cmd_list = 'kubectl exec {pod} -n {ns} -- '.format(ns=namespace, pod=name).split(" ")

            quotePos = command.find('"')
            if quotePos > -1:
                splitpart1 = command[:quotePos].split(" ")
                cmd_list = cmd_list + splitpart1
                qpos2 = command.rfind('"')
                cmd_list.append(command[quotePos + 1:qpos2])

                cmd_list.remove("")
            else:
                cmd_list = cmd_list + command.split(" ")
            cmd_list.remove("")
            res = TestUtil.run_command(cmd_list, timeout=None)
            Logger.logger.info(res)
            return res

        # return self.client_CoreV1Api.connect_get_namespaced_pod_exec(
        #     name=name, namespace=namespace, command=command, async_req=True, stderr=True, stdin=False, stdout=True,
        #     tty=False)

    @staticmethod
    def update_env(namespace: str, name: str, envs: dict, kind: str = "deployment"):
        envs = " ".join(['{}={}'.format(i, j) for i, j in envs.items()])
        return TestUtil.run_command(
            'kubectl set env {kind} {name} -n {ns} {envs}'.format(ns=namespace, name=name, envs=envs, kind=kind).split(
                " "), timeout=None)

    @staticmethod
    def delete_env(namespace: str, name: str, env: str, kind: str = "deployments"):
        return TestUtil.run_command(
            'kubectl set env {kind} {name} -n {ns} {env}-'.format(ns=namespace, name=name, env=env, kind=kind).split(
                " "), timeout=None)

    @staticmethod
    def copy_file_to_pod(namespace: str, pod_name: str, src_file_path: str, dest_file_path: str):
        return TestUtil.run_command(
            'kubectl -n {ns} cp {src_file_path} {pod_name}:{dest_file_path}'.format(ns=namespace,
                                                                                    src_file_path=src_file_path,
                                                                                    pod_name=pod_name,
                                                                                    dest_file_path=dest_file_path).split(
                " "), timeout=None)

    def delete_workload(self, namespace, application):
        # 1. get application kind - to select proper api
        # 2. get list of applications in name space
        # 3. check if application exists
        # 4. deploy application

        kind = application['kind'] if isinstance(application, dict) else application.kind

        if 'Deployment' == kind:
            status = self.client_AppsV1Api.delete_namespaced_deployment(namespace=namespace, name=get_name(application))
        elif 'ReplicaSet' == kind:
            status = self.client_AppsV1Api.delete_namespaced_replica_set(namespace=namespace, name=get_name(application))
        elif 'StatefulSet' == kind:
            status = self.client_AppsV1Api.delete_namespaced_stateful_set(namespace=namespace, name=get_name(application))
        elif "ClusterRole" == kind:
            status = self.client_RbacAuthorizationV1Api.delete_cluster_role(name=get_name(application))
        elif "ClusterRoleBinding" == kind:
            status = self.client_RbacAuthorizationV1Api.delete_cluster_role_binding(name=get_name(application))
        elif "CustomResourceDefinition" == kind:
            status = self.client_ApiextensionsV1Api.delete_custom_resource_definition(name=application["metadata"]["name"])
        elif 'DaemonSet' == kind:
            status = self.client_AppsV1Api.delete_namespaced_daemon_set(namespace=namespace, name=get_name(application))
        elif 'Pod' == kind:
            status = self.client_CoreV1Api.delete_namespaced_pod(namespace=namespace, name=get_name(application))
        elif 'Namespace' == kind:
            status = self.client_CoreV1Api.delete_namespace(name=namespace)
        elif 'ConfigMap' == kind:
            status = self.client_CoreV1Api.delete_namespaced_config_map(namespace=namespace,
                                                                        _request_timeout=None)
        else:
            raise Exception('Unsupported Kind ,{0}, deploy application failed'.format(kind))
        return status

    def delete_pod(self, namespace: str, name: str):
        return self.run(method=self.client_CoreV1Api.delete_namespaced_pod, name=name, namespace=namespace)

    def list_of_replica_sets_in_namespace(self, namespace='default'):
        status = self.run(method=self.client_AppsV1Api.list_namespaced_replica_set, namespace=namespace)
        return status

    def get_config_map(self, namespace, name):
        status = self.run(method=self.client_CoreV1Api.read_namespaced_config_map, name=name, namespace=namespace)
        return status


#{"source":5000,"exposed":5000}
    def portforward(self, cluster_name, namespace, pod_name, port,ip='0.0.0.0'):

        # # #VERY FUGLY
        # cmd="eval $(minikube -p {} docker-env)".format(cluster_name)
        # subprocess.Popen(cmd, shell=True)
        if isinstance(port,dict):
            cmd=f"kubectl -n {namespace} port-forward {pod_name} {port['exposed']}:{port['source']} --address {ip}" #--address 0.0.0.0
        else:
            cmd="kubectl -n {} port-forward {} 33334:{}".format(namespace, pod_name, port)
        Logger.logger.info(f'k8s portforward cmd: {cmd}')
        c = subprocess.Popen(cmd, shell=True)
        return c
    
    def get_ks_cronjob_schedule(self, namespace):
        cronjobs = self.run(method=self.client_BatchV1beta1Api.list_namespaced_cron_job, namespace=namespace)
        for cj in cronjobs.items:
            if "ks-scheduled-scan" in cj.metadata.name:
                return cj.spec._schedule

    def get_ks_cronjob_name(self, namespace):
        cronjobs_name=[]
        cronjobs = self.run(method=self.client_BatchV1beta1Api.list_namespaced_cron_job, namespace=namespace)
        for cj in cronjobs.items:
            if "ks-scheduled-scan" in cj.metadata.name:
                cronjobs_name.append(cj.metadata.name)
        return cronjobs_name

    def is_ks_cronjob_created(self, framework_name, namespace=statics.CA_NAMESPACE_FROM_HELM_NAME):
        cronjobs = self.run(method=self.client_BatchV1beta1Api.list_namespaced_cron_job, namespace=namespace)
        for cj in cronjobs.items:
            if "ks-scheduled-scan-{}".format(framework_name.lower()) in cj.metadata.name:
                return True 
        return False

    def get_vuln_scan_cronjob(self, namespace=statics.CA_NAMESPACE_FROM_HELM_NAME):
        cronjobs = self.run(method=self.client_BatchV1beta1Api.list_namespaced_cron_job, namespace=namespace)
        result = []
        for cj in cronjobs.items:
            if statics.CA_VULN_SCAN_CRONJOB_ARMO_TIER_LABEL_FIELD in cj.metadata.labels.keys() and \
                    cj.metadata.labels[statics.CA_VULN_SCAN_CRONJOB_ARMO_TIER_LABEL_FIELD] == \
                    statics.CA_VULN_SCAN_CRONJOB_ARMO_TIER_LABEL_NAME:
                result.append(cj)
        return result

    def get_registry_scan_cronjob(self, namespace=statics.CA_NAMESPACE_FROM_HELM_NAME):
        cronjobs = self.run(method=self.client_BatchV1beta1Api.list_namespaced_cron_job, namespace=namespace)
        result = []
        for cj in cronjobs.items:
            if statics.CA_VULN_SCAN_CRONJOB_ARMO_TIER_LABEL_FIELD in cj.metadata.labels.keys() and \
                    cj.metadata.labels[statics.CA_VULN_SCAN_CRONJOB_ARMO_TIER_LABEL_FIELD] == \
                    statics.CA_REGISTRY_SCAN_CRONJOB_ARMO_TIER_LABEL_NAME:
                result.append(cj)
        return result

    def get_namespaced_pods_information(self, namespace='default'):
        return self.run(method=self.client_CoreV1Api.list_namespaced_pod, namespace=namespace).items

    def cleanup(self, namespace):
        self.delete_namespace(namespace=namespace)

    def get_running_service_info(self, namespace):
        return self.run(method=self.client_CoreV1Api.list_namespaced_service, namespace=namespace)

    def get_pod_logs(self, pod_name='', container='', namespace='default', previous=False):
        api_response = self.client_CoreV1Api.read_namespaced_pod_log(name=pod_name,
                                                                     namespace=namespace, previous=previous)
        return api_response

    def is_hostsensor_triggered(self):
        api_response = self.client_AppsV1Api.list_daemon_set_for_all_namespaces()
        for item in api_response.items:
            if "host-scanner" in item.metadata.name:
                return True
        return False

    @staticmethod
    def convert_workload_to_dict(workload, f_json: bool = False, indent: int = 2):
        import json
        if not workload:
            return []
        try:
            if isinstance(workload, list):
                workload = [KubectlWrapper.to_dict(i) for i in workload] if len(workload) > 1 else \
                    KubectlWrapper.to_dict(workload[0])
            else:
                workload = KubectlWrapper.to_dict(workload)
            return json.dumps(workload, indent=indent) if f_json else workload
        except:
            return workload

    @staticmethod
    def to_dict(workload):
        workload = {"workload": workload} if isinstance(workload, str) else workload.to_dict()
        KubectlWrapper.convert_datetime_to_string(workload=workload)
        return workload

    @staticmethod
    def convert_datetime_to_string(workload: dict):
        for k, v in workload.items():
            if isinstance(v, datetime.datetime):
                workload[k] = v.strftime("%Y-%m-%dT%H:%M:%SZ")
            if isinstance(v, dict):
                KubectlWrapper.convert_datetime_to_string(workload=v)
            if isinstance(v, list):
                for i in v:
                    if isinstance(i, dict):
                        KubectlWrapper.convert_datetime_to_string(workload=i)

    @staticmethod
    def register_cluster(temp_script_file: str, customer: str, user: str, psw: str, retries=3):
        err = ""
        for i in range(retries):
            try:
                status, result = TestUtil.run_command(command_args=[temp_script_file, '-u', user, '-p', psw,
                                                                    '-c', customer])
                assert status == 0, f"status: {status} retry: {i}, error {result}"
                return
            except Exception as e:
                err = e
        raise Exception(f"fail to register cluster: {err}")

    @staticmethod
    def get_kind_from_wl(wl: dict):
        if 'kind' in wl.keys():
            return wl['kind']
        return ''

    @staticmethod
    def get_name_from_wl(wl: dict):
        if 'metadata' in wl.keys() and 'name' in wl['metadata'].keys():
            return wl['metadata']['name']
        return ''

    @staticmethod
    def get_namespace_from_wl(wl: dict):
        if 'metadata' in wl.keys() and 'namespace' in wl['metadata'].keys():
            return wl['metadata']['namespace']
        return ''

    @staticmethod
    def get_api_version_from_wl(wl: dict):
        if 'apiVersion' in wl.keys():
            return wl['apiVersion']
        return ''

    def get_dynamic_client(self, api_version, kind):
        return self.client_dynamic.resources.get(api_version=api_version, kind=kind)

    @staticmethod
    def add_new_service_account_to_cluster_admin(service_account: str, namespace: str):
        add_sa_cmd = f'kubectl create serviceaccount {service_account}'
        TestUtil.run_command(add_sa_cmd.split(" "), timeout=None)
        add_binding_cmd = f'kubectl create clusterrolebinding {service_account}-binding --clusterrole=cluster-admin ' \
                          f'--serviceaccount={namespace}:{service_account}'
        TestUtil.run_command(add_binding_cmd.split(" "), timeout=None)

    @staticmethod
    def add_new_namespace(namespace: str):
        TestUtil.run_command("kubectl create namespace alerts".split(" "), timeout=None)


def get_name(obj: dict):
    return obj["metadata"]["name"]

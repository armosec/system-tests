import json
import os
import re
import time
import base64
import kubernetes.client
import requests
import json

from systest_utils import statics, Logger, TestUtil
from datetime import datetime, timezone

from tests_scripts.helm.base_vuln_scan import BaseVulnerabilityScanning
from systest_utils.wlid import Wlid

DEFAULT_BRANCH = "release"


def is_accesstoken_credentials(credentials):
    return 'username' in credentials and 'password' in credentials and credentials['username'] != '' and credentials[
        'password'] != ''


# class VulnerabilityScanningProxy - is a class that is used to test Helm proxy.
# test runs vulnerability scanning on a cluster with proxy and checks that the scan results are updated on backend.

class VulnerabilityScanningProxy(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanningProxy, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                         kubernetes_obj=kubernetes_obj)

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('1. apply cluster resources')

        Logger.logger.info('1.1 apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('1.2 apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)

        Logger.logger.info('1.3 apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)

        Logger.logger.info('2. verify all pods are running')
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        since_time = datetime.now(timezone.utc).astimezone().isoformat()

        Logger.logger.info('3. install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart()

        Logger.logger.info('3.1 verify helm installation')
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        Logger.logger.info('4. Get the scan result from Backend')
        # In order to check proxy it is enough to check that at least one pod is updated on backend.
        expected_number_of_pods = 1
        be_summary, _ = self.wait_for_report(timeout=400, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=expected_number_of_pods)
        self.test_total_is_rce_count(be_summary)
        Logger.logger.info('5. Test no errors in results')
        self.test_no_errors_in_scan_result(be_summary)

        return self.cleanup()


class VulnerabilityScanning(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanning, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                    kubernetes_obj=kubernetes_obj)

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        # P1 install helm-chart (armo)
        # 1.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()

        # 1.2 install armo helm-chart
        self.install_armo_helm_chart()

        # 1.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        # P2 Install Wikijs
        # 2.1 install Wikijs
        # 2.2 verify installation
        cluster, namespace = self.setup(apply_services=False)

        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)

        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        # P3 run kubescape and Vulnerability scanning
        # 3.1 run kubescape
        # 3.2 get pending statuses with each scan (just over app namespace) (from be) (time-out 10 min)
        Logger.logger.info('Get the scan result from Backend')
        expected_number_of_pods = self.get_expected_number_of_pods(
            namespace=namespace)
        be_summary, _ = self.wait_for_report(timeout=600, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=expected_number_of_pods)
        self.test_total_is_rce_count(be_summary)

        # P4 check result
        # 4.1 check results (> from expected result)
        Logger.logger.info('Test no errors in results')
        self.test_no_errors_in_scan_result(be_summary)

        Logger.logger.info('Get scan result csv')
        self.backend.get_scan_results_sum_summary_CSV(namespace=namespace,
                                                      expected_results=expected_number_of_pods)
        # check CSV with fixable and critical severity filters
        self.backend.get_scan_results_sum_summary_CSV(namespace=namespace,
                                                      expected_results=self.count_containers_with_severity(be_summary,
                                                                                                           "Critical",
                                                                                                           True),
                                                      severity="Critical", fixable=True)

        # P5 get CVEs results
        # 5.1 get container scan id
        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)

        # 5.2 get CVEs for containers
        Logger.logger.info('Test cve result')
        self.test_cve_result(since_time=since_time, containers_scan_id=containers_scan_id, be_summary=be_summary,
                             expected_number_of_pods=self.get_expected_number_of_pods(namespace=namespace))

        Logger.logger.info('Get scan result details csv')
        self.backend.get_scan_results_details_csv(containers_scan_id=containers_scan_id)

        # 4.2 Check logs for error- if there is 1 error- test fail
        Logger.logger.info('Test no errors in armo-system-component logs')
        self.test_no_errors_in_armo_system_logs()

        # 4.3 test cluster info from BE
        Logger.logger.info('Test no errors in cluster api')
        self.test_cluster_info()

        # Logger.logger.info('validate all cluster cve data arrived')
        #  self.test_all_images_vuln_scan_reported(in_cluster_images=in_cluster_images, since_time=since_time)

        return self.cleanup()


class VulnerabilityScanningTriggerScanOnNewImage(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanningTriggerScanOnNewImage, self).__init__(test_driver=test_driver, test_obj=test_obj,
                                                                         backend=backend,
                                                                         kubernetes_obj=kubernetes_obj)

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        # P1 Install Wikijs
        # 1.1 install Wikijs
        # 1.2 verify installation
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_yaml_file(yaml_file=self.test_obj["deployment"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        # P2 install helm-chart (armo)
        # 2.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()

        # 2.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # 2.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        # P3 run kubescape and Vulnerability scanning
        # 3.1 run kubescape
        # 3.2 get pending statuses with each scan (just over app namespace) (from be)
        Logger.logger.info('Get the scan result from Backend')
        be_summary, _ = self.wait_for_report(timeout=900, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=self.get_expected_number_of_pods(
                                                 namespace=namespace))

        # P4 check result
        # 4.1 check results (> from expected result)
        Logger.logger.info('Test no errors in results')
        self.test_no_errors_in_scan_result(be_summary)
        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)
        self.test_cve_result(since_time=since_time, containers_scan_id=containers_scan_id, be_summary=be_summary,
                             expected_number_of_pods=self.get_expected_number_of_pods(namespace=namespace))
        # 4.2 Check logs for error- if there is 1 error- test fail
        Logger.logger.info('Test no errors in armo-system-component logs')
        self.test_no_errors_in_armo_system_logs()
        # 4.3 Check armo components health

        return self.cleanup()


class VulnerabilityScanningCVEExceptions(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanningCVEExceptions, self).__init__(test_driver=test_driver, test_obj=test_obj,
                                                                 backend=backend,
                                                                 kubernetes_obj=kubernetes_obj)

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        # P1 Install Wikijs
        # 1.1 install Wikijs
        # 1.2 verify installation
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('apply workload')
        workload_objs: list = self.apply_yaml_file(yaml_file=self.test_obj["deployment"], namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        # P2 install helm-chart (armo)
        # 2.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()

        # 2.2 install armo helm-chart
        self.install_armo_helm_chart(helm_kwargs=self.test_obj.get_arg("helm_kwargs", default={}))

        # 2.3 verify installation
        self.verify_running_pods(timeout=360, namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        # P3 run kubescape and Vulnerability scanning
        # 3.1 run kubescape
        # 3.2 get pending statuses with each scan (just over app namespace) (from be) (time-out 10 min)
        Logger.logger.info('Get the scan result from Backend')
        be_summary, _ = self.wait_for_report(timeout=560, report_type=self.backend.get_scan_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=self.get_expected_number_of_pods(
                                                 namespace=namespace))

        # P4 check result
        # 4.1 check results (> from expected result)
        Logger.logger.info('Test no errors in results')

        self.test_no_errors_in_scan_result(be_summary)
        containers_scan_id = self.get_container_scan_id(be_summary=be_summary)
        self.test_cve_result(since_time=since_time, containers_scan_id=containers_scan_id, be_summary=be_summary,
                             expected_number_of_pods=self.get_expected_number_of_pods(namespace=namespace))
        # 4.2 Check logs for error- if there is 1 error- test fail

        # 5.0 set several cves exceptions
        cves_list = self.get_some_cve_exceptions_list(Wlid.get_name(wlids))
        cve_exception_guid, cve_exception_guid_time = self.wait_for_report(timeout=360,
                                                                           report_type=self.backend.set_cves_exceptions,
                                                                           cves_list=cves_list,
                                                                           cluster_name=self.kubernetes_obj.get_cluster_name(),
                                                                           namespace=namespace,
                                                                           conatiner_name=Wlid.get_name(wlids))

        # 5.1 rescan
        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        self.wait_for_report(timeout=360, report_type=self.backend.scan_image_in_namespace,
                             cluster_name=self.kubernetes_obj.get_cluster_name(), namespace=namespace)

        # 5.2 Get the scan result from Backend
        Logger.logger.info('Get the scan result from Backend')
        self.wait_for_report(timeout=420, report_type=self.test_applied_cve_exceptions,
                             namespace=namespace, since_time=since_time,
                             cve_exception_guid=cve_exception_guid, cves_list=cves_list)

        Logger.logger.info('Test no errors in armo-system-component logs')
        self.test_no_errors_in_armo_system_logs()
        # 4.3 Check armo components health

        return self.cleanup()


class VulnerabilityScanningRegistry(BaseVulnerabilityScanning):
    # 1. apply public-registry (contains nginx-vuln-scan-new-image.yaml nginx image) tagged as nginx:test
    # 2.
    # 3. push it to the new registry
    # 4. clear that image
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanningRegistry, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                            kubernetes_obj=kubernetes_obj)
        if 'expected_payloads' in self.test_obj.kwargs:
            self.expected_payloads = self.test_obj.kwargs['expected_payloads']

    def setup_phase(self, cluster, namespace):
        Logger.logger.info('find string in log')
        credentials = self.get_registry_credentials()
        properties = self.test_obj.kwargs['properties'] if 'properties' in self.test_obj.kwargs else None

        secret_data, registry = self.apply_registry_related(cluster, namespace, credentials=credentials,
                                                            properties=properties)
        return secret_data, registry

    def start(self):

        cluster, namespace = self.setup_helm_chart()
        secret_data, registry = self.setup_phase(cluster, namespace)

        # trigger scanning of an image from a registry

        # check results from BE
        Logger.logger.info('exposing websocket (port-fwd)')
        self.expose_websocket(cluster)
        Logger.logger.info('applying registry secret')
        self.apply_registry_secret(secret_data)
        Logger.logger.info('applying registry configmap(if given)')
        has_config_map = self.create_registry_configmap(registry)

        Logger.logger.info('waiting for vuln pod to be ready before triggering scan registry')
        time.sleep(120)

        self.send_registry_scan_command(registry)

        Logger.logger.info('find string in log')
        if has_config_map:
            Logger.logger.info('verify registry configmap')

            cm_applied = f'scanRegistries:registry({registry}) loaded configmap  successful'
            running_pods = self.get_ready_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                               name=statics.CA_OPERATOR_DEPLOYMENT_FROM_HELM_NAME)
            self.wait_for_report(timeout=600, report_type=self.find_string_in_log,
                                 namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                 pod_name=running_pods[0].metadata.name,
                                 containers=statics.CA_OPERATOR_CONTAINER_FROM_HELM_NAME,
                                 previous=False,
                                 string_in_log=cm_applied)

        img_no_tag = self.expected_payloads['image'].split(':')

        # dependent on vuln-scan prints

        if not self.is_image_excluded(img_no_tag[0]):
            Logger.logger.info('verify image in registry was sent to event receiver')

            running_pods = self.get_ready_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                               name=statics.CA_VULN_SCAN_DEPLOYMENT_FROM_HELM_NAME)
            successful_vuln_scan_log = f'posting to event receiver image {registry}/{self.expected_payloads["image"]} wlid  finished successfully response body:'
            self.wait_for_report(timeout=600, report_type=self.find_string_in_log,
                                 namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                 pod_name=running_pods[0].metadata.name,
                                 containers=statics.CA_VULN_SCAN_CONTAINER_FROM_HELM_NAME,
                                 previous=False,
                                 string_in_log=successful_vuln_scan_log)

            Logger.logger.info('verify image in registry was sent to event receiver: SUCCESS')

        else:
            Logger.logger.info('verify image in registry was excluded properly')

            cm_exclude = f"image registry scan::{registry}/{img_no_tag[0]} was excluded"
            running_pods = self.get_ready_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                               name=statics.CA_OPERATOR_DEPLOYMENT_FROM_HELM_NAME)
            self.wait_for_report(timeout=600, report_type=self.find_string_in_log,
                                 namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                 pod_name=running_pods[0].metadata.name,
                                 containers=statics.CA_OPERATOR_CONTAINER_FROM_HELM_NAME,
                                 previous=False,
                                 string_in_log=cm_exclude)

            Logger.logger.info('verify image in registry was excluded properly: SUCCESS')

        return self.cleanup()

    def get_registry_credentials(self):
        username = os.getenv('REGISTRY_USERNAME')
        password = os.getenv('REGISTRY_PASSWORD')
        return {'username': username, 'password': password} if username and password else None

    def is_image_excluded(self, img):
        return 'configmap_data' in self.test_obj.kwargs and (
                self.test_obj.kwargs['configmap_data'] is not None and 'exclude' in self.test_obj.kwargs[
            'configmap_data'] and img in self.test_obj.kwargs['configmap_data']['exclude'])

    def create_registry_configmap(self, registry):
        if 'configmap_data' not in self.test_obj.kwargs or self.test_obj.kwargs['configmap_data'] is None:
            return False

        # delete existing configmap
        try:
            self.kubernetes_obj.delete_config_map(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                  name=statics.CA_VULN_REGISTRY_SCAN_CONFIGMAP_HELM_NAME)
        except:
            pass
        configmap_metadata = kubernetes.client.V1ObjectMeta(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                            name=statics.CA_VULN_REGISTRY_SCAN_CONFIGMAP_HELM_NAME,
                                                            labels={'armo.tier': 'registry-scan'})
        self.test_obj.kwargs['configmap_data']['registry'] = registry

        cm_data = [self.test_obj.kwargs['configmap_data']]
        cm_data = {"registries": json.dumps(cm_data)}

        cm = kubernetes.client.V1ConfigMap(data=cm_data, kind='ConfigMap', api_version='v1',
                                           metadata=configmap_metadata)
        try:
            a = self.kubernetes_obj.client_CoreV1Api.create_namespaced_config_map(
                namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, body=cm)
        except Exception as ex:
            print(ex)
        return True

    def send_registry_scan_command(self, registry):
        data = {
            "commands": [
                {
                    "CommandName": "scanRegistry",
                    "args": {
                        "registryInfo-v1": {
                            "registryName": registry,
                        }
                    }
                }
            ]
        }
        if 'is_https' in self.test_obj.kwargs:
            is_https = self.test_obj.kwargs['is_https']
            data["commands"][0]["args"]["registryInfo-v1"]["isHTTPS"] = is_https
        payload = json.dumps(data)
        resp = requests.post('http://0.0.0.0:4002/v1/triggerAction', data=payload)
        print(resp)
        if resp.status_code < 200 or resp.status_code >= 300:
            raise Exception(f'bad response: {resp.text}')

    def apply_registry_secret(self, secretData):
        # delete existing secret if exists
        # apply secret
        try:
            self.kubernetes_obj.delete_secret(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                              name=statics.CA_VULN_REGISTRY_SCAN_SECRET_HELM_NAME)
        except:
            # secret did not exist :)
            pass
        secretMetadata = kubernetes.client.V1ObjectMeta(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                        name=statics.CA_VULN_REGISTRY_SCAN_SECRET_HELM_NAME,
                                                        labels={'armo.tier': 'registry-scan'})
        secret = kubernetes.client.V1Secret(data=secretData, kind='Secret', api_version='v1', metadata=secretMetadata)
        a = self.kubernetes_obj.client_CoreV1Api.create_namespaced_secret(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                                          body=secret)

    def expose_websocket(self, cluster):
        running_pods = self.get_ready_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME,
                                           name=statics.CA_OPERATOR_DEPLOYMENT_FROM_HELM_NAME)
        try:
            self.port_forward_proc = self.kubernetes_obj.portforward(cluster, statics.CA_NAMESPACE_FROM_HELM_NAME,
                                                                     running_pods[0].metadata.name,
                                                                     {"source": 4002, "exposed": 4002})
            if self.port_forward_proc is None or self.port_forward_proc.stderr is not None:
                raise Exception('port forwarding to operator failed')
            Logger.logger.info('expose_websocket done')
        except Exception as e:
            print(e)

    def create_secret_data(self, registry, credentials=None, properties=None):
        # refer to https://hub.armosec.io/docs/registry-vulnerability-scan
        base = {"registry": registry, 'kind': ''}
        if credentials is None:
            base['auth_method'] = 'public'
        elif is_accesstoken_credentials(credentials):
            base['auth_method'] = 'accesstoken'
            base['username'] = credentials['username']
            base['password'] = credentials['password']

        if properties is not None:
            if 'http' in properties and properties['http']:
                base['http'] = True

            if 'skipTLSVerify' in properties and properties['skipTLSVerify']:
                base['skipTLSVerify'] = True

        secret_as_str = json.dumps([base])
        secret_as_byte = bytes(secret_as_str, 'utf-8')
        return base64.b64encode(secret_as_byte).decode('utf-8')

    def apply_registry_related(self, cluster, namespace, credentials=None, properties=None):

        registry = f"public-registry.{namespace}:5000"
        if ('registry' in self.test_obj.kwargs and self.test_obj.kwargs['registry'] == 'local') or \
                'registry' not in self.test_obj.kwargs:
            Logger.logger.info('apply registry workload')
            workload_objs: list = self.apply_yaml_file(yaml_file=self.test_obj["deployment"], namespace=namespace)
            self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)
        else:
            registry = self.test_obj.kwargs['registry']

        secret_data = {
            "registriesAuth": self.create_secret_data(registry, credentials=credentials, properties=properties)}

        return secret_data, registry

    def setup_helm_chart(self, helm_kwargs: dict = None):
        cluster, namespace = self.setup(apply_services=True)

        # P2 install helm-chart (armo)
        # 2.1 add and update armo in repo
        Logger.logger.info('install armo helm-chart')
        self.add_and_upgrade_armo_to_repo()

        # 2.2 install armo helm-chart
        kwargs = {"triggerNewImageScan": True}
        if helm_kwargs:
            kwargs.update(helm_kwargs)
        self.install_armo_helm_chart(kwargs)

        # 2.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)
        time.sleep(10)
        return cluster, namespace


class VulnerabilityScanningRegistryBackendTrigger(VulnerabilityScanningRegistry):
    # 1. apply public-registry (contains nginx-vuln-scan-new-image.yaml nginx image) tagged as nginx:test
    # 2.
    # 3. push it to the new registry
    # 4. clear that image
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanningRegistryBackendTrigger, self).__init__(test_driver=test_driver, test_obj=test_obj,
                                                                          backend=backend,
                                                                          kubernetes_obj=kubernetes_obj)
        if 'expected_layers' in self.test_obj.kwargs:
            self.expected_layers = self.create_vulnerabilities_expected_results(
                expected_results=self.test_obj.kwargs['expected_layers'])

    def assert_registry_in_designators(self, be_summary, registry):
        foundRegistry = False
        for item in be_summary:
            if item['designators']['attributes']['registryName'] == registry + '/':
                foundRegistry = True
                break

        assert foundRegistry == True

    def start(self):
        assert self.backend != None;
        f'the test {self.test_driver.test_name} must run with backend'

        since_time = datetime.now(timezone.utc).astimezone().isoformat()
        cluster, namespace = self.setup_helm_chart()
        secret_data, registry = self.setup_phase(cluster, namespace)

        # trigger scanning of an image from a registry

        # check results from BE
        Logger.logger.info('applying registry secret')
        self.apply_registry_secret(secret_data)

        Logger.logger.info('waiting for vuln pod to be ready before triggering scan registry')
        time.sleep(120)

        # Logger.logger.info("test registry connectivity")
        # self.check_connectivity_for_single_registry(registry=registry)

        Logger.logger.info("create scan by backend trigger")
        cluster_name = self.kubernetes_obj.get_cluster_name()
        self.backend.create_scan_registry_request(cluster_name=cluster_name,
                                                  registry_name=registry)

        Logger.logger.info('Get the scan result from Backend')
        be_summary, _ = self.wait_for_report(timeout=720,
                                             report_type=self.backend.get_scan_registry_results_sum_summary,
                                             namespace=namespace, since_time=since_time,
                                             expected_results=1)

        # P4 check result
        # 4.1 check results (> from expected result)
        Logger.logger.info('Test no errors in results')

        self.test_no_errors_in_scan_result(be_summary)
        self.assert_registry_in_designators(be_summary, registry)
        # assert be_summary['designtaors']['attributes']['registryName'] == registry + "/"
        containers_scan_id = self.get_image_scan_id(be_summary=be_summary)
        scan_id = self.get_scan_id(be_summary=be_summary)
        Logger.logger.info('Test results against expected results')
        self.test_registry_cve_result(since_time=since_time, containers_scan_id=containers_scan_id,
                                      be_summary=be_summary)
        Logger.logger.info('Test layers filter')

        layers = self.backend.get_registry_container_layers(scan_id)

        assert layers == self.expected_layers, \
            'container scan id {containers_scan_id} received layers: {layers}\n expected layers: {expected}'.format(
                containers_scan_id=scan_id,
                layers=layers,
                expected=self.expected_layers)
        Logger.logger.info('Delete registry scanId: {}'.format(scan_id))
        self.backend.delete_registry_scan(scan_id)

        time.sleep(30)
        be_summary = self.backend.get_scan_registry_results_sum_summary(cluster_name=cluster_name,
                                                                        namespace=namespace, since_time=since_time,
                                                                        expected_results=0)

        assert len(be_summary) == 0, \
            'Deleted registry returned in summery: {}'.format(be_summary)

        registries = self.backend.get_registry_container_cve(since_time=since_time,
                                                             containers_scan_id=scan_id, total_cve=0)

        assert len(registries) == 0, \
            'Deleted registry returned in details: {}'.format(registries)

        return self.cleanup()

    def check_connectivity_for_single_registry(self, registry, auth_method=None, expected_statuses=None):

        # default is all statuses passed and public auth
        if expected_statuses == None:
            expected_statuses = {
                statics.TEST_REGISTRY_CONNECTIVITY_AUTHENTICATION_STATUS: statics.TEST_REGISTRY_CONNECTIVITY_PASSED_STATUS,
                statics.TEST_REGISTRY_CONNECTIVITY_INFORMATION_STATUS: statics.TEST_REGISTRY_CONNECTIVITY_PASSED_STATUS,
                statics.TEST_REGISTRY_CONNECTIVITY_RETRIEVE_REPOSITORIES_STATUS: statics.TEST_REGISTRY_CONNECTIVITY_PASSED_STATUS,
            }
        if auth_method == None:
            auth_method = {}
            auth_method["type"] = "public"
            auth_method["username"] = ""
            auth_method["password"] = ""

        cluster_name = self.kubernetes_obj.get_cluster_name()

        Logger.logger.info('sending test registry connectivity request')
        resp = self.backend.test_registry_connectivity_request(cluster_name=cluster_name, registry_name=registry,
                                                               auth_method=auth_method,
                                                               excluded_repositories=self.get_excluded_repositories())

        Logger.logger.info('testing registry connectivity response')
        self.check_test_registry_connectivity_response(resp=resp, cluster_name=cluster_name, registry_name=registry)

        job_id = resp['jobID']
        Logger.logger.info('waiting before sending get job report request, sleeping for 30 seconds')
        time.sleep(30)
        Logger.logger.info('sending get job report request')
        resp = self.backend.get_job_report_request(job_id=job_id)

        Logger.logger.info('testing job report response')
        self.check_job_report_response(resp=resp, job_id=job_id, expected_statuses=expected_statuses)

        if self.is_passed_statuses(expected_statuses):
            Logger.logger.info('sending get repositories list request')
            resp = self.backend.get_repositories_list(job_id=job_id)

            Logger.logger.info('testing repositories list response')
            self.check_repositories_list_response(resp=resp, job_id=job_id)

    def is_passed_statuses(self, expected_statuses):
        for status in expected_statuses:
            if expected_statuses[status] != statics.TEST_REGISTRY_CONNECTIVITY_PASSED_STATUS:
                return False

        return True

    def check_job_report_response(self, resp, job_id, expected_statuses):
        assert resp['jobID'] == job_id, \
            'jobID is not {}: {}'.format(job_id, resp['jobID'])
        for status in expected_statuses:
            assert resp["data"][status]['status'] == expected_statuses[status], \
                'job status is wrong: expected {} but got:{}'.format(expected_statuses[status],
                                                                     resp["data"][status]['status'])

    def check_repositories_list_response(self, resp, job_id):
        assert resp['jobID'] == job_id, \
            'jobID is not {}: {}'.format(job_id, resp['jobID'])

        for repo in self.get_excluded_repositories():
            for response_repo in resp['repositories']:
                assert not response_repo['repositoryName'].endswith(repo), \
                    'repo {} is in repositories: {}'.format(repo, resp['repositories'])

    def is_excluded_repositories(self):
        return 'excluded_repositories' in self.test_obj.kwargs

    def get_excluded_repositories(self):
        if self.is_excluded_repositories():
            return self.test_obj.kwargs['excluded_repositories']
        else:
            return []

    def check_test_registry_connectivity_response(self, resp, cluster_name, registry_name):
        assert resp['action'] == statics.TEST_REGISTRY_CONNECTIVITY_COMMAND, \
            'action is not testRegistryConnectivity: {}'.format(resp['action'])

        assert resp['clusterName'] == cluster_name, \
            'cluster name is not {}: {}'.format(cluster_name, resp['clusterName'])

        assert resp['registryName'] == registry_name, \
            'registry name is not {}: {}'.format(registry_name, resp['registryName'])

        assert resp['jobID'] != '', \
            'jobID is empty: {}'.format(resp['jobID'])


class VulnerabilityScanningTriggeringWithCronJob(BaseVulnerabilityScanning):
    def __init__(self, test_obj=None, cacli=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanningTriggeringWithCronJob, self).__init__(test_obj=test_obj, backend=backend,
                                                                         kubernetes_obj=kubernetes_obj,
                                                                         test_driver=test_driver)

    def start(self):
        # test Agenda:
        self.ignore_agent = True
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info('apply services')
        self.apply_directory(path=self.test_obj[("services", None)], namespace=namespace)

        Logger.logger.info('apply config-maps')
        self.apply_directory(path=self.test_obj[("config_maps", None)], namespace=namespace)

        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=180)

        Logger.logger.info("Installing helm-chart")
        # 2.1 add and update armo in repo
        self.add_and_upgrade_armo_to_repo()
        # 2.2 install armo helm-chart
        self.install_armo_helm_chart()

        # 2.3 verify installation
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=240)
        TestUtil.sleep(60, "wait till data will arrive to backend")

        Logger.logger.info("Test create vuln-scan cronjob")
        cj = self.test_create_vuln_scan_cronjob(namespaces_list=[namespace],
                                                schedule_string=self.test_obj.get_arg("schedule_time"))

        Logger.logger.info("Test update vuln-scan cronjob")
        cj = self.test_update_vuln_scan_cronjob(cron_job=cj,
                                                schedule_string=self.test_obj.get_arg("schedule_time"))

        Logger.logger.info("Test delete vuln-scan cronjob")
        self.test_delete_vuln_scan_cronjob(cron_job=cj)

        return self.cleanup()


class RegistryScanningTriggeringWithCronJob(VulnerabilityScanningRegistry):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(RegistryScanningTriggeringWithCronJob, self).__init__(test_driver=test_driver, test_obj=test_obj,
                                                                    backend=backend,
                                                                    kubernetes_obj=kubernetes_obj)
        self.expected_layers = self.create_vulnerabilities_expected_results(
            expected_results=self.test_obj.kwargs['expected_layers'])

    def start(self):
        # create registry scan cronjob and check
        # update both cronjob schedule and depth (in configmap)
        # delete cronjob and check that cronjob and configmap (and secret if there is auth) are deleted

        cluster, namespace = self.setup_helm_chart()
        secret_data, registry = self.setup_phase(cluster, namespace)
        Logger.logger.info('applying registry secret')
        self.apply_registry_secret(secret_data)

        Logger.logger.info("Test create registry-scan cronjob")
        auth_method = {
            "type": "private",
            "username": "test",
            "password": "test"
        }
        cj = self.test_create_registry_scan_cronjob(registry_name=registry,
                                                    schedule_string=self.test_obj.get_arg("schedule_time"),
                                                    credentials=auth_method)

        Logger.logger.info("Test update registry-scan cronjob")
        new_auth = {
            "type": "private",
            "username": "updated_test",
            "password": "updated_test"
        }
        cj = self.test_update_registry_scan_cronjob(cron_job=cj,
                                                    schedule_string=self.test_obj.get_arg("updating_schedule_time"),
                                                    depth=self.test_obj.get_arg("depth"), auth_method=new_auth)

        Logger.logger.info("Test delete registry-scan cronjob ")
        self.test_delete_registry_scan_cronjob(cron_job=cj, credentials=new_auth)

        Logger.logger.info("Test create registry-scan cronjob - deprecated API")
        cj = self.test_create_registry_scan_cronjob_deprecated(registry_name=registry,
                                                               schedule_string=self.test_obj.get_arg("schedule_time"))

        Logger.logger.info("Test update registry-scan cronjob - deprecated API")
        cj = self.test_update_registry_scan_cronjob_deprecated(cron_job=cj,
                                                               schedule_string=self.test_obj.get_arg(
                                                                   "updating_schedule_time"))

        Logger.logger.info("Test delete registry-scan cronjob - deprecated API")
        self.test_delete_registry_scan_cronjob_deprecated(cron_job=cj)

        return self.cleanup()


class VulnerabilityScanningTestRegistryConnectivity(VulnerabilityScanningRegistryBackendTrigger):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(VulnerabilityScanningTestRegistryConnectivity, self).__init__(test_driver=test_driver, test_obj=test_obj,
                                                                            backend=backend,
                                                                            kubernetes_obj=kubernetes_obj)

    def start(self):
        self.setup_helm_chart()

        Logger.logger.info('waiting for vuln pod to be ready before triggering scan registry')
        time.sleep(120)

        Logger.logger.info('Test check_public_quay_registry')
        self.check_public_quay_registry()

        if not self.is_excluded_repositories():
            Logger.logger.info('Test check_wrong_registry_name')
            self.check_wrong_registry_name()

            Logger.logger.info('Test check_wrong_auth')
            self.check_wrong_auth()

        return self.cleanup()

    def check_public_quay_registry(self):
        # check that we can connect to public quay.io, all statuses are passed, and excluded repositories are not in response
        registry = "quay.io/armosec"
        self.check_connectivity_for_single_registry(registry=registry)

    def check_wrong_registry_name(self):
        # check that we get failed status when trying to connect to wrong registry name
        registry = "quiy.io/armosec"
        expected_statuses = {
            statics.TEST_REGISTRY_CONNECTIVITY_INFORMATION_STATUS: statics.TEST_REGISTRY_CONNECTIVITY_FAILED_STATUS,
        }
        self.check_connectivity_for_single_registry(registry=registry, expected_statuses=expected_statuses)

    def check_wrong_auth(self):
        # check that we get passed status for information, and failed status for authentication
        registry = "quay.io/armosec"
        auth_method = {}
        auth_method["type"] = "private"
        auth_method["username"] = "accesstoken"
        auth_method["password"] = "invalid"

        expected_statuses = {
            statics.TEST_REGISTRY_CONNECTIVITY_AUTHENTICATION_STATUS: statics.TEST_REGISTRY_CONNECTIVITY_FAILED_STATUS,
            statics.TEST_REGISTRY_CONNECTIVITY_INFORMATION_STATUS: statics.TEST_REGISTRY_CONNECTIVITY_PASSED_STATUS,
        }
        self.check_connectivity_for_single_registry(registry=registry, expected_statuses=expected_statuses,
                                                    auth_method=auth_method)
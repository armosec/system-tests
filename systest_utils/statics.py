import os

SUCCESS = True
FAILURE = False

SERVER = 3.0
CLIENT = 3.1

MASTER = 4.0
SLAVE = 4.1

DEFAULT_WT_PATH = os.path.abspath(os.path.join('configurations', 'workload-templates'))
DEFAULT_DOCKER_FILE_PATH = os.path.abspath(os.path.join('configurations', 'dockerfiles'))
DEFAULT_SP_PATH = os.path.abspath(os.path.join('configurations', 'signing-profiles'))
DEFAULT_KS_EXCEPTIONS_PATH = os.path.abspath(os.path.join('configurations', 'ks-exceptions'))
DEFAULT_KS_CUSTOM_FW_PATH = os.path.abspath(os.path.join('configurations', 'ks-custom-fw'))

RESOURCES_PATH = os.path.abspath('resources')

DEFAULT_GRYPE_BINARIES_PATH = os.path.abspath('grype-versioning/grype-binaries')
# k8s paths
DEFAULT_K8S_PATHS = os.path.abspath(os.path.join('configurations', 'k8s_workloads'))
DEFAULT_DEPLOYMENT_PATH = os.path.join(DEFAULT_K8S_PATHS, 'deployments')
DEFAULT_SERVICE_PATH = os.path.join(DEFAULT_K8S_PATHS, 'services')
DEFAULT_SERVICE_ACCOUNT_PATH = os.path.join(DEFAULT_K8S_PATHS, 'service-accounts')
DEFAULT_CLUSTER_ROLE_PATH = os.path.join(DEFAULT_K8S_PATHS, 'rbac')
DEFAULT_CLUSTER_ROLE_BINDING_PATH = os.path.join(DEFAULT_K8S_PATHS, 'rbac')
DEFAULT_ROLE_PATH = os.path.join(DEFAULT_K8S_PATHS, 'role')
DEFAULT_ROLE_BINDING_PATH = os.path.join(DEFAULT_K8S_PATHS, 'role-binding')
DEFAULT_NETWORK_POLICY_PATH = os.path.join(DEFAULT_K8S_PATHS, 'network-policy')
DEFAULT_SECRETE_PATH = os.path.join(DEFAULT_K8S_PATHS, 'secrets')
DEFAULT_NAMESPACE_PATH = os.path.join(DEFAULT_K8S_PATHS, 'namespaces')
DEFAULT_CONFIGMAP_PATH = os.path.join(DEFAULT_K8S_PATHS, 'config-map')

# kubescape
DEFAULT_EXCEPTIONS_PATH = os.path.join(RESOURCES_PATH, 'kubescape', 'exceptions')
DEFAULT_INPUT_YAML_PATH = os.path.join(RESOURCES_PATH, 'kubescape', 'yaml_file')

# vulnerability_scanning paths
DEFAULT_VULNERABILITY_SCANNING_PATHS = os.path.abspath(os.path.join('configurations', 'vulnerability_scanning'))
DEFAULT_VULNERABILITY_EXPECTED_RESULTS = os.path.abspath(
    os.path.join(DEFAULT_VULNERABILITY_SCANNING_PATHS, 'expected_results'))
DEFAULT_KUBESCAPE_EXPECTED_RESULTS = os.path.abspath(os.path.join('configurations', 'ks-expected-results'))

# vulnerability_scanning be_results
SCAN_RESULT_CATEGORIES_FIELD = "categories"
SCAN_RESULT_CONTAINER_NAME_FIELD = "containerName"
SCAN_RESULT_IMAGE_TAG_NAME_FIELD = "imageTag"
SCAN_RESULT_NAME_FIELD = "name"
SCAN_RESULT_IS_RCE_FIELD = "isRce"
SCAN_RESULT_CONTAINER_SCAN_ID_FIELD = "containersScanID"
SCAN_RESULT_SEVERITIES_STATS_FIELD = "severitiesStats"
SCAN_RESULT_SEVERITY_FIELD = "severity"
SCAN_RESULT_IMAGEHASH_FIELD = "imageHash"
SCAN_RESULT_ERRORS_FIELD = "errors"
SCAN_RESULT_STATUS_FIELD = "status"
SCAN_RESULT_TOTAL_FIELD = 'total'
SCAN_RESULT_RCETOTAL_FIELD = 'rceTotal'
SCAN_RESULT_IS_RELEVANT_FIELD = "relevantLabel"
SCAN_RESULT_IS_RELEVANT_FIELD_TRUE = "yes"
SCAN_RESULT_IS_RELEVANT_FIELD_FALSE = "no"
SCAN_RESULT_IS_RELEVANT_FIELD_UNKNOWN = ""

BASIC_NAMESPACE_YAML = "basic_ns.yaml"

__DEFAULT_KEY_ID__ = "99d368694eb64f4d9eef46a60c18af82"

DEFAULT_XML_PATH = os.path.abspath("results_xml_format")

CLUSTER_ATTRIBUTE_FIELD = "cluster"

AUTO_ATTACH_LABEL = "armo.attach"
AUTO_ATTACH_SECRET_LABEL = "armo.secret"
AUTO_ATTACH_SECRET_VALUE = "protect"

# kubernetes cluster - kube-system
K8S_NAMESPACE_NAME = "kube-system"
K8S_ETCD_POD_NAME = "etcd-minikube"
K8S_ETCD_CONTAINER_NAME = "etcd"
K8S_API_SERVER_POD_NAME = "kube-apiserver-minikube"
K8S_API_SERVER_CONTAINER_NAME = "kube-apiserver"
KS_PORT_FORWARD = 33334

# kubernetes cluster - armo-system
HELM_REPO = "kubescape/kubescape-cloud-operator"
CA_NAMESPACE_NAME = "kubescape"
CA_NAMESPACE_FROM_HELM_NAME = "kubescape"
CA_HELM_NAME = "kubescape"
CA_CONFIG = "ks-cloud-config"
CA_OPERATOR_CONTAINER_FROM_HELM_NAME = "operator"
CA_OPERATOR_DEPLOYMENT_FROM_HELM_NAME = "operator"
CA_COLLECTOR_CONTAINER_FROM_HELM_NAME = "kollector"
CA_COLLECTOR_DEPLOYMENT_FROM_HELM_NAME = "kollector"
CA_AGGREGATOR_DEPLOYMENT_NAME = "kollector"
CA_VULN_SCAN_CONTAINER_FROM_HELM_NAME = "kubevuln"
CA_VULN_SCAN_DEPLOYMENT_FROM_HELM_NAME = "kubevuln"
CA_VULN_SCAN_CRONJOB_START_NAME = "kubevuln-scheduler"
CA_VULN_SCAN_CRONJOB_CLUSTER_NAME_FILED = "clusterName"
CA_VULN_SCAN_CRONJOB_NAME_FILED = "name"
CA_VULN_SCAN_CRONJOB_CRONTABSCHEDULE_FILED = "cronTabSchedule"
CA_VULN_SCAN_CRONJOB_ARMO_TIER_LABEL_FIELD = "armo.tier"
CA_VULN_SCAN_CRONJOB_ARMO_TIER_LABEL_NAME = "vuln-scan"
CA_REGISTRY_SCAN_CRONJOB_ARMO_TIER_LABEL_NAME = "registry-scan"
CA_KS_SCAN_CRONJOB_ARMO_TIER_LABEL_NAME = "kubescape-scan"
CA_REGISTRY_SCAN_CRONJOB_REGISTRY_NAME_FIELD = "registryName"
CA_REGISTRY_SCAN_CRONJOB_REGISTRY_NAME_ANNOTATION_FIELD = "armo.cloud/registryname"
# armo-system secrets & configs
CA_VULN_REGISTRY_SCAN_SECRET_HELM_NAME = 'kubescape-registry-scan'
CA_VULN_REGISTRY_SCAN_CONFIGMAP_HELM_NAME = 'kubescape-registry-scan'


CA_VULN_SCAN_RESOURCE_API_VERSION = 'result.vulnscan.com/v1'

# posture related
ALL_RESOURCES_COUNT_FIELD = "totalResources"
WARN_RESOURCES_COUNT_FIELD = "warningResources"
FAILED_RESOURCES_COUNT_FIELD = "failedResources"

FRAMEWORK_REPORTS_FIELD = "frameworkReports"
CONTROLS_FIELD = "controls"
RULE_REPORTS_FIELD = "ruleReports"
RULE_RESPONSE_FIELD = "ruleResponse"

BE_FAILED_RESOURCES_COUNT_FIELD = "failedResourcesCount"
BE_WARNING_RESOURCES_COUNT_FIELD = "warningResourcesCount"
BE_SKIPPED_RESOURCES_COUNT_FIELD = "skippedResourcesCount"
BE_CORDS_FIELD = "cords"
BE_REPORT_GUID_FIELD = "reportGUID"
BE_REPORT_TIMESTAMP_FIELD = "timestamp"
BE_NAME_FILED = "name"

BE_TOTAL_CONTROLS_FILED = 'totalControls'
BE_FAILED_CONTROLS_FILED = 'failedControls'
BE_WARNING_CONTROLS_FILED = 'warningControls'
BE_STATUS_TEXT_FILED = 'statusText'

# in-cluster components details
KUBESCAPE_COMPONENT_NAME = 'kubescape'
OPERATOR_COMPONENT_NAME = 'operator'
KUBEVULN_COMPONENT_NAME = 'kubevuln'
KOLLECTOR_COMPONENT_NAME = 'kollector'
GATEWAY_COMPONENT_NAME = 'gateway'

KUBESCAPE_COMPONENT_TAG = 'kubescape-tag'
OPERATOR_COMPONENT_TAG = 'operator-tag'
KUBEVULN_COMPONENT_TAG = 'kubevuln-tag'
KOLLECTOR_COMPONENT_TAG = 'kollector-tag'
GATEWAY_COMPONENT_TAG = 'gateway-tag'

TEST_REGISTRY_CONNECTIVITY_PASSED_STATUS = "Passed"
TEST_REGISTRY_CONNECTIVITY_FAILED_STATUS = "Failed"
TEST_REGISTRY_CONNECTIVITY_COMMAND = "testRegistryConnectivity"
CREATE_REGISTRY_CJ_COMMAND = "setRegistryScanCronJob"
UPDATE_REGISTRY_CJ_COMMAND = "updateRegistryScanCronJob"
DELETE_REGISTRY_CJ_COMMAND = "deleteRegistryScanCronJob"
TEST_REGISTRY_CONNECTIVITY_INFORMATION_STATUS = "registryInformation"
TEST_REGISTRY_CONNECTIVITY_AUTHENTICATION_STATUS = "registryAuthentication"
TEST_REGISTRY_CONNECTIVITY_RETRIEVE_REPOSITORIES_STATUS = "retrieveRepositories"

#storage aggregated API
HELM_STORAGE_FEATURE="enableStorage"
STORAGE_SBOM_PLURAL = "sbomspdxv2p3s"
STORAGE_FILTERED_SBOM_PLURAL = "sbomspdxv2p3filtereds"
STORAGE_CVES_PLURAL = "vulnerabilitymanifests"
STORAGE_AGGREGATED_API_GROUP = "spdx.softwarecomposition.kubescape.io"
STORAGE_AGGREGATED_API_VERSION = "v1beta1"
STORAGE_AGGREGATED_API_NAMESPACE = "kubescape"

STORAGE_CVE_LABEL = "kubescape.io/context"
STORAGE_FILTERED_CVE_LABEL_VALUE = "filtered"

RELEVANCY_KIND_LABEL = "kubescape.io/workload-kind"
RELEVANCY_NAME_LABEL = "kubescape.io/workload-name"
RELEVANCY_NAMESPACE_LABEL = "kubescape.io/workload-namespace"
RELEVANCY_CONTAINER_LABEL = "kubescape.io/workload-container-name"


#relevancy feature
HELM_RELEVANCY_FEATURE="nodeAgent.enabled"
FILTERED_CVES_KEY="withRelevancy"
ALL_CVES_KEY="AllCVEs"

class Statistics(object):
    clear_state = "clear"
    attached_state = "attached"
    signed_state = "signed"
    testing_state = "test"
    final_state = "final"

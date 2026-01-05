import os


# test webhook

ARMO_TEST_WEBHOOK_API = "/api/v1/systemTestSiemWebhook"

# seccomp workloads statuses

SECCOMP_STATUS_UNKNOWN = 0
SECCOMP_STATUS_MISSING_RUNTIME_INFO = 1
SECCOMP_STATUS_MISSING = 2
SECCOMP_STATUS_OVERLY_PERMISSIVE = 3
SECCOMP_STATUS_OPTIMIZED = 4
SECCOMP_STATUS_MISCONFIGURED = 5

SECURITY_FRAMEWORKS = ["security"]
SECURITY_FRAMEWORK_TYPETAG = "security"


SUCCESS = True
FAILURE = False

SERVER = 3.0
CLIENT = 3.1

MASTER = 4.0
SLAVE = 4.1

# helm proxy constants
DEFAULT_HELM_PROXY_PATH = os.path.abspath(os.path.join('configurations', 'helm-proxy'))
HELM_PROXY_URL = "http://httpd-proxy.default:80"


DEFAULT_WT_PATH = os.path.abspath(os.path.join('configurations', 'workload-templates'))
DEFAULT_DOCKER_FILE_PATH = os.path.abspath(os.path.join('configurations', 'dockerfiles'))
DEFAULT_SP_PATH = os.path.abspath(os.path.join('configurations', 'signing-profiles'))
DEFAULT_KS_EXCEPTIONS_PATH = os.path.abspath(os.path.join('configurations', 'ks-exceptions'))
DEFAULT_KS_CUSTOM_FW_PATH = os.path.abspath(os.path.join('configurations', 'ks-custom-fw'))

DEFAULT_CDR_MOCK_PATH = os.path.abspath(os.path.join('configurations', 'cdr_mock', 'cdr.json'))

RESOURCES_PATH = os.path.abspath('resources')

DEFAULT_GRYPE_BINARIES_PATH = os.path.abspath('grype-versioning/grype-binaries')
# k8s paths
DEFAULT_K8S_PATHS = os.path.abspath(os.path.join('configurations', 'k8s_workloads'))
DEFAULT_DEPLOYMENT_PATH = os.path.join(DEFAULT_K8S_PATHS, 'deployments')
DEFAULT_KNOWN_SERVERS_PATH = os.path.join(DEFAULT_K8S_PATHS, 'known-servers')
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

# smart remediation tests
DEFAULT_SMART_REMEDIATION_PATH = os.path.join(DEFAULT_K8S_PATHS, 'smart-remediation')

# seccomp tests
DEFAULT_SECCOMP_PATH = os.path.join(DEFAULT_K8S_PATHS, 'seccomp')

# synchronizer tests
DEFAULT_SYNCHRONIZER_PATH = os.path.join(DEFAULT_K8S_PATHS, 'synchronizer')
DEFAULT_SYNCHRONIZER_CRDS_PATH = os.path.abspath(os.path.join('configurations', 'kubescape-crds', 'supported'))

# kubescape
DEFAULT_EXCEPTIONS_PATH = os.path.join(RESOURCES_PATH, 'kubescape', 'exceptions')
DEFAULT_INPUT_YAML_PATH = os.path.join(RESOURCES_PATH, 'kubescape', 'yaml_file')

# notifications
DEFAULT_NOTIFICATIONS_PATHS = os.path.abspath(os.path.join('configurations', 'notifications'))
DEFAULT_NOTIFICATIONS_DEPLOYMENT_PATH = os.path.join(DEFAULT_NOTIFICATIONS_PATHS, 'deployments')
DEFAULT_NOTIFICATIONS_JOB_PATH = os.path.join(DEFAULT_NOTIFICATIONS_PATHS, 'jobs')

# workflows
DEFAULT_WORKFLOWS_PATHS = os.path.abspath(os.path.join('configurations', 'workflows_notifications'))
DEFAULT_WORKFLOWS_DEPLOYMENT_PATH = os.path.join(DEFAULT_WORKFLOWS_PATHS, 'deployments')

# registry
DEFAULT_REGISTRY_PATHS = os.path.abspath(os.path.join('configurations', 'registry'))

# kdr
DEFAULT_KDR_DEPLOYMENT_PATH = os.path.join(DEFAULT_K8S_PATHS, 'deployments')

DEFAULT_DEPLOY_INTEGRATIONS_PATH = os.path.join(DEFAULT_K8S_PATHS, 'integrations')
DEFAULT_INTEGRATIONS_PATH = os.path.abspath(os.path.join('configurations', 'integrations'))

# kubescape config
ACCOUNT_ID_KEY = "accountID"
CLOUD_REPORT_URL_KEY = "cloudReportURL"
CLOUD_API_URL_KEY = "cloudAPIURL"

# vuln_scan paths
DEFAULT_VULNERABILITY_SCANNING_PATHS = os.path.abspath(os.path.join('configurations', 'vuln_scan'))
DEFAULT_VULNERABILITY_EXPECTED_RESULTS = os.path.abspath(
    os.path.join(DEFAULT_VULNERABILITY_SCANNING_PATHS, 'expected_results'))
DEFAULT_KUBESCAPE_EXPECTED_RESULTS = os.path.abspath(os.path.join('configurations', 'ks-expected-results'))

# vuln_scan be_results
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
SCAN_RESULT_RELEVANT_FIX_COUNT = 'relevantFixCount'
SCAN_RESULT_RCE_FIX_COUNT = 'rceFixCount'
SCAN_RESULT_FIX_COUNT_FIELD = 'fixedTotal'
SCAN_RESULT_IS_FIXED_FIELD = "isFixed"
SCAN_RESULT_RELEVANT_TOTAL_FIELD = 'relevantTotal'
SCAN_RESULT_IS_RELEVANT_FIELD = "relevantLabel"
SCAN_HAS_RELEVANCY_DATA_FIELD = "hasRelevancyData"
SCAN_RESULT_IS_RELEVANT_FIELD_TRUE = "yes"
SCAN_RESULT_IS_RELEVANT_FIELD_FALSE = "no"
SCAN_RESULT_IS_RELEVANT_FIELD_UNKNOWN = ""

DESIGNATORS_FIELD = "designators"

BASIC_NAMESPACE_YAML = "basic_ns.yaml"

__DEFAULT_KEY_ID__ = "99d368694eb64f4d9eef46a60c18af82"

DEFAULT_XML_PATH = os.path.abspath("results_xml_format")

CLUSTER_ATTRIBUTE_FIELD = "cluster"
CUSTOMER_GUID_ATTRIBUTE_FIELD = "customerGUID"

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
HELM_REPO = "kubescape/kubescape-operator"
CA_NAMESPACE_NAME = "kubescape"
CA_NAMESPACE_FROM_HELM_NAME = "kubescape"
CA_HELM_NAME = "kubescape"
CA_CONFIG = "ks-cloud-config"
KS_SECRET = "cloud-secret"
CA_CONFIGMAP_SERVICE_DISCOVERY_KEY = "services"
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
STORAGE_COMPONENT_NAME = 'storage'
NODE_AGENT_COMPONENT_NAME = 'nodeAgent'

KUBESCAPE_COMPONENT_TAG = 'kubescape-tag'
OPERATOR_COMPONENT_TAG = 'operator-tag'
KUBEVULN_COMPONENT_TAG = 'kubevuln-tag'
KOLLECTOR_COMPONENT_TAG = 'kollector-tag'
GATEWAY_COMPONENT_TAG = 'gateway-tag'
STORAGE_COMPONENT_TAG = 'storage-tag'
NODE_AGENT_COMPONENT_TAG = 'nodeAgent-tag'

TEST_REGISTRY_CONNECTIVITY_PASSED_STATUS = "Passed"
TEST_REGISTRY_CONNECTIVITY_FAILED_STATUS = "Failed"
TEST_REGISTRY_CONNECTIVITY_COMMAND = "testRegistryConnectivity"
CREATE_REGISTRY_CJ_COMMAND = "setRegistryScanCronJob"
UPDATE_REGISTRY_CJ_COMMAND = "updateRegistryScanCronJob"
DELETE_REGISTRY_CJ_COMMAND = "deleteRegistryScanCronJob"
TEST_REGISTRY_CONNECTIVITY_INFORMATION_STATUS = "registryInformation"
TEST_REGISTRY_CONNECTIVITY_AUTHENTICATION_STATUS = "registryAuthentication"
TEST_REGISTRY_CONNECTIVITY_RETRIEVE_REPOSITORIES_STATUS = "retrieveRepositories"

# storage aggregated API
HELM_STORAGE_FEATURE = "kubescapeStorage.enabled"
STORAGE_SBOM_PLURAL = "sbomsyfts"
STORAGE_CVES_PLURAL = "vulnerabilitymanifests"
STORAGE_AGGREGATED_API_GROUP = "spdx.softwarecomposition.kubescape.io"
STORAGE_AGGREGATED_API_VERSION = "v1beta1"
STORAGE_AGGREGATED_API_NAMESPACE = "kubescape"

KNOWN_SERVERS_PLURAL = "knownservers"
GENERATED_NETWORK_POLICY_PLURAL = "generatednetworkpolicies"

APPLICATION_PROFILE_PLURAL = "applicationprofiles"
NETWORK_NEIGHBOR_PLURAL = "networkneighborhoods"

STORAGE_CVE_LABEL = "kubescape.io/context"
STORAGE_FILTERED_CVE_LABEL_VALUE = "filtered"

RELEVANCY_KIND_LABEL = "kubescape.io/workload-kind"
RELEVANCY_NAME_LABEL = "kubescape.io/workload-name"
RELEVANCY_NAMESPACE_LABEL = "kubescape.io/workload-namespace"
RELEVANCY_TEMPLATE_HASH_LABEL = "kubescape.io/instance-template-hash"
RELEVANCY_RESOURCE_VERSION_LABEL = "kubescape.io/workload-resource-version"
RELEVANCY_CONTAINER_LABEL = "kubescape.io/workload-container-name"
RELEVANCY_INSTANCE_ID_LABEL = "kubescape.io/instance-id"
RELEVANCY_NODE_NAME_LABEL = "kubescape.io/node-name"
RELEVANCY_RESOURCE_SIZE_LABEL = "kubescape.io/resource-size"
RELEVANCY_SYNC_CHECKSUM_LABEL = "kubescape.io/sync-checksum"
RELEVANCY_WLID_ANNOTATION = "kubescape.io/wlid"

RELEVANCY_CONTAINER_ANNOTATIONS = "kubescape.io/workload-container-name"
RELEVANCY_IMAGE_ANNOTATIONS = "kubescape.io/image-id"


HELM_VULNERABILITY_SCAN = "capabilities.vulnerabilityScan"
HELM_VULNERABILITY_SCAN_ENABLED = "enable"
HELM_VULNERABILITY_SCAN_DISABLED = "disable"

HELM_NODE_SBOM_GENERATION = "capabilities.nodeSbomGeneration"
HELM_NODE_SBOM_GENERATION_ENABLED = "enable"
HELM_NODE_SBOM_GENERATION_DISABLED = "disable"

HELM_SYNC_SBOM = "capabilities.syncSBOM"
HELM_SYNC_SBOM_ENABLED = "enable"
HELM_SYNC_SBOM_DISABLED = "disable"

# relevancy feature
HELM_NETWORK_POLICY_FEATURE = "capabilities.networkPolicyService"
HELM_NODE_AGENT_LEARNING_PERIOD = "nodeAgent.config.learningPeriod"
HELM_NODE_AGENT_MAX_LEARNING_PERIOD = "nodeAgent.config.maxLearningPeriod"
HELM_NODE_AGENT_UPDATE_PERIOD = "nodeAgent.config.updatePeriod"
HELM_RELEVANCY_FEATURE = "capabilities.relevancy"
HELM_RELEVANCY_FEATURE_ENABLED = "enable"
HELM_RELEVANCY_FEATURE_DISABLED = "disable"
HELM_MAX_IMAGE_SIZE = "kubevuln.config.maxImageSize"
HELM_SCAN_TIMEOUT = "kubevuln.config.scanTimeout"
HELM_OFFLINE_VULN_DB = "grypeOfflineDB.enabled"
FILTERED_CVES_KEY = "withRelevancy"
ALL_CVES_KEY = "AllCVEs"

# in cluster limits
HELM_NODE_AGENT_REQ_CPU = "nodeAgent.resources.requests.cpu"
HELM_NODE_AGENT_LIMITS_CPU = "nodeAgent.resources.limits.cpu"
HELM_NODE_AGENT_REQ_MEMORY = "nodeAgent.resources.requests.memory"
HELM_NODE_AGENT_LIMITS_MEMORY = "nodeAgent.resources.limits.memory"
HELM_STORAGE_REQ_CPU = "storage.resources.requests.cpu"
HELM_STORAGE_LIMITS_CPU = "storage.resources.limits.cpu"
HELM_STORAGE_REQ_MEMORY = "storage.resources.requests.memory"
HELM_STORAGE_LIMITS_MEMORY = "storage.resources.limits.memory"

# cli arguments
CREATE_TEST_FIRST_TIME_RESULTS = "create_first_time_results"

RUNTIME_INCIDENT_RESPONSE_TYPE_KILL = "Kill"
RUNTIME_INCIDENT_RESPONSE_TYPE_PAUSE = "Pause"
RUNTIME_INCIDENT_RESPONSE_TYPE_STOP = "Stop"
RUNTIME_INCIDENT_RESPONSE_TYPE_APPLY_NETWORK_POLICY = "ApplyNetworkPolicy"
RUNTIME_INCIDENT_RESPONSE_TYPE_APPLY_SECCOMP_PROFILE = "ApplySeccompProfile"

RUNTIME_INCIDENT_APPLIED_STATUS_SUCCESS = "Success"
RUNTIME_INCIDENT_APPLIED_STATUS_FAILED = "Failed"

class Statistics(object):
    clear_state = "clear"
    attached_state = "attached"
    signed_state = "signed"
    testing_state = "test"
    final_state = "final"

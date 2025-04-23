OLD_CLUSTER_NAME = 'afek-cluster'
OLD_INCIDENT_NAME = 'Unexpected process launched'


MALWARE_INCIDENT_MD5 = 'bf454dc9a0f3d7b0584d124c0f12afe6'
MALICIOUS_DOMAIN = 'sodiumlaurethsulfatedesyroyer.com'

CDR_ALERT_TYPE = 3

class NodeAgentK8s:
    NAMESPACE = "kubescape"
    CONFIGMAP_NAME = "node-agent"
    NAME = "node-agent"
    JSON_KEY = "config.json"
    TEST_MODE = {"testMode": "true"}
    KIND = "DaemonSet"
    

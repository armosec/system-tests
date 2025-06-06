import random
from tests_scripts.workflows.workflows import Workflows

from tests_scripts.workflows.utils import (
    SYSTEM_HEALTH,
    SYSTEM_HEALTH_WORKFLOW_NAME_SLACK,
    get_env,
    NOTIFICATIONS_SVC_DELAY_FIRST_SCAN,
    EXPECTED_CREATE_RESPONSE,
    SLACK_CHANNEL_NAME,
    SECURITY_RISKS,
    SECURITY_RISKS_ID,
    VULNERABILITIES,
    SEVERITIES_MEDIUM,
    SEVERITIES_HIGH,
    VULNERABILITIES_WORKFLOW_NAME_SLACK,
    SECURITY_RISKS_WORKFLOW_NAME_SLACK,
    COMPLIANCE_WORKFLOW_NAME_SLACK,
    COMPLIANCE
)
from systest_utils import Logger, TestUtil
import time
from infrastructure import KubectlWrapper
from systest_utils import Logger, TestUtil



class WorkflowsSlackNotifications(Workflows):

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                 kubernetes_obj=kubernetes_obj)
        self.fw_name = None
        self.cluster = None
        self.wait_for_agg_to_end = False
        self.helm_kwargs = {
          
        }



    def start(self):
        """
        Agenda:
        1. Post custom framework
        2. Create new workflows
        3. Validate workflows created successfully
        4. Apply deployment
        5. Install kubescape with helm-chart
        6. Trigger first scan
        7. Apply second deployment
        8. Update custom framework
        9. Add SA to cluster-admin
        10. Trigger second scan
        11. Assert all messages sent
        12. Cleanup
        """

        
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'
        self.cluster, self.namespace = self.setup(apply_services=False)

        rand = str(random.randint(10000000, 99999999))
        
        Logger.logger.info("Stage 1: Post custom framework")
        security_risks_workflow_slack = SECURITY_RISKS_WORKFLOW_NAME_SLACK + self.cluster + "_" + rand
        vulnerabilities_workflow_slack = VULNERABILITIES_WORKFLOW_NAME_SLACK + self.cluster + "_" + rand
        compliance_workflow_slack = COMPLIANCE_WORKFLOW_NAME_SLACK + self.cluster + "_" + rand
        system_health_workflow_slack = SYSTEM_HEALTH_WORKFLOW_NAME_SLACK + self.cluster + "_" + rand
        ks_custom_fw, fw = self.post_custom_framework(framework_file="system-test-framework-high-comp.json",
                                           cluster_name=self.cluster)
        self.fw_name = ks_custom_fw['name']
        
        Logger.logger.info("Stage 2: Create new workflows")
        workflow_body = self.build_securityRisk_workflow_body(name=security_risks_workflow_slack, severities=SEVERITIES_MEDIUM, channel_name=SLACK_CHANNEL_NAME, channel_id=get_env("SLACK_CHANNEL_ID"), cluster=self.cluster, namespace=self.namespace, category=SECURITY_RISKS, securityRiskIDs=SECURITY_RISKS_ID)
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        workflow_body = self.build_vulnerabilities_workflow_body(name=vulnerabilities_workflow_slack, severities=SEVERITIES_HIGH, channel_name=SLACK_CHANNEL_NAME, channel_id=get_env("SLACK_CHANNEL_ID"), cluster=self.cluster, namespace=self.namespace, category=VULNERABILITIES, cvss=6)
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        workflow_body = self.build_compliance_workflow_body(name=compliance_workflow_slack, channel_name=SLACK_CHANNEL_NAME, channel_id=get_env("SLACK_CHANNEL_ID"), cluster=self.cluster, namespace=self.namespace, category=COMPLIANCE, driftPercentage=15)
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        workflow_body = self.build_system_health_workflow_body(name=system_health_workflow_slack, channel_name=SLACK_CHANNEL_NAME, channel_id=get_env("SLACK_CHANNEL_ID"), cluster=self.cluster, namespace=self.namespace, category=SYSTEM_HEALTH, cluster_status=["healthy", "degraded", "disconnected"])
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        before_test_message_ts = time.time()

        Logger.logger.info("Stage 3: Validate workflows created successfully")
        guid = self.validate_workflow(vulnerabilities_workflow_slack, SLACK_CHANNEL_NAME)
        self.add_workflow_test_guid(guid)
        guid = self.validate_workflow(security_risks_workflow_slack, SLACK_CHANNEL_NAME)
        self.add_workflow_test_guid(guid)
        guid = self.validate_workflow(compliance_workflow_slack, SLACK_CHANNEL_NAME)
        self.add_workflow_test_guid(guid)
        guid = self.validate_workflow(system_health_workflow_slack, SLACK_CHANNEL_NAME)
        self.add_workflow_test_guid(guid)

        Logger.logger.info('Stage 4: Apply deployment')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=self.namespace)
        self.verify_all_pods_are_running(namespace=self.namespace, workload=workload_objs, timeout=240)

        Logger.logger.info('Stage 6: Install kubescape with helm-chart')
        self.install_kubescape(self.helm_kwargs)

        report_guid_init = self.get_report_guid(
            cluster_name=self.cluster, wait_to_result=True, framework_name="AllControls"
        )


        Logger.logger.info('Stage 7: Trigger first scan')
        self.backend.create_kubescape_job_request(cluster_name=self.cluster, framework_list=[self.fw_name])

        report_guid_first = self.get_report_guid(
            cluster_name=self.cluster, wait_to_result=True, framework_name=self.fw_name, old_report_guid=report_guid_init
        )
        TestUtil.sleep(NOTIFICATIONS_SVC_DELAY_FIRST_SCAN, "waiting for first scan to be saved in notification service")

        
        Logger.logger.info('Stage 8: Apply second deployment')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments1"], namespace=self.namespace)
        self.verify_all_pods_are_running(namespace=self.namespace, workload=workload_objs, timeout=240)
        

        Logger.logger.info('Stage 9: Update custom framework')
        self.put_custom_framework(framework_file="system-test-framework-low-comp.json",
                                  framework_guid=fw['guid'], cluster_name=self.cluster)

        Logger.logger.info('Stage 10: Add SA to cluster-admin')
        KubectlWrapper.add_new_service_account_to_cluster_admin(service_account="service-account",
                                                                namespace=self.namespace)

        Logger.logger.info('Stage 11: Trigger second scan')
        self.backend.create_kubescape_job_request(cluster_name=self.cluster, framework_list=[self.fw_name])
        report_guid_second = self.get_report_guid(
            cluster_name=self.cluster, wait_to_result=True, framework_name=self.fw_name, old_report_guid=report_guid_first
        )
        
        Logger.logger.info('Stage 12: Assert all messages sent')
        self.assert_messages_sent(before_test_message_ts, self.cluster, self.namespace)

        Logger.logger.info('Stage 13: Cleanup')
        return self.cleanup()
    

    def cleanup(self, **kwargs):
        if self.fw_name:
            self.wait_for_report(report_type=self.backend.delete_custom_framework, framework_name=self.fw_name)
        return super().cleanup(**kwargs)
    
    
    def post_custom_framework(self, framework_file, cluster_name, framework_name = None):
        framework_name, ks_custom_fw = self.create_ks_custom_fw(cluster_name=cluster_name,
                                                                framework_file=framework_file,
                                                                custom_framework_name=framework_name)

        report_fw, _ = self.wait_for_report(report_type=self.backend.post_custom_framework, fw_object=ks_custom_fw)
        return ks_custom_fw, report_fw
      
    def put_custom_framework(self, framework_file, framework_guid: str, cluster_name: str):
        framework_name, ks_custom_fw = self.create_ks_custom_fw(cluster_name=cluster_name,
                                                                framework_file=framework_file,
                                                                framework_guid=framework_guid)
        report_fw, _ = self.wait_for_report(report_type=self.backend.put_custom_framework, fw_object=ks_custom_fw)
        return ks_custom_fw, report_fw
    
    def assert_security_risks_message_sent(self, messages, cluster, namespace):
        found = 0
        for message in messages:
            message_string = str(message)
            if "Risk:" in message_string and cluster in message_string and namespace in message_string:
                found += 1
        assert found > 0, "expected to have at least one security risk message"

    def assert_vulnerability_message_sent(self, messages, cluster, namespace):
        found = 0
        for message in messages:
            message_string = str(message)
            if "New Vulnerability found" in message_string and cluster in message_string and ("http1" in message_string or "http2" in message_string) and namespace in message_string:
                found += 1
        assert found > 0, "expected to have at least one vulnerability message"

    def assert_misconfiguration_message_sent(self, messages, cluster):
        found = 0
        for message in messages:
            message_string = str(message)
            if "Your compliance score has decreased by" in message_string and cluster in message_string:
                found += 1
        assert found > 0, f"expected to have exactly one new misconfiguration message, found {found}"

    def assert_system_health_message_sent(self, messages, cluster, status):
        if status == "healthy":
            expected_message = "Cluster successfully connected"
        elif status == "degraded":
            expected_message = "Cluster degraded"
        elif status == "disconnected":
            expected_message = "Cluster disconnected"
        else:
            raise ValueError(f"Invalid status: {status}")
        
        found = 0
        for message in messages:
            message_string = str(message)
            if expected_message in message_string and cluster in message_string:
                found += 1
        assert found > 0, "expected to have at least one system health message"
    
    def assert_messages_sent(self, begin_time, cluster, namespace, attempts=30, sleep_time=10):
        found_security_risks =  False
        found_vulnerabilities = False
        found_misconfigurations = False 
        found_system_health = False

        for i in range(attempts):
            if found_security_risks and found_vulnerabilities and found_misconfigurations and found_system_health:
                break
            try:
                messages = self.test_obj["getMessagesFunc"](begin_time)
                found = str(messages).count(cluster)
                assert found > 1, f"expected to have at least 1 messages, found {found}"
                if not found_security_risks:
                    self.assert_security_risks_message_sent(messages, cluster, namespace)
                    Logger.logger.info("Security risks message sent")
                    found_security_risks = True
                if not found_vulnerabilities:
                    self.assert_vulnerability_message_sent(messages, cluster, namespace)
                    Logger.logger.info("Vulnerabilities message sent")
                    found_vulnerabilities = True
                if not found_misconfigurations:
                    self.assert_misconfiguration_message_sent(messages, cluster)
                    Logger.logger.info("Misconfigurations message sent")
                    found_misconfigurations = True
                if not found_system_health:
                    self.assert_system_health_message_sent(messages, cluster, "healthy") 
                    Logger.logger.info("System health message sent")
                    found_system_health = True
                    break

            except AssertionError as e:
                Logger.logger.info(f"iteration: {i}: {e}")
                if i == attempts - 1:
                    raise
                TestUtil.sleep(sleep_time, f"iteration: {i}, waiting additional {sleep_time} seconds for messages to arrive")
    



    
    def build_securityRisk_workflow_body(self, name, severities, channel_name,  channel_id, cluster, namespace, category, securityRiskIDs, guid=None):
        workflow_body = { 
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": name,
            "scope": [
                {
                    "cluster": cluster,
                    "namespace": namespace
                }
            ],
            "conditions": [
                {
                    "category": category,
                    "parameters": {
                        "severities": severities,
                        "securityRiskIDs": [securityRiskIDs]
                    
                    }
                }
            ],
            "notifications": [
                {
                    "provider": "slack",
                    "slackChannels": [
                        {
                            "id": channel_id,
                            "name": channel_name
                        }
                    ]
                }
            ]
        }
        return workflow_body
    
    def build_vulnerabilities_workflow_body(self, name, severities, channel_name, channel_id, cluster, namespace, category, cvss, guid=None):
        workflow_body = { 
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": name,
            "scope": [
                {
                    "cluster": cluster,
                    "namespace": namespace
                }
            ],
            "conditions": [
                {
                    "category": category,
                    "parameters": {
                        "severities": severities,
                        "cvss": cvss,
                        "inUse": True,          
                        "fixable": True         
                    }
                }
            ],
            "notifications": [
                {
                    "provider": "slack",
                    "slackChannels": [
                        {
                            "id": channel_id,
                            "name": channel_name
                        }
                    ]
                }
            ]
        }
        return workflow_body
    
    def build_compliance_workflow_body(self, name, channel_name, channel_id, cluster, namespace, category, driftPercentage,  guid=None):
        workflow_body = { 
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": name,
            "scope": [
                {
                    "cluster": cluster
                }
            ],
            "conditions": [
                {
                    "category": category,
                    "parameters": {
                        "driftPercentage": driftPercentage
                    }
                }
            ],
            "notifications": [
                {
                    "provider": "slack",
                    "slackChannels": [
                        {
                            "id": channel_id,
                            "name": channel_name
                        }
                    ]
                }
            ]
        }
        return workflow_body

    def build_system_health_workflow_body(self, name, channel_name, channel_id, cluster, namespace, category, cluster_status, guid=None):
        workflow_body = { 
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": name,
            "scope": [
                {
                    "cluster": cluster
                }
            ],
            "conditions": [
                {
                    "category": category,
                    "parameters": {
                        "clusterStatus": cluster_status
                    }
                }
            ],
            "notifications": [
                {
                    "provider": "slack",
                    "slackChannels": [
                        {
                            "id": channel_id,
                            "name": channel_name
                        }
                    ]
                }
            ]
        }

        return workflow_body
         
    
    def validate_workflow(self, expected_name, expected_slack_channel):
        workflows = self.backend.get_workflows()
        assert workflows["total"]["value"] >= 1, f"Expected total value to be greater or equal to 1, but got {workflows['total']['value']}"

        found = False
        for workflow in workflows["response"]:
            if workflow["name"] == expected_name:
                slack_channel = workflow["notifications"][0]["slackChannels"][0]["name"]
                assert slack_channel == expected_slack_channel, f"Expected slack channel {expected_slack_channel} but got {slack_channel}"

                found = True
                break

        assert found, f"Workflow with name {expected_name} not found"

        return workflow["guid"]
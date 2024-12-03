from tests_scripts.workflows.workflows import Workflows

from tests_scripts.workflows.utils import (
    get_env,
    NOTIFICATIONS_SVC_DELAY,
    NOTIFICATIONS_SVC_DELAY_FIRST_SCAN,
    EXPECTED_CREATE_RESPONSE,
    SLACK_CHANNEL_NAME,
    SECURITY_RISKS,
    SECURITY_RISKS_ID,
    VULNERABILITIES,
    SEVERITIES_CRITICAL,
    SEVERITIES_HIGH,
    VULNERABILITIES_WORKFLOW_NAME_SLACK,
    SECURITY_RISKS_WORKFLOW_NAME_SLACK,
    COMPLIANCE_WORKFLOW_NAME_SLACK,
    COMPLIANCE
)
from systest_utils import Logger, TestUtil
import time
from infrastructure import KubectlWrapper
from systest_utils import Logger, statics, TestUtil



class WorkflowsSlackNotifications(Workflows):

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(Workflows, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                 kubernetes_obj=kubernetes_obj)
        self.fw_name = None
        self.cluster = None
        self.wait_for_agg_to_end = False


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
        self.cluster, namespace = self.setup(apply_services=False)
        
        Logger.logger.info("Stage 1: Post custom framework")
        self.fw_name = "systest-fw-" + self.cluster
        _, fw = self.post_custom_framework(framework_file="system-test-framework-high-comp.json",
                                           cluster_name=self.cluster)

        
        Logger.logger.info("Stage 2: Create new workflows")
        workflow_body = self.build_securityRisk_workflow_body(name=SECURITY_RISKS_WORKFLOW_NAME_SLACK + self.cluster, severities=SEVERITIES_CRITICAL, channel_name=SLACK_CHANNEL_NAME, channel_id=get_env("SLACK_CHANNEL_ID"), cluster=self.cluster, namespace=namespace, category=SECURITY_RISKS, securityRiskIDs=SECURITY_RISKS_ID)
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        workflow_body = self.build_vulnerabilities_workflow_body(name=VULNERABILITIES_WORKFLOW_NAME_SLACK + self.cluster, severities=SEVERITIES_HIGH, channel_name=SLACK_CHANNEL_NAME, channel_id=get_env("SLACK_CHANNEL_ID"), cluster=self.cluster, namespace=namespace, category=VULNERABILITIES, cvss=6)
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        workflow_body = self.build_compliance_workflow_body(name=COMPLIANCE_WORKFLOW_NAME_SLACK + self.cluster, channel_name=SLACK_CHANNEL_NAME, channel_id=get_env("SLACK_CHANNEL_ID"), cluster=self.cluster, namespace=namespace, category=COMPLIANCE, driftPercentage=15)
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        before_test_message_ts = time.time()

        Logger.logger.info("Stage 3: Validate workflows created successfully")
        self.validate_workflow(VULNERABILITIES_WORKFLOW_NAME_SLACK + self.cluster, SLACK_CHANNEL_NAME)
        self.validate_workflow(SECURITY_RISKS_WORKFLOW_NAME_SLACK + self.cluster, SLACK_CHANNEL_NAME)
        self.validate_workflow(COMPLIANCE_WORKFLOW_NAME_SLACK + self.cluster, SLACK_CHANNEL_NAME)

        Logger.logger.info('Stage 4: Apply deployment')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=240)

        Logger.logger.info('Stage 6: Install kubescape with helm-chart')
        self.install_kubescape()


        Logger.logger.info('Stage 7: Trigger first scan')
        self.backend.create_kubescape_job_request(cluster_name=self.cluster, framework_list=[self.fw_name])
        TestUtil.sleep(NOTIFICATIONS_SVC_DELAY_FIRST_SCAN, "waiting for first scan to be saved in notification service")
        
        Logger.logger.info('Stage 8: Apply second deployment')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments1"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=240)
        

        Logger.logger.info('Stage 9: Update custom framework')
        self.put_custom_framework(framework_file="system-test-framework-low-comp.json",
                                  framework_guid=fw['guid'], cluster_name=self.cluster)

        Logger.logger.info('Stage 10: Add SA to cluster-admin')
        KubectlWrapper.add_new_service_account_to_cluster_admin(service_account="service-account",
                                                                namespace=namespace)

        Logger.logger.info('Stage 11: Trigger second scan')
        self.backend.create_kubescape_job_request(cluster_name=self.cluster, framework_list=[self.fw_name])
        TestUtil.sleep(NOTIFICATIONS_SVC_DELAY, "waiting for second scan to be saved in notification service")
        
        Logger.logger.info('Stage 12: Assert all messages sent')
        self.assert_messages_sent(before_test_message_ts, self.cluster)

        Logger.logger.info('Stage 13: Cleanup')
        return self.cleanup()
    

    def cleanup(self, **kwargs):
        self.delete_and_assert_workflow(self.return_workflow_guid(SECURITY_RISKS_WORKFLOW_NAME_SLACK + self.cluster))
        self.delete_and_assert_workflow(self.return_workflow_guid(VULNERABILITIES_WORKFLOW_NAME_SLACK + self.cluster))
        self.delete_and_assert_workflow(self.return_workflow_guid(COMPLIANCE_WORKFLOW_NAME_SLACK + self.cluster))
        return super().cleanup(**kwargs)
    
    
    def post_custom_framework(self, framework_file, cluster_name: str):
        framework_name, ks_custom_fw = self.create_ks_custom_fw(cluster_name=cluster_name,
                                                                framework_file=framework_file)
        report_fw, _ = self.wait_for_report(report_type=self.backend.post_custom_framework, fw_object=ks_custom_fw)
        return ks_custom_fw, report_fw
      
    def put_custom_framework(self, framework_file, framework_guid: str, cluster_name: str):
        framework_name, ks_custom_fw = self.create_ks_custom_fw(cluster_name=cluster_name,
                                                                framework_file=framework_file,
                                                                framework_guid=framework_guid)
        report_fw, _ = self.wait_for_report(report_type=self.backend.put_custom_framework, fw_object=ks_custom_fw)
        return ks_custom_fw, report_fw
    
    def assert_security_risks_message_sent(self, messages, cluster):
        found = 0
        for message in messages:
            message_string = str(message)
            if "Risk:" in message_string and cluster in message_string:
                found += 1
        assert found > 0, "expected to have at least one security risk message"

    def assert_vulnerability_message_sent(self, messages, cluster):
        found = 0
        for message in messages:
            message_string = str(message)
            if "New Vulnerability found" in message_string and cluster:
                found += 1
        assert found > 0, "expected to have at least one vulnerability message"

    def assert_misconfiguration_message_sent(self, messages, cluster):
        found = 0
        for message in messages:
            message_string = str(message)
            if "Your compliance score has decreased by" in message_string and cluster in message_string:
                found += 1
        assert found > 0, f"expected to have exactly one new misconfiguration message, found {found}"


    
    def assert_messages_sent(self, begin_time, cluster):
        for i in range(5):
            try:
                messages = self.test_obj["getMessagesFunc"](begin_time)
                found = str(messages).count(cluster)
                assert found > 1, f"expected to have at least 1 messages, found {found}"
                self.assert_security_risks_message_sent(messages, cluster)
                self.assert_vulnerability_message_sent(messages, cluster)
                self.assert_misconfiguration_message_sent(messages, cluster)
            except AssertionError:
                if i == 0:
                    raise
                TestUtil.sleep(30, "waiting additional 30 seconds for messages to arrive")

    
    def install_kubescape(self, helm_kwargs: dict = None):
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
    

    def create_and_assert_workflow(self, workflow_body, expected_response, update=False):
        if update:
            workflow_res = self.backend.update_workflow(body=workflow_body)
        else:
            workflow_res = self.backend.create_workflow(body=workflow_body)
        
        
        assert workflow_res == expected_response, f"Expected {expected_response}, but got {workflow_res['response']}"
        return workflow_res
    
    def delete_and_assert_workflow(self, workflow_guid):
        workflow_delete_res = self.backend.delete_workflow(workflow_guid)
        assert workflow_delete_res == "Workflow deleted", f"Expected 'Workflow deleted', but got {workflow_delete_res['response']}"
        workflows = self.backend.get_workflows()["response"]
        for workflow in workflows:
            assert workflow["guid"] != workflow_guid, f"Expected workflow with guid {workflow_guid} to be deleted, but it still exists"


    def return_workflow_guid(self, workflow_name):
        workflows = self.backend.get_workflows()["response"]
        for workflow in workflows:
            if workflow["name"] == workflow_name:
                return workflow["guid"]
        print(f"Workflow with name {workflow_name} not found")
        return None
    
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
                    "cluster": cluster,
                    "namespace": namespace
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
from tests_scripts.workflows.workflows import Workflows
from tests_scripts.workflows.utils import (
    SYSTEM_HEALTH,
    SYSTEM_HEALTH_WORKFLOW_NAME_TEAMS,
    get_env,
    NOTIFICATIONS_SVC_DELAY_FIRST_SCAN,
    EXPECTED_CREATE_RESPONSE,
    TEAMS_CHANNEL_NAME,
    SECURITY_RISKS,
    SECURITY_RISKS_ID,
    VULNERABILITIES,
    SEVERITIES_MEDIUM,
    SEVERITIES_HIGH,
    VULNERABILITIES_WORKFLOW_NAME_TEAMS,
    SECURITY_RISKS_WORKFLOW_NAME_TEAMS,
    COMPLIANCE_WORKFLOW_NAME_TEAMS,
    COMPLIANCE,
    WEBHOOK_NAME
)
from systest_utils import Logger, TestUtil
import time
from infrastructure import KubectlWrapper
from systest_utils import Logger, TestUtil
import random




class WorkflowsTeamsNotifications(Workflows):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                 kubernetes_obj=kubernetes_obj)
        self.fw_name = None
        self.cluster = None
        self.wait_for_agg_to_end = False
        self.channel_guid = None


    def start(self):
        """
        Agenda:
        1. Post custom framework
        2. Create webhook
        3. Create new workflows
        4. Validate workflows created successfully
        5. Apply deployment
        6. Install kubescape with helm-chart
        7. Trigger first scan
        8. Apply second deployment
        9. Update custom framework
        10. Add SA to cluster-admin
        11. Trigger second scan
        12. Assert all messages sent
        13. Cleanup
        """

        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'
        self.cluster, namespace = self.setup(apply_services=False)

        rand = str(random.randint(10000000, 99999999))

        
        Logger.logger.info("Stage 1: Post custom framework")
        ks_custom_fw, fw = self.post_custom_framework(framework_file="system-test-framework-high-comp.json",
                                           cluster_name=self.cluster)
        self.fw_name = ks_custom_fw['name']
        
        Logger.logger.info("Stage 2: Create webhook")
        self.webhook_name = WEBHOOK_NAME + self.cluster + "_" + rand
        self.create_teams_webhook(name=self.webhook_name)
        self.channel_guid = self.get_channel_guid_by_name(self.webhook_name)
        
        Logger.logger.info("Stage 3: Create new workflows")
        workflow_body = self.build_securityRisk_workflow_body(name=SECURITY_RISKS_WORKFLOW_NAME_TEAMS + self.cluster, severities=SEVERITIES_MEDIUM, channel_name=TEAMS_CHANNEL_NAME, channel_guid=self.channel_guid, cluster=self.cluster, namespace=namespace, category=SECURITY_RISKS, webhook_url=get_env("CHANNEL_WEBHOOK"), securityRiskIDs=SECURITY_RISKS_ID)
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        workflow_body = self.build_vulnerabilities_workflow_body(name=VULNERABILITIES_WORKFLOW_NAME_TEAMS + self.cluster, severities=SEVERITIES_HIGH, channel_name=TEAMS_CHANNEL_NAME, channel_guid=self.channel_guid, cluster=self.cluster, namespace=namespace, category=VULNERABILITIES, cvss=6, webhook_url=get_env("CHANNEL_WEBHOOK"))
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        workflow_body = self.build_compliance_workflow_body(name=COMPLIANCE_WORKFLOW_NAME_TEAMS + self.cluster, channel_name=TEAMS_CHANNEL_NAME, channel_guid=self.channel_guid, cluster=self.cluster, namespace=namespace, category=COMPLIANCE, driftPercentage=15, webhook_url=get_env("CHANNEL_WEBHOOK"))
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        workflow_body = self.build_system_health_workflow_body(name=SYSTEM_HEALTH_WORKFLOW_NAME_TEAMS + self.cluster, channel_name=TEAMS_CHANNEL_NAME, channel_guid=self.channel_guid, cluster=self.cluster, category=SYSTEM_HEALTH, cluster_status=["healthy", "degraded", "disconnected"], webhook_url=get_env("CHANNEL_WEBHOOK"))
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        before_test_message_ts = time.time()
        Logger.logger.info(f"before_test_message_ts: {before_test_message_ts}")

        Logger.logger.info("Stage 4: Validate workflows created successfully")
        guid = self.validate_workflow(VULNERABILITIES_WORKFLOW_NAME_TEAMS + self.cluster, TEAMS_CHANNEL_NAME)
        self.add_workflow_test_guid(guid)
        guid = self.validate_workflow(SECURITY_RISKS_WORKFLOW_NAME_TEAMS + self.cluster, TEAMS_CHANNEL_NAME)
        self.add_workflow_test_guid(guid)
        guid = self.validate_workflow(COMPLIANCE_WORKFLOW_NAME_TEAMS + self.cluster, TEAMS_CHANNEL_NAME)
        self.add_workflow_test_guid(guid)
        guid = self.validate_workflow(SYSTEM_HEALTH_WORKFLOW_NAME_TEAMS + self.cluster, TEAMS_CHANNEL_NAME)
        self.add_workflow_test_guid(guid)

        Logger.logger.info('Stage 5: Apply deployment')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        self.verify_all_pods_are_running(namespace=namespace, workload=workload_objs, timeout=240)

        Logger.logger.info('Stage 6: Install kubescape with helm-chart')
        self.install_kubescape()

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
        report_guid_second = self.get_report_guid(
            cluster_name=self.cluster, wait_to_result=True, framework_name=self.fw_name, old_report_guid=report_guid_first
        )
        
        Logger.logger.info('Stage 12: Assert all messages sent')
        self.assert_messages_sent(before_test_message_ts, self.cluster, attempts=50, sleep_time=10)

        Logger.logger.info('Stage 13: Cleanup')
        return self.cleanup()
    

    
    def cleanup(self, **kwargs):
        super().cleanup_workflows()
        if self.channel_guid:
            try:
                self.delete_channel_by_guid(self.channel_guid)
                Logger.logger.info(f"Deleted webhook channel with guid {self.channel_guid}")
            except Exception as e:
                Logger.logger.error(f"Failed to delete channel with name {self.webhook_name} and guid {self.channel_guid}, got exception {e}")
        if self.fw_name:
            self.wait_for_report(report_type=self.backend.delete_custom_framework, framework_name=self.fw_name)
        return super().cleanup(**kwargs)
    
    def create_teams_webhook(self, name):
        webhook_body = {
            "guid": "",
            "name": name,
            "webhookURL": get_env("CHANNEL_WEBHOOK")
        }
        try:
            r = self.backend.create_teams_webhook(webhook_body)
        except (Exception, BaseException) as e:
            if "already exists" in str(e):
                Logger.logger.info("Teams channel already exists")
                return
            raise e
        
        assert r == "Teams channel created", f"Expected 'Teams channel created', but got {r['response']}"

    def get_channel_guid_by_name(self, channel_name):
        channels = self.backend.get_teams_webhooks()
        for channel in channels:
            if channel["name"] == channel_name:
                return channel["guid"]
        return "Channel not found"
    

    def delete_channel_by_guid(self, channel_guid):
        r = self.backend.delete_teams_webhook(body={"innerFilters": [{"guid": channel_guid}]})
        assert r == "Teams channel deleted", f"Expected 'Teams channel deleted', but got {r['response']}"
        channels = self.backend.get_teams_webhooks()
        for channel in channels:
            if channel["guid"] == channel_guid:
                return f"Channel with guid {channel_guid} not deleted"
        return "Channel deleted"


    
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
            if "New Vulnerability found" in message_string and cluster in message_string and ("http1" in message_string or "http2" in message_string):
                found += 1
        assert found > 0, "expected to have at least one vulnerability message"

    def assert_misconfiguration_message_sent(self, messages, cluster):
        found = 0
        for message in messages:
            message_string = str(message)
            # split message check for debug
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
    
    def assert_messages_sent(self, begin_time, cluster, attempts=30, sleep_time=10):
        found_security_risk = False
        found_vulnerability = False
        found_misconfiguration = False
        found_system_health = False
        for i in range(attempts):
            if found_misconfiguration and found_security_risk and found_vulnerability and found_system_health:
                break
            try:
                messages = self.test_obj["getMessagesFunc"](begin_time)
                found = str(messages).count(cluster)
                assert found > 1, f"expected to have at least 1 messages, found {found}"
                Logger.logger.info(f"number of messages found: {found}")

                if not found_system_health:
                    self.assert_system_health_message_sent(messages, cluster, "healthy")
                    Logger.logger.info("System health message found")
                    found_system_health = True
                    break

                if not found_security_risk:
                    self.assert_security_risks_message_sent(messages, cluster)
                    Logger.logger.info("Security risks message found")
                    found_security_risk = True
                if not found_vulnerability:
                    self.assert_vulnerability_message_sent(messages, cluster)
                    Logger.logger.info("Vulnerability message found")
                    found_vulnerability = True
                if not found_misconfiguration:
                    self.assert_misconfiguration_message_sent(messages, cluster)
                    Logger.logger.info("Misconfiguration message found")
                    found_misconfiguration = True
                    break
            except AssertionError as e:
                Logger.logger.info(f"iteration: {i}: {e}")
                if i == attempts - 1:
                    raise
                TestUtil.sleep(sleep_time, f"iteration: {i}, waiting additional {sleep_time} seconds for messages to arrive")

    
    def build_securityRisk_workflow_body(self, name, severities, channel_name,  channel_guid, cluster, namespace, category, webhook_url, securityRiskIDs, guid=None):
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
                    "provider": "teams",
                    "teamsChannels": [
                        {
                            "guid": channel_guid,
                            "name": channel_name,
                            "webhookURL": webhook_url
                        }
                    ]
                }
            ]
        }
        return workflow_body
    
    def build_vulnerabilities_workflow_body(self, name, severities, channel_name, channel_guid, cluster, namespace, category, cvss, webhook_url, guid=None):
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
                    "provider": "teams",
                    "teamsChannels": [
                        {
                            "guid": channel_guid,
                            "name": channel_name,
                            "webhookURL": webhook_url
                        }
                    ]
                }
            ]
        }
        return workflow_body
    
    def build_compliance_workflow_body(self, name, channel_name, channel_guid, cluster, namespace, category, driftPercentage, webhook_url, guid=None):
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
                    "provider": "teams",
                    "teamsChannels": [
                        {
                            "guid": channel_guid,
                            "name": channel_name,
                            "webhookURL": webhook_url
                        }
                    ]
                }
            ]
        }
        return workflow_body
    
    def build_system_health_workflow_body(self, name, channel_name, channel_guid, cluster, category, cluster_status, webhook_url, guid=None):
        workflow_body = {
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": name,
            "scope": [
                {
                    "cluster": cluster,
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
                    "provider": "teams",
                    "teamsChannels": [
                        {
                            "guid": channel_guid,
                            "name": channel_name,
                            "webhookURL": webhook_url
                        }
                    ]
                }
            ]
        }
        return workflow_body
    
    def validate_workflow(self, expected_name, expected_teams_channel):
        workflows = self.backend.get_workflows()
        assert workflows["total"]["value"] >= 1, f"Expected total value to be greater or equal to 1, but got {workflows['total']['value']}"

        for workflow in workflows["response"]:
            if workflow["name"] == expected_name:
                teams_channel = workflow["notifications"][0]["teamsChannels"][0]["name"]
                assert teams_channel == expected_teams_channel, f"Expected Teams channel {expected_teams_channel} but got {teams_channel}"
                return workflow["guid"]

        raise AssertionError(f"Workflow with name {expected_name} not found")

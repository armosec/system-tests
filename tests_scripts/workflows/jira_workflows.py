from tests_scripts.workflows.workflows import Workflows
from tests_scripts.workflows.utils import (
    get_env,
    NOTIFICATIONS_SVC_DELAY_FIRST_SCAN,
    EXPECTED_CREATE_RESPONSE,
    JIRA_PROVIDER_NAME,
    SECURITY_RISKS,
    SECURITY_RISKS_ID,
    VULNERABILITIES,
    SEVERITIES_CRITICAL,
    SEVERITIES_HIGH,
    SEVERITIES_MEDIUM,
    VULNERABILITIES_WORKFLOW_NAME_JIRA,
    SECURITY_RISKS_WORKFLOW_NAME_JIRA,
    SECURITY_RISKS_ID
)
from systest_utils import Logger, TestUtil
import time
import json
from infrastructure import KubectlWrapper
from systest_utils import Logger, statics, TestUtil




class WorkflowsJiraNotifications(Workflows):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(Workflows, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                 kubernetes_obj=kubernetes_obj)
        self.fw_name = None
        self.cluster = None
        self.wait_for_agg_to_end = False


    def start(self):
        """
        Agenda:
        1. Create new workflows
        2. Validate workflows created successfully
        3. Apply deployment
        4. Install kubescape with helm-chart
        5. Trigger first scan
        6. Assert jira ticket was created
        7. Cleanup
        """

        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'
        self.cluster, self.namespace = self.setup(apply_services=False)
        
                
        Logger.logger.info("Stage 1: Create new workflows")
        workflow_body = self.build_securityRisk_workflow_body(name=SECURITY_RISKS_WORKFLOW_NAME_JIRA + self.cluster, severities=SEVERITIES_MEDIUM, siteId=get_env("JIRA_SITE_ID"), projectId=get_env("JIRA_PROJECT_ID"), cluster=self.cluster, namespace=None, category=SECURITY_RISKS, securityRiskIDs=SECURITY_RISKS_ID, issueTypeId=get_env("JIRA_ISSUE_TYPE_ID"))
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        workflow_body = self.build_vulnerabilities_workflow_body(name=VULNERABILITIES_WORKFLOW_NAME_JIRA + self.cluster, severities=SEVERITIES_HIGH, siteId=get_env("JIRA_SITE_ID"), projectId=get_env("JIRA_PROJECT_ID"), cluster=self.cluster, namespace=namespace, category=VULNERABILITIES, cvss=6, issueTypeId=get_env("JIRA_ISSUE_TYPE_ID"))
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)

        Logger.logger.info("Stage 2: Validate workflows created successfully")
        self.validate_workflow(SECURITY_RISKS_WORKFLOW_NAME_JIRA + self.cluster, JIRA_PROVIDER_NAME)
        self.validate_workflow(VULNERABILITIES_WORKFLOW_NAME_JIRA + self.cluster, JIRA_PROVIDER_NAME)

        Logger.logger.info('Stage 3: Apply deployment')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=self.namespace)
        self.verify_all_pods_are_running(namespace=self.namespace, workload=workload_objs, timeout=240)

        Logger.logger.info('Stage 4: Install kubescape with helm-chart')
        self.install_kubescape()
        time.sleep(60)

        Logger.logger.info('Stage 5: Trigger first scan')
        self.backend.create_kubescape_job_request(cluster_name=self.cluster, framework_list=[self.fw_name])
                     
        Logger.logger.info('Stage 6: Assert jira tickets was created')
        self.assert_jira_tickets_was_created(self.cluster)

        Logger.logger.info('Stage 7: Cleanup')
        return self.cleanup()
    

    def cleanup(self, **kwargs):
            self.delete_and_assert_workflow(self.return_workflow_guid(SECURITY_RISKS_WORKFLOW_NAME_JIRA + self.cluster))
            self.delete_and_assert_workflow(self.return_workflow_guid(VULNERABILITIES_WORKFLOW_NAME_JIRA + self.cluster))
            return super().cleanup(**kwargs)
    
    def assert_jira_tickets_was_created(self, cluster_name, attempts=20, sleep_time=30):
       
        vuln_body = {
            "innerFilters": [
                {
                    "severity": "High",
                    "cluster": cluster_name,
                    "namespace": self.namespace,
                    "cvssInfo.baseScore": "6|greater",
                    "isRelevant": "Yes"
                }
            ]
        }
        found_sr = False

        for i in range(attempts):
            try:
                if not found_sr:
                    r = self.backend.get_security_risks_list(cluster_name=cluster_name, namespace=self.namespace, security_risk_ids=[SECURITY_RISKS_ID])
                    r = r.text
                    self.assert_security_risks_jira_ticket_created(response=r, security_risk_id=SECURITY_RISKS_ID)
                    found_sr = True
                r2 = self.backend.get_vulns_v2(body=vuln_body, expected_results=1, scope=None)
                self.assert_vulnerability_jira_ticket_created(response=r2)
            except (AssertionError, Exception) as e:
                Logger.logger.info(f"iteration: {i}: {e}")
                if i == attempts - 1:
                    raise
                TestUtil.sleep(sleep_time, f"iteration: {i}, waiting additional {sleep_time} seconds for messages to arrive")
            
       
        

    
    
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
    
    def assert_security_risks_jira_ticket_created(self, response, security_risk_id):
        try:
            response_json = json.loads(response)
        except json.JSONDecodeError as e:
            raise AssertionError(f"Response is not valid JSON: {e}")

        risks = response_json.get("response", [])
        assert len(risks) > 0, "No security risks found in the response"

        for risk in risks:
            tickets = risk.get("tickets", [])
            assert len(tickets) > 0, f"No tickets associated with security risk with ID {security_risk_id}. response: {response}"

    def assert_vulnerability_jira_ticket_created(self, response):
        assert len(response) > 0, "No vulnerabilities found in the response"
        vulnerabilities_with_tickets = 0
        for risk in response:
            tickets = risk.get("tickets", [])
            if len(tickets) > 0:
                vulnerabilities_with_tickets += 1
        assert vulnerabilities_with_tickets > 0, "No vulnerabilities have associated tickets"


    def assert_vulnerability_message_sent(self, messages, cluster):
        found = 0
        for message in messages:
            message_string = str(message)
            if "New Vulnerability found" in message_string and cluster in message_string and "http1" in message_string:
                found += 1
        assert found > 0, "expected to have at least one vulnerability message"

    def assert_misconfiguration_message_sent(self, messages, cluster):
        found = 0
        for message in messages:
            message_string = str(message)
            if "Your compliance score has decreased by" in message_string and cluster in message_string:
                found += 1
        assert found > 0, f"expected to have exactly one new misconfiguration message, found {found}"


    
    def install_kubescape(self, helm_kwargs: dict = None):
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, replicas=9)
    

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
    
    def build_securityRisk_workflow_body(self, name, severities, siteId,  projectId, cluster, namespace, category, securityRiskIDs, issueTypeId, guid=None):
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
                    "provider": "jira",
                    "jiraTicketIdentifiers": [
                        {
                            "siteId": siteId,
                            "projectId": projectId,
                            "issueTypeId": issueTypeId,
                            "fields": {}
                        }
                    ]
                }
            ]
        }
        return workflow_body
    
    def build_vulnerabilities_workflow_body(self, name, severities, siteId, projectId, cluster, namespace, category, cvss, issueTypeId, guid=None):
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
                    "provider": "jira",
                    "jiraTicketIdentifiers": [
                        {
                            "siteId": siteId,
                            "projectId": projectId,
                            "issueTypeId": issueTypeId,
                            "fields": {}
                        }
                    ]
                }
            ]
        }
        return workflow_body
    
      
    def validate_workflow(self, expected_name, expected_provider):
        workflows = self.backend.get_workflows()
        assert workflows["total"]["value"] >= 1, f"Expected total value to be greater or equal to 1, but got {workflows['total']['value']}"

        found = False
        for workflow in workflows["response"]:
            if workflow["name"] == expected_name:
                provider = workflow["notifications"][0]["provider"]
                assert provider == expected_provider, f"Expected provider {expected_provider} but got {provider}"
                found = True
                break

        assert found, f"Workflow with name {expected_name} not found"


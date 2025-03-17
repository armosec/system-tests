from tests_scripts.workflows.workflows import Workflows
from tests_scripts.workflows.utils import (
    extract_text_from_adf,
    get_env,
    EXPECTED_CREATE_RESPONSE,
    JIRA_PROVIDER_NAME,
    SECURITY_RISKS,
    SECURITY_RISKS_ID,
    VULNERABILITIES,
    SEVERITIES_HIGH,
    SEVERITIES_MEDIUM,
    VULNERABILITIES_WORKFLOW_NAME_JIRA,
    SECURITY_RISKS_WORKFLOW_NAME_JIRA,
    SECURITY_RISKS_ID
)
import time
import json
from systest_utils import Logger, TestUtil, statics




class WorkflowsJiraNotifications(Workflows):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                 kubernetes_obj=kubernetes_obj)
        self.fw_name = None
        self.cluster = None
        self.wait_for_agg_to_end = False
        self.site_name = "cyberarmor-io"


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
        jiraCollaborationGUID = self.backend.get_jira_collaboration_guid_by_site_name(self.site_name)
        workflow_body = self.build_securityRisk_workflow_body(name=SECURITY_RISKS_WORKFLOW_NAME_JIRA + self.cluster, severities=SEVERITIES_MEDIUM, jiraCollaborationGUID=jiraCollaborationGUID, siteId=get_env("JIRA_SITE_ID"), projectId=get_env("JIRA_PROJECT_ID"), cluster=self.cluster, namespace=self.namespace, category=SECURITY_RISKS, securityRiskIDs=SECURITY_RISKS_ID, issueTypeId=get_env("JIRA_ISSUE_TYPE_ID"))
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        workflow_body = self.build_vulnerabilities_workflow_body(name=VULNERABILITIES_WORKFLOW_NAME_JIRA + self.cluster, severities=SEVERITIES_HIGH, jiraCollaborationGUID=jiraCollaborationGUID, siteId=get_env("JIRA_SITE_ID"), projectId=get_env("JIRA_PROJECT_ID"), cluster=self.cluster, namespace=self.namespace, category=VULNERABILITIES, cvss=6, issueTypeId=get_env("JIRA_ISSUE_TYPE_ID"))
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)
        before_test_message_ts = time.time()

        Logger.logger.info("Stage 2: Validate workflows created successfully")
        guid = self.validate_workflow(SECURITY_RISKS_WORKFLOW_NAME_JIRA + self.cluster, JIRA_PROVIDER_NAME)
        self.add_workflow_test_guid(guid)
        guid = self.validate_workflow(VULNERABILITIES_WORKFLOW_NAME_JIRA + self.cluster, JIRA_PROVIDER_NAME)
        self.add_workflow_test_guid(guid)

        Logger.logger.info('Stage 3: Apply deployment')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=self.namespace)
        self.verify_all_pods_are_running(namespace=self.namespace, workload=workload_objs, timeout=240)

        Logger.logger.info('Stage 4: Install kubescape with helm-chart')
        self.install_kubescape()
        time.sleep(60)

        Logger.logger.info('Stage 5: Trigger first scan')
        self.backend.create_kubescape_job_request(cluster_name=self.cluster, framework_list=[self.fw_name])
                     
        Logger.logger.info('Stage 6: Assert jira tickets was created')
        self.assert_jira_tickets_was_created(before_test_message_ts, self.cluster)

        Logger.logger.info('Stage 7: Cleanup')
        return self.cleanup()
    

    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)
    
    
    def assert_jira_tickets_was_created(self, begin_time, cluster_name, attempts=20, sleep_time=20):
       
        vuln_body = {
            "innerFilters": [
                {
                    "severity": "High",
                    "cluster": cluster_name,
                    "namespace": self.namespace,
                    "cvssInfo.baseScore": "6|greater",
                    "isRelevant": "Yes",
                    "workload": "http1",
                }
            ]
        }
        found_sr = False
        found_vuln = False

        for i in range(attempts):
            if found_sr and found_vuln:
                self.unlink_issues(response_sr)
                self.unlink_issues(response_vuln)
                break
            try:
                issues = self.test_obj["getMessagesFunc"](begin_time)
                assert len(issues) > 0, "No messages found in the channel"
                if not found_sr:
                    r = self.backend.get_security_risks_list(cluster_name=cluster_name, namespace=self.namespace, security_risk_ids=[SECURITY_RISKS_ID])
                    r = r.text
                    response_sr = json.loads(r)
                    self.assert_security_risks_jira_ticket_created(response=response_sr, security_risk_id=SECURITY_RISKS_ID)
                    Logger.logger.info("Security risk jira ticket created")
                    found_sr = True
                
                if not found_vuln:
                    response_vuln = self.backend.get_vulns_v2(body=vuln_body, enrich_tickets=True)
                    self.assert_vulnerability_jira_ticket_created(issues=issues, response=response_vuln, cluster=cluster_name, cves=["CVE-2023-27522"])
                    Logger.logger.info("Vulnerability jira ticket created")
                    found_vuln = True
               
            except (AssertionError, Exception) as e:
                Logger.logger.info(f"iteration: {i}: {e}")
                if i == attempts - 1:
                    Logger.logger.error(f"Failed to assert jira tickets was created after {attempts} attempts, cleaning up")
                    response_vuln = self.backend.get_vulns_v2(body=vuln_body, enrich_tickets=True)
                    self.unlink_issues(response_vuln)
                    raise
                TestUtil.sleep(sleep_time, f"iteration: {i}, waiting additional {sleep_time} seconds for messages to arrive")

    def unlink_issues(self, response):
        if not response:
            return 
    
        if "response" not in response:
            return
        
        for item in response["response"]:  
            if len(item["tickets"]) > 0:
                for ticket in item["tickets"]:
                    self.backend.unlink_issue(ticket["guid"])
       
        

    
    
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

        risks = response.get("response", [])
        assert len(risks) > 0, "No security risks found in the response"

        for risk in risks:
            tickets = risk.get("tickets", [])
            assert len(tickets) > 0, f"No tickets associated with security risk with ID {security_risk_id}. response: {response}"

    def assert_vulnerability_jira_ticket_created(self, issues, response, cluster, cves=[]):
        assert response, "No vulnerabilities found in the response"
        assert issues, "No messages found in the channel"

        for cve in cves:

            # Check if CVE exists in Jira issues
            jira_issue = next((issue for issue in issues if cve in issue["fields"]["summary"] and cluster in extract_text_from_adf(issue["fields"]["description"])), None)
            assert jira_issue, f"No vulnerability with CVE {cve} and cluster {cluster} found in Jira issues."
            Logger.logger.info(f"Found vulnerability with CVE {cve} and cluster {cluster} in Jira issues")

            # # Check if CVE exists in Jira issues
            # jira_issue = next((issue for issue in issues if cve in issue["fields"]["summary"]), None)
            # assert jira_issue, f"No vulnerability with CVE {cve} found in Jira issues."
            # Logger.logger.info(f"Found vulnerability with CVE {cve} in Jira issues")

            # Check if CVE exists in the response vulnerabilities
            response_vuln = next((vuln for vuln in response if vuln["name"] == cve), None)
            assert response_vuln, f"No vulnerability with CVE {cve} found in response."
            Logger.logger.info(f"Found vulnerability with CVE {cve} in response")

            # Validate tickets associated with the vulnerability
            tickets = response_vuln.get("tickets", [])
            assert tickets, f"No tickets associated with vulnerability with CVE {cve}."
            ticket_link_titles = [ticket["linkTitle"] for ticket in tickets]
            assert jira_issue["key"] in ticket_link_titles, f"No ticket associated with vulnerability with CVE {cve} found in Jira."
    


    def assert_misconfiguration_message_sent(self, messages, cluster):
        found = 0
        for message in messages:
            message_string = str(message)
            if "Your compliance score has decreased by" in message_string and cluster in message_string:
                found += 1
        assert found > 0, f"expected to have exactly one new misconfiguration message, found {found}"
    



    
    def build_securityRisk_workflow_body(self, name, severities, jiraCollaborationGUID, siteId,  projectId, cluster, namespace, category, securityRiskIDs, issueTypeId, guid=None):
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
                            "collaborationGUID": jiraCollaborationGUID,
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
    
    def build_vulnerabilities_workflow_body(self, name, severities, jiraCollaborationGUID, siteId, projectId, cluster, namespace, category, cvss, issueTypeId, guid=None):
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
                            "collaborationGUID": jiraCollaborationGUID,
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
        body = {
                    "pageSize": 150, 
                    "pageNum": 1, 
                    "innerFilters": [{
                        "name": expected_name
                    }],
                    "orderBy": "updatedTime:desc"
                }
        workflows = self.backend.get_workflows(body=body)
        assert workflows["total"]["value"] == 1, f"Expected total value to be equal to 1, but got {workflows['total']['value']}"

        workflow = workflows["response"][0]
        assert workflow["name"] == expected_name, f"Expected name {expected_name} but got {workflow['name']}"
        assert workflow["notifications"][0]["provider"] == expected_provider, f"Expected provider {expected_provider} but got {workflow['notifications'][0]['provider']}"
        assert workflow["guid"], f"Expected guid to be not None, but got {workflow['guid']}"
        return workflow["guid"]


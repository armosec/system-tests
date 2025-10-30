import time
from .base_helm import BaseHelm
from ..kubescape.base_kubescape import BaseKubescape
from systest_utils import statics, Logger, TestUtil
from ..workflows.utils import get_jira_ticket_by_id
import json

DEFAULT_JIRA_SITE_NAME = "cyberarmor-io"

# configuration of auto closure settings
# isEnabled: True to enable auto closure
# issueTypeIdToResolvedStatusId: map of issue type id to resolved status id
# example: { "10060": "10054" } # Bug issue type id to Done status id
DEFAULT_AUTO_CLOSURE_SETTINGS =  {
                                    "isEnabled": True,
                                    "issueTypeIdToResolvedStatusId": {
                                        "10060": "10054", # Bug issue type id to Done status id
                                        "10102": "10054" # System tests issue type id to Done status id
                                    }
                                }
                                

def setup_jira_config(backend, site_name=DEFAULT_JIRA_SITE_NAME, auto_closure_settings=DEFAULT_AUTO_CLOSURE_SETTINGS):       
    """Setup and validate Jira configuration. Returns necessary Jira config objects.
    
    Args:
        backend: Backend instance with Jira API methods
        site_name (str): Name of the Jira site (default: cyberarmor-io)
        
    Returns:
        tuple: (site, project, issueType, jiraCollaborationGUID)
    """
    Logger.logger.info('check jira connection status')
    connectionStatus = backend.get_integration_status("jira")
    assert connectionStatus, "Connection status is empty"
    assert len(connectionStatus) ==  1, "Got more than one connection status"
    jiraStatus = next((status for status in connectionStatus if status['provider'] == 'jira'), None)
    assert jiraStatus, "Jira is missing form connection status"
    assert jiraStatus['status'] == "connected", "Jira is not connected"
    jiraCollaborationGUID = backend.get_jira_collaboration_guid_by_site_name(site_name)

    Logger.logger.info('get cyberarmor-io site')   
    projectsResp = backend.search_jira_projects(body={'innerFilters': [{'jiraCollabGUID': jiraCollaborationGUID}]})
    assert projectsResp, "Jira projects response is empty"
    site = next((site for site in projectsResp['availableSites'] if site['name'] == site_name), None)
    assert site, f"{site_name} is missing from available sites"

    Logger.logger.info('get Jira System Tests project')       
    projectsResp = backend.search_jira_projects({'innerFilters': [{'jiraCollabGUID': jiraCollaborationGUID, 'siteId': site['id'], 'name': 'Jira System Tests'}]})
    assert projectsResp, "Jira projects response is empty"
    project = next((project for project in projectsResp['projects'] if project['name'] == 'Jira System Tests'), None)
    assert project, "Jira System Tests is missing from projects"

    Logger.logger.info('update Jira configuration')
    if auto_closure_settings:
        project['autoClosureSettings'] = auto_closure_settings

    update_body = {
        "jiraCollabGUID": jiraCollaborationGUID, 
        'selectedSite': site, 
        'projects':[project],
    }

    
    backend.update_jira_config(update_body)

    Logger.logger.info('verify Jira configuration')
    config = backend.get_jira_config()
    assert config, "Jira configuration is empty"
    assert 'jiraConnections' in config and isinstance(config['jiraConnections'], list) and config['jiraConnections'], "No Jira connections found in the configuration"
    connection = next(
        (conn for conn in config['jiraConnections'] if conn.get('selectedSite', {}).get('name') == site_name),
        None
    )
    assert connection, f"No Jira connection found for site '{site_name}'"
    assert 'projects' in connection and isinstance(connection['projects'], list) and connection['projects'][0]['name'] == 'Jira System Tests', "Jira project is not Jira System Tests"


    Logger.logger.info('get jira test issue type')
    issueTypesRes = backend.search_jira_issue_types({'innerFilters': [{'jiraCollabGUID': jiraCollaborationGUID, 'siteId': site['id'], 'projectId': project['id'], 'name': 'System Test Issue Type'}]})
    assert issueTypesRes, "Jira issue types response is empty"
    issueType = next((issueType for issueType in issueTypesRes['response'] if issueType['name'] == 'System Test Issue Type'), None)
    assert issueType, "System Test Issue Type is missing from issue types"

    Logger.logger.info('verify issue type schema')
    schema = backend.search_jira_schema({'innerFilters': [{'jiraCollabGUID': jiraCollaborationGUID,
        'siteId': site['id'], 'projectId': project['id'], 'issueTypeId': issueType['id'],
        'includeFields': 'summary,description,reporter,labels,assignee,users,user'}]})
    assert schema, "Jira schema response is empty"
    assert len(schema['response'])> 0 , "Jira schema response is empty"
    for field in schema['response']:
        field['topValues'] = None

    return site, project, issueType, jiraCollaborationGUID


class JiraIntegration(BaseKubescape, BaseHelm):
    def __init__(
            self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None
    ):
        super(JiraIntegration, self).__init__(
            test_driver=test_driver,
            test_obj=test_obj,
            backend=backend,
            kubernetes_obj=kubernetes_obj,
        )

        self.helm_kwargs = {
            "capabilities.relevancy": "enable",
            "capabilities.configurationScan": "enable",
            "capabilities.continuousScan": "disable",
            "capabilities.nodeScan": "disable",
            "capabilities.vulnerabilityScan": "enable",
            "capabilities.runtimeObservability": "enable",
            "grypeOfflineDB.enabled": "true",
            statics.HELM_NODE_SBOM_GENERATION: statics.HELM_NODE_SBOM_GENERATION_DISABLED,
        }

        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)
        
        self.wait_for_agg_to_end = False
        self.site_name = DEFAULT_JIRA_SITE_NAME

    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""

    

    def start(self):
        if self.test_driver.test_name == "jira_integration" and self.backend.server == "https://api.armosec.io": # skip test for production
            Logger.logger.info(f"Skipping test '{self.test_driver.test_name}' for production backend")
            return statics.SUCCESS, ""
        Logger.logger.info(f"Setup jira configuration")
        self.setup_jira_config()
        Logger.logger.info(f"Setup cluster and run posture scan")
        self.setup_cluster_and_run_posture_scan()
        Logger.logger.info(f"Create Jira issue for posture")
        self.create_jira_issue_for_posture()      
        Logger.logger.info(f"Create Jira issue for security risks")
        self.create_jira_issue_for_security_risks() 
        Logger.logger.info(f"Wait for vulnerabilities results")
        self.wait_for_vuln_results()
        Logger.logger.info(f"Create image ticket")
        self.create_vuln_tickets()
        Logger.logger.info(f"Test update Jira ticket status")
        self.test_update_jira_ticket_status()
        return self.cleanup()
    

    def setup_jira_config(self, site_name="cyberarmor-io"):
        """Setup Jira configuration using the standalone function."""
        self.site, self.project, self.issueType, self.jiraCollaborationGUID = setup_jira_config(self.backend, site_name)

    def setup_cluster_and_run_posture_scan(self):
        cluster, namespace = self.setup(apply_services=False)
        print("Debug: cluster: ", cluster)

        Logger.logger.info(f"Apply workload")
        workload = self.apply_yaml_file(
            yaml_file=self.test_obj["workload"], namespace=namespace
        )
        self.verify_all_pods_are_running(
            namespace=namespace, workload=workload, timeout=300
        )

        Logger.logger.info(f"Install Helm Chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.verify_running_pods(
            namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360
        )       
        
        Logger.logger.info(f"Get report guid")
        report_guid = self.get_report_guid(
            cluster_name=cluster, wait_to_result=True, framework_name="AllControls"
        )
        assert report_guid != "", "report guid is empty"


        # to make sure kubernetes resources are created
        time.sleep(20)
        Logger.logger.info(f"Trigger posture scan")
        self.backend.trigger_posture_scan(cluster)

        report_guid_new = self.get_report_guid(
            cluster_name=cluster, wait_to_result=True, framework_name="AllControls", old_report_guid=report_guid
        )
        self.report_guid = report_guid_new
        self.namespace = namespace
        self.cluster = cluster

    def create_jira_issue(self, issue, retries=3, sleep=45):
        return self.backend.create_jira_issue(issue)
    

    def create_jira_issue_for_posture(self):
        resource = self.get_posture_resource()
        controlId = resource['failedControls'][0]
        resourceHash = resource['resourceHash']

        Logger.logger.info(f"Create Jira issue for resource {resourceHash} and control {controlId}")
        issue = self.test_obj["issueTemplate"].copy()
        issue["collaborationGUID"] = self.backend.get_jira_collaboration_guid_by_site_name(self.site_name)
        issue['siteId'] = self.site['id']
        issue['projectId'] = self.project['id']
        issue['issueTypeId'] = self.issueType['id']
        issue['owner'] = {"resourceHash": resourceHash}
        issue['subjects'] = [{"controlId": controlId}]
        issue['fields']['summary'] = f"Jira System Test control Issue cluster:{self.cluster} namespace:{self.namespace} resource:{resourceHash}"
        ticket = self.create_jira_issue(issue)
        self.postureTicket = ticket
        Logger.logger.info(f"DEBUG: Posture ticket structure: {ticket}")
        assert ticket['owner']['resourceHash'] == resourceHash, "Resource hash is not matching"
        assert ticket['subjects'][0]['controlID'] == controlId, "Control id is not matching"

        Logger.logger.info(f"Verify Jira issue in resource")
        resource = self.get_posture_resource()
        assert len(resource['tickets']) > 0, "Resource is missing Jira issue" 

        Logger.logger.info(f"Verify Jira issue in control")
        controls = self.backend.get_posture_controls(framework_name="AllControls", report_guid=self.report_guid,control_id=controlId)
        assert len(controls) == 1, "Expected one control"        
        assert len(controls[0]['tickets']) > 0, "Control is missing Jira issue"

        Logger.logger.info(f"Verify Jira issue in cluster")
        req = {"innerFilters": [{"reportGUID": self.report_guid}]}
        clusters = self.backend.get_posture_clusters(req)
        assert len(clusters) == 1, "Expected one cluster"        
        assert len(clusters[0]['tickets']) > 0, "Cluster is missing Jira issue"

        Logger.logger.info(f"unlink Jira issue")
        self.backend.unlink_issue(ticket['guid'])

    def get_posture_resource(self):
        resourcesRes = self.backend.get_posture_resources(framework_name="AllControls", report_guid=self.report_guid,namespace=self.namespace,resource_name="nginx")
        assert len(resourcesRes) == 1, "Expected one resource"
        return resourcesRes[0]
    

    def create_jira_issue_for_security_risks(self):
        security_risk_id = "R_0011"

        resource, t = self.wait_for_report(
            report_type=self.get_security_risks_resource,
            timeout=220, 
            sleep_interval=10,
            security_risk_id=security_risk_id,
        )

        # resource = self.get_security_risks_resource(security_risk_id)
        resourceHash = resource['k8sResourceHash']

        Logger.logger.info(f"Create Jira issue for resource {resourceHash} and security_risk_id {security_risk_id}")
        issue = self.test_obj["issueTemplate"].copy()
        issue["collaborationGUID"] = self.backend.get_jira_collaboration_guid_by_site_name(self.site_name)
        issue['issueType'] = "securityIssue"
        issue['siteId'] = self.site['id']
        issue['projectId'] = self.project['id']
        issue['issueTypeId'] = self.issueType['id']
        issue['owner'] = {"resourceHash": resourceHash}
        issue['subjects'] = [{"securityRiskID": security_risk_id}]
        issue['fields']['summary'] = f"Jira System Test security risks Issue cluster:{self.cluster} namespace:{self.namespace} resource:{resourceHash}"
        ticket = self.create_jira_issue(issue)
        assert ticket, "Jira ticket is empty"
        self.securityTicket = ticket
        assert ticket['owner']['resourceHash'] == resourceHash, "Resource hash is not matching"
        assert ticket['subjects'][0]['securityRiskID'] == security_risk_id, "security risk id is not matching"

        Logger.logger.info(f"Verify Jira issue in security risks resource")
        resource = self.get_security_risks_resource(security_risk_id, other_filters={"resourceName":"nginx"})
        assert len(resource['tickets']) > 0, "Resource is missing Jira issue" 

        Logger.logger.info(f"Verify Jira issue in security risk list")
        security_risk = self.get_security_risks_list(security_risk_id)
        assert len(security_risk['tickets']) > 0, f"Security risk {security_risk_id} is missing Jira issue"

        Logger.logger.info(f"Verify Jira issue |exists filter in security risks resource")
        self.verify_security_risks_resource_exists(security_risk_id)
        assert len(security_risk['tickets']) > 0, f"Security risk is missing Jira issue"

        Logger.logger.info(f"Verify Jira issue |missing filter in security risks resource")
        self.verify_security_risks_resource_missing(security_risk_id)

        Logger.logger.info(f"unlink Jira issue")
        self.backend.unlink_issue(ticket['guid'])


    def get_security_risks_list(self, security_risk_id, other_filters={}):
        security_risk_ids = [security_risk_id] if security_risk_id else []
        r = self.backend.get_security_risks_list(self.cluster, self.namespace, security_risk_ids, other_filters=other_filters)
        response = json.loads(r.text)
        if response["response"] is None:
            response["response"] = []
        assert len(response["response"]) == 1 , "Expected one security risk"
        return response["response"][0]

    def verify_security_risks_resource_exists(self, security_risk_id):
        r = self.backend.get_security_risks_resources(cluster_name=self.cluster, namespace=self.namespace, security_risk_id=security_risk_id, other_filters={"tickets":"|exists"})
        response = json.loads(r.text)
        if response["response"] is None:
            response["response"] = []
        assert len(response["response"]) == 1 , f"Expected one resource for security risks but got {response}"

    def verify_security_risks_resource_missing(self, security_risk_id):
        r = self.backend.get_security_risks_resources(cluster_name=self.cluster, namespace=self.namespace, security_risk_id=security_risk_id, other_filters={"tickets":"|missing"})
        response = json.loads(r.text)
        assert response["response"] is None , "Expected no resource for security risks"


    def get_security_risks_resource(self, security_risk_id, other_filters={}):
        r = self.backend.get_security_risks_resources(cluster_name=self.cluster, namespace=self.namespace, security_risk_id=security_risk_id, other_filters=other_filters)
        response = json.loads(r.text)
        if response["response"] is None:
            response["response"] = []
        assert len(response["response"]) == 1 , f"Expected one resource for security risks but got {response}"
        return response["response"][0]
    
    def wait_for_vuln_results(self):
        Logger.logger.info('get nginx workload vulnerabilities')
        body = {"innerFilters": [
            {
                "cluster": self.cluster,
                "namespace": self.namespace,
                "workload": "nginx",
                "kind":"deployment",
            }]}
        wl_list, _ = self.wait_for_report(timeout=600, report_type=self.backend.get_vuln_v2_workloads,
                                              body=body,expected_results=1, enrich_tickets=True) 
        self.vulnWL = wl_list[0]

        Logger.logger.info('get nginx workload image')
        image = self.backend.get_vuln_v2_images(body=body, expected_results=1, enrich_tickets=True)
        self.vulnImage = image[0]

        Logger.logger.info('get nginx workload vulnerabilities')
        body['orderBy'] = "severityScore:desc"
        body['pageSize'] = 1
        vulns = self.backend.get_vulns_v2(body=body, expected_results=1, enrich_tickets=True)
        self.vuln = vulns[0]

    def create_vuln_tickets(self):
        Logger.logger.info('create global ticket for CVE')
        issue = self.test_obj["issueTemplate"].copy()
        issue["collaborationGUID"] = self.backend.get_jira_collaboration_guid_by_site_name(self.site_name)
        issue['issueType'] = "vulnerability"
        issue['siteId'] = self.site['id']
        issue['projectId'] = self.project['id']
        issue['issueTypeId'] = self.issueType['id']        
        issue['subjects'] = [{"cveName": self.vuln['name'],"severity": self.vuln['severity'] , "component": self.vuln['componentInfo']['name'], "componentVersion": self.vuln['componentInfo']['version']}]
        issue['fields']['summary'] = f"Jira System Test global Issue CVE:{self.vuln['name']}"
        globalCVEicket = self.create_jira_issue(issue)
        assert globalCVEicket, "Jira ticket is empty"

        Logger.logger.info('create  ticket for workload CVE')
        issue["collaborationGUID"] = self.backend.get_jira_collaboration_guid_by_site_name(self.site_name)
        issue['owner'] = {"cluster": self.vulnWL['cluster'], "namespace": self.vulnWL['namespace'], "kind": self.vulnWL['kind'], "name": self.vulnWL['name']}
        issue['fields']['summary'] = f"Jira System Test CVE Issue for workload cluster:{self.cluster} namespace:{self.namespace} image:{self.vulnImage['repository']}"
        workloadCVEicket = self.create_jira_issue(issue)
        assert workloadCVEicket, "Jira ticket is empty"
        assert workloadCVEicket, "Jira ticket is empty"



        Logger.logger.info('create global ticket for image')
        del issue['owner']
        issue["collaborationGUID"] = self.backend.get_jira_collaboration_guid_by_site_name(self.site_name)
        issue['issueType'] = "image"
        issue['subjects'] = [{"imageRepository": self.vulnImage['repository']}]
        issue['fields']['summary'] = f"Jira System Test global Issue image:{self.vulnImage['repository']}"
        globalImageTicket = self.create_jira_issue(issue)
        assert globalImageTicket, "Jira ticket is empty"

        Logger.logger.info('create ticket for image in workload')
        issue["collaborationGUID"] = self.backend.get_jira_collaboration_guid_by_site_name(self.site_name)
        issue['owner'] = {"cluster": self.vulnWL['cluster'], "namespace": self.vulnWL['namespace'], "kind": self.vulnWL['kind'], "name": self.vulnWL['name']}
        issue['fields']['summary'] = f"Jira System Test image Issue for workload cluster:{self.cluster} namespace:{self.namespace} image:{self.vulnImage['repository']}"
        workloadImageTicket = self.create_jira_issue(issue)
        assert workloadImageTicket, "Jira ticket is empty"
 

        Logger.logger.info(f"Verify Jira issue in image")
        body={"innerFilters": [{"digest": self.vulnImage['digest'], "kind":self.vulnWL['kind'], "workload" : self.vulnWL['name'], "cluster":self.cluster, "namespace":self.namespace}]}
        image = self.backend.get_vuln_v2_images(body=body, scope='workload', enrich_tickets=True)
        assert len(image) == 1, f"Expected one image, got: {image}"
        assert len(image[0]['tickets']) > 0, "Image is missing Jira issue"

        Logger.logger.info(f"Verify Jira issue in vulnerability")
        vulns = self.backend.get_vulns_v2(body={"innerFilters": [{"id": self.vuln['id'], "kind":self.vulnWL['kind'], "workload" : self.vulnWL['name'], "cluster":self.cluster, "namespace":self.namespace, "tickets":"|exists"}]}, scope='workload', enrich_tickets=True)
        assert len(vulns) > 0, f"Expected at least one vulnerability, got: {vulns}" 
        assert len(vulns[0]['tickets']) > 0, "Image is missing Jira issue"

        Logger.logger.info(f"Verify Jira issue in component")
        components = self.backend.get_vuln_v2_components(body={"innerFilters": [{"name": self.vuln['componentInfo']['name'],"version": self.vuln['componentInfo']['version'], "kind":self.vulnWL['kind'], "workload" : self.vulnWL['name'], "cluster":self.cluster, "namespace":self.namespace}]}, scope='workload', enrich_tickets=True)
        assert len(components) == 1, f"Expected one component, got: {components}"
        assert len(components[0]['tickets']) > 0, "Image is missing Jira issue"

        Logger.logger.info(f"Verify Jira issue in workload")
        workloads = self.backend.get_vuln_v2_workloads(body={"innerFilters": [{"resourceHash": self.vulnWL['resourceHash']}]}, enrich_tickets=True)
        assert len(workloads) == 1, f"Expected one workload, got: {workloads}"
        assert len(workloads[0]['tickets']) > 0, "Image is missing Jira issue"

        Logger.logger.info(f"unlink Jira issues")
        self.backend.unlink_issue(globalCVEicket['guid'])
        self.backend.unlink_issue(workloadCVEicket['guid'])
        self.backend.unlink_issue(globalImageTicket['guid'])
        self.backend.unlink_issue(workloadImageTicket['guid'])

    def test_update_jira_ticket_status(self):
        """Test the update_jira_ticket_status API and verify status change in Jira."""
        Logger.logger.info("Testing update_jira_ticket_status API")
        
        # Use the posture ticket created earlier
        if not hasattr(self, 'postureTicket') or not self.postureTicket:
            error_msg = "No posture ticket available for status update test"
            Logger.logger.error(error_msg)
            raise Exception(error_msg)
            
        ticket = self.postureTicket
        Logger.logger.info(f"DEBUG: Full ticket structure for status update: {ticket}")
        
        # Get the Jira issue ID from linkTitle field (e.g., "ETNP-18")
        issue_id = ticket.get('linkTitle')
        
        if not issue_id:
            error_msg = f"No issue ID found in posture ticket linkTitle field. Available keys: {list(ticket.keys())}"
            Logger.logger.error(error_msg)
            raise Exception(error_msg)
            
        Logger.logger.info(f"Testing status update for ticket: {issue_id}")
        
        # Get current status from Jira before update
        try:
            jira_ticket_before = get_jira_ticket_by_id(issue_id, self.site_name)
            current_status = jira_ticket_before['fields']['status']
            Logger.logger.info(f"Current ticket status: {current_status['name']} (ID: {current_status['id']})")
        except Exception as e:
            Logger.logger.warning(f"Could not get initial ticket status from Jira: {e}")
            jira_ticket_before = None
        
        # Get the "Done" status ID from auto closure settings
        done_status_id = DEFAULT_AUTO_CLOSURE_SETTINGS['issueTypeIdToResolvedStatusId'].get(self.issueType['id'], "10054")
        
        # Prepare payload for update_jira_ticket_status API
        update_payload = {
            "integrationGUID": self.backend.get_jira_collaboration_guid_by_site_name(self.site_name),
            "siteID": self.site['id'],
            "issueID": issue_id,
            "statusID": done_status_id,
            "comment": "This issue was resolved by system test"
        }
        
        Logger.logger.info(f"Updating ticket status with payload: {update_payload}")
        
        # Call the update_jira_ticket_status API
        try:
            response = self.backend.update_jira_ticket_status(update_payload)
            Logger.logger.info(f"Update ticket status response: {response}")
            
            # If we get here, the API call was successful (status 200-299)
            Logger.logger.info("✓ update_jira_ticket_status API call successful")
            
        except Exception as e:
            Logger.logger.error(f"✗ update_jira_ticket_status API call failed: {e}")
            raise
        
        # Verify the status change in Jira with retry logic
        Logger.logger.info("Verifying status change in Jira...")
        max_retries = 20
        sleep_interval = 3
        
        for attempt in range(1, max_retries + 1):
            try:
                Logger.logger.info(f"Checking status change attempt {attempt}/{max_retries}")
                jira_ticket_after = get_jira_ticket_by_id(issue_id, self.site_name)
                new_status = jira_ticket_after['fields']['status']
                Logger.logger.info(f"Current ticket status: {new_status['name']} (ID: {new_status['id']})")
                
                # Check if status was actually changed
                if new_status['id'] == done_status_id:
                    Logger.logger.info(f"✓ Ticket status successfully updated in Jira after {attempt} attempts")
                    break
                else:
                    if attempt == max_retries:
                        # Last attempt failed
                        error_msg = f"✗ Ticket status not updated after {max_retries} attempts. Expected: {done_status_id}, Got: {new_status['id']}"
                        Logger.logger.error(error_msg)
                        raise Exception(error_msg)
                    else:
                        Logger.logger.info(f"Status not yet updated (attempt {attempt}/{max_retries}), waiting {sleep_interval} seconds...")
                        time.sleep(sleep_interval)
                        
            except Exception as e:
                if "Ticket status not updated after" in str(e):
                    # Re-raise our own assertion error
                    raise
                elif attempt == max_retries:
                    # Last attempt and got an error
                    error_msg = f"Could not verify status change in Jira after {max_retries} attempts: {e}"
                    Logger.logger.error(error_msg)
                    raise Exception(error_msg)
                else:
                    Logger.logger.warning(f"Error checking status (attempt {attempt}/{max_retries}): {e}, retrying in {sleep_interval} seconds...")
                    time.sleep(sleep_interval)
            
        Logger.logger.info("✓ update_jira_ticket_status test completed successfully")

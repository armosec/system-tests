from .base_helm import BaseHelm
from ..kubescape.base_kubescape import BaseKubescape
from systest_utils import statics, Logger, TestUtil


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
        }

        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)

    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""

    

    def start(self):
        Logger.logger.info(f"Setup jira configuration")
        self.setup_jira_config()
        Logger.logger.info(f"Setup cluster and run posture scan")
        self.setup_cluster_and_run_posture_scan()
        Logger.logger.info(f"Create Jira issue")
        self.create_jira_issue_for_posture()       
        Logger.logger.info(f"Wait for vulnerabilities results")
        self.wait_for_vuln_results()
        Logger.logger.info(f"Create image ticket")
        self.create_vuln_tickets()
        return self.cleanup()
    

    def setup_jira_config(self):       
        Logger.logger.info('check jira connection status')
        connectionStatus = self.backend.get_integration_status("jira")
        assert connectionStatus, "Connection status is empty"
        assert len(connectionStatus) ==  1, "Got more than one connection status"
        jiraStatus = next((status for status in connectionStatus if status['provider'] == 'jira'), None)
        assert jiraStatus, "Jira is missing form connection status"
        assert jiraStatus['status'] == "connected", "Jira is not connected"

        Logger.logger.info('get cyberarmor-io site')       
        projectsResp = self.backend.search_jira_projects({})
        assert projectsResp, "Jira projects response is empty"
        site = next((site for site in projectsResp['availableSites'] if site['name'] == 'cyberarmor-io'), None)
        assert site, "cyberarmor-io is missing from available sites"

        Logger.logger.info('get Jira System Tests project')       
        projectsResp = projectsResp = self.backend.search_jira_projects({'innerFilters': [{'siteId': site['id'], 'name': 'Jira System Tests'}]})
        assert projectsResp, "Jira projects response is empty"
        project = next((project for project in projectsResp['projects'] if project['name'] == 'Jira System Tests'), None)
        assert project, "Jira System Tests is missing from projects"

        Logger.logger.info('update Jira configuration')
        self.backend.update_jira_config({'selectedSite': site, 'projects':[project]})

        Logger.logger.info('verify Jira configuration')
        config = self.backend.get_jira_config()
        assert config, "Jira configuration is empty"
        assert config['selectedSite']['name'] == 'cyberarmor-io', "Jira site is not cyberarmor-io"
        assert config['projects'][0]['name'] == 'Jira System Tests', "Jira project is not Jira System Tests"


        Logger.logger.info('get jira test issue type')
        issueTypesRes = self.backend.search_jira_issue_types({'innerFilters': [{'siteId': site['id'], 'projectId': project['id'], 'name': 'System Test Issue Type'}]})
        assert issueTypesRes, "Jira issue types response is empty"
        issueType = next((issueType for issueType in issueTypesRes['response'] if issueType['name'] == 'System Test Issue Type'), None)
        assert issueType, "System Test Issue Type is missing from issue types"

        Logger.logger.info('verify issue type schema')
        schema = self.backend.search_jira_schema({'innerFilters': [{
            'siteId': site['id'], 'projectId': project['id'], 'issueTypeId': issueType['id'],
            'includeFields': 'summary,description,reporter,labels,assignee,users,user'}]})
        assert schema, "Jira schema response is empty"
        assert len(schema['response'])> 0 , "Jira schema response is empty"
        for field in schema['response']:
            field['topValues'] = None
                
        #uncomment to update expected 
        #TestUtil.save_expceted_json(schema, "configurations/expected-result/integrations/expectedJiraSchema.json")     
        TestUtil.compare_with_expected_file("configurations/expected-result/integrations/expectedJiraSchema.json", schema, {})
        #set site, project and issueType for the test
        self.site = site
        self.project = project
        self.issueType = issueType

    def setup_cluster_and_run_posture_scan(self):
        cluster, namespace = self.setup(apply_services=False)
        print("Debug: cluster: ", cluster)

        Logger.logger.info(f"Install Helm Chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.verify_running_pods(
            namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360
        )

        Logger.logger.info(f"Apply workload")
        workload = self.apply_yaml_file(
            yaml_file=self.test_obj["workload"], namespace=namespace
        )
        self.verify_all_pods_are_running(
            namespace=namespace, workload=workload, timeout=300
        )

        Logger.logger.info(f"Trigger a scan")
        self.backend.trigger_posture_scan(
            cluster_name=cluster,
            framework_list=["AllControls"],
            with_host_sensor="false",
        )

        Logger.logger.info(f"Get report guid")
        report_guid = self.get_report_guid(
            cluster_name=cluster, wait_to_result=True, framework_name="AllControls"
        )
        assert report_guid != "", "report guid is empty"
        self.report_guid = report_guid
        self.namespace = namespace
        self.cluster = cluster

    def create_jira_issue_for_posture(self):
        resource = self.get_posture_resource()
        controlId = resource['failedControls'][0]
        resourceHash = resource['resourceHash']

        Logger.logger.info(f"Create Jira issue for resource {resourceHash} and control {controlId}")
        issue = self.test_obj["issueTemplate"].copy()
        issue['siteId'] = self.site['id']
        issue['projectId'] = self.project['id']
        issue['issueTypeId'] = self.issueType['id']
        issue['owner'] = {"resourceHash": resourceHash}
        issue['subjects'] = [{"controlId": controlId}]
        issue['fields']['summary'] = f"Jira System Test control Issue cluster:{self.cluster} namespace:{self.namespace} resource:{resourceHash}"
        ticket = self.backend.create_jira_issue(issue)
        assert ticket, "Jira ticket is empty"
        self.postureTicket = ticket
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
    
    def wait_for_vuln_results(self):
        Logger.logger.info('get nginx workload vulnerabilities')
        body = {"innerFilters": [
            {
                "cluster": self.cluster,
                "namespace": self.namespace,
                "name": "nginx",
                "kind":"deployment",
            }]}
        wl_list, _ = self.wait_for_report(timeout=600, report_type=self.backend.get_vuln_v2_workloads,
                                              body=body,expected_results=1)  
        self.vulnWL = wl_list[0]
        body['innerFilters'][0]['workload'] = "nginx"
        del body['innerFilters'][0]['name']

        Logger.logger.info('get nginx workload image')
        image = self.backend.get_vuln_v2_images(body=body, expected_results=1)
        self.vulnImage = image[0]

        Logger.logger.info('get nginx workload vulnerabilities')
        body['orderBy'] = "severityScore:desc"
        body['pageSize'] = 1
        vulns = self.backend.get_vulns_v2(body=body, expected_results=1)
        self.vuln = vulns[0]

    def create_vuln_tickets(self):
        Logger.logger.info('create global ticket for CVE')
        issue = self.test_obj["issueTemplate"].copy()
        issue['issueType'] = "vulnerability"
        issue['siteId'] = self.site['id']
        issue['projectId'] = self.project['id']
        issue['issueTypeId'] = self.issueType['id']        
        issue['subjects'] = [{"cveName": self.vuln['name'],"severity": self.vuln['severity'] , "component": self.vuln['componentInfo']['name'], "componentVersion": self.vuln['componentInfo']['version']}]
        issue['fields']['summary'] = f"Jira System Test global Issue CVE:{self.vuln['name']}"
        globalCVEicket = self.backend.create_jira_issue(issue)
        assert globalCVEicket, "Jira ticket is empty"

        Logger.logger.info('create  ticket for workload CVE')
        issue['owner'] = {"cluster": self.vulnWL['cluster'], "namespace": self.vulnWL['namespace'], "kind": self.vulnWL['kind'], "name": self.vulnWL['name']}
        issue['fields']['summary'] = f"Jira System Test CVE Issue for workload cluster:{self.cluster} namespace:{self.namespace} image:{self.vulnImage['repository']}"
        workloadCVEicket = self.backend.create_jira_issue(issue)
        assert workloadCVEicket, "Jira ticket is empty"
        assert workloadCVEicket, "Jira ticket is empty"



        Logger.logger.info('create global ticket for image')
        del issue['owner']
        issue['issueType'] = "image"
        issue['subjects'] = [{"imageRepository": self.vulnImage['repository']}]
        issue['fields']['summary'] = f"Jira System Test global Issue image:{self.vulnImage['repository']}"
        globalImageTicket = self.backend.create_jira_issue(issue)
        assert globalImageTicket, "Jira ticket is empty"

        Logger.logger.info('create ticket for image in workload')
        issue['owner'] = {"cluster": self.vulnWL['cluster'], "namespace": self.vulnWL['namespace'], "kind": self.vulnWL['kind'], "name": self.vulnWL['name']}
        issue['fields']['summary'] = f"Jira System Test image Issue for workload cluster:{self.cluster} namespace:{self.namespace} image:{self.vulnImage['repository']}"
        workloadImageTicket = self.backend.create_jira_issue(issue)
        assert workloadImageTicket, "Jira ticket is empty"
 

        Logger.logger.info(f"Verify Jira issue in image")
        body={"innerFilters": [{"digest": self.vulnImage['digest'], "kind":self.vulnWL['kind'], "workload" : self.vulnWL['name'], "cluster":self.cluster, "namespace":self.namespace}]}
        image = self.backend.get_vuln_v2_images(body=body, scope='workload')
        assert len(image) == 1, "Expected one image"
        assert len(image[0]['tickets']) > 0, "Image is missing Jira issue"

        Logger.logger.info(f"Verify Jira issue in vulnerability")
        vulns = self.backend.get_vulns_v2(body={"innerFilters": [{"id": self.vuln['id'], "kind":self.vulnWL['kind'], "workload" : self.vulnWL['name'], "cluster":self.cluster, "namespace":self.namespace}]}, scope='workload')
        assert len(vulns) == 1, "Expected one vulnerability"
        assert len(vulns[0]['tickets']) > 0, "Image is missing Jira issue"

        Logger.logger.info(f"Verify Jira issue in component")
        components = self.backend.get_vuln_v2_components(body={"innerFilters": [{"name": self.vuln['componentInfo']['name'],"version": self.vuln['componentInfo']['version'], "kind":self.vulnWL['kind'], "workload" : self.vulnWL['name'], "cluster":self.cluster, "namespace":self.namespace}]}, scope='workload')
        assert len(components) == 1, "Expected one component"
        assert len(components[0]['tickets']) > 0, "Image is missing Jira issue"

        Logger.logger.info(f"Verify Jira issue in workload")
        workloads = self.backend.get_vuln_v2_workloads(body={"innerFilters": [{"resourceHash": self.vulnWL['resourceHash']}]})
        assert len(workloads) == 1, "Expected one workload"
        assert len(workloads[0]['tickets']) > 0, "Image is missing Jira issue"

        Logger.logger.info(f"unlink Jira issuez")
        self.backend.unlink_issue(globalCVEicket['guid'])
        self.backend.unlink_issue(workloadCVEicket['guid'])
        self.backend.unlink_issue(globalImageTicket['guid'])
        self.backend.unlink_issue(workloadImageTicket['guid'])

    









    

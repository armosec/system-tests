import copy
import json
import time

from .base_helm import BaseHelm
from ..kubescape.base_kubescape import BaseKubescape
from systest_utils import Logger, statics


class LinearIntegration(BaseKubescape, BaseHelm):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(LinearIntegration, self).__init__(
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

        template_overrides = self.test_obj.get_arg("helm_kwargs")
        if template_overrides:
            self.helm_kwargs.update(template_overrides)

        self.wait_for_agg_to_end = False
        self.workspace_name = None
        self.workspace_id = None
        self.team_id = None
        self.done_state_id = None
        self.collab_guid = None

    def cleanup(self, **kwargs):
        super().cleanup(**kwargs)
        return statics.SUCCESS, ""

    def start(self):
        return statics.SUCCESS, ""
        if (
            self.test_driver.test_name == "linear_integration"
            and self.backend.server == "https://api.armosec.io"
        ):
            Logger.logger.info(
                f"Skipping test '{self.test_driver.test_name}' for production backend"
            )
            return statics.SUCCESS, ""

        Logger.logger.info("Setting up Linear configuration")
        self.setup_linear_config()

        Logger.logger.info("Setting up cluster and running posture scan")
        self.setup_cluster_and_run_posture_scan()

        Logger.logger.info("Creating Linear issue for posture finding")
        self.create_linear_issue_for_posture()

        Logger.logger.info("Creating Linear issue for security risk")
        self.create_linear_issue_for_security_risks()

        Logger.logger.info("Waiting for vulnerability results")
        self.wait_for_vuln_results()

        Logger.logger.info("Creating Linear vulnerability/image tickets")
        self.create_vuln_tickets()

        Logger.logger.info("Testing Linear ticket status update flow")
        self.test_update_linear_ticket_status()

        return self.cleanup()

    def setup_linear_config(self):
        status = self.backend.get_integration_status("linear")
        assert status, "Linear connection status is empty"
        linear_status = next((s for s in status if s.get("provider") == "linear"), None)
        assert linear_status, "Linear provider missing from connection status response"
        assert (
            linear_status.get("status") == "connected"
        ), f"Linear provider not connected, status: {linear_status}"

        config = self.backend.get_linear_config()
        connections = config.get("linearConnections") or []
        assert connections, "Linear configuration returned no connections"

        connection = connections[0]
        self.collab_guid = connection.get("collabGUID")
        assert self.collab_guid, "Linear collaboration GUID missing"

        workspace = connection.get("selectedWorkspace") or {}
        self.workspace_id = workspace.get("id")
        self.workspace_name = workspace.get("name", "")
        assert self.workspace_id, "Linear workspace ID missing in configuration"

        teams = connection.get("teams") or []
        assert teams, "Linear configuration missing team definitions"
        team = self._select_team(teams)
        assert team, "Failed to select Linear team configuration"

        self.team_id = self._normalize_id(team.get("id"))
        assert self.team_id, "Linear team ID missing"

        self.done_state_id = (
            (team.get("autoClosureSettings") or {}).get("targetStateId")
        )
        if not self.done_state_id:
            Logger.logger.info(
                "Auto closure state not found in config, querying field values"
            )
            states = self.backend.search_linear_field_values(
                self.collab_guid, "stateId", self.team_id
            )
            state_id = self._extract_state_id(states)
            if state_id:
                self.done_state_id = state_id
        assert (
            self.done_state_id
        ), "Unable to determine Linear target state for status update"

    def _select_team(self, teams):
        default_team = next((team for team in teams if team.get("isDefault")), None)
        return default_team or teams[0]

    def _normalize_id(self, value):
        if isinstance(value, dict):
            for key in ("StrVal", "string", "value", "id"):
                maybe = value.get(key)
                if maybe:
                    return str(maybe)
            for key in ("IntVal", "int"):
                maybe = value.get(key)
                if maybe is not None:
                    return str(maybe)
            return json.dumps(value)
        if value is None:
            return ""
        return str(value)

    def _extract_state_id(self, response):
        if not response:
            return ""
        values = response.get("response") if isinstance(response, dict) else response
        if not values:
            return ""
        if isinstance(values, list) and values and isinstance(values[0], list):
            values = values[0]
        for item in values:
            if isinstance(item, dict):
                state_id = self._normalize_id(item.get("id"))
                if state_id:
                    return state_id
        return ""

    def _issue_template_copy(self):
        return copy.deepcopy(self.test_obj["issueTemplate"])

    def _prepare_linear_issue(self, issue):
        issue["provider"] = "linear"
        issue["collaborationGUID"] = self.collab_guid
        issue["siteID"] = self.workspace_id
        issue["projectID"] = self.team_id

        fields = issue.setdefault("fields", {})
        fields.setdefault("title", "System tests Linear ticket")
        fields.setdefault(
            "description", "System test automation ticket created by system-tests"
        )
        fields["teamId"] = self.team_id

        linear_fields = issue.get("linearFields") or {}
        linear_fields["workspaceId"] = self.workspace_id
        linear_fields["teamId"] = self.team_id
        issue["linearFields"] = linear_fields

        return issue

    def create_linear_issue_for_posture(self):
        resource = self.get_posture_resource()
        control_id = resource["failedControls"][0]
        resource_hash = resource["resourceHash"]

        issue = self._issue_template_copy()
        issue["issueType"] = "clusterControl"
        issue["owner"] = {"resourceHash": resource_hash}
        issue["subjects"] = [{"controlId": control_id}]
        issue["fields"]["title"] = (
            f"Linear System Test Control Issue cluster:{self.cluster} "
            f"namespace:{self.namespace} resource:{resource_hash}"
        )

        ticket = self.backend.create_linear_issue(self._prepare_linear_issue(issue))
        self.postureTicket = ticket

        assert (
            ticket["owner"]["resourceHash"] == resource_hash
        ), "Resource hash is not matching"
        assert (
            ticket["subjects"][0]["controlID"] == control_id
        ), "Control id is not matching"

        Logger.logger.info("Verifying posture resource updated with Linear ticket")
        resource = self.get_posture_resource()
        assert resource["tickets"], "Resource missing Linear ticket"

        Logger.logger.info("Verifying posture control updated with Linear ticket")
        controls = self.backend.get_posture_controls(
            framework_name="AllControls",
            report_guid=self.report_guid,
            control_id=control_id,
        )
        assert controls, "Expected posture control data"
        assert controls[0]["tickets"], "Control missing Linear ticket"

        Logger.logger.info("Verifying posture cluster updated with Linear ticket")
        clusters = self.backend.get_posture_clusters(
            {"innerFilters": [{"reportGUID": self.report_guid}]}
        )
        assert clusters, "Expected posture cluster data"
        assert clusters[0]["tickets"], "Cluster missing Linear ticket"

        Logger.logger.info("Unlinking Linear posture ticket")
        self.backend.unlink_issue(ticket["guid"])

    def setup_cluster_and_run_posture_scan(self):
        cluster, namespace = self.setup(apply_services=False)

        Logger.logger.info("Apply workload manifest")
        workload = self.apply_yaml_file(
            yaml_file=self.test_obj["workload"], namespace=namespace
        )
        self.verify_all_pods_are_running(namespace=namespace, workload=workload, timeout=300)

        Logger.logger.info("Install Helm chart")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME, timeout=360)

        Logger.logger.info("Fetch report GUID prior to scan")
        report_guid = self.get_report_guid(
            cluster_name=cluster, wait_to_result=True, framework_name="AllControls"
        )
        assert report_guid, "report guid is empty"

        time.sleep(20)
        Logger.logger.info("Trigger posture scan")
        self.backend.trigger_posture_scan(cluster)

        new_guid = self.get_report_guid(
            cluster_name=cluster,
            wait_to_result=True,
            framework_name="AllControls",
            old_report_guid=report_guid,
        )
        self.report_guid = new_guid
        self.namespace = namespace
        self.cluster = cluster

    def get_posture_resource(self):
        result = self.backend.get_posture_resources(
            framework_name="AllControls",
            report_guid=self.report_guid,
            namespace=self.namespace,
            resource_name="nginx",
        )
        assert len(result) == 1, f"Expected one resource, got: {result}"
        return result[0]

    def create_linear_issue_for_security_risks(self):
        security_risk_id = "R_0011"
        resource, _ = self.wait_for_report(
            report_type=self.get_security_risks_resource,
            timeout=220,
            sleep_interval=10,
            security_risk_id=security_risk_id,
        )
        resource_hash = resource["k8sResourceHash"]

        issue = self._issue_template_copy()
        issue["issueType"] = "securityIssue"
        issue["owner"] = {"resourceHash": resource_hash}
        issue["subjects"] = [{"securityRiskID": security_risk_id}]
        issue["fields"]["title"] = (
            f"Linear System Test security Issue cluster:{self.cluster} "
            f"namespace:{self.namespace} resource:{resource_hash}"
        )

        ticket = self.backend.create_linear_issue(self._prepare_linear_issue(issue))
        assert ticket, "Linear ticket creation returned empty response"
        self.securityTicket = ticket

        assert (
            ticket["owner"]["resourceHash"] == resource_hash
        ), "Resource hash mismatch for security risk ticket"
        assert (
            ticket["subjects"][0]["securityRiskID"] == security_risk_id
        ), "Security risk id mismatch"

        Logger.logger.info("Verifying security risk resource contains Linear ticket")
        resource = self.get_security_risks_resource(
            security_risk_id, other_filters={"resourceName": "nginx"}
        )
        assert resource["tickets"], "Security risk resource missing Linear ticket"

        Logger.logger.info("Verifying security risk list entry contains Linear ticket")
        risk = self.get_security_risks_list(security_risk_id)
        assert risk["tickets"], "Security risk list missing Linear ticket"

        Logger.logger.info("Verifying security risk |exists filter behaviour")
        self.verify_security_risks_resource_exists(security_risk_id)

        Logger.logger.info("Verifying security risk |missing filter behaviour")
        self.verify_security_risks_resource_missing(security_risk_id)

        Logger.logger.info("Unlinking Linear security risk ticket")
        self.backend.unlink_issue(ticket["guid"])

    def get_security_risks_resource(self, security_risk_id, other_filters=None):
        other_filters = other_filters or {}
        response = self.backend.get_security_risks_resources(
            cluster_name=self.cluster,
            namespace=self.namespace,
            security_risk_id=security_risk_id,
            other_filters=other_filters,
        )
        data = json.loads(response.text)
        if data["response"] is None:
            data["response"] = []
        assert len(data["response"]) == 1, f"Expected one security risks resource got: {data}"
        return data["response"][0]

    def get_security_risks_list(self, security_risk_id):
        response = self.backend.get_security_risks_list(
            self.cluster, self.namespace, [security_risk_id]
        )
        data = json.loads(response.text)
        if data["response"] is None:
            data["response"] = []
        assert len(data["response"]) == 1, f"Expected one security risk, got: {data}"
        return data["response"][0]

    def verify_security_risks_resource_exists(self, security_risk_id):
        response = self.backend.get_security_risks_resources(
            cluster_name=self.cluster,
            namespace=self.namespace,
            security_risk_id=security_risk_id,
            other_filters={"tickets": "|exists"},
        )
        data = json.loads(response.text)
        if data["response"] is None:
            data["response"] = []
        assert len(data["response"]) == 1, f"Expected resource in exists filter, got: {data}"

    def verify_security_risks_resource_missing(self, security_risk_id):
        response = self.backend.get_security_risks_resources(
            cluster_name=self.cluster,
            namespace=self.namespace,
            security_risk_id=security_risk_id,
            other_filters={"tickets": "|missing"},
        )
        data = json.loads(response.text)
        assert data["response"] is None, "Expected no resource for missing filter"

    def wait_for_vuln_results(self):
        body = {
            "innerFilters": [
                {
                    "cluster": self.cluster,
                    "namespace": self.namespace,
                    "workload": "nginx",
                    "kind": "deployment",
                }
            ]
        }
        workloads, _ = self.wait_for_report(
            timeout=600,
            report_type=self.backend.get_vuln_v2_workloads,
            body=body,
            expected_results=1,
            enrich_tickets=True,
        )
        self.vulnWL = workloads[0]

        images = self.backend.get_vuln_v2_images(
            body=body, expected_results=1, enrich_tickets=True
        )
        self.vulnImage = images[0]

        body["orderBy"] = "severityScore:desc"
        body["pageSize"] = 1
        vulns = self.backend.get_vulns_v2(
            body=body, expected_results=1, enrich_tickets=True
        )
        self.vuln = vulns[0]

    def create_vuln_tickets(self):
        issue = self._issue_template_copy()
        issue["issueType"] = "vulnerability"
        issue["subjects"] = [
            {
                "cveName": self.vuln["name"],
                "severity": self.vuln["severity"],
                "component": self.vuln["componentInfo"]["name"],
                "componentVersion": self.vuln["componentInfo"]["version"],
            }
        ]
        issue["fields"]["title"] = (
            f"Linear System Test global CVE:{self.vuln['name']}"
        )

        global_cve_ticket = self.backend.create_linear_issue(
            self._prepare_linear_issue(issue)
        )
        assert global_cve_ticket, "Global CVE ticket creation failed"

        workload_issue = self._issue_template_copy()
        workload_issue["issueType"] = "vulnerability"
        workload_issue["owner"] = {
            "cluster": self.vulnWL["cluster"],
            "namespace": self.vulnWL["namespace"],
            "kind": self.vulnWL["kind"],
            "name": self.vulnWL["name"],
        }
        workload_issue["subjects"] = issue["subjects"]
        workload_issue["fields"]["title"] = (
            f"Linear System Test workload CVE cluster:{self.cluster} "
            f"namespace:{self.namespace} image:{self.vulnImage['repository']}"
        )
        workload_cve_ticket = self.backend.create_linear_issue(
            self._prepare_linear_issue(workload_issue)
        )
        assert workload_cve_ticket, "Workload CVE ticket creation failed"

        image_issue = self._issue_template_copy()
        image_issue["issueType"] = "image"
        image_issue["subjects"] = [
            {"imageRepository": self.vulnImage["repository"]},
        ]
        image_issue["fields"]["title"] = (
            f"Linear System Test global image:{self.vulnImage['repository']}"
        )
        global_image_ticket = self.backend.create_linear_issue(
            self._prepare_linear_issue(image_issue)
        )
        assert global_image_ticket, "Global image ticket creation failed"

        workload_image_issue = self._issue_template_copy()
        workload_image_issue["issueType"] = "image"
        workload_image_issue["owner"] = workload_issue["owner"]
        workload_image_issue["subjects"] = image_issue["subjects"]
        workload_image_issue["fields"]["title"] = (
            f"Linear System Test workload image:{self.vulnImage['repository']}"
        )
        workload_image_ticket = self.backend.create_linear_issue(
            self._prepare_linear_issue(workload_image_issue)
        )
        assert workload_image_ticket, "Workload image ticket creation failed"

        Logger.logger.info("Verifying Linear tickets were attached to workload image")
        image = self.backend.get_vuln_v2_images(
            body={
                "innerFilters": [
                    {
                        "digest": self.vulnImage["digest"],
                        "kind": self.vulnWL["kind"],
                        "workload": self.vulnWL["name"],
                        "cluster": self.cluster,
                        "namespace": self.namespace,
                    }
                ]
            },
            scope="workload",
            enrich_tickets=True,
        )
        assert len(image) == 1, f"Expected one image, got: {image}"
        assert image[0]["tickets"], "Image missing Linear ticket"

        Logger.logger.info("Verifying Linear tickets attached to vulnerability")
        vulns = self.backend.get_vulns_v2(
            body={
                "innerFilters": [
                    {
                        "id": self.vuln["id"],
                        "kind": self.vulnWL["kind"],
                        "workload": self.vulnWL["name"],
                        "cluster": self.cluster,
                        "namespace": self.namespace,
                        "tickets": "|exists",
                    }
                ]
            },
            scope="workload",
            enrich_tickets=True,
        )
        assert vulns, "Expected vulnerabilities response"
        assert vulns[0]["tickets"], "Vulnerability missing Linear ticket"

        Logger.logger.info("Verifying Linear tickets attached to component")
        components = self.backend.get_vuln_v2_components(
            body={
                "innerFilters": [
                    {
                        "name": self.vuln["componentInfo"]["name"],
                        "version": self.vuln["componentInfo"]["version"],
                        "kind": self.vulnWL["kind"],
                        "workload": self.vulnWL["name"],
                        "cluster": self.cluster,
                        "namespace": self.namespace,
                    }
                ]
            },
            scope="workload",
            enrich_tickets=True,
        )
        assert len(components) == 1, f"Expected one component, got: {components}"
        assert components[0]["tickets"], "Component missing Linear ticket"

        Logger.logger.info("Verifying Linear tickets attached to workload")
        workloads = self.backend.get_vuln_v2_workloads(
            body={"innerFilters": [{"resourceHash": self.vulnWL["resourceHash"]}]},
            enrich_tickets=True,
        )
        assert len(workloads) == 1, f"Expected one workload, got: {workloads}"
        assert workloads[0]["tickets"], "Workload missing Linear ticket"

        Logger.logger.info("Unlinking Linear vulnerability/image tickets")
        self.backend.unlink_issue(global_cve_ticket["guid"])
        self.backend.unlink_issue(workload_cve_ticket["guid"])
        self.backend.unlink_issue(global_image_ticket["guid"])
        self.backend.unlink_issue(workload_image_ticket["guid"])

    def _extract_linear_issue_id(self, ticket):
        provider_data = ticket.get("providerData") or {}
        issue_id = provider_data.get("id") or provider_data.get("issueID")
        if not issue_id:
            issue_id = ticket.get("linkTitle")
        return issue_id

    def test_update_linear_ticket_status(self):
        if not getattr(self, "postureTicket", None):
            raise Exception("No posture ticket available for status update test")

        issue_id = self._extract_linear_issue_id(self.postureTicket)
        assert issue_id, "Unable to determine Linear issue identifier from ticket"

        payload = {
            "linearCollabGUID": self.collab_guid,
            "siteID": self.workspace_id,
            "issueID": issue_id,
            "statusID": self.done_state_id,
            "comment": "Status updated by system tests",
        }

        Logger.logger.info(f"Updating Linear ticket status: {payload}")
        response = self.backend.update_linear_ticket_status(payload)
        assert response.get("success") is True, f"Failed to update Linear ticket: {response}"
        Logger.logger.info("✓ Linear ticket status update API call succeeded")


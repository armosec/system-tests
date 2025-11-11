import json
import time
from typing import Any, Dict, List, Optional

from systest_utils import Logger, TestUtil, statics
from tests_scripts.workflows.workflows import Workflows
from tests_scripts.workflows.utils import (
    EXPECTED_CREATE_RESPONSE,
    LINEAR_PROVIDER_NAME,
    SECURITY_RISKS,
    SECURITY_RISKS_ID,
    SECURITY_RISKS_WORKFLOW_NAME_LINEAR,
    SEVERITIES_HIGH,
    SEVERITIES_MEDIUM,
    VULNERABILITIES,
    VULNERABILITIES_WORKFLOW_NAME_LINEAR,
)


class WorkflowsLinearNotifications(Workflows):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)
        self.fw_name = None
        self.cluster: Optional[str] = None
        self.namespace: Optional[str] = None
        self.wait_for_agg_to_end = False

        self.collab_guid: Optional[str] = None
        self.workspace_id: Optional[str] = None
        self.team_id: Optional[str] = None
        self.done_state_id: Optional[str] = None

        self.helm_kwargs = {
            statics.HELM_RELEVANCY_FEATURE: statics.HELM_RELEVANCY_FEATURE_ENABLED,
            statics.HELM_NODE_SBOM_GENERATION: statics.HELM_NODE_SBOM_GENERATION_DISABLED,
        }

    def start(self):
        assert self.backend is not None, f"the test {self.test_driver.test_name} must run with backend"

        self.cluster, self.namespace = self.setup(apply_services=False)

        Logger.logger.info("Stage 1: Load Linear configuration and create workflows")
        self._load_linear_configuration()

        workflow_body = self.build_security_risk_workflow_body(
            name=SECURITY_RISKS_WORKFLOW_NAME_LINEAR + self.cluster,
            severities=SEVERITIES_MEDIUM,
            cluster=self.cluster,
            namespace=self.namespace,
            category=SECURITY_RISKS,
            security_risk_id=SECURITY_RISKS_ID,
        )
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)

        workflow_body = self.build_vulnerabilities_workflow_body(
            name=VULNERABILITIES_WORKFLOW_NAME_LINEAR + self.cluster,
            severities=SEVERITIES_HIGH,
            cluster=self.cluster,
            namespace=self.namespace,
            category=VULNERABILITIES,
            cvss=6,
        )
        self.create_and_assert_workflow(workflow_body, EXPECTED_CREATE_RESPONSE, update=False)

        before_test_message_ts = time.time()

        Logger.logger.info("Stage 2: Validate workflows created successfully")
        guid = self.validate_workflow(SECURITY_RISKS_WORKFLOW_NAME_LINEAR + self.cluster, LINEAR_PROVIDER_NAME)
        self.add_workflow_test_guid(guid)
        guid = self.validate_workflow(VULNERABILITIES_WORKFLOW_NAME_LINEAR + self.cluster, LINEAR_PROVIDER_NAME)
        self.add_workflow_test_guid(guid)

        Logger.logger.info("Stage 3: Install kubescape with helm-chart")
        self.install_kubescape(helm_kwargs=self.helm_kwargs)
        time.sleep(60)

        Logger.logger.info("Stage 4: Apply deployment")
        workload_objs: List[Dict[str, Any]] = self.apply_directory(path=self.test_obj["deployments"], namespace=self.namespace)
        self.verify_all_pods_are_running(namespace=self.namespace, workload=workload_objs, timeout=240)

        Logger.logger.info("Stage 5: Trigger first scan")
        self.backend.create_kubescape_job_request(cluster_name=self.cluster, framework_list=[self.fw_name])

        Logger.logger.info("Stage 6: Assert Linear tickets were created")
        self.assert_linear_tickets_were_created(before_test_message_ts, self.cluster)

        Logger.logger.info("Stage 7: Cleanup")
        return self.cleanup()

    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)

    def _load_linear_configuration(self):
        status = self.backend.get_integration_status(LINEAR_PROVIDER_NAME)
        linear_status = next((s for s in status or [] if s.get("provider") == LINEAR_PROVIDER_NAME), None)
        assert linear_status and linear_status.get("status") == "connected", f"Linear provider not connected, status: {linear_status}"

        config = self.backend.get_linear_config()
        connections = config.get("linearConnections") or []
        assert connections, "Linear configuration returned no connections"

        connection = connections[0]
        self.collab_guid = connection.get("collabGUID")
        assert self.collab_guid, "Linear collaboration GUID missing from configuration"

        workspace = connection.get("selectedWorkspace") or {}
        self.workspace_id = workspace.get("id")
        assert self.workspace_id, "Linear workspace ID missing from configuration"

        teams = connection.get("teams") or []
        assert teams, "Linear configuration missing team definitions"
        team = self._select_team(teams)
        assert team, "Failed to select Linear team configuration"

        self.team_id = self._normalize_id(team.get("id"))
        assert self.team_id, "Linear team ID missing"

        self.done_state_id = (team.get("autoClosureSettings") or {}).get("targetStateId")
        if not self.done_state_id:
            states = self.backend.search_linear_field_values(self.collab_guid, "stateId", self.team_id)
            self.done_state_id = self._extract_state_id(states)

    def _select_team(self, teams: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        return next((team for team in teams if team.get("isDefault")), teams[0] if teams else None)

    def _normalize_id(self, value: Any) -> str:
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

    def _extract_state_id(self, response: Any) -> Optional[str]:
        if not response:
            return None
        values = response.get("response") if isinstance(response, dict) else response
        if not values:
            return None
        if isinstance(values, list) and values and isinstance(values[0], list):
            values = values[0]
        for item in values:
            if isinstance(item, dict):
                state_id = self._normalize_id(item.get("id"))
                if state_id:
                    return state_id
        return None

    def build_security_risk_workflow_body(
        self,
        name: str,
        severities: List[str],
        cluster: str,
        namespace: str,
        category: str,
        security_risk_id: str,
        guid: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": name,
            "scope": [
                {
                    "cluster": cluster,
                    "namespace": namespace,
                }
            ],
            "conditions": [
                {
                    "category": category,
                    "parameters": {
                        "severities": severities,
                        "securityRiskIDs": [security_risk_id],
                    },
                }
            ],
            "notifications": [
                {
                    "provider": LINEAR_PROVIDER_NAME,
                    "linearTicketIdentifiers": [self._linear_ticket_identifiers()],
                }
            ],
        }

    def build_vulnerabilities_workflow_body(
        self,
        name: str,
        severities: List[str],
        cluster: str,
        namespace: str,
        category: str,
        cvss: int,
        guid: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "guid": guid,
            "updatedTime": "",
            "updatedBy": "",
            "enabled": True,
            "name": name,
            "scope": [
                {
                    "cluster": cluster,
                    "namespace": namespace,
                }
            ],
            "conditions": [
                {
                    "category": category,
                    "parameters": {
                        "severities": severities,
                        "cvss": cvss,
                        "inUse": True,
                        "fixable": True,
                    },
                }
            ],
            "notifications": [
                {
                    "provider": LINEAR_PROVIDER_NAME,
                    "linearTicketIdentifiers": [self._linear_ticket_identifiers()],
                }
            ],
        }

    def _linear_ticket_identifiers(self) -> Dict[str, Any]:
        identifiers: Dict[str, Any] = {
            "workspaceId": self.workspace_id,
            "teamId": self.team_id,
        }
        fields: Dict[str, Any] = {}
        if self.collab_guid:
            fields["collaborationGUID"] = self.collab_guid
        if self.done_state_id:
            fields["stateId"] = self.done_state_id
        identifiers["fields"] = fields
        return identifiers

    def assert_linear_tickets_were_created(self, begin_time: float, cluster_name: str, attempts: int = 30, sleep_time: int = 20):
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

        security_risks_response: Optional[Dict[str, Any]] = None
        vulnerabilities_response: Optional[List[Dict[str, Any]]] = None
        linear_issues: Optional[List[Dict[str, Any]]] = None

        for i in range(attempts):
            try:
                issues = self.test_obj["getMessagesFunc"](begin_time, cluster=cluster_name)
                Logger.logger.debug(f"Retrieved {len(issues) if issues else 0} issues from Linear")
                if issues:
                    Logger.logger.debug(f"First Linear issue: {issues[0]}")

                assert issues and len(issues) > 0, f"No Linear issues found for cluster {cluster_name}"
                linear_issues = issues

                if security_risks_response is None:
                    sr_raw = self.backend.get_security_risks_list(
                        cluster_name=cluster_name,
                        namespace=self.namespace,
                        security_risk_ids=[SECURITY_RISKS_ID],
                    )
                    security_risks_response = json.loads(sr_raw.text)
                    self.assert_security_risks_linear_ticket_created(
                        issues=linear_issues,
                        response=security_risks_response,
                        security_risk_id=SECURITY_RISKS_ID,
                        cluster=cluster_name,
                    )
                    Logger.logger.info("Security risk Linear ticket created")

                if vulnerabilities_response is None:
                    vulnerabilities_response = self.backend.get_vulns_v2(body=vuln_body, enrich_tickets=True)
                    self.assert_vulnerability_linear_ticket_created(
                        issues=linear_issues,
                        vulnerabilities=vulnerabilities_response,
                        cluster=cluster_name,
                        cves=["CVE-2023-27522"],
                    )
                    Logger.logger.info("Vulnerability Linear ticket created")

                if security_risks_response and vulnerabilities_response:
                    break
            except (AssertionError, Exception) as e:
                Logger.logger.info(f"iteration: {i}: {e}")
                if i == attempts - 1:
                    Logger.logger.error(
                        f"Failed to assert Linear tickets were created after {attempts} attempts, cleaning up"
                    )
                    raise
                TestUtil.sleep(sleep_time, f"iteration: {i}, waiting additional {sleep_time} seconds for tickets to arrive")

        self._cleanup_linear_tickets(security_risks_response, vulnerabilities_response)

    def assert_security_risks_linear_ticket_created(
        self,
        issues: List[Dict[str, Any]],
        response: Dict[str, Any],
        security_risk_id: str,
        cluster: str,
    ):
        risks = response.get("response", [])
        assert risks, "No security risks found in response"

        for risk in risks:
            if security_risk_id and risk.get("securityRiskID") != security_risk_id:
                continue
            tickets = risk.get("tickets", [])
            assert tickets, f"No tickets associated with security risk {security_risk_id}"
            assert any(ticket.get("provider") == LINEAR_PROVIDER_NAME for ticket in tickets), (
                f"No Linear tickets associated with security risk {security_risk_id}"
            )

            issue = next(
                (
                    issue
                    for issue in issues
                    if "Risk:" in (issue.get("title") or "")
                    and cluster in self._issue_text(issue)
                ),
                None,
            )
            assert issue, f"No Linear issue found for security risk {security_risk_id} in cluster {cluster}"
            Logger.logger.info("Security risk linear ticket created")
            return

        raise AssertionError(f"Security risk {security_risk_id} not found in response")

    def assert_vulnerability_linear_ticket_created(
        self,
        issues: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
        cluster: str,
        cves: List[str],
    ):
        assert vulnerabilities, "No vulnerabilities found in response"

        for cve in cves:
            vulnerability = next((v for v in vulnerabilities if v.get("name") == cve), None)
            assert vulnerability, f"No vulnerability with CVE {cve} found in response"

            tickets = vulnerability.get("tickets", [])
            assert tickets, f"No tickets associated with vulnerability {cve}"
            assert any(ticket.get("provider") == LINEAR_PROVIDER_NAME for ticket in tickets), (
                f"No Linear tickets associated with vulnerability {cve}"
            )

            issue = next(
                (
                    issue
                    for issue in issues
                    if cve in self._issue_text(issue)
                    and cluster in self._issue_text(issue)
                ),
                None,
            )
            assert issue, f"No Linear issue found containing CVE {cve} for cluster {cluster}"
            Logger.logger.info(f"Vulnerability Linear ticket created for CVE {cve} in cluster {cluster}")

    @staticmethod
    def _issue_text(issue: Dict[str, Any]) -> str:
        parts: List[str] = []
        for key in ("title", "description"):
            value = issue.get(key)
            if isinstance(value, str):
                parts.append(value)

        description_data = issue.get("descriptionData")
        if description_data:
            try:
                parts.append(json.dumps(description_data))
            except (TypeError, ValueError):
                parts.append(str(description_data))

        return " ".join(parts)

    def _cleanup_linear_tickets(
        self,
        security_risks_response: Optional[Dict[str, Any]],
        vulnerabilities_response: Optional[List[Dict[str, Any]]],
    ):
        if security_risks_response:
            self.unlink_issues(security_risks_response)

        if not vulnerabilities_response:
            return

        for vulnerability in vulnerabilities_response:
            for ticket in vulnerability.get("tickets", []):
                guid = ticket.get("guid")
                if guid:
                    self.backend.unlink_issue(guid)

    def validate_workflow(self, expected_name: str, expected_provider: str) -> str:
        body = {
            "pageSize": 150,
            "pageNum": 1,
            "innerFilters": [
                {
                    "name": expected_name,
                }
            ],
            "orderBy": "updatedTime:desc",
        }
        workflows = self.backend.get_workflows(body=body)
        assert workflows["total"]["value"] == 1, (
            f"Expected total value to be equal to 1 for workflow {expected_name}, "
            f"but got {workflows['total']['value']}"
        )

        workflow = workflows["response"][0]
        assert workflow["name"] == expected_name, f"Expected name {expected_name} but got {workflow['name']}"
        notification = workflow["notifications"][0]
        assert (
            notification["provider"] == expected_provider
        ), f"Expected provider {expected_provider} but got {notification['provider']}"
        identifiers = notification.get("linearTicketIdentifiers")
        assert identifiers, "Expected Linear ticket identifiers to be present"
        return workflow["guid"]


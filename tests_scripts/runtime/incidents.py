import json
import time


from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import statics, Logger
from tests_scripts.helm.base_helm import BaseHelm

__RELATED_ALERTS_KEY__ = "relatedAlerts"
__RESPONSE_FIELD__ = "response"




class Incidents(BaseHelm):
    """
        check incidents page.
    """

    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(Incidents, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)
        self.helm_kwargs = {
            "capabilities.manageWorkloads":"enable",
            "capabilities.configurationScan": "disable",
            "capabilities.continuousScan": "disable",
            "capabilities.nodeScan": "disable",
            "capabilities.vulnerabilityScan": "disable",
            "grypeOfflineDB.enabled": "false",
            # not clear why
            "capabilities.relevancy": "enable",
            # enable application profile, malware and runtime detection
            "capabilities.runtimeObservability": "enable",
            "capabilities.malwareDetection": "enable",
            "capabilities.runtimeDetection": "enable",
            "capabilities.nodeProfileService": "enable",
            "alertCRD.installDefault": True,
            "alertCRD.scopeClustered": True,
            # short learning period
            "nodeAgent.config.maxLearningPeriod": "60s",
            "nodeAgent.config.learningPeriod": "50s",
            "nodeAgent.config.updatePeriod": "30s",
            "nodeAgent.config.nodeProfileInterval": "1m",
            # "nodeAgent.image.repository": "docker.io/amitschendel/node-agent",
            # "nodeAgent.image.tag": "v0.0.5",
        }
        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)

    def start(self):
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        cluster, namespace = self.setup()

        Logger.logger.info(". Install armo helm-chart before application so we will have final AP")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=360,
                             namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        Logger.logger.info('Simulate unexpected process')
        inc = self.simulate_unexpected_process(deployments_path=self.test_obj["deployments"],
                                               cluster=cluster, namespace=namespace, command="cat /etc/hosts", expected_incident_name="Unexpected process launched")

        self.check_incident_unique_values(inc)
        self.check_incidents_per_severity()
        self.check_incidents_overtime()
        self.wait_for_report(self.check_alerts_of_incident, sleep_interval=5, timeout=360, incident=inc)
        # Ben disabled them (they are not working but not used by frontend, waiting for Amir's response)
        #self.check_raw_alerts_overtime()
        #self.check_raw_alerts_list()

        self.resolve_incident(inc)
        self.check_incident_resolved(inc)
        self.wait_for_report(self.check_overtime_resolved_incident, sleep_interval=5, timeout=30)

        self.resolve_incident_false_positive(inc)
        self.check_incident_resolved_false_positive(inc)
        #self.wait_for_report(self.check_process_graph, sleep_interval=5, timeout=30, incident=inc)
        self.wait_for_report(self.verify_kdr_monitored_counters, sleep_interval=25, timeout=600, cluster=cluster)

        return self.cleanup()

    def simulate_unexpected_process(self, deployments_path: str, cluster: str, namespace: str, command: str, expected_incident_name: str = "Unexpected process launched"):
        Logger.logger.info(f"Simulate unexpected process from {deployments_path}")
        Logger.logger.info(f"Apply workload from {deployments_path} to {namespace}")
        workload_objs: list = self.apply_directory(path=deployments_path, namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)
        if isinstance(wlids, str):
            wlids = [wlids]
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=180, namespace=namespace)

        Logger.logger.info(
            f'workloads are running, waiting for application profile finalizing before exec into pod {wlids}')
        self.wait_for_report(self.verify_application_profiles, wlids=wlids, namespace=namespace)
        time.sleep(30)
        self.exec_pod(wlid=wlids[0], command=command)

        Logger.logger.info("Get incidents list")
        incs, _ = self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=5,
                                       cluster=cluster, namespace=namespace,
                                       incident_name=[expected_incident_name])
        Logger.logger.info(f"Got incidents list {json.dumps(incs)}")
        inc, _ = self.wait_for_report(self.verify_incident_completed, timeout=10 * 60, sleep_interval=10,
                                      incident_id=incs[0]['guid'])
        Logger.logger.info(f"Got incident {json.dumps(inc)}")
        assert inc.get(__RELATED_ALERTS_KEY__, None) is None or len(
            inc[__RELATED_ALERTS_KEY__]) == 0, f"Expected no related alerts in the incident API {json.dumps(inc)}"
        
        return inc

    def verify_kdr_monitored_counters(self, cluster: str):
        Logger.logger.info("Get monitored assets")
        resp = self.backend.get_kdr_monitored_counters(cluster=cluster)
        assert resp is not None, f"Failed to get monitored assets {json.dumps(resp)}"
        assert resp.get("clustersCount", 0) > 0, f"Failed to get monitored assets {json.dumps(resp)}"
        assert resp.get("nodesCount", 0) > 0, f"Failed to get monitored assets {json.dumps(resp)}"
        assert resp.get("namespacesCount", 0) > 0, f"Failed to get monitored assets {json.dumps(resp)}"
        assert resp.get("podsCount", 0) > 0, f"Failed to get monitored assets {json.dumps(resp)}"
        assert resp.get("containersCount", 0) > 0, f"Failed to get monitored assets {json.dumps(resp)}"
        Logger.logger.info(f"Got monitored assets {json.dumps(resp)}")

    def check_process_graph(self, incident):
        Logger.logger.info("Get process graph")
        resp = self.backend.get_process_graph(incident_id=incident['guid'])
        expected_process_graph = {"graphNodes": [
            {"graphNodeType": "Node", "graphNodeID": f"{incident['guid']}-Node-{incident['nodeName']}",
             "graphNodeLabel": f"{incident['nodeName']}", "hasIncident": False, "graphNodeBadge": 0,
             "nodeMetadata": {}},
            {"graphNodeType": "Pod", "graphNodeID": f"{incident['guid']}-Pod-{incident['podName']}",
             "graphNodeLabel": f"{incident['podName']}", "hasIncident": False, "graphNodeBadge": 0,
             "nodeMetadata": {"workloadKind": "Deployment", "workloadName": "redis-sleep", "workloadNamespace": incident['workloadNamespace']}},
            {"graphNodeType": "Container", "graphNodeID": f"{incident['guid']}-Container-redis",
             "graphNodeLabel": "redis", "hasIncident": False, "graphNodeBadge": 0, "nodeMetadata": {
                "image": "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
                "workloadKind": "Deployment", "workloadName": "redis-sleep", "workloadNamespace": incident['workloadNamespace']}},
            {"graphNodeType": "Process", "graphNodeID": f"{incident['guid']}-Process-ls:{incident['infectedPID']}",
             "graphNodeLabel": f"ls:{incident['infectedPID']}", "hasIncident": True, "graphNodeBadge": 0,
             "nodeMetadata": {"processID": incident['infectedPID'], "processName": "ls"}},
            # {"graphNodeType": "Files", "graphNodeID": f"{incident['guid']}-Files-ls:{incident['infectedPID']}-Files",
            #  "graphNodeLabel": "", "hasIncident": False, "graphNodeBadge": 6,
            #  "nodeMetadata": {"ruleIDs": ["R0002"], "processID": incident['infectedPID'], "processName": "ls"}}
             ],
            "graphEdges": [{"from": f"{incident['guid']}-Node-{incident['nodeName']}",
                            "to": f"{incident['guid']}-Pod-{incident['podName']}",
                            "edgeType": "directed"},
                           {"from": f"{incident['guid']}-Pod-{incident['podName']}",
                            "to": f"{incident['guid']}-Container-redis", "edgeType": "directed"},
                           {"from": f"{incident['guid']}-Container-redis",
                            "to": f"{incident['guid']}-Process-ls:{incident['infectedPID']}",
                            "edgeType": "directed"},
                        #    {"from": f"{incident['guid']}-Process-ls:{incident['infectedPID']}",
                        #     "to": f"{incident['guid']}-Files-ls:{incident['infectedPID']}-Files",
                        #     "edgeType": "directed"}
                            ]}
        assert resp is not None, f"Failed to get process graph {json.dumps(resp)}"
        for k, v in enumerate(expected_process_graph['graphNodes']):
            for k1, v1 in v.items():
                assert resp['graphNodes'][k][k1] == v1, f"Failed to get process graph node {k}, {k1}, {resp['graphNodes'][k][k1]}. {json.dumps(resp)}"
        for k, v in enumerate(expected_process_graph['graphEdges']):
            for k1, v1 in v.items():
                assert resp['graphEdges'][k][k1] == v1, f"Failed to get process graph edge {k}, {k1}, {resp['graphEdges'][k][k1]}. {json.dumps(resp)}"

        Logger.logger.info(f"Got process graph {json.dumps(resp)}")

    def check_raw_alerts_list(self):
        Logger.logger.info("Get raw alerts list")
        resp = self.backend.get_raw_alerts_list()
        assert resp[__RESPONSE_FIELD__] is not None, f"Failed to get raw alerts list {json.dumps(resp)}"
        assert len(resp[__RESPONSE_FIELD__]) > 0, f"Failed to get raw alerts list {len(resp['response'])}"
        Logger.logger.info(f"Got raw alerts list. Trying with cursor next page {json.dumps(resp)}")
        assert resp.get("cursor", None) is not None, f"Failed to get raw alerts list cursor {json.dumps(resp)}"
        resp = self.backend.get_raw_alerts_list(cursor=resp["cursor"])
        assert resp[__RESPONSE_FIELD__] is not None, f"Failed to get raw alerts list {json.dumps(resp)}"
        assert len(resp[__RESPONSE_FIELD__]) > 0, f"Failed to get raw alerts list {len(resp['response'])}"
        Logger.logger.info(f"Got raw alerts list {json.dumps(resp)}")

    def check_raw_alerts_overtime(self):
        Logger.logger.info("Get raw alerts over time")
        resp = self.backend.get_raw_alerts_overtime()
        assert resp['alertsPerDay'] is not None, f"Failed to get raw alerts over time {json.dumps(resp)}"
        assert len(resp['alertsPerDay']) > 0, f"Failed to get raw alerts over time {len(resp['alertsPerDay'])}"
        today = time.strftime("%Y-%m-%d")
        assert resp['alertsPerDay'][-1].get("date",
                                            "") == today, f"Failed to get raw alerts over time date {json.dumps(resp)}"
        assert resp['alertsPerDay'][-1].get("count",
                                            0) > 0, f"Failed to get raw alerts over time count {json.dumps(resp)}"
        Logger.logger.info(f"Got raw alerts over time {json.dumps(resp)}")

    def resolve_incident(self, incident):
        Logger.logger.info("Resolve incident")
        _ = self.backend.resolve_incident(incident_id=incident['guid'], resolution="Suspicious")

    def resolve_incident_false_positive(self, incident):
        Logger.logger.info("Resolve incident false positive")
        _ = self.backend.resolve_incident(incident_id=incident['guid'], resolution="FalsePositive")

    def check_incident_resolved(self, incident):
        Logger.logger.info("Check resolved incident")
        Logger.logger.info("Get incidents list")
        filters_dict = {
            "guid": incident['guid']
        }
        response = self.backend.get_incidents(filters=filters_dict)
        incs = response['response']
        assert len(incs) == 1, f"Failed to get incident list for guid '{incident['guid']}' {json.dumps(incs)}"
        assert incs[0]["isDismissed"], f"Failed to get resolved incident {json.dumps(incs)}"
        assert incs[0].get("markedAsFalsePositive", False) is False, f"markedAsFalsePositive==true {json.dumps(incs)}"
        # assert incs[0].get("resolvedBy", "") != "", f"resolvedBy==None {json.dumps(incs)}" // not working with API keys?
        assert incs[0].get("resolvedAt", "") != "", f"resolvedAt==None {json.dumps(incs)}"

        Logger.logger.info(f"Got resolved incident {json.dumps(incs)}")

    def check_incident_resolved_false_positive(self, incident):
        Logger.logger.info("Check resolved incident false positive")
        Logger.logger.info("Get incidents list")
        filters_dict = {
            "guid": incident['guid']
        }
        response = self.backend.get_incidents(filters=filters_dict)
        incs = response['response']
        assert len(incs) == 1, f"Failed to get incident list for guid '{incident['guid']}' {json.dumps(incs)}"
        assert incs[0]["isDismissed"], f"Failed to get resolved incident false positive {json.dumps(incs)}"
        assert incs[0].get("markedAsFalsePositive", False), f"markedAsFalsePositive==false {json.dumps(incs)}"
        Logger.logger.info(f"Got resolved incident false positive {json.dumps(incs)}")

    def check_alerts_of_incident(self, incident):
        Logger.logger.info("Get alerts of incident")
        resp = self.backend.get_alerts_of_incident(incident_id=incident['guid'])
        alerts = resp[__RESPONSE_FIELD__]
        assert alerts is not None, f"Failed to get alerts of incident {json.dumps(incident)}"
        assert len(alerts) > 1, f"Failed to get alerts of incident {incident['guid']}, got {resp}"
        Logger.logger.info(f"Got alerts of incident {json.dumps(alerts)}")
        self.check_alerts_unique_values(incident)

    def check_alerts_unique_values(self, incident):
        Logger.logger.info("Check unique values of alerts")
        unique_values_req = {
            "fields": {"ruleID": ""},
            #"innerFilters": [{"ruleID": "R0001,R0002,R0003,R0004"}],
            "innerFilters": [{"ruleID": "R0001,R0004"}],
            "pageSize": 100,
            "pageNum": 1
        }
        unique_values = self.backend.get_alerts_unique_values(incident_id=incident['guid'], request=unique_values_req)
        assert unique_values is not None, f"Failed to get unique values of alerts {json.dumps(incident)}"
        #expected_values = {"ruleID": ["R0001", "R0002", "R0003", "R0004"]}
        expected_values = {"ruleID": ["R0001", "R0004"]}
        # don't check the count, it's dynamic
        assert unique_values[
                   "fields"] == expected_values, f"Failed to get unique values of alerts {json.dumps(incident)} {json.dumps(unique_values)}"

    def check_incidents_per_severity(self):
        Logger.logger.info("Get incidents per severity")
        resp = self.backend.get_incidents_per_severity()
        assert resp[__RESPONSE_FIELD__] is not None, f"Failed to get incidents per severity {json.dumps(resp)}"
        assert len(resp[__RESPONSE_FIELD__]) > 0, f"Failed to get incidents per severity {json.dumps(resp)}"

    def check_incidents_overtime(self):
        Logger.logger.info("Get incidents over time")
        resp = self.backend.get_incidents_overtime()
        assert resp[__RESPONSE_FIELD__] is not None, f"Failed to get incidents over time {json.dumps(resp)}"
        assert len(resp[__RESPONSE_FIELD__]) > 0, f"Failed to get incidents over time {len(resp[__RESPONSE_FIELD__])}"
        today = time.strftime("%Y-%m-%d")
        assert resp[__RESPONSE_FIELD__][-1].get("date",
                                                "") == today, f"Failed to get incidents over time date {json.dumps(resp)}"
        assert resp[__RESPONSE_FIELD__][-1].get("count",
                                                0) > 0, f"Failed to get incidents over time count {json.dumps(resp)}"
        assert resp[__RESPONSE_FIELD__][-1].get("newCount",
                                                0) > 0, f"Failed to get incidents over time newCount {json.dumps(resp)}"
        Logger.logger.info(f"Got incidents over time {json.dumps(resp)}")

    def check_overtime_resolved_incident(self):
        Logger.logger.info("Get resolved incidents over time")
        resp = self.backend.get_incidents_overtime()
        assert resp[__RESPONSE_FIELD__] is not None, f"Failed to get incidents over time {json.dumps(resp)}"
        assert len(resp[__RESPONSE_FIELD__]) > 0, f"Failed to get incidents over time {len(resp[__RESPONSE_FIELD__])}"
        today = time.strftime("%Y-%m-%d")
        assert resp[__RESPONSE_FIELD__][-1].get("date",
                                                "") == today, f"Failed to get incidents over time date {json.dumps(resp)}"
        assert resp[__RESPONSE_FIELD__][-1].get("count",
                                                0) > 0, f"Failed to get incidents over time count {json.dumps(resp)}"
        assert resp[__RESPONSE_FIELD__][-1].get("newCount",
                                                0) > 0, f"Failed to get incidents over time newCount {json.dumps(resp)}"
        assert resp[__RESPONSE_FIELD__][-1].get("dismissedCount",
                                                0) > 0, f"Failed to get incidents over time dismissedCount {json.dumps(resp)}"
        Logger.logger.info(f"Got resolved incidents over time {json.dumps(resp)}")

    def check_incident_unique_values(self, incident):
        Logger.logger.info("Check unique values of incident")
        unique_values_req = {
            "fields": {"clusterName": "", "containerName": "", "name": "",
                       "podName": "", "workloadKind": "", "workloadName": "",
                       "incidentSeverity": "", "mitreTactic": "", "isDismissed": "", "incidentCategory": "",
                       "nodeName": ""},
            "innerFilters": [{"guid": incident['guid']}],
            "pageSize": 100,
            "pageNum": 1
        }
        unique_values = self.backend.get_incident_unique_values(unique_values_req)

        assert unique_values is not None, f"Failed to get unique values of incident {json.dumps(incident)}"
        expected_values_for_sensitive_fa = {'fields': {'clusterName': [incident["clusterName"]], 'containerName': ['redis'],
                                      'incidentCategory': ['Anomaly'], 'incidentSeverity': ['Medium'],
                                      'isDismissed': ['false'], 'mitreTactic': ['TA0006'],
                                      'name': ['Unexpected Sensitive File Access'], 'nodeName': [incident["nodeName"]],
                                      "podName": [incident["podName"]],
                                      'workloadKind': ['Deployment'],
                                      'workloadName': ['redis-sleep']},
                           'fieldsCount': {'clusterName': [{'key': incident["clusterName"], 'count': 1}],
                                           'containerName': [{'key': 'redis', 'count': 1}],
                                           'incidentCategory': [{'key': 'Anomaly', 'count': 1}],
                                           'incidentSeverity': [{'key': 'Medium', 'count': 1}],
                                           'isDismissed': [{'key': 'false', 'count': 1}],
                                           'mitreTactic': [{'key': 'TA0006', 'count': 1}],
                                           'name': [{'key': 'Unexpected Sensitive File Access', 'count': 1}],
                                           'nodeName': [{'key': incident["nodeName"], 'count': 1}],
                                           'podName': [{'key': incident["podName"], 'count': 1}],
                                           'workloadKind': [{'key': 'Deployment', 'count': 1}],
                                           'workloadName': [{'key': 'redis-sleep', 'count': 1}]}}
        expected_values_unexpected_process = {"fields": {"clusterName": [incident["clusterName"]], "containerName": ["redis"],
                                      "incidentCategory": ["Anomaly"], "incidentSeverity": ["Medium"],
                                      "isDismissed": ["false"], "mitreTactic": ["TA0002"],
                                      "name": ["Unexpected process launched"], "nodeName": [incident["nodeName"]],
                                      "podName": [incident["podName"]],
                                      "workloadKind": ["Deployment"],
                                      "workloadName": ["redis-sleep"]},
                           "fieldsCount": {"clusterName": [{"key": incident["clusterName"], "count": 1}],
                                           "containerName": [{"key": "redis", "count": 1}],
                                           "incidentCategory": [{"key": "Anomaly", "count": 1}],
                                           "incidentSeverity": [{"key": "Medium", "count": 1}],
                                           "isDismissed": [{"key": "false", "count": 1}],
                                           "mitreTactic": [{"key": "TA0002", "count": 1}],
                                           "name": [{"key": "Unexpected process launched", "count": 1}],
                                           "nodeName": [{"key": incident["nodeName"], "count": 1}],
                                           "podName": [{"key": incident["podName"], "count": 1}],
                                           "workloadKind": [{"key": "Deployment", "count": 1}],
                                           "workloadName": [{"key": "redis-sleep", "count": 1}]}}
        expected_values = expected_values_for_sensitive_fa
        if incident["name"] == "Unexpected process launched":
            expected_values = expected_values_unexpected_process
        assert unique_values == expected_values, f"Failed to get unique values of incident {json.dumps(incident)} {json.dumps(unique_values)}"
        Logger.logger.info(f"Got unique values of incident {json.dumps(unique_values)}")

    def verify_incident_completed(self, incident_id):
        response = self.backend.get_incident(incident_id)
        assert response['attributes']['incidentStatus'] == "completed", f"Not completed incident {json.dumps(response)}"
        assert response['processTree'] is not None, f"Failed to get processTree {json.dumps(response)}"
        assert response['processTree'][
                   'processTree'] is not None, f"Failed to get processTree/processTree {json.dumps(response)}"
        actual_process_tree = response['processTree']['processTree']
        if "children" in actual_process_tree and len(actual_process_tree["children"]) > 0:
            actual_process_tree = actual_process_tree["children"][0]
        assert "cat" in actual_process_tree['comm'], f"Unexpected process tree comm {json.dumps(actual_process_tree)}"
        assert actual_process_tree['pid'] > 0, f"Unexpected process tree pid {json.dumps(actual_process_tree)}"
        # optional fields
        assert "cat /etc/hosts" in actual_process_tree.get('cmdline', "cat /etc/hosts"), f"Unexpected process tree cmdline {json.dumps(actual_process_tree)}"
        assert "/data" in actual_process_tree.get('cwd', '/data'), f"Unexpected process tree cwd {json.dumps(actual_process_tree)}"
        assert "/bin/busybox" in actual_process_tree.get('hardlink', "/bin/busybox"), f"Unexpected process tree path {json.dumps(actual_process_tree)}"
        assert not actual_process_tree.get('upperLayer', False), f"Unexpected process tree upperLayer {json.dumps(actual_process_tree)}"

        return response

    def verify_incident_in_backend_list(self, cluster, namespace, incident_name = None):
        Logger.logger.info("Get incidents list")
        filters_dict = {
            "designators.attributes.cluster": cluster,
            "designators.attributes.namespace": namespace,
        }
        if isinstance(incident_name,str):
            filters_dict["name"] = incident_name
        elif isinstance(incident_name, list):
            filters_dict["name"] = ','.join(incident_name)

        response = self.backend.get_incidents(filters=filters_dict)
        incs = response['response']
        assert len(incs) > 0, f"Failed to get incidents list {json.dumps(incs)}"
        return incs

    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)

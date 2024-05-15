from tests_scripts.helm.base_helm import BaseHelm
from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import statics, Logger, TestUtil
import json
import time

__RELATED_ALERTS_KEY__ = "relatedAlerts"
__RESPONSE_FIELD__ = "response"

class Incidents(BaseHelm):
    '''
        check incidents page.
    '''

    def __init__(self, test_obj: TestConfiguration = None, backend=None, test_driver=None):
        super(Incidents, self).__init__(test_obj=test_obj, backend=backend, test_driver=test_driver)
        self.helm_kwargs = {
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
            "alertCRD.installDefault" : True,
            "alertCRD.scopeClustered" : True,
            # short learning period
            "nodeAgent.config.maxLearningPeriod": "60s",
            "nodeAgent.config.learningPeriod": "50s",
            "nodeAgent.config.updatePeriod": "30s",
            # "nodeAgent.image.repository": "docker.io/amitschendel/node-agent",
            # "nodeAgent.image.tag": "v0.0.5",
        }
        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)

    def start(self):
        assert self.backend != None; f'the test {self.test_driver.test_name} must run with backend'

        cluster, namespace = self.setup()

        Logger.logger.info(". Install armo helm-chart before application so we will have final AP")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=360, namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

        Logger.logger.info('apply workloads')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)
        if isinstance(wlids, str):
            wlids = [wlids]
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=180, namespace=namespace)

        Logger.logger.info(f'workloads are running, waiting for application profile finalizing before exec into pod {wlids}')
        self.wait_for_report(self.verify_application_profiles, wlids=wlids, namespace=namespace)
        time.sleep(6)
        self.exec_pod(wlid=wlids[0], command="ls -l /tmp")

        Logger.logger.info("Get incidents list")
        incs, _ = self.wait_for_report(self.verify_incident_in_backend_list, timeout=30, sleep_interval=5, cluster=cluster, namespace=namespace, incident_name="Unexpected process launched")
        Logger.logger.info(f"Got incidents list {json.dumps(incs)}")
        inc, _ = self.wait_for_report(self.verify_incident_completed,timeout=5*60, sleep_interval=5, incident_id=incs[0]['guid'])
        Logger.logger.info(f"Got incident {json.dumps(inc)}")
        assert inc.get(__RELATED_ALERTS_KEY__, None) is None or len(inc[__RELATED_ALERTS_KEY__]) == 0, f"Expected no related alerts in the incident API {json.dumps(inc)}"
        
        self.check_incident_unique_values(inc)
        self.check_incidents_per_severity()
        self.check_incidents_overtime()
        self.wait_for_report(self.check_alerts_of_incident,sleep_interval=5, timeout=180, incident=inc)
        self.check_raw_alerts_overtime()
        self.check_raw_alerts_list()

        self.resolve_incident(inc)
        self.check_incident_resolved(inc)
        self.check_overtime_resolved_incident()

        self.reslove_incident_false_positive(inc)
        self.check_incident_resolved_false_positive(inc)

        return self.cleanup()
    
    def check_raw_alerts_list(self):
        Logger.logger.info("Get raw alerts list")
        resp = self.backend.get_raw_alerts_list()
        assert resp[__RESPONSE_FIELD__] != None, f"Failed to get raw alerts list {json.dumps(resp)}"
        assert len(resp[__RESPONSE_FIELD__]) > 0, f"Failed to get raw alerts list {len(resp['response'])}"
        Logger.logger.info(f"Got raw alerts list. Trying with cursor next page {json.dumps(resp)}")
        assert resp.get("cursor", None) != None, f"Failed to get raw alerts list cursor {json.dumps(resp)}"
        # resp = self.backend.get_raw_alerts_list(cursor=resp["cursor"])
        # assert resp[__RESPONSE_FIELD__] != None, f"Failed to get raw alerts list {json.dumps(resp)}"
        # assert len(resp[__RESPONSE_FIELD__]) > 0, f"Failed to get raw alerts list {len(resp['response'])}"
        # Logger.logger.info(f"Got raw alerts list {json.dumps(resp)}")
        
    
    def check_raw_alerts_overtime(self):
        Logger.logger.info("Get raw alerts over time")
        resp = self.backend.get_raw_alerts_overtime()
        assert resp['alertsPerDay'] != None, f"Failed to get raw alerts over time {json.dumps(resp)}"
        assert len(resp['alertsPerDay']) > 0, f"Failed to get raw alerts over time {len(resp['alertsPerDay'])}"
        today = time.strftime("%Y-%m-%d")
        assert resp['alertsPerDay'][-1].get("date", "") == today, f"Failed to get raw alerts over time date {json.dumps(resp)}"
        assert resp['alertsPerDay'][-1].get("count", 0) > 0, f"Failed to get raw alerts over time count {json.dumps(resp)}"
        Logger.logger.info(f"Got raw alerts over time {json.dumps(resp)}")
    
    def resolve_incident(self, incident):
        Logger.logger.info("Resolve incident")
        _ = self.backend.resolve_incident(incident_id=incident['guid'], resolution="Suspicious")

    def reslove_incident_false_positive(self, incident):
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
        assert incs[0].get("markedAsFalsePositive", False) == False, f"markedAsFalsePositive==true {json.dumps(incs)}"        
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
        assert alerts != None, f"Failed to get alerts of incident {json.dumps(incident)}"
        assert len(alerts) > 1, f"Failed to get alerts of incident {incident['guid']}, got {resp}"
        Logger.logger.info(f"Got alerts of incident {json.dumps(alerts)}")
        self.check_alerts_unique_values(incident)

    def check_alerts_unique_values(self, incident):
        Logger.logger.info("Check unique values of alerts")
        unique_values_req = {
            "fields":{"ruleID":""},
            "innerFilters":[{"ruleID":"R0001,R0003,R0004"}],
            "pageSize":100,
            "pageNum":1
            }
        unique_values = self.backend.get_alerts_unique_values(incident_id=incident['guid'], request=unique_values_req)
        assert unique_values != None, f"Failed to get unique values of alerts {json.dumps(incident)}"
        expected_values = {"ruleID": ["R0001", "R0003", "R0004"]}
        # don't check the count, it's dynamic
        assert unique_values["fields"] == expected_values, f"Failed to get unique values of alerts {json.dumps(incident)} {json.dumps(unique_values)}"
    
    def check_incidents_per_severity(self):
        Logger.logger.info("Get incidents per severity")
        resp = self.backend.get_incidents_per_severity()
        assert resp[__RESPONSE_FIELD__] != None, f"Failed to get incidents per severity {json.dumps(resp)}"
        assert len(resp[__RESPONSE_FIELD__]) > 0, f"Failed to get incidents per severity {json.dumps(resp)}"

    def check_incidents_overtime(self):
        Logger.logger.info("Get incidents over time")
        resp = self.backend.get_incidents_overtime()
        assert resp[__RESPONSE_FIELD__] != None, f"Failed to get incidents over time {json.dumps(resp)}"
        assert len(resp[__RESPONSE_FIELD__]) > 0, f"Failed to get incidents over time {len(resp[__RESPONSE_FIELD__])}"
        today = time.strftime("%Y-%m-%d")
        assert resp[__RESPONSE_FIELD__][-1].get("date", "") == today, f"Failed to get incidents over time date {json.dumps(resp)}"
        assert resp[__RESPONSE_FIELD__][-1].get("count", 0) > 0, f"Failed to get incidents over time count {json.dumps(resp)}"
        assert resp[__RESPONSE_FIELD__][-1].get("newCount", 0) > 0, f"Failed to get incidents over time newCount {json.dumps(resp)}"
        Logger.logger.info(f"Got incidents over time {json.dumps(resp)}")

    def check_overtime_resolved_incident(self):
        Logger.logger.info("Get resolved incidents over time")
        resp = self.backend.get_incidents_overtime()
        assert resp[__RESPONSE_FIELD__] != None, f"Failed to get incidents over time {json.dumps(resp)}"
        assert len(resp[__RESPONSE_FIELD__]) > 0, f"Failed to get incidents over time {len(resp[__RESPONSE_FIELD__])}"
        today = time.strftime("%Y-%m-%d")
        assert resp[__RESPONSE_FIELD__][-1].get("date", "") == today, f"Failed to get incidents over time date {json.dumps(resp)}"
        assert resp[__RESPONSE_FIELD__][-1].get("count", 0) > 0, f"Failed to get incidents over time count {json.dumps(resp)}"
        assert resp[__RESPONSE_FIELD__][-1].get("newCount", 0) > 0, f"Failed to get incidents over time newCount {json.dumps(resp)}"
        assert resp[__RESPONSE_FIELD__][-1].get("dismissedCount", 0) > 0, f"Failed to get incidents over time dismissedCount {json.dumps(resp)}"
        Logger.logger.info(f"Got resolved incidents over time {json.dumps(resp)}")

    def check_incident_unique_values(self, incident):
        Logger.logger.info("Check unique values of incident")
        unique_values_req = {
            "fields":{"clusterName":"","containerName":"","name":"",
                      "workloadNamespace":"","podName":"","workloadKind|workloadName":"",
                      "incidentSeverity":"","mitreTactic":"","isDismissed":"","incidentCategory":"",
                      "nodeName":""},
            "innerFilters":[{"guid":incident['guid']}],
            "pageSize":100,
            "pageNum":1
            }
        unique_values = self.backend.get_incident_unique_values(unique_values_req)
        
        assert unique_values != None, f"Failed to get unique values of incident {json.dumps(incident)}"
        expected_values = {"fields": {"clusterName": [incident["clusterName"]], "containerName": ["redis"], "incidentCategory": ["Anomaly"], "incidentSeverity": ["Medium"], "isDismissed": ["false"], "mitreTactic": ["TA0002"], "name": ["Unexpected process launched"],"nodeName":[incident["nodeName"]], "podName": [incident["podName"]], "workloadKind|workloadName": ["Deployment|redis-sleep"], "workloadNamespace": [incident["workloadNamespace"]]}, "fieldsCount": {"clusterName": [{"key": incident["clusterName"], "count": 1}], "containerName": [{"key": "redis", "count": 1}], "incidentCategory": [{"key": "Anomaly", "count": 1}], "incidentSeverity": [{"key": "Medium", "count": 1}], "isDismissed": [{"key": "false", "count": 1}], "mitreTactic": [{"key": "TA0002", "count": 1}], "name": [{"key": "Unexpected process launched", "count": 1}],"nodeName":[{"key": incident["nodeName"], "count": 1}], "podName": [{"key": incident["podName"], "count": 1}], "workloadKind|workloadName": [{"key": "Deployment|redis-sleep", "count": 1}], "workloadNamespace": [{"key": incident["workloadNamespace"], "count": 1}]}}
        assert unique_values == expected_values, f"Failed to get unique values of incident {json.dumps(incident)} {json.dumps(unique_values)}"
        Logger.logger.info(f"Got unique values of incident {json.dumps(unique_values)}")

    def verify_incident_completed(self, incident_id):
        response = self.backend.get_incident(incident_id)
        assert response['attributes']['incidentStatus'] == "completed", f"Not completed incident {json.dumps(response)}"
        return response

    def verify_incident_in_backend_list(self, cluster, namespace, incident_name):
        Logger.logger.info("Get incidents list")
        filters_dict = {
            "designators.attributes.cluster": cluster,
            "designators.attributes.namespace": namespace,
            "name": incident_name
        }

        response = self.backend.get_incidents(filters=filters_dict)
        incs = response['response']
        assert len(incs) > 0, f"Failed to get incidents list {json.dumps(incs)}"
        return incs

    def verify_application_profiles(self, wlids:list, namespace):
        Logger.logger.info("Get application profiles")
        k8s_data = self.kubernetes_obj.get_dynamic_client("spdx.softwarecomposition.kubescape.io/v1beta1", "ApplicationProfile").get(namespace=namespace, _preload_content=False).items
        assert k8s_data != None, "Failed to get application profiles"
        assert len(k8s_data) >= len(wlids), f"Failed to get all application profiles {len(k8s_data)}"
        Logger.logger.info(f"Application profiles are presented {len(k8s_data)}")
        ap_wlids = [i.metadata.annotations['kubescape.io/wlid'] for i in k8s_data]
        for i in wlids:
            assert i in ap_wlids, f"Failed to get application profile for {i}"
        # kubescape.io/status: completed, kubescape.io/completion: complete
        not_complete_application_profiles = [i for i in k8s_data if i.metadata.annotations['kubescape.io/completion'] != 'complete' or i.metadata.annotations['kubescape.io/status'] != 'completed']        
        assert len(not_complete_application_profiles) == 0, f"Application profiles are not complete {json.dumps([i.metadata for i in not_complete_application_profiles])}"

    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)

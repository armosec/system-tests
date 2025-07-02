from systest_utils import Logger, statics
from tests_scripts.runtime.incidents import Incidents
from infrastructure.backend_api import EventReceiver
from tests_scripts.runtime.consts import CDR_ALERT_TYPE, NodeAgentK8s
import json
import time

class CADRIncidents(Incidents):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        """
        agenda:

        1. Install armo helm-chart before application so we will have final AP
        2. Apply deployments to namespaces
        3. Verify running pods in namespaces
        4. Simulate unexpected process in namespaces
        5. Send mock data of cdr alerts combining the incident response with the unexpected process
        6. Verify the incident data in the backend
        7. Open CDR incident and verify the alerts
        """

    def start(self):
        assert self.backend is not None, f"the test {self.test_driver.test_name} must run with backend"
        Logger.logger.info("1. Install armo helm-chart.")
        cluster, namespace = self.setup()
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=360,
                             namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
        Logger.logger.info("2. Enable node agent test mode.")
        self.enable_node_agent_test_mode()
        Logger.logger.info("3. Deploy deployments.")
        wlids = self.deploy_and_wait(deployments_path=self.test_obj["deployments"], cluster=cluster, namespace=namespace)
        self.create_application_profile(wlids=wlids, namespace=namespace)
        Logger.logger.info("4. Simulate unexpected process.")
        self._test_unexpected_process(wlids=wlids, command="cat /etc/hosts", cluster=cluster, namespace=namespace)
        return self.cleanup()

    def _test_unexpected_process(self, wlids: list, command: str, cluster: str, namespace: str, 
                                expected_incident_name: str = "Unexpected process launched"):
        Logger.logger.info(f"Simulate unexpected process from {wlids}")
        self.exec_pod(wlid=wlids[0], command=command)
        Logger.logger.info("Get incidents list")
        incs, _ = self.wait_for_report(self.verify_incident_in_backend_list, timeout=120, sleep_interval=10,
                                       cluster=cluster, namespace=namespace,
                                       incident_name=[expected_incident_name])
        inc = incs[0]
        public_ip = inc["cloudMetadata"].get("public_ip", "")
        Logger.logger.info("5. Send mock data of cdr alerts.")
        self._prepare_and_send_cdr_alerts(node_ip=public_ip, customer_guid=self.backend.get_customer_guid())
        Logger.logger.info("6. Verify the incident data in the backend.")
        inc, _ = self.wait_for_report(self.verify_incident_status_completed, timeout=15 * 60, sleep_interval=10,
                                      incident_id=inc["guid"])
        Logger.logger.info(f"Got incident {json.dumps(inc)}")
        self._verify_incident_alerts(incident_id=inc["guid"], public_ip=public_ip)
        return inc

    def _verify_incident_alerts(self, incident_id: str, public_ip: str):
        response = self.backend.get_alerts_of_incident(incident_id=incident_id)
        alerts = response["response"]
        assert len(alerts) > 3, f"Failed to get alerts of incident {incident_id}, got {alerts}"
        Logger.logger.info(f"Got alerts of incident {json.dumps(alerts)}")
        expected_rule_ids =["C0002", "C0001"]
        cdr_rule_ids = []

        for alert in alerts:
            if alert["alertType"] == CDR_ALERT_TYPE:
                assert alert["cdrevent"]["eventData"]["awsCloudTrail"]["sourceIPAddress"] == public_ip, f"Wrong source IP {alert}"
                cdr_rule_ids.append(alert["ruleID"])
        
        assert len(cdr_rule_ids) == len(expected_rule_ids), f"Failed to get expected rule ids, got {cdr_rule_ids}"
        for rule_id in expected_rule_ids:
            assert rule_id in cdr_rule_ids, f"Failed to get expected rule id {rule_id}, got {cdr_rule_ids}"
        
        return alerts
    
    def _prepare_and_send_cdr_alerts(self, node_ip: str, customer_guid: str):
        cdr_mock_path = self.test_obj["cdr_mock_path"]
        with open(cdr_mock_path, "r") as f:
            cdr_mock = json.load(f)

        for rule in cdr_mock["ruleFailures"]:
            rule["eventData"]["awsCloudTrail"]["sourceIPAddress"] = node_ip

        cdr_mock["customerGUID"] = customer_guid
        
        event_receiver = self._get_event_receiver()
        event_receiver.post_cdr_alerts(cdr_mock)

    def enable_node_agent_test_mode(self):
        self.kubernetes_obj.add_value_to_configmap(namespace=NodeAgentK8s.NAMESPACE, configmap_name=NodeAgentK8s.CONFIGMAP_NAME, values_to_add=NodeAgentK8s.TEST_MODE, json_key=NodeAgentK8s.JSON_KEY)
        self.kubernetes_obj.restart_workloads_in_namespace(namespace=NodeAgentK8s.NAMESPACE, kind=NodeAgentK8s.KIND, name=NodeAgentK8s.NAME)
        time.sleep(30)
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=360,
                             namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

    def _get_event_receiver(self):
        event_receiver_server = self.test_driver.backend_obj.get_event_receiver_server()
        return EventReceiver(server=event_receiver_server, customer_guid=self.backend.get_customer_guid(), api_key=self.backend.get_access_key())

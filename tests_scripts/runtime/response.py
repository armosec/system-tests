

import json
from systest_utils import Logger, statics
from tests_scripts.runtime.incidents import Incidents


class IncidentResponse(Incidents):
    """
    This class is used to test the incident response functionality of the system.
    It inherits from the Incidents class and provides additional functionality for incident response testing.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def start(self):
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        cluster, namespace = self.setup(apply_services=False)


        Logger.logger.info(". Install armo helm-chart before application so we will have final AP")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=360,
                             namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)


        # namespace = self.create_namespace()
        Logger.logger.info('Simulate unexpected process')
        inc = self.simulate_unexpected_process(deployments_path=self.test_obj["deployments"],
                                               cluster=cluster, namespace=namespace, command="cat /etc/hosts", expected_incident_name="Unexpected process launched")
        
        Logger.logger.info('Simulate unexpected process - done')


        # testing happy flow - order is important because, for example, if we apply seccomp profile and then kill process, the kill process will fail
        tests_to_body = {
            "ApplyNetworkPolicy": {
                "responseType": statics.RUNTIME_INCIDENT_RESPONSE_TYPE_APPLY_NETWORK_POLICY,
                "networkPolicyKind": "kubernetes"
            },
            "KillProcess": {
                "responseType": statics.RUNTIME_INCIDENT_RESPONSE_TYPE_KILL            
                },
            "PauseContainer": {
                "responseType": statics.RUNTIME_INCIDENT_RESPONSE_TYPE_PAUSE            
                },
            "StopContainer": {
                "responseType": statics.RUNTIME_INCIDENT_RESPONSE_TYPE_STOP
                },
            "ApplySeccompProfile": {
                "responseType": statics.RUNTIME_INCIDENT_RESPONSE_TYPE_APPLY_SECCOMP_PROFILE            
            },
        }

        tests_to_errors = {}

        for test_name, body in tests_to_body.items():
            try:
                Logger.logger.info(f"Testing {test_name} with body {body}")
                self.response_and_assert(incident_guid=inc["guid"], body=body)
            except Exception as e:
                Logger.logger.error(f"Failed to test {test_name} with body {body}, got exception {e}")
                tests_to_errors[test_name] = str(e)

        if len(tests_to_errors) > 0:
            Logger.logger.error(f"Failed to test the following tests: {tests_to_errors}")
            raise Exception(f"Failed to test the following tests: {tests_to_errors}")

        
        return self.cleanup()
    
    def cleanup(self, **kwargs):
        return statics.SUCCESS, "Cleanup done"

    def response_and_assert(self, incident_guid, body):
        """
        This function is used to send a response to an incident and assert the response.
        :param incident_guid: The GUID of the incident to respond to.
        :param body: The body of the response.
        :return: The response from the backend.
        """
        Logger.logger.info(f"Response to incident {incident_guid} with body {body}")
        _ = self.backend.response_incident(incident_id=incident_guid, body=body)
        
        auditlog, _ = self.wait_for_report(self.verify_audit_log, timeout=120, sleep_interval=10,
                                            incident_guid=incident_guid, action=body["responseType"])
    
    def verify_audit_log(self, incident_guid, action):
        Logger.logger.info("Get incidents list")

        if action == statics.RUNTIME_INCIDENT_RESPONSE_TYPE_KILL:
            action = "Kill Process"
        elif action == statics.RUNTIME_INCIDENT_RESPONSE_TYPE_PAUSE:
            action = "Pause Container"
        elif action == statics.RUNTIME_INCIDENT_RESPONSE_TYPE_STOP:
            action = "Stop Container"
        elif action == statics.RUNTIME_INCIDENT_RESPONSE_TYPE_APPLY_NETWORK_POLICY:
            action = "Apply Network Policy"
        elif action == statics.RUNTIME_INCIDENT_RESPONSE_TYPE_APPLY_SECCOMP_PROFILE:
            action = "Apply Seccomp Profile"
        
        body = {
                "pageSize": 50,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "eventOwner.incidentGUID": incident_guid,
                        "details.action": action,
                        "details.event": "Applied,Initiated"
                    }
                ],
                "orderBy": "eventTime:asc"
            }

        response = self.backend.audit_log_incident(incident_id=incident_guid, body=body)
        incs = response['response']
        assert len(incs) == 2, f"Failed to get incidents list {json.dumps(incs)}"

        init_log = incs[0]
        Logger.logger.info(f"verify Initiated audit log of action {action} and incident guid {incident_guid}:")
        assert init_log["details"]["action"] == action, f"expected action {action} but got {init_log['details']['action']}"
        assert init_log["eventOwner"]["incidentGUID"] == incident_guid, f"Expected incident guid {incident_guid} but got {init_log['eventOwner']['incidentGUID']}"
        assert init_log["details"]["event"] == "Initiated", f"Expected event Initiated but got {init_log['details']['event']}"
        assert init_log["details"]["status"] == "Success", f"Expected status Success but got {init_log['details']['status']}"
 

        applied_log = incs[1]
        Logger.logger.info("verify Applied audit log of action {action} and incident guid {incident_guid}:")
        assert applied_log["details"]["action"] == action, f"Failed to get incidents list {json.dumps(incs)}"
        assert applied_log["eventOwner"]["incidentGUID"] == incident_guid, f"Failed to get incidents list {json.dumps(incs)}"
        assert applied_log["details"]["event"] == "Applied", f"Expected event Applied but got {applied_log['details']['event']}"
        assert applied_log["details"]["status"] == "Success", f"Expected status Success but got {applied_log['details']['status']}"
        return incs
        

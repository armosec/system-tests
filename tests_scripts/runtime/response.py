

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

        """
        agenda:

        1. Simulate unexpected process
        2. Apply network policy - should succeed
        3. Kill process - should succeed
        4. Pause container - should succeed
        5. Stop container - should succeed
        6. Apply seccomp profile - should succeed
        7. Kill process - should fail

        """

    def start(self):
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        cluster, namespace_test_network_policy = self.setup(apply_services=False)
        namespace_test_kill_process = self.create_namespace()
        namespace_test_container = self.create_namespace()
        namespace_apply_seccomp_profile = self.create_namespace()
        namespaces = [namespace_test_network_policy, namespace_test_kill_process, namespace_test_container, namespace_apply_seccomp_profile]



        Logger.logger.info(". Install armo helm-chart before application so we will have final AP")
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
        self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=360,
                             namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)


        # namespace = self.create_namespace()
        

        Logger.logger.info(f"1. Apply deployments to namespaces {namespaces}")
        namespace_to_workload_objs = {}
        for namespace in namespaces:
            workload_objs = self.apply_directory(path=self.test_obj["deployments"], namespace=namespace)
            namespace_to_workload_objs[namespace] = workload_objs
            Logger.logger.info(f"Applied deployments to namespace {namespace} with workload objects {workload_objs}")


        Logger.logger.info(f"2. Verify running pods in namespaces {namespaces}")
        namespace_to_wlid = {}
        for namespace in namespaces:
            _ = self.wait_for_report(self.verify_running_pods, sleep_interval=5, timeout=180, namespace=namespace)
            namespace_to_wlid[namespace] = self.get_wlid(workload=namespace_to_workload_objs[namespace], namespace=namespace, cluster=cluster)


        Logger.logger.info('3. Simulate unexpected process')
        wait_for_application_profile_cache = 30

        for namespace in namespaces:

            _ = self.simulate_unexpected_process(deployments_path=self.test_obj["deployments"],
                                                cluster=cluster,
                                                namespace=namespace, 
                                                command="cat /etc/hosts", 
                                                expected_incident_name="Unexpected process launched",
                                                apply_workload=False,
                                                wlids=namespace_to_wlid[namespace],
                                                verify_backend=False,
                                                wait_for_application_profile_cache=wait_for_application_profile_cache,
                                                )
            
            # after we waited on first iteration, no need to wait again
            if wait_for_application_profile_cache < 0:
                wait_for_application_profile_cache = 0
            Logger.logger.info(f"Simulated unexpected process in namespace {namespace} with wlids {namespace_to_wlid[namespace]}")
        
        Logger.logger.info('4. Verify unexpected process on backend')
        namespace_to_incident = {}
        for namespace in namespaces:
            namespace_to_incident[namespace] = self.verify_unexpected_process_on_backend(
                cluster=cluster,
                namespace=namespace,
                expected_incident_name="Unexpected process launched")
        


        # testing happy flow - order is important because, for example, if we apply seccomp profile and then kill process, the kill process will fail
        tests_to_body = {
            "ApplyNetworkPolicy": {
                "phases": {
                    "step 1: Apply Network Policy": {
                        "body": {
                            "responseType": statics.RUNTIME_INCIDENT_RESPONSE_TYPE_APPLY_NETWORK_POLICY,
                            "networkPolicyKind": "kubernetes"
                        },
                        "expected_applied_status": statics.RUNTIME_INCIDENT_APPLIED_STATUS_SUCCESS,
                        "timeout": 150,
                        "sleep_interval": 20,
                    },
                },
                "incident": namespace_to_incident[namespace_test_network_policy]
                
            },
            "KillProcess": {
                "phases": {
                    "step 1: Kill Process": {
                        "body": {
                            "responseType": statics.RUNTIME_INCIDENT_RESPONSE_TYPE_KILL            
                        },
                        "expected_applied_status": statics.RUNTIME_INCIDENT_APPLIED_STATUS_SUCCESS,
                        "timeout": 90,
                        "sleep_interval": 20,
                    },
                },
                "incident": namespace_to_incident[namespace_test_kill_process]
            },
            "Container": {
                "phases": {
                    "step 1: Pause Container": {
                        "body": {
                            "responseType": statics.RUNTIME_INCIDENT_RESPONSE_TYPE_PAUSE            
                        },
                        "expected_applied_status": statics.RUNTIME_INCIDENT_APPLIED_STATUS_SUCCESS,
                        "timeout": 90,
                        "sleep_interval": 20,
                        },
                    "step 2: Stop Container": {
                        "body": {
                            "responseType": statics.RUNTIME_INCIDENT_RESPONSE_TYPE_STOP
                        },
                        "expected_applied_status": statics.RUNTIME_INCIDENT_APPLIED_STATUS_SUCCESS,
                        "timeout": 90,
                        "sleep_interval": 20,
                    },
                },
                "incident": namespace_to_incident[namespace_test_container]
            },
            "ApplySeccompProfile": {
                "phases": {
                    "step 1: Apply Seccomp Profile": {
                        "body": {
                            "responseType": statics.RUNTIME_INCIDENT_RESPONSE_TYPE_APPLY_SECCOMP_PROFILE            
                        },
                        "expected_applied_status": statics.RUNTIME_INCIDENT_APPLIED_STATUS_SUCCESS,
                        "timeout": 150,
                        "sleep_interval": 10,
                    },
                },
                "incident": namespace_to_incident[namespace_apply_seccomp_profile]
            },
        }

        tests_to_errors = {}

        Logger.logger.info(f"5. Testing incident response with tests {tests_to_body.keys()}")
        for test_name, test_body in tests_to_body.items():
            incident = test_body["incident"]
            for phase_name in test_body["phases"]:
                body = test_body["phases"][phase_name]["body"]
                expected_applied_status = test_body["phases"][phase_name]["expected_applied_status"]
                timeout = test_body["phases"][phase_name]["timeout"]
                sleep_interval = test_body["phases"][phase_name]["sleep_interval"]

                Logger.logger.info(f"Testing {test_name} phase {phase_name} with body {body}")
                try:
                    self.response_and_assert(incident_guid=incident["guid"], body=body, expected_applied_status=expected_applied_status, timeout=timeout, sleep_interval=sleep_interval)
                    Logger.logger.info(f"Test {test_name} phase {phase_name} passed")
                except Exception as e:
                    Logger.logger.error(f"Failed to test {test_name} phase {phase_name} with body {body}, got exception {e}")
                    tests_to_errors[test_name] = str(e)


        if len(tests_to_errors) > 0:
            for test_name, error in tests_to_errors.items():
                Logger.logger.error(f"Test {test_name} failed with error: {error}")
            raise Exception(f"Failed to test the following tests: {tests_to_errors}")

        
        return self.cleanup()
    
    def cleanup(self, **kwargs):
        return statics.SUCCESS, "Cleanup done"

    def response_and_assert(self, incident_guid, body, expected_applied_status, timeout=120, sleep_interval=10):
        """
        This function is used to send a response to an incident and assert the response.
        :param incident_guid: The GUID of the incident to respond to.
        :param body: The body of the response.
        :return: The response from the backend.
        """
        Logger.logger.info(f"Response to incident {incident_guid} with body {body}")
        _ = self.backend.response_incident(incident_id=incident_guid, body=body)
        
        auditlog, _ = self.wait_for_report(self.verify_audit_log, timeout=timeout, sleep_interval=sleep_interval,
                                            incident_guid=incident_guid, action=body["responseType"])
        
        self.verify_audit_log_results(auditlog, incident_guid, body["responseType"], expected_applied_status)

    
    def verify_audit_log_results(self, logs, incident_guid, action, expected_applied_status):
        init_log = logs[0]
        Logger.logger.info(f"verify Initiated audit log of action {action} and incident guid {incident_guid}:")
        assert init_log["details"]["action"] == action, f"expected action {action} but got {init_log['details']['action']}"
        assert init_log["eventOwner"]["incidentGUID"] == incident_guid, f"Expected incident guid {incident_guid} but got {init_log['eventOwner']['incidentGUID']}"
        assert init_log["details"]["event"] == "Initiated", f"Expected event Initiated but got {init_log['details']['event']}"
        assert init_log["details"]["status"] == "Success", f"Expected status Success but got {init_log['details']['status']}"
 

        applied_log = logs[1]
        Logger.logger.info("verify Applied audit log of action {action} and incident guid {incident_guid}:")
        assert applied_log["details"]["action"] == action, f"Failed to get incidents list {json.dumps(logs)}"
        assert applied_log["eventOwner"]["incidentGUID"] == incident_guid, f"Failed to get incidents list {json.dumps(logs)}"
        assert applied_log["details"]["event"] == "Applied", f"Expected event Applied but got {applied_log['details']['event']}"
        assert applied_log["details"]["status"] == expected_applied_status, f"Expected status {expected_applied_status} but got {applied_log['details']['status']}"

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
        logs = response['response']
        assert len(logs) == 2, f"Failed to get incidents list, expected 2 results but got {len(logs)}: {json.dumps(logs)}"
        return logs

        

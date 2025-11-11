import inspect

from tests_scripts.runtime.alerts import enrich_slack_alert_notifications, enrich_teams_alert_notifications
from tests_scripts.users_notifications.alert_notifications import get_messages_from_slack_channel, get_messages_from_teams_channel
from .structures import KubescapeConfiguration, TestConfiguration
from os.path import join
from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH, DEFAULT_CDR_MOCK_PATH



class RuntimeTests(object):
    
    @staticmethod
    def basic_incident_presented():
        from tests_scripts.runtime.incidents import Incidents
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Incidents,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            # create_test_tenant=True,
        )
    
    @staticmethod
    def kdr_runtime_policies_configurations():
        from tests_scripts.runtime.policies import RuntimePoliciesConfigurations
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=RuntimePoliciesConfigurations,
            create_test_tenant=True,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
        )
    
    @staticmethod
    def kdr_teams_alerts():
        from tests_scripts.runtime.alerts import IncidentsAlerts
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=IncidentsAlerts,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            getMessagesFunc=get_messages_from_teams_channel,
            enrichAlertChannelFunc=enrich_teams_alert_notifications,

        )

    @staticmethod
    def kdr_slack_alerts():
        from tests_scripts.runtime.alerts import IncidentsAlerts
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=IncidentsAlerts,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            getMessagesFunc=get_messages_from_slack_channel,
            enrichAlertChannelFunc=enrich_slack_alert_notifications,
        )
    
    @staticmethod
    def kdr_response_by_user():
        from tests_scripts.runtime.response import IncidentResponse
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=IncidentResponse,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            tests=["ApplyNetworkPolicy", "ApplySeccompProfile"],
            with_private_node_agent=False,
            # create_test_tenant=True,
        )
    
    @staticmethod
    def cadr_incident_presented():
        from tests_scripts.runtime.cadr import CADRIncidents
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CADRIncidents,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            cdr_mock_path=DEFAULT_CDR_MOCK_PATH,
            # create_test_tenant=True,
        )
    
    @staticmethod
    def runtime_stress_test():
        """
        Runtime Stress Test - Multi-namespace load testing (same tenant/cluster)
        
        Creates multiple namespaces within the SAME tenant/cluster to generate load.
        All namespaces share the same Kubescape installation and customer GUID.
        
        You MUST provide stress_config with:
        - namespace_count: number of namespaces to create (all in same tenant)
        - duration_minutes: how long to run the test
        - alert_profiles: list of alert types to generate
        
        Example below shows trigger alerts (malware, unexpected process) 
        and non-trigger alerts (benign DNS, benign network).
        """
        from tests_scripts.runtime.stress_test import RuntimeStressTest
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=RuntimeStressTest,
            deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
            # REQUIRED: You must configure stress test parameters
            stress_config={
                "namespace_count": 1,  
                "duration_minutes": 5,
                "ramp_up_seconds": 30,
                "pods_per_namespace": 1,  
                "alert_profiles": [
                    # {
                    #     "name": "malware_file_operations",
                    #     "rate_per_minute": 10000,
                    #     "worker_count": 5,
                    #     "is_trigger": True,
                    #     "command": 'SRC=/tmp/mal-$(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1); DST=/tmp/mal-$(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1); cp /root/malware.o "$SRC" 2>/dev/null || ls /root/malware.o; mv "$SRC" "$DST" 2>/dev/null || true; ls "$DST" 2>/dev/null || true',
                    #     "use_shell": True,
                    #     "description": "Copy malware file to random tmp location"
                    # },
                    # {
                    #     "name": "unexpected_file_operations",
                    #     "rate_per_minute": 10000,
                    #     "worker_count": 5,
                    #     "is_trigger": True,
                    #     "command": 'SRC=/tmp/file-$(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1); touch "$SRC"; DST=/tmp/file-$(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1); mv "$SRC" "$DST" 2>/dev/null || true; ls "$DST" 2>/dev/null || true',
                    #     "use_shell": True,
                    #     "description": "Create and list random file"
                    # },
                    # # Non-trigger alerts (benign activity)
                    {
                        "name": "benign_dns_lookup",
                        "rate_per_minute": 10000,
                        "worker_count": 5,
                        "is_trigger": False,
                        "command": 'nslookup $(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1).nip.io || true',
                        "use_shell": True,
                        "description": "Non-trigger DNS lookup to random nip.io subdomain"
                    },
                    {
                        "name": "benign_network_activity",
                        "rate_per_minute": 10000,
                        "worker_count": 5,
                        "is_trigger": False,
                        "command": 'wget --timeout=2 -q -O- $(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1).nip.io || true',
                        "use_shell": True,
                        "description": "Non-trigger network activity"
                    }
                ]
            }
        )
    
    # @staticmethod
    # def kdr_webhook_alerts():
    #     from tests_scripts.runtime.alerts import IncidentsAlerts
    #     return TestConfiguration(
    #         name=inspect.currentframe().f_code.co_name,
    #         test_obj=IncidentsAlerts,
    #         deployments=join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long"),
    #         getMessagesFunc=get_messages_from_webhook_channel,
    #         enrichAlertChannelFunc=enrich_webhooks_alert_notifications,
    #     )
    
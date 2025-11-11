import inspect

from .structures import TestConfiguration
from systest_utils import statics
from systest_utils import TestUtil
from os.path import join


class IntegrationsTests(object):

    # C-0016 - Allow privilege escalation
    @staticmethod
    def jira_integration():
        from tests_scripts.helm.jira_integration import JiraIntegration
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,           
            workload=join(statics.DEFAULT_DEPLOY_INTEGRATIONS_PATH, "nginx-deployment.yaml"),   
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json")),          
            test_obj=JiraIntegration)
    
    @staticmethod
    def linear_integration():
        from tests_scripts.helm.linear_integration import LinearIntegration
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            workload=join(statics.DEFAULT_DEPLOY_INTEGRATIONS_PATH, "nginx-deployment.yaml"),
            issueTemplate=TestUtil.get_expected_json(
                join(statics.DEFAULT_INTEGRATIONS_PATH, "linear_issue_template.json")
            ),
            test_obj=LinearIntegration
        )
    
    @staticmethod
    def siem_integrations():
        from tests_scripts.integrations.siem import SIEMIntegrations
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=SIEMIntegrations,
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json"))
        )

   
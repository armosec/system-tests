import inspect

from .structures import TestConfiguration
from systest_utils import statics
from systest_utils import TestUtil


class IntegrationsTests(object):

    # C-0016 - Allow privilege escalation
    @staticmethod
    def jira_integration():
        from tests_scripts.helm.jira_integration import JiraIntegration
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,           
            workload=join(statics.DEFAULT_DEPLOY_INTEGRATIONS_PATH, "nginx-deployment.yaml"),   
            issueTemplate = TestUtil.get_expected_json(join(statics.DEFAULT_INTEGRATIONS_PATH, "issueTmpl.json")),          
            test_obj=JiraIntegration)

   
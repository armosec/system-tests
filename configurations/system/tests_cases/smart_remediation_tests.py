import inspect

from .structures import TestConfiguration
from systest_utils import statics


class SmartRemediationTests(object):

    # C-0016 - Allow privilege escalation
    @staticmethod
    def smart_remediation_c0016():
        from tests_scripts.helm.smart_remediation import SmartRemediation
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            control="C-0016",
            workload=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "nginx-deployment.yaml"),
            workload_fix=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "c0016-fixed.yaml"),
            test_obj=SmartRemediation)

    # C-0017 - Immutable container filesystem
    @staticmethod
    def smart_remediation_c0017():
        from tests_scripts.helm.smart_remediation import SmartRemediation
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            control="C-0017",
            workload=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "nginx-deployment.yaml"),
            workload_fix=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "c0017-fixed.yaml"),
            test_obj=SmartRemediation)

    # C-0034 - Automatic mapping of service account
    @staticmethod
    def smart_remediation_c0034():
        from tests_scripts.helm.smart_remediation import SmartRemediation
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            control="C-0034",
            workload=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "nginx-deployment.yaml"),
            workload_fix=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "c0034-fixed.yaml"),
            test_obj=SmartRemediation)

    # C-0045 - Writable hostPath mount
    @staticmethod
    def smart_remediation_c0045():
        from tests_scripts.helm.smart_remediation import SmartRemediation
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            control="C-0045",
            workload=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "nginx-deployment.yaml"),
            workload_fix=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "c0045-fixed.yaml"),
            test_obj=SmartRemediation)

    # C-0046 - Insecure capabilities
    @staticmethod
    def smart_remediation_c0046():
        from tests_scripts.helm.smart_remediation import SmartRemediation
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            control="C-0046",
            workload=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "nginx-deployment.yaml"),
            workload_fix=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "c0046-fixed.yaml"),
            test_obj=SmartRemediation)

    # C-0048 - Insecure capabilities
    @staticmethod
    def smart_remediation_c0048():
        from tests_scripts.helm.smart_remediation import SmartRemediation
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            control="C-0048",
            workload=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "nginx-deployment.yaml"),
            workload_fix=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "c0048-fixed.yaml"),
            test_obj=SmartRemediation)

    # C-0057 - Privileged container
    @staticmethod
    def smart_remediation_c0057():
        from tests_scripts.helm.smart_remediation import SmartRemediation
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            control="C-0057",
            workload=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "nginx-deployment.yaml"),
            workload_fix=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "c0057-fixed.yaml"),
            test_obj=SmartRemediation)

    # C-0074 - Container runtime socket mounted
    @staticmethod
    def smart_remediation_c0074():
        from tests_scripts.helm.smart_remediation import SmartRemediation
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            control="C-0074",
            workload=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "nginx-deployment.yaml"),
            workload_fix=join(statics.DEFAULT_SMART_REMEDIATION_PATH, "c0074-fixed.yaml"),
            test_obj=SmartRemediation)

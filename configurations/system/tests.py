from configurations.system.tests_cases.integrations_tests import IntegrationsTests
from configurations.system.tests_cases.network_policy_tests import NetworkPolicyTests
from configurations.system.tests_cases.smart_remediation_tests import SmartRemediationTests
from configurations.system.tests_cases.synchronizer_tests import SynchronizerTests
from systest_utils import TestUtil
from .tests_cases import KubescapeTests, KSMicroserviceTests, RuntimeTests
from .tests_cases.ks_vuln_scan_tests import KsVulnerabilityScanningTests
from .tests_cases.notifications_tests import NotificationSTests
from .tests_cases.payments_tests import PaymentTests
from .tests_cases.relevant_vuln_scanning_tests import RelevantVulnerabilityScanningTests
from .tests_cases.seccomp_tests import SeccompProfileTests
from .tests_cases.security_risks_tests import SecurityRisksTests
from .tests_cases.vuln_scan_tests import VulnerabilityScanningTests


def all_tests_names():
    tests = list()

    tests.extend(TestUtil.get_class_methods(KubescapeTests))
    tests.extend(TestUtil.get_class_methods(VulnerabilityScanningTests))
    tests.extend(TestUtil.get_class_methods(KSMicroserviceTests))
    tests.extend(TestUtil.get_class_methods(KsVulnerabilityScanningTests))
    tests.extend(TestUtil.get_class_methods(PaymentTests))
    tests.extend(TestUtil.get_class_methods(RelevantVulnerabilityScanningTests))
    tests.extend(TestUtil.get_class_methods(NetworkPolicyTests))
    tests.extend(TestUtil.get_class_methods(NotificationSTests))
    tests.extend(TestUtil.get_class_methods(SmartRemediationTests))
    tests.extend(TestUtil.get_class_methods(SynchronizerTests))
    tests.extend(TestUtil.get_class_methods(RuntimeTests))
    tests.extend(TestUtil.get_class_methods(SecurityRisksTests))
    tests.extend(TestUtil.get_class_methods(IntegrationsTests))
    tests.extend(TestUtil.get_class_methods(SeccompProfileTests))
    return tests


def get_test(test_name):
    if test_name in TestUtil.get_class_methods(KubescapeTests):
        return KubescapeTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(VulnerabilityScanningTests):
        return VulnerabilityScanningTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(KSMicroserviceTests):
        return KSMicroserviceTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(KsVulnerabilityScanningTests):
        return KsVulnerabilityScanningTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(PaymentTests):
        return PaymentTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(RelevantVulnerabilityScanningTests):
        return RelevantVulnerabilityScanningTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(NetworkPolicyTests):
        return NetworkPolicyTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(NotificationSTests):
        return NotificationSTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(SmartRemediationTests):
        return SmartRemediationTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(SynchronizerTests):
        return SynchronizerTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(RuntimeTests):
        return RuntimeTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(SecurityRisksTests):
        return SecurityRisksTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(IntegrationsTests):
        return IntegrationsTests().__getattribute__(test_name)()
    if test_name in TestUtil.get_class_methods(SeccompProfileTests):
        return SeccompProfileTests().__getattribute__(test_name)()


ALL_TESTS = all_tests_names()

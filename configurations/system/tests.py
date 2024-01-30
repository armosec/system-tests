from configurations.system.tests_cases.network_policy_tests import NetworkPolicyTests
from systest_utils import TestUtil

from .tests_cases import KubescapeTests, KSMicroserviceTests
from .tests_cases.vuln_scan_tests import VulnerabilityScanningTests
from .tests_cases.ks_vuln_scan_tests import KsVulnerabilityScanningTests
from .tests_cases.payments_tests import PaymentTests
from .tests_cases.relevant_vuln_scanning_tests import RelevantVulnerabilityScanningTests
from .tests_cases.notifications_tests import NotificationSTests



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


ALL_TESTS = all_tests_names()

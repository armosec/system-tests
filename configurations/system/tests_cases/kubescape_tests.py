import os
import inspect
from configurations.system.git_repository import GitRepository
from .structures import TestConfiguration

from systest_utils.statics import DEFAULT_KS_CUSTOM_FW_PATH
from .structures import KubescapeConfiguration


class KubescapeTests(object):

    @staticmethod
    def scan_nsa():
        from tests_scripts.kubescape.scan import Scan
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Scan,
            policy_scope='framework',
            policy_name='NSA'
        )

    @staticmethod
    def scan_mitre():
        from tests_scripts.kubescape.scan import Scan
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Scan,
            policy_scope='framework',
            policy_name='MITRE'
        )
    
    @staticmethod
    def scan_security():
        from tests_scripts.kubescape.scan import Scan
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Scan,
            policy_scope='framework',
            policy_name='security'
        )

    @staticmethod
    def scan_with_exceptions():
        from tests_scripts.kubescape.scan import ScanWithExceptions
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithExceptions,
            policy_scope='framework',
            policy_name='MITRE',
            exceptions='kube-ns.json',
            controls_tested=["C-0002"]
        )
    
    @staticmethod
    def scan_compliance_score():
        from tests_scripts.kubescape.scan import ScanComplianceScore
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanComplianceScore,
            policy_scope='framework',
            policy_name='nsa,mitre,cis-v1.23-t1.0.1',
            submit=True,
            account=True
        )

    @staticmethod
    def scan_repository():
        from tests_scripts.kubescape.scan import ScanUrl
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanUrl,
            policy_scope='framework',
            policy_name='MITRE',
            url="https://github.com/armosec/kubescape"
        )

    @staticmethod
    def scan_repository_from_url_and_submit_to_backend():
        from tests_scripts.kubescape.scan import ScanGitRepositoryAndSubmit
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanGitRepositoryAndSubmit,
            policy_scope='framework',
            policy_name='AllControls',
            submit=True,
            account=True,
            git_repository=GitRepository(name='kubescape', owner="armosec", branch="master",
                                         url="https://github.com/armosec/kubescape"),
            expected_helm_files=[
                "examples/helm_chart/templates/serviceaccount.yaml",
                "examples/helm_chart/templates/cronjob.yaml"
            ],
            clone_before=False,
            create_test_tenant=True
        )

    @staticmethod
    def scan_local_repository_and_submit_to_backend():
        from tests_scripts.kubescape.scan import ScanGitRepositoryAndSubmit
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanGitRepositoryAndSubmit,
            policy_scope='framework',
            policy_name='MITRE',
            submit=True,
            account=True,
            git_repository=GitRepository(name='examples', owner="kubernetes", branch="master",
                                         url="https://github.com/kubernetes/examples"),
            clone_before=True,
            create_test_tenant=True
        )

    @staticmethod
    def scan_local_file():
        from tests_scripts.kubescape.scan import ScanLocalFile
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanLocalFile,
            policy_scope='framework',
            policy_name='NSA',
            yamls=['nginx.yaml'],
            resources=1
        )

    @staticmethod
    def scan_local_glob_files():
        from tests_scripts.kubescape.scan import ScanLocalFile
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanLocalFile,
            policy_scope='framework',
            policy_name='NSA',
            yamls=['hipster_shop/*.yaml'],
            resources=13
        )

    @staticmethod
    def scan_local_list_of_files():
        from tests_scripts.kubescape.scan import ScanLocalFile
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanLocalFile,
            policy_scope='framework',
            policy_name='allControls',
            yamls=['nginx.yaml'],
            resources=1
        )

    @staticmethod
    def scan_nsa_and_submit_to_backend():
        from tests_scripts.kubescape.scan import ScanAndSubmitToBackend
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanAndSubmitToBackend,
            policy_scope='framework',
            policy_name='NSA',
            submit=True,
            account=True,
            resources_for_test=[
                {'kind': 'Deployment', 'name': 'apache', 'namespace': 'system-test', 'apiVersion': 'apps/v1'},
                {'kind': 'Namespace', 'name': 'system-test', 'namespace': '', 'apiVersion': 'v1'}],
            yaml="apache.yaml",
            namespace="system-test"
        )
    
    @staticmethod
    def scan_security_and_submit_to_backend():
        from tests_scripts.kubescape.scan import ScanAndSubmitToBackend
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanAndSubmitToBackend,
            policy_scope='framework',
            policy_name='security',
            submit=True,
            account=True,
            resources_for_test=[
                {'kind': 'Deployment', 'name': 'apache', 'namespace': 'system-test', 'apiVersion': 'apps/v1'}],
            yaml="apache.yaml",
            namespace="system-test"
        )

    @staticmethod
    def scan_mitre_and_submit_to_backend():
        from tests_scripts.kubescape.scan import ScanAndSubmitToBackend
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanAndSubmitToBackend,
            policy_scope='framework',
            policy_name='MITRE',
            submit=True,
            account=True,
            resources_for_test=[
                {'kind': 'Deployment', 'name': 'apache', 'namespace': 'system-test', 'apiVersion': 'apps/v1'},
                {'kind': 'Namespace', 'name': 'system-test', 'namespace': '', 'apiVersion': 'v1'}],
            yaml="apache.yaml",
            namespace="system-test"
        )

    @staticmethod
    def scan_with_exception_to_backend():
        from tests_scripts.kubescape.scan import ScanWithExceptionToBackend
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithExceptionToBackend,
            policy_scope='framework',
            policy_name='NSA',
            submit=True,
            account=True,
            exceptions="exclude-control-apache.json,exclude-control-sa-resourceID-apache.json",
            yaml="apache.yaml"
        )

    @staticmethod
    def scan_with_custom_framework():
        from tests_scripts.kubescape.scan import ScanWithCustomFramework
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithCustomFramework,
            policy_scope='framework',
            submit=True,
            account=True,
            framework_file="system-test-framework.json"
        )

    @staticmethod
    def scan_customer_configuration():
        from tests_scripts.kubescape.scan import CustomerConfiguration
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=CustomerConfiguration,
            policy_scope='control',
            policy_name='C-0001',
            submit=False,
            account=True,
            yaml=['custom_input.yaml'],
            input_kind='untrustedRegistries',
            input_name='bad.registry'
        )

    @staticmethod
    def offline_support():
        from tests_scripts.kubescape.scan import OfflineSupport
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=OfflineSupport,
            policy_scope='framework',
            policy_name='NSA',
            yaml=["apache.yaml"],
            namespace="system-test",
            expected_results='apache.json'
        )

    @staticmethod
    def host_scanner():
        from tests_scripts.kubescape.scan import HostScanner
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=HostScanner,
            policy_scope='control',
            policy_name='C-0069,C-0070',
            submit=False,
            account=False,
        )

    @staticmethod
    def host_scanner_with_hostsensorrule():
        from tests_scripts.kubescape.scan import HostScanner
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=HostScanner,
            policy_scope='control',
            policy_name='C-0052,C-0069,C-0070,C-0092,C-0093,C-0094,C-0095,C-0096,C-0097,C-0098,C-0099,C-0100',
            submit=False,
            account=False,
        )

    @staticmethod
    def unified_configuration_config_view():
        from tests_scripts.kubescape.config import ConfigView
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ConfigView,
        )
    
    @staticmethod
    def unified_configuration_config_set():
        from tests_scripts.kubescape.config import ConfigSet
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ConfigSet,
            set_key="secretKey",
            set_value="123",
        )
    
    @staticmethod
    def unified_configuration_config_delete():
        from tests_scripts.kubescape.config import ConfigDelete
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ConfigDelete,
        )
    
    @staticmethod
    def scan_custom_framework_scanning_cluster_scope_testing():
        from tests_scripts.kubescape.scan import TestScanningScope
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=TestScanningScope,
            policy_scope='framework',
            keep_local=True,
            framework_file=os.path.abspath(os.path.join(DEFAULT_KS_CUSTOM_FW_PATH, "system-test-framework-scanning-scope.json")),
            policy_name="systest-fw-custom-scanning-scope-cluster-only",
            scope_control_counter=5,
        )
    
    @staticmethod
    def scan_custom_framework_scanning_file_scope_testing():
        from tests_scripts.kubescape.scan import TestScanningFileScope
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=TestScanningFileScope,
            policy_scope='framework',
            keep_local=True,
            yamls=['nginx.yaml'],
            framework_file=os.path.abspath(os.path.join(DEFAULT_KS_CUSTOM_FW_PATH, "system-test-framework-scanning-file-scope.json")),
            policy_name="systest-fw-custom-scanning-scope-file",
            scope_control_counter=5,
        )
    
    @staticmethod
    def scan_custom_framework_scanning_cluster_and_file_scope_testing():
        from tests_scripts.kubescape.scan import TestScanningFileScope
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=TestScanningFileScope,
            policy_scope='framework',
            keep_local=True,
            yamls=['nginx.yaml'],
            framework_file=os.path.abspath(os.path.join(DEFAULT_KS_CUSTOM_FW_PATH, "system-test-framework-scanning-cluster-and-file-scope.json")),
            policy_name="systest-fw-custom-scanning-scope-cluster-and-files",
            scope_control_counter=5,
        )
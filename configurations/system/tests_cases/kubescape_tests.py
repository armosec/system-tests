import inspect
from configurations.system.git_repository import GitRepository

# from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
from .structures import KubescapeConfiguration


class KubescapeTests(object):

    @staticmethod
    def scan_nsa():
        from tests_scripts.kubescape.scan import Scan
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Scan,
            policy_scope='framework',
            policy_name='nsa'
        )

    @staticmethod
    def scan_mitre():
        from tests_scripts.kubescape.scan import Scan
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=Scan,
            policy_scope='framework',
            policy_name='mitre'
        )

    @staticmethod
    def scan_with_exceptions():
        from tests_scripts.kubescape.scan import ScanWithExceptions
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanWithExceptions,
            policy_scope='framework',
            policy_name='mitre',
            exceptions='kube-ns.json',
            controls_tested=["C-0002"]
        )

    @staticmethod
    def scan_repository():
        from tests_scripts.kubescape.scan import ScanUrl
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanUrl,
            policy_scope='framework',
            policy_name='mitre',
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
            clone_before=False
        )

    @staticmethod
    def scan_local_repository_and_submit_to_backend():
        from tests_scripts.kubescape.scan import ScanGitRepositoryAndSubmit
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanGitRepositoryAndSubmit,
            policy_scope='framework',
            policy_name='mitre',
            submit=True,
            account=True,
            git_repository=GitRepository(name='examples', owner="kubernetes", branch="master",
                                         url="https://github.com/kubernetes/examples"),
            clone_before=True
        )

    @staticmethod
    def scan_local_file():
        from tests_scripts.kubescape.scan import ScanLocalFile
        return KubescapeConfiguration(
            name=inspect.currentframe().f_code.co_name,
            test_obj=ScanLocalFile,
            policy_scope='framework',
            policy_name='nsa',
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
            policy_name='nsa',
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
            policy_name='all',
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
            policy_name='nsa',
            submit=True,
            account=True,
            resources_for_test=[
                {'kind': 'Deployment', 'name': 'apache', 'namespace': 'system-test', 'apiVersion': 'apps/v1'},
                {'kind': 'Namespace', 'name': 'system-test', 'namespace': '', 'apiVersion': 'v1'}],
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
            policy_name='mitre',
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
            policy_name='nsa',
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
            policy_name='nsa',
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

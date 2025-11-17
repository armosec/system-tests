#!/usr/bin/env python3
"""
PR Validation Script: Validates that API mappings in system_test_mapping.json
are accurate for tests related to changed files in a PR.

Usage:
    python validate_api_mapping.py [base_branch] [head_branch]
    
    If no branches specified, uses git diff to detect changes.
"""

import sys
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def load_json_file(path):
    """Load JSON file."""
    with open(path, 'r') as f:
        return json.load(f)

def get_changed_files(base_branch=None, head_branch=None):
    """Get list of changed files in the PR."""
    if base_branch and head_branch:
        # Compare two branches
        cmd = ['git', 'diff', '--name-only', f'{base_branch}...{head_branch}']
    else:
        # Use staged + unstaged changes
        cmd = ['git', 'diff', '--name-only', 'HEAD']
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
        return files
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}Error getting changed files: {e}{Colors.END}")
        return []

def find_related_tests(changed_files: List[str], test_file_mapping: Dict[str, List[str]]) -> Set[str]:
    """
    Find tests that are related to the changed files.
    
    Args:
        changed_files: List of changed file paths
        test_file_mapping: Mapping of test names to their implementation files
    
    Returns:
        Set of test names that should be validated
    """
    related_tests = set()
    
    for changed_file in changed_files:
        # Normalize path
        changed_file = changed_file.replace('tests_scripts/', '')
        
        # Check if it's a test file
        if changed_file.startswith('tests_scripts/') or 'tests_scripts' in changed_file:
            changed_file = changed_file.replace('tests_scripts/', '')
            
            # Find tests that use this file
            for test_name, test_files in test_file_mapping.items():
                for test_file in test_files:
                    if test_file in changed_file or changed_file in test_file:
                        related_tests.add(test_name)
                        break
        
        # Also check for configuration changes
        elif 'system_test_mapping.json' in changed_file:
            # If mapping file changed, validate all tests
            return set(test_file_mapping.keys())
        
        # Check for backend_api.py changes
        elif 'backend_api.py' in changed_file:
            print(f"{Colors.YELLOW}⚠️  backend_api.py was modified - this may affect API mappings{Colors.END}")
    
    return related_tests

def extract_api_calls_from_file(file_path: Path) -> Set[str]:
    """Extract backend API method calls from a file."""
    if not file_path.exists():
        return set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find API method calls
        pattern = r'(?:self\.backend|backend|test_obj\.backend)\.(\w+)\('
        matches = re.findall(pattern, content)
        return set(matches)
    except Exception as e:
        print(f"{Colors.YELLOW}Warning: Could not read {file_path}: {e}{Colors.END}")
        return set()

def get_expected_apis_for_test(test_name: str, test_files: List[str], api_method_mapping: Dict) -> List[Dict]:
    """Get the expected API list for a test based on its implementation."""
    tests_dir = Path('/workspace/tests_scripts')
    
    # Collect all API methods used
    api_methods = set()
    for test_file in test_files:
        file_path = tests_dir / test_file
        methods = extract_api_calls_from_file(file_path)
        api_methods.update(methods)
    
    # Convert to API format
    api_list = []
    for method_name in api_methods:
        if method_name in api_method_mapping:
            api_info = api_method_mapping[method_name]
            api_list.append(api_info)
    
    # Sort for comparison
    api_list.sort(key=lambda x: (x['path'], x['method']))
    return api_list

def compare_api_lists(expected: List[Dict], actual: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """
    Compare expected and actual API lists.
    
    Returns:
        (missing_apis, extra_apis)
    """
    # Convert to sets for comparison
    expected_set = {(api['method'], api['path']) for api in expected}
    actual_set = {(api['method'], api['path']) for api in actual}
    
    missing = expected_set - actual_set
    extra = actual_set - expected_set
    
    # Convert back to dict format
    missing_apis = [{'method': m, 'path': p} for m, p in sorted(missing)]
    extra_apis = [{'method': m, 'path': p} for m, p in sorted(extra)]
    
    return missing_apis, extra_apis

def create_test_file_mapping() -> Dict[str, List[str]]:
    """Create mapping of test names to implementation files."""
    # This is the same mapping from update_mapping_with_methods.py
    # In production, this could be generated dynamically
    mappings = {
        # Kubescape tests
        'scan_nsa': ['kubescape/scan.py'],
        'scan_mitre': ['kubescape/scan.py'],
        'scan_security': ['kubescape/scan.py'],
        'scan_repository': ['kubescape/scan.py'],
        'scan_local_file': ['kubescape/scan.py'],
        'scan_local_glob_files': ['kubescape/scan.py'],
        'scan_local_list_of_files': ['kubescape/scan.py'],
        'scan_with_exceptions': ['kubescape/scan.py'],
        'scan_custom_framework_scanning_file_scope_testing': ['kubescape/scan.py'],
        'scan_custom_framework_scanning_cluster_scope_testing': ['kubescape/scan.py'],
        'scan_custom_framework_scanning_cluster_and_file_scope_testing': ['kubescape/scan.py'],
        'scan_nsa_and_submit_to_backend': ['kubescape/scan.py'],
        'scan_mitre_and_submit_to_backend': ['kubescape/scan.py'],
        'scan_local_repository_and_submit_to_backend': ['kubescape/scan.py'],
        'scan_repository_from_url_and_submit_to_backend': ['kubescape/scan.py'],
        'scan_with_exception_to_backend': ['kubescape/scan.py'],
        'scan_with_global_exception_to_backend': ['kubescape/scan.py'],
        'scan_with_custom_framework': ['kubescape/scan.py'],
        'scan_compliance_score': ['kubescape/scan.py'],
        'scan_customer_configuration': ['kubescape/scan.py'],
        'attackchains_all': ['kubescape/scan.py'],
        
        # Payment tests
        'stripe_webhook': ['payments/webhook.py', 'payments/base_stripe.py'],
        'stripe_checkout': ['payments/checkout.py', 'payments/base_stripe.py'],
        'stripe_billing_portal': ['payments/portal.py', 'payments/base_stripe.py'],
        'stripe_plans': ['payments/plans.py', 'payments/base_stripe.py'],
        
        # Notification tests
        'user_email_settings': ['users_notifications/email_settings.py'],
        'user_alert_channels': ['users_notifications/alert_channels.py'],
        
        # Registry tests
        'test_registry_scanning': ['registry/registry_connectors.py'],
        
        # Vulnerability scanning
        'vuln_scan': ['helm/vuln_scan.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'vuln_scan_proxy': ['helm/vuln_scan.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'vuln_v2_views': ['helm/vuln_scan.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'vuln_v2_views_kev': ['helm/vuln_scan.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'vuln_scan_cve_exceptions': ['helm/vuln_scan.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'host_scanner': ['helm/vuln_scan.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'host_scanner_with_hostsensorrule': ['helm/vuln_scan.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'sbom_test': ['helm/vuln_scan.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'vuln_scan_triggering_with_cron_job': ['helm/ks_vuln_scan.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        
        # Kubescape microservice
        'ks_microservice_ns_creation': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'ks_microservice_on_demand': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'ks_microservice_mitre_framework_on_demand': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'ks_microservice_nsa_and_mitre_framework_demand': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'ks_microservice_triggering_with_cron_job': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'ks_microservice_update_cronjob_schedule': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'ks_microservice_delete_cronjob': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'ks_microservice_create_2_cronjob_mitre_and_nsa': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'ks_microservice_create_2_cronjob_mitre_and_nsa_proxy': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        
        # Network policy
        'network_policy': ['helm/network_policy.py', 'helm/base_network_policy.py', 'kubernetes/base_k8s.py'],
        'network_policy_data_appended': ['helm/network_policy.py', 'helm/base_network_policy.py', 'kubernetes/base_k8s.py'],
        'network_policy_pod_restarted': ['helm/network_policy.py', 'helm/base_network_policy.py', 'kubernetes/base_k8s.py'],
        'network_policy_known_servers_cache': ['helm/network_policy.py', 'helm/base_network_policy.py', 'kubernetes/base_k8s.py'],
        'network_policy_multiple_replicas': ['helm/network_policy.py', 'helm/base_network_policy.py', 'kubernetes/base_k8s.py'],
        'network_policy_known_servers': ['helm/network_policy.py', 'helm/base_network_policy.py', 'kubernetes/base_k8s.py'],
        
        # Relevancy/CVE
        'relevantCVEs': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevancy_fix_vuln': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevancy_golang_dynamic': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevancy_java_and_python': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevancy_java': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevancy_golang': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevancy_python': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevancy_large_image': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevant_data_is_appended': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevancy_enabled_stop_sniffing': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevancy_disabled_installation': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevancy_storage_disabled': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        'relevancy_multiple_containers': ['helm/relevant_cve.py', 'helm/base_vuln_scan.py', 'kubernetes/base_k8s.py'],
        
        # Seccomp
        'seccomp_profile_pod': ['helm/seccomp.py', 'kubernetes/base_k8s.py'],
        'seccomp_profile_container': ['helm/seccomp.py', 'kubernetes/base_k8s.py'],
        'seccomp_profile_workloads_list': ['helm/seccomp.py', 'kubernetes/base_k8s.py'],
        'seccomp_profile_generate': ['helm/seccomp.py', 'kubernetes/base_k8s.py'],
        
        # Smart remediation
        'smart_remediation_all_controls': ['helm/smart_remediation.py', 'kubernetes/base_k8s.py'],
        
        # Synchronizer
        'synchronizer': ['helm/synchronizer.py', 'kubernetes/base_k8s.py'],
        'synchronizer_reconciliation': ['helm/synchronizer.py', 'kubernetes/base_k8s.py'],
        'synchronizer_proxy': ['helm/synchronizer.py', 'kubernetes/base_k8s.py'],
        'synchronizer_race_condition': ['helm/synchronizer.py', 'kubernetes/base_k8s.py'],
        'synchronizer_kubescape_crds': ['helm/synchronizer.py', 'kubernetes/base_k8s.py'],
        
        # Integrations
        'jira_integration': ['helm/jira_integration.py', 'kubernetes/base_k8s.py'],
        'linear_integration': ['helm/linear_integration.py', 'kubernetes/base_k8s.py'],
        
        # Security risks
        'securityrisks_all': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'sr_r_0035_attack_chain': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'sr_r_0005_control': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'sr_r_0007_control_networkpolicy': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'sr_r_0037_vulnerability': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'sr_with_exceptions': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        'sr_ac_scan_status': ['helm/ks_microservice.py', 'kubernetes/base_k8s.py'],
        
        # Runtime/KDR
        'basic_incident_presented': ['runtime/incidents.py'],
        'kdr_runtime_policies_configurations': ['runtime/policies.py'],
        'kdr_teams_alerts': ['runtime/alerts.py'],
        'kdr_slack_alerts': ['runtime/alerts.py'],
        'kdr_webhook_alerts': ['runtime/alerts.py'],
        'kdr_response_by_user': ['runtime/response.py'],
        'cadr_incident_presented': ['runtime/cadr.py'],
        'runtime_stress_test': ['runtime/stress_test.py'],
        
        # Workflows
        'slack_notifications_workflows': ['workflows/slack_workflows.py'],
        'teams_notifications_workflows': ['workflows/teams_workflows.py'],
        'jira_notifications_workflows': ['workflows/jira_workflows.py'],
        'linear_notifications_workflows': ['workflows/linear_workflows.py'],
        'workflows_configurations': ['workflows/conf_workflows.py'],
        
        # Accounts
        'clusters': ['accounts/clusters.py'],
        'cloud_connect_aws_cspm_single': ['accounts/connect_cspm_single.py', 'accounts/accounts.py'],
        'cloud_connect_aws_cadr_single': ['accounts/connect_cadr_single.py', 'accounts/accounts.py'],
        'cloud_organization_aws_cspm': ['accounts/connect_cspm_org.py', 'accounts/accounts.py'],
        'cloud_organization_aws_cadr': ['accounts/connect_cadr_org.py', 'accounts/accounts.py'],
        'cloud_vulnscan_aws': ['accounts/vulnscan.py', 'accounts/accounts.py'],
        
        # SIEM
        'siem_integrations': ['integrations/siem.py'],
    }
    
    return mappings

def validate_pr():
    """Main validation function."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}  PR API Mapping Validation{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    # Load data
    system_mapping = load_json_file('/workspace/system_test_mapping.json')
    api_method_mapping = load_json_file('/workspace/api_method_http_mapping.json')
    test_file_mapping = create_test_file_mapping()
    
    # Get changed files
    base_branch = sys.argv[1] if len(sys.argv) > 1 else None
    head_branch = sys.argv[2] if len(sys.argv) > 2 else None
    
    changed_files = get_changed_files(base_branch, head_branch)
    
    if not changed_files:
        print(f"{Colors.GREEN}✅ No changes detected - validation passed{Colors.END}\n")
        return 0
    
    print(f"{Colors.BLUE}📁 Changed files ({len(changed_files)}):{Colors.END}")
    for f in changed_files[:10]:
        print(f"   • {f}")
    if len(changed_files) > 10:
        print(f"   ... and {len(changed_files) - 10} more")
    print()
    
    # Find related tests
    related_tests = find_related_tests(changed_files, test_file_mapping)
    
    if not related_tests:
        print(f"{Colors.GREEN}✅ No test files changed - validation passed{Colors.END}\n")
        return 0
    
    print(f"{Colors.BLUE}🧪 Related tests ({len(related_tests)}):{Colors.END}")
    for test in sorted(related_tests)[:10]:
        print(f"   • {test}")
    if len(related_tests) > 10:
        print(f"   ... and {len(related_tests) - 10} more")
    print()
    
    # Validate each related test
    issues = []
    for test_name in sorted(related_tests):
        if test_name not in system_mapping:
            issues.append((test_name, 'missing', None, None))
            continue
        
        test_config = system_mapping[test_name]
        actual_apis = test_config.get('tested_dashboard_apis', [])
        
        # Get expected APIs
        test_files = test_file_mapping.get(test_name, [])
        expected_apis = get_expected_apis_for_test(test_name, test_files, api_method_mapping)
        
        # Compare
        missing_apis, extra_apis = compare_api_lists(expected_apis, actual_apis)
        
        if missing_apis or extra_apis:
            issues.append((test_name, 'mismatch', missing_apis, extra_apis))
    
    # Report results
    if not issues:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ All API mappings are correct!{Colors.END}\n")
        return 0
    
    # Print issues
    print(f"\n{Colors.RED}{Colors.BOLD}❌ Found {len(issues)} test(s) with incorrect API mappings:{Colors.END}\n")
    
    for test_name, issue_type, missing, extra in issues:
        print(f"{Colors.BOLD}Test: {test_name}{Colors.END}")
        
        if issue_type == 'missing':
            print(f"  {Colors.RED}❌ Test not found in system_test_mapping.json{Colors.END}")
        else:
            if missing:
                print(f"  {Colors.RED}Missing APIs ({len(missing)}):{Colors.END}")
                for api in missing:
                    print(f"    • {api['method']:6} {api['path']}")
            
            if extra:
                print(f"  {Colors.YELLOW}Extra APIs ({len(extra)}):{Colors.END}")
                for api in extra:
                    print(f"    • {api['method']:6} {api['path']}")
        print()
    
    # Print instructions
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}📋 How to fix:{Colors.END}\n")
    print(f"1. Run the update script to regenerate the API mappings:")
    print(f"   {Colors.CYAN}python3 update_mapping_with_methods.py{Colors.END}\n")
    print(f"2. Review the changes to ensure they're correct\n")
    print(f"3. Commit the updated system_test_mapping.json file:\n")
    print(f"   {Colors.CYAN}git add system_test_mapping.json{Colors.END}")
    print(f"   {Colors.CYAN}git commit -m 'Update API mappings for modified tests'{Colors.END}\n")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    return 1

if __name__ == '__main__':
    exit_code = validate_pr()
    sys.exit(exit_code)

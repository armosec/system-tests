#!/usr/bin/env python3
"""
PR Validation Script: Validates that API mappings in system_test_mapping.json
are accurate for tests related to changed files in a PR.

Usage:
    python scripts/validate_api_mapping.py [base_branch] [head_branch]
    
    If no branches specified, uses git diff to detect changes.
"""

import sys
import json
import re
import subprocess
import os
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

def get_repo_root():
    """Get the repository root directory."""
    # Try to find the repo root by looking for system_test_mapping.json
    current_dir = Path(__file__).parent.parent  # Start from scripts/ parent
    
    # Check if we're in the repo root
    if (current_dir / 'system_test_mapping.json').exists():
        return current_dir
    
    # If not found, check if we're in a CI environment
    workspace_path = Path('/workspace')
    if workspace_path.exists() and (workspace_path / 'system_test_mapping.json').exists():
        return workspace_path
    
    # Fallback to current working directory
    cwd = Path.cwd()
    if (cwd / 'system_test_mapping.json').exists():
        return cwd
    
    # Last resort - use the directory containing this script's parent
    return current_dir

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
    repo_root = get_repo_root()
    tests_dir = repo_root / 'tests_scripts'
    
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

def get_test_file_mapping_from_system_mapping(system_mapping: Dict) -> Dict[str, List[str]]:
    """
    Extract test-to-file mapping from system_test_mapping.json.
    Reads the test_implementation_files field from each test.
    """
    mappings = {}
    for test_name, test_config in system_mapping.items():
        impl_files = test_config.get('test_implementation_files', [])
        if impl_files:
            # Convert absolute paths to relative paths for comparison
            relative_files = [f.replace('tests_scripts/', '') for f in impl_files]
            mappings[test_name] = relative_files
    return mappings

def validate_implementation_files(system_mapping: Dict) -> List[Tuple[str, str, List[str]]]:
    """
    Validate that test_implementation_files are correct.
    
    Returns:
        List of (test_name, issue_type, missing_files)
    """
    issues = []
    
    for test_name, test_config in system_mapping.items():
        impl_files = test_config.get('test_implementation_files', [])
        
        if not impl_files:
            # Test has no implementation files defined
            issues.append((test_name, 'no_files', []))
            continue
        
        # Check if files exist
        missing_files = []
        repo_root = get_repo_root()
        for file_path in impl_files:
            full_path = repo_root / file_path
            if not full_path.exists():
                missing_files.append(file_path)
        
        if missing_files:
            issues.append((test_name, 'missing_files', missing_files))
    
    return issues

def validate_pr():
    """Main validation function."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}  PR API Mapping Validation{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    # Load data
    repo_root = get_repo_root()
    system_mapping = load_json_file(repo_root / 'system_test_mapping.json')
    
    # Check if api_method_mapping.json exists, if not use the mapping from update script
    api_method_mapping_path = repo_root / 'api_method_http_mapping.json'
    if api_method_mapping_path.exists():
        api_method_mapping = load_json_file(str(api_method_mapping_path))
    else:
        # Import from update script
        import sys
        sys.path.insert(0, str(repo_root / 'scripts'))
        from update_mapping_with_methods import get_api_method_mapping
        api_method_mapping = get_api_method_mapping()
    
    test_file_mapping = get_test_file_mapping_from_system_mapping(system_mapping)
    
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
    
    # First, validate implementation files for all tests (not just related ones)
    print(f"{Colors.BLUE}🔍 Validating implementation files...{Colors.END}")
    impl_file_issues = validate_implementation_files(system_mapping)
    
    # Filter to only related tests if there are changes
    if related_tests:
        impl_file_issues = [(name, type, files) for name, type, files in impl_file_issues 
                           if name in related_tests]
    
    if impl_file_issues:
        print(f"{Colors.YELLOW}⚠️  Found {len(impl_file_issues)} test(s) with implementation file issues{Colors.END}")
    else:
        print(f"{Colors.GREEN}✅ All implementation files valid{Colors.END}")
    print()
    
    # Validate each related test
    api_issues = []
    for test_name in sorted(related_tests):
        if test_name not in system_mapping:
            api_issues.append((test_name, 'missing', None, None))
            continue
        
        test_config = system_mapping[test_name]
        actual_apis = test_config.get('tested_dashboard_apis', [])
        
        # Get expected APIs
        test_files = test_file_mapping.get(test_name, [])
        expected_apis = get_expected_apis_for_test(test_name, test_files, api_method_mapping)
        
        # Compare
        missing_apis, extra_apis = compare_api_lists(expected_apis, actual_apis)
        
        if missing_apis or extra_apis:
            api_issues.append((test_name, 'mismatch', missing_apis, extra_apis))
    
    # Report results
    if not impl_file_issues and not api_issues:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ All validations passed!{Colors.END}")
        print(f"   • Implementation files: correct")
        print(f"   • API mappings: correct\n")
        return 0
    
    # Print implementation file issues first
    if impl_file_issues:
        print(f"\n{Colors.RED}{Colors.BOLD}❌ Implementation File Issues:{Colors.END}\n")
        
        for test_name, issue_type, missing_files in impl_file_issues:
            print(f"{Colors.BOLD}Test: {test_name}{Colors.END}")
            
            if issue_type == 'no_files':
                print(f"  {Colors.RED}❌ No implementation files defined{Colors.END}")
                print(f"     The 'test_implementation_files' field is empty or missing")
            
            elif issue_type == 'missing_files':
                print(f"  {Colors.RED}❌ Implementation files not found ({len(missing_files)}):{Colors.END}")
                for file_path in missing_files:
                    print(f"    • {file_path}")
            
            print()
    
    # Print API mapping issues
    if api_issues:
        print(f"\n{Colors.RED}{Colors.BOLD}❌ API Mapping Issues:{Colors.END}\n")
        
        for test_name, issue_type, missing, extra in api_issues:
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
    
    if impl_file_issues:
        print(f"{Colors.BOLD}For implementation file issues:{Colors.END}")
        print(f"  • If files are missing: Check that file paths are correct")
        print(f"  • If field is empty: Run the update script to auto-detect files")
        print()
    
    if api_issues:
        print(f"{Colors.BOLD}For API mapping issues:{Colors.END}")
    
    print(f"1. Run the update script to regenerate all mappings:")
    print(f"   {Colors.CYAN}python3 scripts/update_mapping_with_methods.py{Colors.END}\n")
    print(f"   This will:")
    print(f"   • Auto-detect implementation files from test configurations")
    print(f"   • Extract API calls from those files")
    print(f"   • Update both fields in system_test_mapping.json\n")
    print(f"2. Review the changes to ensure they're correct:\n")
    print(f"   {Colors.CYAN}git diff system_test_mapping.json{Colors.END}\n")
    print(f"3. Commit the updated system_test_mapping.json file:\n")
    print(f"   {Colors.CYAN}git add system_test_mapping.json{Colors.END}")
    print(f"   {Colors.CYAN}git commit -m 'Update API mappings for modified tests'{Colors.END}\n")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    return 1

if __name__ == '__main__':
    exit_code = validate_pr()
    sys.exit(exit_code)

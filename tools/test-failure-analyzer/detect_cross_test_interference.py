#!/usr/bin/env python3
"""
Cross-Test Interference Detection Module

Detects potential cross-test interference issues by analyzing:
- Bulk operations that might affect shared resources
- Parallel test execution
- Shared resource identifiers
- Unexpected state mutations
"""

import re
import ast
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from dateutil import parser as dateparser


def find_parallel_tests(
    current_test: Any,  # FailureEntry
    all_tests: List[Dict[str, Any]],
    window_minutes: int = 15
) -> List[str]:
    """
    Find tests that ran in parallel with current_test.
    Uses all_tests (includes successful tests) for correlation.
    
    Args:
        current_test: FailureEntry with time_start and time_end
        all_tests: List of all tests with timestamps
        window_minutes: Time window for considering tests parallel (default: 15)
    
    Returns:
        List of test names that ran in parallel
    """
    parallel = []
    if not current_test.time_start or not current_test.time_end:
        return parallel
    
    try:
        t1_start = dateparser.isoparse(current_test.time_start)
        t1_end = dateparser.isoparse(current_test.time_end)
    except Exception:
        return parallel
    
    current_test_name = current_test.test.get('name') if hasattr(current_test, 'test') else None
    
    for test_info in all_tests:
        test_name = test_info.get('name')
        if test_name == current_test_name:
            continue  # Skip self
        
        if not test_info.get('time_start') or not test_info.get('time_end'):
            continue
        
        try:
            t2_start = dateparser.isoparse(test_info['time_start'])
            t2_end = dateparser.isoparse(test_info['time_end'])
        except Exception:
            continue
        
        # Direct overlap: test windows intersect
        if t1_start <= t2_end and t2_start <= t1_end:
            parallel.append(test_name)
        else:
            # Proximity overlap: tests within window_minutes of each other
            gap_before = abs((t1_start - t2_end).total_seconds() / 60)
            gap_after = abs((t2_start - t1_end).total_seconds() / 60)
            if gap_before <= window_minutes or gap_after <= window_minutes:
                parallel.append(test_name)
    
    return parallel


def detect_bulk_operations(
    test_code: str,
    config: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Detect bulk operations in test code that use filters instead of specific identifiers.
    
    Args:
        test_code: Python test code as string
        config: Configuration dict with patterns
    
    Returns:
        List of detected bulk operations with details
    """
    bulk_ops = []
    patterns = config.get('cross_test_interference', {}).get('patterns', {})
    bulk_op_patterns = patterns.get('bulk_operations', [
        r"change_.*_status",
        r"delete_.*",
        r"update_.*",
        r"resolve_.*"
    ])
    filter_fields = patterns.get('filter_fields', ['name', 'type', 'cluster', 'namespace'])
    specific_params = patterns.get('specific_identifier_params', ['*_guids', '*_ids', 'guid', 'id'])
    
    # Build regex pattern for bulk operations
    bulk_op_regex = '|'.join(bulk_op_patterns)
    
    # Pattern: backend.{operation}(..., inner_filters=[...]) or filters=[...]
    # Look for operations that use filters but don't have specific identifier parameters
    pattern = rf'backend\.({bulk_op_regex})\s*\([^)]*(?:inner_filters|filters)\s*=\s*\[([^\]]+)\]'
    
    for match in re.finditer(pattern, test_code, re.IGNORECASE):
        operation = match.group(1)
        filters_str = match.group(2)
        
        # Check if specific identifier parameter exists in the call
        # Look for *_guids, *_ids, guid, or id parameters
        call_start = match.start()
        call_end = match.end()
        full_call = test_code[max(0, call_start-200):call_end+200]
        
        has_specific_id = False
        for param_pattern in specific_params:
            param_regex = param_pattern.replace('*', r'\w+')
            if re.search(rf'{param_regex}\s*=', full_call, re.IGNORECASE):
                has_specific_id = True
                break
        
        # Extract filter fields
        filter_fields_found = []
        for field in filter_fields:
            if re.search(rf'["\']?{field}["\']?\s*:', filters_str, re.IGNORECASE):
                filter_fields_found.append(field)
        
        # Extract filter values (string literals)
        filter_values = []
        string_pattern = r'["\']([^"\']+)["\']'
        for val_match in re.finditer(string_pattern, filters_str):
            filter_values.append(val_match.group(1))
        
        if filter_fields_found and not has_specific_id:
            bulk_ops.append({
                'operation': operation,
                'filters': filter_fields_found,
                'filter_values': filter_values,
                'line': test_code[:match.start()].count('\n') + 1,
                'has_specific_id': False,
                'risk': 'high'
            })
        elif filter_fields_found:
            bulk_ops.append({
                'operation': operation,
                'filters': filter_fields_found,
                'filter_values': filter_values,
                'line': test_code[:match.start()].count('\n') + 1,
                'has_specific_id': True,
                'risk': 'low'  # Has specific ID, lower risk
            })
    
    return bulk_ops


def extract_resource_identifiers(
    test_code: str,
    test_name: str
) -> Dict[str, List[str]]:
    """
    Extract resource identifiers from test code.
    
    Args:
        test_code: Python test code as string
        test_name: Name of the test
    
    Returns:
        Dict mapping resource types to identifiers
    """
    identifiers = {
        'incident_names': [],
        'policy_names': [],
        'exception_names': [],
        'cluster_names': [],
        'namespace_names': [],
        'other': []
    }
    
    # Extract string literals that might be resource names
    # Look for common patterns like:
    # - "Unexpected process launched"
    # - expected_incident_name = "..."
    # - cluster = "..."
    # - namespace = "..."
    
    # Pattern: variable = "value" or 'value'
    assignment_pattern = r'(\w+)\s*=\s*["\']([^"\']+)["\']'
    for match in re.finditer(assignment_pattern, test_code):
        var_name = match.group(1).lower()
        value = match.group(2)
        
        if 'incident' in var_name or 'incident_name' in var_name:
            identifiers['incident_names'].append(value)
        elif 'policy' in var_name:
            identifiers['policy_names'].append(value)
        elif 'exception' in var_name:
            identifiers['exception_names'].append(value)
        elif 'cluster' in var_name:
            identifiers['cluster_names'].append(value)
        elif 'namespace' in var_name:
            identifiers['namespace_names'].append(value)
        elif len(value) > 5:  # Potential resource name
            identifiers['other'].append(value)
    
    # Extract from filter dictionaries
    filter_pattern = r'\{[^}]*["\'](\w+)["\']\s*:\s*["\']([^"\']+)["\']'
    for match in re.finditer(filter_pattern, test_code):
        field = match.group(1).lower()
        value = match.group(2)
        
        if field == 'name':
            # Could be incident, policy, or exception name
            identifiers['incident_names'].append(value)
            identifiers['policy_names'].append(value)
        elif field == 'cluster':
            identifiers['cluster_names'].append(value)
        elif field == 'namespace':
            identifiers['namespace_names'].append(value)
    
    # Deduplicate
    for key in identifiers:
        identifiers[key] = list(set(identifiers[key]))
    
    return identifiers


def detect_cross_test_interference(
    failures: List[Any],  # List[FailureEntry]
    all_tests: List[Dict[str, Any]],
    raw_log: str,
    mapping: Dict[str, Any],
    config: Dict[str, Any],
    test_code_map: Optional[Dict[str, str]] = None
) -> List[Dict[str, Any]]:
    """
    Main function to detect cross-test interference.
    
    Args:
        failures: List of FailureEntry objects
        all_tests: List of all tests with timestamps
        raw_log: Raw log text
        mapping: Test mapping dictionary
        config: Configuration dictionary
        test_code_map: Optional map of test_name -> test_code
    
    Returns:
        List of interference signals, one per failure
    """
    interference_config = config.get('cross_test_interference', {})
    if not interference_config.get('enabled', True):
        return []
    
    window_minutes = interference_config.get('time_window_minutes', 15)
    signals = []
    
    for failure in failures:
        test_name = failure.test.get('name') if hasattr(failure, 'test') else None
        if not test_name:
            continue
        
        signal = {
            'test': test_name,
            'interference_detected': False,
            'parallel_tests': [],
            'bulk_operations': [],
            'shared_resources': [],
            'recommendations': []
        }
        
        # Find parallel tests
        parallel_tests = find_parallel_tests(failure, all_tests, window_minutes)
        signal['parallel_tests'] = parallel_tests
        
        if not parallel_tests:
            signals.append(signal)
            continue
        
        # Get test code if available
        test_code = None
        if test_code_map and test_name in test_code_map:
            test_code = test_code_map[test_name]
        else:
            # Try to find test file from mapping
            test_info = mapping.get(test_name, {})
            test_files = test_info.get('test_implementation_files', [])
            # Could read file here, but for now skip if not in map
        
        if test_code:
            # Detect bulk operations in this test
            bulk_ops = detect_bulk_operations(test_code, config)
            signal['bulk_operations'] = bulk_ops
            
            # Extract resource identifiers
            resource_ids = extract_resource_identifiers(test_code, test_name)
            signal['shared_resources'] = resource_ids
            
            # Check if parallel tests share resources
            for parallel_test_name in parallel_tests:
                # Try to get parallel test code
                parallel_test_code = None
                if test_code_map and parallel_test_name in test_code_map:
                    parallel_test_code = test_code_map[parallel_test_name]
                
                if parallel_test_code:
                    parallel_resources = extract_resource_identifiers(parallel_test_code, parallel_test_name)
                    parallel_bulk_ops = detect_bulk_operations(parallel_test_code, config)
                    
                    # Check for shared resources
                    for resource_type, values in resource_ids.items():
                        if values:
                            parallel_values = parallel_resources.get(resource_type, [])
                            shared = set(values) & set(parallel_values)
                            if shared:
                                signal['interference_detected'] = True
                                signal['shared_resources'].append({
                                    'type': resource_type,
                                    'values': list(shared),
                                    'parallel_test': parallel_test_name
                                })
                    
                    # Check if parallel test has bulk operations that might affect this test
                    for bulk_op in parallel_bulk_ops:
                        if bulk_op.get('risk') == 'high':
                            # Check if filter values match this test's resources
                            for filter_val in bulk_op.get('filter_values', []):
                                for resource_type, values in resource_ids.items():
                                    if filter_val in values:
                                        signal['interference_detected'] = True
                                        signal['recommendations'].append(
                                            f"Parallel test '{parallel_test_name}' uses bulk operation "
                                            f"'{bulk_op['operation']}' with filter matching this test's "
                                            f"{resource_type}: {filter_val}"
                                        )
        
        signals.append(signal)
    
    return signals


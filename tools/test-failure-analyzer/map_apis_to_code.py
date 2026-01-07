#!/usr/bin/env python3
"""
Map tested APIs to their handler code chunks.

This script reads system_test_mapping.json to find tested APIs, matches them
to endpoints in the code index, and extracts the corresponding handler chunks.

Usage:
    python map_apis_to_code.py \
      --test-name jira_integration \
      --mapping system_test_mapping.json \
      --index code-index.json \
      --output artifacts/api-code-map.json
"""

import argparse
import json
import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple


def normalize_test_name(test_name: str) -> str:
    """
    Normalize test name for mapping lookup.

    The analyzer can receive names like "ST (siem_integrations)" from logs/job names.
    Mapping keys are expected to be the raw key (e.g., "siem_integrations").
    """
    if not test_name:
        return test_name
    s = str(test_name).strip()
    m = re.match(r"^ST\s*\(\s*([^)]+?)\s*\)\s*$", s)
    if m:
        return m.group(1).strip()
    return s


def load_test_mapping(mapping_path: str) -> Dict[str, Any]:
    """Load system_test_mapping.json."""
    if not os.path.exists(mapping_path):
        print(f"Error: Test mapping file not found: {mapping_path}", file=sys.stderr)
        sys.exit(1)
    
    with open(mapping_path, 'r') as f:
        return json.load(f)


def load_code_index(index_path: str) -> Dict[str, Any]:
    """Load code index JSON file."""
    if not os.path.exists(index_path):
        print(f"Error: Code index file not found: {index_path}", file=sys.stderr)
        sys.exit(1)
    
    with open(index_path, 'r') as f:
        return json.load(f)


def normalize_path(path: str) -> str:
    """
    Normalize API path for matching.
    
    Removes trailing slashes and ensures consistent format.
    """
    if not path:
        return ""
    # Remove trailing slash
    path = path.rstrip('/')
    # Ensure starts with /
    if not path.startswith('/'):
        path = '/' + path
    return path


_PARAM_SEGMENT_RE = re.compile(r"^(?:\{[^}]+\}|:[^/]+|<[^>]+>)$")


def _split_segments(path: str) -> List[str]:
    """Split a normalized path into segments, excluding empty."""
    return [s for s in normalize_path(path).split("/") if s]


def _is_param_segment(seg: str) -> bool:
    """Return True if this segment is a path parameter placeholder."""
    return bool(_PARAM_SEGMENT_RE.match(seg))


def _segments_match(api_seg: str, endpoint_seg: str) -> bool:
    """
    Segment match with path-param awareness.

    Treat {param}, :param, <param> as wildcards that match any concrete segment.
    """
    if api_seg == endpoint_seg:
        return True
    if _is_param_segment(api_seg) or _is_param_segment(endpoint_seg):
        return True
    return False


def paths_equivalent(api_path: str, endpoint_path: str) -> bool:
    """Return True if the two paths match, allowing param placeholders."""
    a = _split_segments(api_path)
    b = _split_segments(endpoint_path)
    if len(a) != len(b):
        return False
    return all(_segments_match(x, y) for x, y in zip(a, b))


def path_is_prefix(api_path: str, endpoint_path: str) -> bool:
    """Return True if endpoint_path matches the prefix of api_path, allowing param placeholders."""
    a = _split_segments(api_path)
    b = _split_segments(endpoint_path)
    if len(b) > len(a):
        return False
    return all(_segments_match(x, y) for x, y in zip(a[:len(b)], b))


def is_generic_handler(endpoint: Dict[str, Any]) -> bool:
    """
    Check if an endpoint is a generic/documentation handler.
    
    Generic handlers should be avoided as they don't contain actual business logic.
    """
    file = endpoint.get("file", "").lower()
    handler = endpoint.get("handler", "").lower()
    package = endpoint.get("package", "").lower()
    
    # Check for documentation/swagger handlers
    if "docs/" in file or file.startswith("docs/"):
        return True
    if "swagger" in file or "swagger" in handler:
        return True
    
    # Check for generic ServeHTTP methods (usually routers, not handlers)
    if handler == "servehttp" and package != "main":
        return True
    
    # Check for test files (shouldn't be matched as handlers)
    if "_test.go" in file:
        return True
    
    return False


def match_endpoint(
    api_method: str,
    api_path: str,
    endpoints: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """
    Match an API (method + path) to an endpoint in the code index.
    
    Args:
        api_method: HTTP method (GET, POST, etc.)
        api_path: API path (e.g., /api/v1/cluster)
        endpoints: List of EndpointInfo from code index
    
    Returns:
        Matching endpoint dict, or None if not found
    """
    normalized_api_path = normalize_path(api_path)
    api_method_upper = api_method.upper()
    
    # Try exact match first (method + path) - excluding generic handlers
    for endpoint in endpoints:
        if is_generic_handler(endpoint):
            continue
            
        endpoint_method = endpoint.get("method", "").upper()
        endpoint_full_path = normalize_path(endpoint.get("fullPath", ""))
        
        # Match method (or "ANY" which handles all methods)
        method_matches = (
            endpoint_method == api_method_upper or 
            endpoint_method == "ANY"
        )
        
        if method_matches and paths_equivalent(normalized_api_path, endpoint_full_path):
            return endpoint
    
    # Try matching without prefix (some endpoints might have prefix in FullPath)
    for endpoint in endpoints:
        if is_generic_handler(endpoint):
            continue
            
        endpoint_method = endpoint.get("method", "").upper()
        endpoint_path = normalize_path(endpoint.get("path", ""))
        endpoint_full_path = normalize_path(endpoint.get("fullPath", ""))
        
        method_matches = (
            endpoint_method == api_method_upper or 
            endpoint_method == "ANY"
        )
        
        # Check if api_path matches either path or fullPath
        if method_matches:
            if paths_equivalent(normalized_api_path, endpoint_path) or paths_equivalent(normalized_api_path, endpoint_full_path):
                return endpoint
    
    # Try partial match (for nested paths)
    # This handles cases like /api/v1/posture/clusters matching /api/v1/posture
    # IMPORTANT: Sort by path length (longest first) to match /api/v1/vulnerability_v2 
    # before /api/v1/vulnerability
    # Filter out generic handlers first
    non_generic_endpoints = [e for e in endpoints if not is_generic_handler(e)]
    sorted_endpoints = sorted(
        non_generic_endpoints,
        key=lambda e: len(normalize_path(e.get("fullPath", ""))),
        reverse=True  # Longest paths first
    )
    
    for endpoint in sorted_endpoints:
        endpoint_method = endpoint.get("method", "").upper()
        endpoint_full_path = normalize_path(endpoint.get("fullPath", ""))
        
        method_matches = (
            endpoint_method == api_method_upper or 
            endpoint_method == "ANY"
        )
        
        if method_matches:
            # Check if api_path starts with endpoint_full_path (nested route), allowing params
            # Only match if the endpoint is reasonably specific (not just /api/v1)
            if path_is_prefix(normalized_api_path, endpoint_full_path):
                # Require at least 3 path segments to avoid matching too generic routes
                path_segments = endpoint_full_path.strip('/').split('/')
                if len(path_segments) >= 3:  # e.g., api/v1/runtime (not just api/v1)
                    return endpoint
    
    # Last resort: match by path only (ignore method) - but still avoid generic handlers
    for endpoint in non_generic_endpoints:
        endpoint_full_path = normalize_path(endpoint.get("fullPath", ""))
        
        if paths_equivalent(normalized_api_path, endpoint_full_path):
            return endpoint
    
    return None


def find_handler_by_api_path(
    api_path: str,
    chunks: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """
    Search for a handler chunk by analyzing the API path.
    
    This is used as a fallback when endpoint matching fails.
    For example, /api/v1/runtime/policies might be handled by:
    - httphandlerv2/runtime/policies_handler.go
    - httphandlerv2/runtime/handler.go (with method name like ListPolicies)
    - repositories/runtimepolicies.go
    
    Args:
        api_path: Full API path (e.g., /api/v1/runtime/policies)
        chunks: List of CodeChunk from code index
    
    Returns:
        Best matching chunk, or None if no good match found
    """
    # Extract path segments
    segments = [s for s in api_path.split('/') if s]
    
    # Common patterns to look for
    # Example: /api/v1/runtime/policies -> look for runtime, policies
    search_terms = []
    for seg in segments:
        if seg not in ['api', 'v1', 'v2', 'v3'] and not _is_param_segment(seg):  # Skip API version + params
            search_terms.append(seg.lower())
    
    if not search_terms:
        return None
    
    # Score each chunk based on how well it matches
    scored_chunks = []
    for chunk in chunks:
        file = chunk.get("file", "").lower()
        name = chunk.get("name", "").lower()
        package = chunk.get("package", "").lower()
        pattern = chunk.get("pattern", "").lower()
        
        # Skip test files
        if "_test.go" in file:
            continue
        
        # Skip generic handlers
        if "docs/" in file or "swagger" in file:
            continue
        
        score = 0
        
        # Check if chunk is marked as a handler
        is_handler = "handler" in pattern or "handler" in name or "handler" in file
        if is_handler:
            score += 10
        
        # Check if file path contains search terms
        for term in search_terms:
            if term in file:
                score += 5
            if term in package:
                score += 3
            if term in name:
                score += 4
        
        # Prefer files in httphandlerv2 or repositories
        if "httphandlerv2/" in file:
            score += 2
        if "repositories/" in file:
            score += 1
        
        # Only consider chunks with some relevance
        if score > 5:
            scored_chunks.append((score, chunk))
    
    if not scored_chunks:
        return None
    
    # Return highest scoring chunk
    scored_chunks.sort(key=lambda x: x[0], reverse=True)
    return scored_chunks[0][1]


def find_handler_chunk(
    handler_name: str,
    handler_package: str,
    chunks: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """
    Find the code chunk for a handler.
    
    Args:
        handler_name: Handler function/method name
        handler_package: Package name
        chunks: List of CodeChunk from code index
    
    Returns:
        Matching chunk dict, or None if not found
    """
    # Try exact match: name + package
    for chunk in chunks:
        chunk_name = chunk.get("name", "")
        chunk_package = chunk.get("package", "")
        chunk_pattern = chunk.get("pattern", "").lower()
        chunk_type = chunk.get("type", "").lower()
        
        # Check if it's a handler pattern (explicit pattern or method ending in Handler)
        is_handler = (
            "handler" in chunk_pattern or 
            chunk_name.lower().endswith("handler") or
            (chunk_type == "method" and "handler" in chunk_name.lower())
        )
        
        if is_handler:
            if chunk_name == handler_name and chunk_package == handler_package:
                return chunk
    
    # Try matching by name only (handler might be in different package)
    # If handler_package is empty, search all packages
    for chunk in chunks:
        chunk_name = chunk.get("name", "")
        chunk_pattern = chunk.get("pattern", "").lower()
        chunk_type = chunk.get("type", "").lower()
        chunk_package = chunk.get("package", "")
        
        is_handler = (
            "handler" in chunk_pattern or 
            chunk_name.lower().endswith("handler") or
            (chunk_type == "method" and "handler" in chunk_name.lower())
        )
        
        # Match by name, optionally by package
        if is_handler and chunk_name == handler_name:
            if not handler_package or chunk_package == handler_package:
                return chunk
    
    # Try case-insensitive match (in case of naming variations)
    handler_name_lower = handler_name.lower()
    for chunk in chunks:
        chunk_name = chunk.get("name", "")
        chunk_type = chunk.get("type", "").lower()
        
        # Check if it's a method with matching name (case-insensitive)
        if chunk_type == "method" and chunk_name.lower() == handler_name_lower:
            return chunk
    
    return None


def deduplicate_apis(apis: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate API entries from the list.
    
    Two APIs are considered duplicates if they have the same method and path.
    """
    seen = set()
    unique_apis = []
    
    for api in apis:
        api_method = api.get("method", "").upper()
        api_path = normalize_path(api.get("path", ""))
        api_key = f"{api_method} {api_path}"
        
        if api_key not in seen:
            seen.add(api_key)
            unique_apis.append(api)
    
    return unique_apis


def find_nested_handler(
    path_segments: List[str],
    chunks: List[Dict[str, Any]],
    handler_packages: List[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Find handler for nested routes like /api/v1/vulnerability_v2/vulnerability.
    
    For vulnerability_v2/vulnerability:
    1. First tries to find VulnerabilitiesV2Handler (main handler)
    2. Then tries to find vulnerabilitiesHandler (nested handler)
    3. Falls back to path-based matching
    
    Args:
        path_segments: List of path segments (e.g., ['vulnerability_v2', 'vulnerability'])
        chunks: List of code chunks
        handler_packages: Optional list of packages to search in
    
    Returns:
        Handler chunk if found, None otherwise
    """
    if not path_segments:
        return None
    
    handler_packages = handler_packages or ["httphandlerv2", "httphandler", "bl"]
    
    # Strategy 1: For nested routes like vulnerability_v2/vulnerability
    # Try to find the main handler first (VulnerabilitiesV2Handler)
    if len(path_segments) >= 2:
        # Extract the prefix (e.g., "vulnerability_v2")
        prefix = path_segments[0]
        nested = path_segments[1]
        
        # Convert prefix to handler name (vulnerability_v2 -> VulnerabilitiesV2Handler)
        prefix_words = prefix.replace('-', '_').split('_')
        # Check if last word is a version suffix (v2, v3, etc.)
        if len(prefix_words) >= 2 and prefix_words[-1].lower().startswith('v') and prefix_words[-1][1:].isdigit():
            # Handle version suffix separately (e.g., vulnerability_v2)
            version_suffix = prefix_words[-1].upper()  # v2 -> V2
            base_words = prefix_words[:-1]
            base_capitalized = ''.join([w.capitalize() for w in base_words if w])
            # Pluralize base word only (vulnerability -> Vulnerabilities)
            if base_capitalized.endswith('y'):
                base_capitalized = base_capitalized[:-1] + 'ies'
            elif not base_capitalized.endswith('s'):
                base_capitalized = base_capitalized + 's'
            main_handler_name = base_capitalized + version_suffix + "Handler"
        else:
            # No version suffix, pluralize normally
            prefix_capitalized = ''.join([w.capitalize() for w in prefix_words if w])
            if prefix_capitalized.endswith('y'):
                prefix_capitalized = prefix_capitalized[:-1] + 'ies'
            elif not prefix_capitalized.endswith('s'):
                prefix_capitalized = prefix_capitalized + 's'
            main_handler_name = prefix_capitalized + "Handler"
        
        # Try to find main handler (e.g., VulnerabilitiesV2Handler)
        for pkg in handler_packages:
            handler_chunk = find_handler_chunk(main_handler_name, pkg, chunks)
            if handler_chunk:
                # Found main handler, now try to find nested handler
                # For vulnerability_v2/vulnerability -> vulnerabilitiesHandler
                nested_words = nested.replace('-', '_').split('_')
                nested_capitalized = ''.join([w.capitalize() for w in nested_words if w])
                # Handle pluralization
                if nested_capitalized.endswith('y'):
                    nested_capitalized = nested_capitalized[:-1] + 'ies'
                elif not nested_capitalized.endswith('s'):
                    nested_capitalized = nested_capitalized + 's'
                # Nested handlers use lowercase first letter (e.g., vulnerabilitiesHandler)
                nested_handler_name = nested_capitalized[0].lower() + nested_capitalized[1:] + "Handler"
                
                # Try to find nested handler (e.g., vulnerabilitiesHandler)
                nested_handler = find_handler_chunk(nested_handler_name, pkg, chunks)
                if nested_handler:
                    return nested_handler
                # If nested handler not found, return main handler
                return handler_chunk
    
    # Strategy 2: Try last segment with pluralization
    last_segment = path_segments[-1]
    words = last_segment.replace('-', '_').split('_')
    capitalized_words = [w.capitalize() for w in words if w]
    potential_handler = ''.join(capitalized_words)
    
    # Handle pluralization
    if potential_handler.endswith('y'):
        potential_handler = potential_handler[:-1] + 'ies'
    elif not potential_handler.endswith('s'):
        potential_handler = potential_handler + 's'
    potential_handler = potential_handler + "Handler"
    
    for pkg in handler_packages:
        handler_chunk = find_handler_chunk(potential_handler, pkg, chunks)
        if handler_chunk:
            return handler_chunk
    
    return None


def map_apis_to_code(
    test_name: str,
    test_mapping: Dict[str, Any],
    code_index: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Map tested APIs to their handler code chunks.
    
    Args:
        test_name: Test name from system_test_mapping.json
        test_mapping: Full test mapping dict
        code_index: Code index dict
    
    Returns:
        Dict mapping API (method + path) to handler chunk info
    """
    original_test_name = test_name
    test_name = normalize_test_name(test_name)
    if test_name != original_test_name:
        print(f"ℹ️  Normalized test name: '{original_test_name}' -> '{test_name}'", file=sys.stderr)

    if test_name not in test_mapping:
        print(f"Error: Test '{test_name}' not found in mapping", file=sys.stderr)
        return {}
    
    test_config = test_mapping[test_name]
    tested_apis = test_config.get("tested_dashboard_apis", [])
    
    if not tested_apis:
        print(f"Warning: No tested_dashboard_apis found for test '{test_name}'", file=sys.stderr)
        return {}
    
    # Deduplicate APIs
    original_count = len(tested_apis)
    tested_apis = deduplicate_apis(tested_apis)
    if original_count != len(tested_apis):
        print(f"📋 Removed {original_count - len(tested_apis)} duplicate API entries", file=sys.stderr)
    
    endpoints = code_index.get("endpoints", [])
    chunks = code_index.get("chunks", [])
    
    api_mappings = {}
    matched_count = 0
    unmatched_apis = []
    
    for api in tested_apis:
        api_method = api.get("method", "")
        api_path = api.get("path", "")
        
        if not api_method or not api_path:
            print(f"Warning: Invalid API entry: {api}", file=sys.stderr)
            continue
        
        # Match endpoint
        endpoint = match_endpoint(api_method, api_path, endpoints)
        
        # If endpoint not found, we'll still try to find handler by path extraction
        # This handles cases where endpoints aren't indexed but handlers exist
        if not endpoint:
            # Create a dummy endpoint for path extraction
            endpoint = {
                "method": api_method,
                "path": api_path,
                "fullPath": api_path,
                "handler": "",
                "package": "",
                "file": "",
                "segment": "",
                "nested": ""
            }
        
        # Find handler chunk
        # The endpoint.Handler field contains the variable name (e.g., "apiV2Hnadler")
        # The actual handler method name is in Segment or Nested field (e.g., "workflows" -> "WorkflowsHandler")
        handler_name = endpoint.get("handler", "")
        handler_package = endpoint.get("package", "")
        segment = endpoint.get("segment", "")
        nested = endpoint.get("nested", "")
        
        # Debug: print endpoint info for first few endpoints
        if len(api_mappings) < 3:
            print(f"   Debug endpoint: {api_method} {api_path}")
            print(f"      Handler: {handler_name}, Segment: {segment}, Nested: {nested}, Package: {handler_package}")
        
        handler_chunk = None
        
        # Try to find handler using Segment/Nested first (more accurate)
        # The Segment field contains the route segment (e.g., "workflows") which maps to handler method (e.g., "WorkflowsHandler")
        if segment:
            # Convert segment to handler method name (e.g., "workflows" -> "WorkflowsHandler")
            # Capitalize first letter properly (handle multi-word segments)
            # Split by common separators and capitalize each word
            words = segment.replace('-', '_').replace('/', '_').split('_')
            capitalized_words = [w.capitalize() for w in words if w]
            handler_method_name = ''.join(capitalized_words) + "Handler"
            if len(api_mappings) < 3:
                print(f"      Trying segment-based: {handler_method_name}")
            handler_chunk = find_handler_chunk(handler_method_name, handler_package, chunks)
            if handler_chunk:
                handler_name = handler_method_name  # Update for output
        
        # If not found, try nested field
        if not handler_chunk and nested:
            words = nested.replace('-', '_').replace('/', '_').split('_')
            capitalized_words = [w.capitalize() for w in words if w]
            handler_method_name = ''.join(capitalized_words) + "Handler"
            if len(api_mappings) < 3:
                print(f"      Trying nested-based: {handler_method_name}")
            handler_chunk = find_handler_chunk(handler_method_name, handler_package, chunks)
            if handler_chunk:
                handler_name = handler_method_name
        
        # Fallback: try original handler name (might be a method name already)
        if not handler_chunk and handler_name:
            if len(api_mappings) < 3:
                print(f"      Trying original handler name: {handler_name}")
            handler_chunk = find_handler_chunk(handler_name, handler_package, chunks)
        
        # If still not found, try extracting handler name from API path
        # This works when endpoints don't have Segment/Nested populated
        if not handler_chunk:
            # Extract path segments (skip "api", "v1", "v2", etc.)
            path_segments = [s for s in api_path.split('/') if s and s not in ['api', 'v1', 'v2']]
            
            if path_segments:
                # Strategy 1: Try nested handler matching (for routes like vulnerability_v2/vulnerability)
                if len(api_mappings) < 3:
                    print(f"      Trying nested handler matching for path segments: {path_segments}")
                
                nested_handler = find_nested_handler(path_segments, chunks)
                if nested_handler:
                    handler_chunk = nested_handler
                    handler_name = nested_handler.get("name", "")
                    handler_package = nested_handler.get("package", "")
                    if len(api_mappings) < 3:
                        print(f"      ✅ Found nested handler: {handler_name} in package {handler_package}")
                
                # Strategy 2: Try last segment (e.g., "/api/v1/integrations" -> "integrations" -> "IntegrationsHandler")
                if not handler_chunk:
                    last_segment = path_segments[-1]
                    words = last_segment.replace('-', '_').split('_')
                    capitalized_words = [w.capitalize() for w in words if w]
                    # Handle pluralization
                    potential_handler = ''.join(capitalized_words)
                    if potential_handler.endswith('y'):
                        potential_handler = potential_handler[:-1] + 'ies'
                    elif not potential_handler.endswith('s'):
                        potential_handler = potential_handler + 's'
                    potential_handler = potential_handler + "Handler"
                    
                    if len(api_mappings) < 3:
                        print(f"      Trying path-based handler (last segment): {potential_handler}")
                    
                    handler_chunk = find_handler_chunk(potential_handler, "", chunks)
                    if handler_chunk:
                        handler_name = potential_handler
                        handler_package = handler_chunk.get("package", "")
                        if len(api_mappings) < 3:
                            print(f"      ✅ Found by last segment: {handler_name} in package {handler_package}")
                
                # Strategy 3: Try last two segments for nested paths (e.g., "/api/v1/posture/clusters" -> "PostureClustersHandler")
                if not handler_chunk and len(path_segments) >= 2:
                    last_two_segments = path_segments[-2:]
                    combined = '_'.join(last_two_segments)
                    words = combined.replace('-', '_').split('_')
                    capitalized_words = [w.capitalize() for w in words if w]
                    potential_handler = ''.join(capitalized_words) + "Handler"
                    
                    if len(api_mappings) < 3:
                        print(f"      Trying path-based handler (last 2 segments): {potential_handler}")
                    
                    handler_chunk = find_handler_chunk(potential_handler, "", chunks)
                    if handler_chunk:
                        handler_name = potential_handler
                        handler_package = handler_chunk.get("package", "")
                        if len(api_mappings) < 3:
                            print(f"      ✅ Found by last 2 segments: {handler_name} in package {handler_package}")
                
                # Strategy 4: Try searching in common handler packages with improved matching
                if not handler_chunk:
                    # Common handler packages in cadashboardbe
                    handler_packages = [
                        "httphandlerv2",
                        "httphandler",
                        "bl",
                    ]
                    
                    # Try with last segment (with pluralization)
                    last_segment = path_segments[-1]
                    words = last_segment.replace('-', '_').split('_')
                    capitalized_words = [w.capitalize() for w in words if w]
                    potential_handler = ''.join(capitalized_words)
                    # Handle pluralization
                    if potential_handler.endswith('y'):
                        potential_handler = potential_handler[:-1] + 'ies'
                    elif not potential_handler.endswith('s'):
                        potential_handler = potential_handler + 's'
                    potential_handler = potential_handler + "Handler"
                    
                    for pkg in handler_packages:
                        handler_chunk = find_handler_chunk(potential_handler, pkg, chunks)
                        if handler_chunk:
                            handler_name = potential_handler
                            handler_package = pkg
                            if len(api_mappings) < 3:
                                print(f"      ✅ Found in package {pkg}: {handler_name}")
                            break
                    
                    # Strategy 5: For nested routes, try finding main handler then nested handler
                    if not handler_chunk and len(path_segments) >= 2:
                        # Try main handler (e.g., VulnerabilitiesV2Handler)
                        prefix = path_segments[0]
                        prefix_words = prefix.replace('-', '_').split('_')
                        # Check if last word is a version suffix (v2, v3, etc.)
                        if len(prefix_words) >= 2 and prefix_words[-1].lower().startswith('v') and prefix_words[-1][1:].isdigit():
                            # Handle version suffix separately
                            version_suffix = prefix_words[-1].upper()
                            base_words = prefix_words[:-1]
                            base_capitalized = ''.join([w.capitalize() for w in base_words if w])
                            # Pluralize base word only
                            if base_capitalized.endswith('y'):
                                base_capitalized = base_capitalized[:-1] + 'ies'
                            elif not base_capitalized.endswith('s'):
                                base_capitalized = base_capitalized + 's'
                            main_handler = base_capitalized + version_suffix + "Handler"
                        else:
                            # No version suffix, pluralize normally
                            prefix_capitalized = ''.join([w.capitalize() for w in prefix_words if w])
                            if prefix_capitalized.endswith('y'):
                                prefix_capitalized = prefix_capitalized[:-1] + 'ies'
                            elif not prefix_capitalized.endswith('s'):
                                prefix_capitalized = prefix_capitalized + 's'
                            main_handler = prefix_capitalized + "Handler"
                        
                        for pkg in handler_packages:
                            main_chunk = find_handler_chunk(main_handler, pkg, chunks)
                            if main_chunk:
                                # Found main handler, use it as fallback
                                handler_chunk = main_chunk
                                handler_name = main_handler
                                handler_package = pkg
                                if len(api_mappings) < 3:
                                    print(f"      ✅ Found main handler (fallback): {handler_name} in package {handler_package}")
                                break
        
        # Strategy 6 (FINAL FALLBACK): Use semantic search based on API path
        # This finds handlers by analyzing file/package names for relevance
        if not handler_chunk:
            if len(api_mappings) < 3:
                print(f"      Trying semantic search fallback for: {api_path}")
            handler_chunk = find_handler_by_api_path(api_path, chunks)
            if handler_chunk:
                handler_name = handler_chunk.get("name", "")
                handler_package = handler_chunk.get("package", "")
                if len(api_mappings) < 3:
                    print(f"      ✅ Found via semantic search: {handler_name} in {handler_chunk.get('file', '')}")
        
        if handler_chunk:
            matched_count += 1
            api_mappings[f"{api_method} {api_path}"] = {
                "matched": True,
                "endpoint": {
                    "method": endpoint.get("method"),
                    "path": endpoint.get("path"),
                    "fullPath": endpoint.get("fullPath"),
                    "handler": handler_name,
                    "package": handler_package,
                    "file": endpoint.get("file")
                },
                "handler_chunk": {
                    "id": handler_chunk.get("id"),
                    "name": handler_chunk.get("name"),
                    "type": handler_chunk.get("type"),
                    "pattern": handler_chunk.get("pattern"),
                    "package": handler_chunk.get("package"),
                    "file": handler_chunk.get("file"),
                    "signature": handler_chunk.get("signature")
                }
            }
            print(f"✅ Matched {api_method} {api_path} -> {handler_name} ({handler_chunk.get('id', 'N/A')})")
        else:
            unmatched_apis.append(f"{api_method} {api_path}")
            api_mappings[f"{api_method} {api_path}"] = {
                "matched": False,
                "endpoint": {
                    "method": endpoint.get("method"),
                    "path": endpoint.get("path"),
                    "fullPath": endpoint.get("fullPath"),
                    "handler": handler_name,
                    "package": handler_package,
                    "file": endpoint.get("file")
                },
                "error": f"Handler chunk not found for '{handler_name}'"
            }
            print(f"⚠️  Handler chunk not found: {api_method} {api_path} -> {handler_name if handler_name else 'no handler name'}")
    
    # Print summary
    total_apis = len(tested_apis)
    print(f"\n📊 Mapping Summary:")
    print(f"   Total APIs: {total_apis}")
    print(f"   Matched: {matched_count}")
    print(f"   Unmatched: {len(unmatched_apis)}")
    
    if unmatched_apis:
        print(f"\n⚠️  Unmatched APIs:")
        for api in unmatched_apis:
            print(f"   - {api}")
    
    return {
        "test_name": test_name,
        "total_apis": total_apis,
        "matched_count": matched_count,
        "unmatched_count": len(unmatched_apis),
        "unmatched_apis": unmatched_apis,
        "mappings": api_mappings
    }


def main():
    parser = argparse.ArgumentParser(
        description="Map tested APIs to their handler code chunks"
    )
    parser.add_argument(
        "--test-name",
        required=True,
        help="Test name from system_test_mapping.json"
    )
    parser.add_argument(
        "--mapping",
        default="system_test_mapping.json",
        help="Path to system_test_mapping.json (default: system_test_mapping.json)"
    )
    parser.add_argument(
        "--index",
        required=True,
        help="Path to code index JSON file"
    )
    parser.add_argument(
        "--output",
        default="artifacts/api-code-map.json",
        help="Path to save API-code mapping JSON (default: artifacts/api-code-map.json)"
    )
    
    args = parser.parse_args()
    
    # Load test mapping and code index
    print(f"Loading test mapping from: {args.mapping}")
    test_mapping = load_test_mapping(args.mapping)
    
    print(f"Loading code index from: {args.index}")
    code_index = load_code_index(args.index)
    
    # Map APIs to code
    print(f"\nMapping APIs for test: {args.test_name}")
    result = map_apis_to_code(args.test_name, test_mapping, code_index)
    
    # Save results
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📄 API-code mapping saved to: {args.output}")
    
    # Exit with error if any APIs unmatched
    if result.get("unmatched_count", 0) > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()


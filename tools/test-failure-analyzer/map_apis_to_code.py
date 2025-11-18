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
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple


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
    
    # Try exact match first (method + path)
    for endpoint in endpoints:
        endpoint_method = endpoint.get("method", "").upper()
        endpoint_full_path = normalize_path(endpoint.get("fullPath", ""))
        
        # Match method (or "ANY" which handles all methods)
        method_matches = (
            endpoint_method == api_method_upper or 
            endpoint_method == "ANY"
        )
        
        if method_matches and endpoint_full_path == normalized_api_path:
            return endpoint
    
    # Try matching without prefix (some endpoints might have prefix in FullPath)
    for endpoint in endpoints:
        endpoint_method = endpoint.get("method", "").upper()
        endpoint_path = normalize_path(endpoint.get("path", ""))
        endpoint_full_path = normalize_path(endpoint.get("fullPath", ""))
        
        method_matches = (
            endpoint_method == api_method_upper or 
            endpoint_method == "ANY"
        )
        
        # Check if api_path matches either path or fullPath
        if method_matches:
            if endpoint_path == normalized_api_path or endpoint_full_path == normalized_api_path:
                return endpoint
    
    # Try partial match (for nested paths)
    # This handles cases like /api/v1/posture/clusters matching /api/v1/posture
    for endpoint in endpoints:
        endpoint_method = endpoint.get("method", "").upper()
        endpoint_full_path = normalize_path(endpoint.get("fullPath", ""))
        
        method_matches = (
            endpoint_method == api_method_upper or 
            endpoint_method == "ANY"
        )
        
        if method_matches:
            # Check if api_path starts with endpoint_full_path (nested route)
            # or endpoint_full_path starts with api_path (prefix route)
            if normalized_api_path.startswith(endpoint_full_path) or endpoint_full_path.startswith(normalized_api_path):
                return endpoint
    
    # Last resort: match by path only (ignore method)
    # This handles cases where endpoints are registered with "ANY" method
    for endpoint in endpoints:
        endpoint_full_path = normalize_path(endpoint.get("fullPath", ""))
        
        if endpoint_full_path == normalized_api_path:
            return endpoint
    
    return None


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
    if test_name not in test_mapping:
        print(f"Error: Test '{test_name}' not found in mapping", file=sys.stderr)
        return {}
    
    test_config = test_mapping[test_name]
    tested_apis = test_config.get("tested_dashboard_apis", [])
    
    if not tested_apis:
        print(f"Warning: No tested_dashboard_apis found for test '{test_name}'", file=sys.stderr)
        return {}
    
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
                # Strategy 1: Try last segment (e.g., "/api/v1/integrations" -> "integrations" -> "IntegrationsHandler")
                last_segment = path_segments[-1]
                words = last_segment.replace('-', '_').split('_')
                capitalized_words = [w.capitalize() for w in words if w]
                potential_handler = ''.join(capitalized_words) + "Handler"
                
                if len(api_mappings) < 3:
                    print(f"      Trying path-based handler (last segment): {potential_handler}")
                
                handler_chunk = find_handler_chunk(potential_handler, "", chunks)
                if handler_chunk:
                    handler_name = potential_handler
                    handler_package = handler_chunk.get("package", "")
                    if len(api_mappings) < 3:
                        print(f"      ✅ Found by last segment: {handler_name} in package {handler_package}")
                
                # Strategy 2: Try last two segments for nested paths (e.g., "/api/v1/posture/clusters" -> "PostureClustersHandler")
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
                
                # Strategy 3: Try searching in common handler packages
                if not handler_chunk:
                    # Common handler packages in cadashboardbe
                    handler_packages = [
                        "httphandlerv2",
                        "httphandler",
                        "bl",
                    ]
                    
                    # Try with last segment
                    last_segment = path_segments[-1]
                    words = last_segment.replace('-', '_').split('_')
                    capitalized_words = [w.capitalize() for w in words if w]
                    potential_handler = ''.join(capitalized_words) + "Handler"
                    
                    for pkg in handler_packages:
                        handler_chunk = find_handler_chunk(potential_handler, pkg, chunks)
                        if handler_chunk:
                            handler_name = potential_handler
                            handler_package = pkg
                            if len(api_mappings) < 3:
                                print(f"      ✅ Found in package {pkg}: {handler_name}")
                            break
        
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


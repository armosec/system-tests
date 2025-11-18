#!/usr/bin/env python3
"""
Trace service connector calls from cadashboardbe to handlers in other repos.

This script finds connector instantiations in cadashboardbe, extracts connector method calls,
and then finds matching handlers in other repositories to extract only relevant handler chunks.

Usage:
    python trace_connectors.py \
      --cadashboardbe-index cadashboardbe-index.json \
      --other-repo-indexes event-ingester-service:event-ingester-index.json,config-service:config-service-index.json \
      --output artifacts/connector-traced-chunks.json
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Set, Optional, Any


def load_code_index(index_path: str, required: bool = True) -> Optional[Dict[str, Any]]:
    """Load code index JSON file."""
    if not os.path.exists(index_path):
        if required:
            print(f"Error: Code index file not found: {index_path}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"⚠️  Code index file not found (skipping): {index_path}", file=sys.stderr)
            return None
    
    with open(index_path, 'r') as f:
        return json.load(f)


def find_connectors(chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Find service connector instantiations and method calls in cadashboardbe.
    
    Looks for patterns like:
    - NewPortalConnector(...)
    - NewUsersNotificationsConnector(...)
    - connector.CallAPI(...)
    - connector.Get(...)
    """
    connectors = []
    
    for chunk in chunks:
        code = chunk.get("code", "")
        pattern = chunk.get("pattern", "").lower()
        name = chunk.get("name", "").lower()
        package = chunk.get("package", "")
        
        # Check if it's a connector-related chunk
        is_connector = (
            "connector" in pattern or
            "connector" in name or
            re.search(r'New.*Connector\s*\(', code, re.IGNORECASE) is not None or
            re.search(r'\.(CallAPI|DoRequest|Get|Post|Put|Delete)', code, re.IGNORECASE) is not None
        )
        
        if is_connector:
            # Extract connector calls from code
            connector_calls = extract_connector_calls_from_code(code, package)
            if connector_calls:
                connectors.append({
                    "chunk": chunk,
                    "connector_calls": connector_calls
                })
    
    return connectors


def extract_connector_calls_from_code(code: str, package: str) -> List[Dict[str, Any]]:
    """
    Extract connector method calls from code.
    
    Returns list of dicts with:
    - connector_type: Type of connector (e.g., "PortalConnector", "UsersNotificationsConnector")
    - method: Method name (e.g., "CallAPI", "Get", "Post")
    - endpoint: API endpoint path
    - service: Service name (inferred from connector type or URL)
    """
    calls = []
    
    # Pattern 1: Connector instantiation
    # e.g., configServiceConnector = NewPortalConnector("https://config-service.com")
    connector_init_patterns = [
        r'(\w+)\s*[:=]\s*New(\w+Connector)\s*\([^)]*["\']([^"\']+)["\']',
        r'(\w+)\s*[:=]\s*New(\w+Connector)\s*\([^)]*\)',
    ]
    
    connector_vars = {}  # Map variable name to connector type and service
    
    for pattern in connector_init_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            var_name = match.group(1)
            connector_type = match.group(2)
            
            # Try to extract service URL if present
            service_url = match.group(3) if len(match.groups()) >= 3 else None
            service = None
            if service_url:
                # Extract service name from URL
                if "config" in service_url.lower():
                    service = "config-service"
                elif "user" in service_url.lower() or "notification" in service_url.lower():
                    service = "users-notification-service"
                elif "event" in service_url.lower() or "ingester" in service_url.lower():
                    service = "event-ingester-service"
            
            # Infer service from connector type name
            if not service:
                connector_lower = connector_type.lower()
                if "portal" in connector_lower or "config" in connector_lower:
                    service = "config-service"
                elif "user" in connector_lower or "notification" in connector_lower:
                    service = "users-notification-service"
                elif "event" in connector_lower or "ingester" in connector_lower:
                    service = "event-ingester-service"
            
            connector_vars[var_name] = {
                "type": connector_type,
                "service": service
            }
    
    # Pattern 2: Connector method calls
    # e.g., configServiceConnector.CallAPI("GET", "/api/v1/cluster", ...)
    # e.g., connector.Get("/api/v1/endpoint")
    method_call_patterns = [
        r'(\w+Connector)\.(CallAPI|DoRequest)\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']',  # CallAPI(method, url)
        r'(\w+Connector)\.(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']+)["\']',  # connector.Get(url)
        r'(\w+)\.(CallAPI|DoRequest)\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']',  # var.CallAPI(method, url)
        r'(\w+)\.(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']+)["\']',  # var.Get(url)
    ]
    
    for pattern in method_call_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            connector_var = match.group(1)
            method_name = match.group(2)
            
            # Determine HTTP method
            if method_name.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                http_method = method_name.upper()
                endpoint = match.group(3) if len(match.groups()) >= 3 else None
            elif len(match.groups()) >= 4:
                # CallAPI(method, url) format
                http_method = match.group(3).upper()
                endpoint = match.group(4)
            else:
                http_method = "GET"  # Default
                endpoint = match.group(3) if len(match.groups()) >= 3 else None
            
            # Get connector info
            connector_info = connector_vars.get(connector_var)
            if not connector_info:
                # Try to infer from variable name
                connector_info = {
                    "type": connector_var.replace("Connector", "") + "Connector",
                    "service": infer_service_from_var_name(connector_var)
                }
            
            if endpoint:
                calls.append({
                    "connector_type": connector_info.get("type", connector_var),
                    "connector_var": connector_var,
                    "method": method_name,
                    "http_method": http_method,
                    "endpoint": endpoint,
                    "service": connector_info.get("service")
                })
    
    return calls


def infer_service_from_var_name(var_name: str) -> Optional[str]:
    """Infer service name from connector variable name."""
    var_lower = var_name.lower()
    
    if "config" in var_lower or "portal" in var_lower:
        return "config-service"
    elif "user" in var_lower or "notification" in var_lower:
        return "users-notification-service"
    elif "event" in var_lower or "ingester" in var_lower:
        return "event-ingester-service"
    
    return None


def find_connector_handlers(
    connector_calls: List[Dict[str, Any]],
    chunks: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Find HTTP handlers in other repos that match the connector calls.
    
    Matches by:
    - Endpoint path
    - HTTP method
    """
    handlers = []
    
    # Find matching handlers in chunks
    for chunk in chunks:
        chunk_code = chunk.get("code", "")
        chunk_name = chunk.get("name", "").lower()
        chunk_pattern = chunk.get("pattern", "").lower()
        
        # Check if it's a handler
        is_handler = (
            "handler" in chunk_pattern or
            chunk_name.endswith("handler") or
            re.search(r'func\s+\w+Handler\s*\(', chunk_code, re.IGNORECASE) is not None or
            re.search(r'ServeHTTP\s*\(', chunk_code, re.IGNORECASE) is not None
        )
        
        if is_handler:
            # Try to match handler with connector calls
            matched_calls = []
            
            for call in connector_calls:
                endpoint = call.get("endpoint", "")
                http_method = call.get("http_method", "GET")
                
                # Check if handler code contains the endpoint path
                if endpoint and endpoint in chunk_code:
                    # Also check if HTTP method matches (if handler code contains method)
                    if http_method.lower() in chunk_code.lower() or "ANY" in chunk_code:
                        matched_calls.append(call)
            
            if matched_calls:
                handlers.append({
                    "chunk": chunk,
                    "matched_calls": matched_calls
                })
    
    return handlers


def trace_connectors(
    cadashboardbe_index: Dict[str, Any],
    other_repo_indexes: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Trace connector calls from cadashboardbe to handlers in other repos.
    """
    cadashboardbe_chunks = cadashboardbe_index.get("chunks", [])
    
    # Find all connectors in cadashboardbe
    print("🔍 Finding service connectors in cadashboardbe...")
    connectors = find_connectors(cadashboardbe_chunks)
    
    print(f"   Found {len(connectors)} connector chunks")
    
    # Collect all connector calls
    all_calls = []
    for connector_info in connectors:
        all_calls.extend(connector_info["connector_calls"])
    
    # Group by service
    calls_by_service = {}
    for call in all_calls:
        service = call.get("service", "unknown")
        if service not in calls_by_service:
            calls_by_service[service] = []
        calls_by_service[service].append(call)
    
    print(f"   Found {len(all_calls)} connector calls")
    service_names = [s for s in calls_by_service.keys() if s and s != "unknown"]
    if service_names:
        print(f"   Calls to {len(service_names)} services: {', '.join(sorted(service_names))}")
    else:
        print(f"   Calls to {len(calls_by_service)} services (service names not identified)")
    
    # Find handlers in other repos
    traced_chunks = {
        "cadashboardbe": {
            "connectors": [c["chunk"] for c in connectors],
            "connector_calls": all_calls
        }
    }
    
    for repo_name, repo_index in other_repo_indexes.items():
        print(f"\n🔍 Searching for handlers in {repo_name}...")
        repo_chunks = repo_index.get("chunks", [])
        handlers = find_connector_handlers(all_calls, repo_chunks)
        
        if handlers:
            print(f"   Found {len(handlers)} matching handler chunks")
            traced_chunks[repo_name] = {
                "handlers": [h["chunk"] for h in handlers],
                "matched_calls": [
                    call for h in handlers for call in h["matched_calls"]
                ]
            }
        else:
            print(f"   No handlers found for connector calls")
    
    return {
        "total_calls": len(all_calls),
        "total_connectors": len(connectors),
        "total_handlers": sum(
            len(traced_chunks.get(repo, {}).get("handlers", []))
            for repo in other_repo_indexes.keys()
        ),
        "traced_chunks": traced_chunks
    }


def main():
    parser = argparse.ArgumentParser(
        description="Trace service connector calls from cadashboardbe to other repos"
    )
    parser.add_argument(
        "--cadashboardbe-index",
        required=True,
        help="Path to cadashboardbe code index JSON file"
    )
    parser.add_argument(
        "--other-repo-indexes",
        required=True,
        help="Comma-separated list of code index JSON files for other repos (format: repo1:path1,repo2:path2)"
    )
    parser.add_argument(
        "--output",
        default="artifacts/connector-traced-chunks.json",
        help="Output file path (default: artifacts/connector-traced-chunks.json)"
    )
    
    args = parser.parse_args()
    
    # Load cadashboardbe index
    print(f"Loading cadashboardbe index from: {args.cadashboardbe_index}")
    cadashboardbe_index = load_code_index(args.cadashboardbe_index)
    
    # Parse and load other repo indexes
    other_repo_indexes = {}
    for repo_spec in args.other_repo_indexes.split(','):
        if ':' in repo_spec:
            repo_name, index_path = repo_spec.split(':', 1)
        else:
            index_path = repo_spec
            repo_name = os.path.basename(index_path).replace('-index.json', '').replace('_index.json', '')
        
        print(f"Loading {repo_name} index from: {index_path}")
        repo_index = load_code_index(index_path, required=False)
        if repo_index:
            other_repo_indexes[repo_name] = repo_index
        else:
            print(f"   Skipping {repo_name} (index not found)")
    
    # Trace connectors
    result = trace_connectors(cadashboardbe_index, other_repo_indexes)
    
    # Save results
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📊 Summary:")
    print(f"   Total connector calls: {result['total_calls']}")
    print(f"   Total connectors: {result['total_connectors']}")
    print(f"   Total handlers: {result['total_handlers']}")
    print(f"\n📄 Traced chunks saved to: {args.output}")


if __name__ == "__main__":
    main()


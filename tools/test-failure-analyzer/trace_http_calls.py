#!/usr/bin/env python3
"""
Trace HTTP calls from cadashboardbe to handlers in other repos.

This script analyzes cadashboardbe code to find HTTP client calls, extracts service URLs and endpoints,
and then finds matching handlers in other repositories to extract only relevant handler chunks.

Usage:
    python trace_http_calls.py \
      --cadashboardbe-index cadashboardbe-index.json \
      --other-repo-indexes event-ingester-service:event-ingester-index.json,config-service:config-service-index.json \
      --output artifacts/http-traced-chunks.json
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.parse import urlparse


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


def find_http_clients(chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Find HTTP client code chunks in cadashboardbe.
    
    Looks for patterns like:
    - http.Get(url, ...)
    - http.Post(url, ...)
    - client.Do(request)
    - connector.CallAPI(...)
    """
    clients = []
    
    for chunk in chunks:
        code = chunk.get("code", "")
        pattern = chunk.get("pattern", "").lower()
        name = chunk.get("name", "").lower()
        package = chunk.get("package", "")
        
        # Check if it's an HTTP client-related chunk
        is_client = (
            "connector" in pattern or
            "connector" in name or
            "client" in pattern or
            "http" in pattern or
            re.search(r'http\.(Get|Post|Put|Delete|Do|Client)', code, re.IGNORECASE) is not None or
            re.search(r'\.(CallAPI|DoRequest|Get|Post|Put|Delete)', code, re.IGNORECASE) is not None
        )
        
        if is_client:
            # Extract HTTP calls from code
            http_calls = extract_http_calls_from_code(code, package)
            if http_calls:
                clients.append({
                    "chunk": chunk,
                    "http_calls": http_calls
                })
    
    return clients


def extract_http_calls_from_code(code: str, package: str) -> List[Dict[str, Any]]:
    """
    Extract HTTP calls from code.
    
    Returns list of dicts with:
    - method: HTTP method (GET, POST, etc.)
    - url: Full URL or endpoint path
    - service: Service name (extracted from URL or connector name)
    """
    calls = []
    
    # Pattern 1: http.Get/Post/Put/Delete calls
    # e.g., http.Get("https://service.com/api/v1/endpoint")
    http_method_pattern = r'http\.(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']+)["\']'
    matches = re.finditer(http_method_pattern, code, re.IGNORECASE)
    for match in matches:
        method = match.group(1).upper()
        url = match.group(2)
        service, endpoint = parse_url(url)
        if service or endpoint:
            calls.append({
                "method": method,
                "url": url,
                "service": service,
                "endpoint": endpoint
            })
    
    # Pattern 2: http.NewRequest + client.Do
    # e.g., req, _ := http.NewRequest("GET", "https://service.com/api", nil)
    new_request_pattern = r'http\.NewRequest\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']'
    matches = re.finditer(new_request_pattern, code, re.IGNORECASE)
    for match in matches:
        method = match.group(1).upper()
        url = match.group(2)
        service, endpoint = parse_url(url)
        if service or endpoint:
            calls.append({
                "method": method,
                "url": url,
                "service": service,
                "endpoint": endpoint
            })
    
    # Pattern 3: Connector method calls
    # e.g., connector.CallAPI("GET", "/api/v1/endpoint", ...)
    # e.g., configServiceConnector.Get("/api/v1/cluster")
    connector_patterns = [
        r'\.(CallAPI|DoRequest)\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']',  # CallAPI(method, url)
        r'\.(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']+)["\']',  # connector.Get(url)
    ]
    
    for pattern in connector_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            if len(match.groups()) >= 2:
                method_or_func = match.group(1)
                url = match.group(2) if len(match.groups()) >= 2 else match.group(1)
                
                # Determine HTTP method
                if method_or_func.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    method = method_or_func.upper()
                elif len(match.groups()) >= 3:
                    method = match.group(2).upper()  # From CallAPI(method, url)
                else:
                    method = "GET"  # Default for Get() calls
                
                service, endpoint = parse_url(url)
                if service or endpoint:
                    calls.append({
                        "method": method,
                        "url": url,
                        "service": service,
                        "endpoint": endpoint
                    })
    
    # Pattern 4: Service URL constants/variables
    # e.g., configServiceConnector = NewPortalConnector("https://config-service.com")
    # Extract base URLs from connector initialization
    connector_init_patterns = [
        r'NewPortalConnector\s*\(\s*["\']([^"\']+)["\']',
        r'New.*Connector\s*\(\s*["\']([^"\']+)["\']',
        r'BaseURL\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    base_urls = {}
    for pattern in connector_init_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            url = match.group(1)
            service, _ = parse_url(url)
            if service:
                # Try to extract connector variable name from context
                # This is a simplified approach - in production, use AST parsing
                base_urls[service] = url
    
    # If we found base URLs, try to match them with endpoints
    for call in calls:
        if not call.get("service") and call.get("endpoint"):
            # Try to match endpoint with known base URLs
            for service, base_url in base_urls.items():
                if call["endpoint"].startswith("/"):
                    call["service"] = service
                    call["url"] = base_url.rstrip("/") + call["endpoint"]
                    break
    
    return calls


def parse_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse URL to extract service name and endpoint.
    
    Returns:
        (service_name, endpoint_path)
    """
    if not url:
        return None, None
    
    # If it's a full URL
    if url.startswith("http://") or url.startswith("https://"):
        try:
            parsed = urlparse(url)
            service = parsed.netloc.split(':')[0]  # Remove port
            endpoint = parsed.path
            return service, endpoint
        except:
            pass
    
    # If it's just a path, try to infer service from common patterns
    if url.startswith("/"):
        # Common service patterns in path
        if "/api/v1/" in url:
            # Try to extract service from path segments
            parts = url.split("/")
            if len(parts) > 1:
                # Could be /service-name/api/... or /api/v1/service-name/...
                if parts[1] == "api":
                    # Format: /api/v1/service-name/...
                    if len(parts) > 3:
                        service = parts[3]
                    else:
                        service = None
                else:
                    # Format: /service-name/...
                    service = parts[1]
            else:
                service = None
        else:
            service = None
        
        return service, url
    
    return None, None


def find_http_handlers(
    http_calls: List[Dict[str, Any]],
    chunks: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Find HTTP handlers in other repos that match the HTTP calls.
    
    Matches by:
    - Endpoint path
    - HTTP method
    """
    handlers = []
    
    # Collect all unique endpoints from calls
    endpoints_by_service = {}
    for call in http_calls:
        service = call.get("service", "unknown")
        endpoint = call.get("endpoint", "")
        method = call.get("method", "GET")
        
        if service not in endpoints_by_service:
            endpoints_by_service[service] = []
        
        endpoints_by_service[service].append({
            "method": method,
            "endpoint": endpoint,
            "url": call.get("url", "")
        })
    
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
            # Try to match handler with endpoints
            matched_endpoints = []
            
            for service, endpoints in endpoints_by_service.items():
                for endpoint_info in endpoints:
                    # Check if handler code contains the endpoint path
                    endpoint_path = endpoint_info["endpoint"]
                    if endpoint_path and endpoint_path in chunk_code:
                        matched_endpoints.append({
                            "service": service,
                            **endpoint_info
                        })
            
            if matched_endpoints:
                handlers.append({
                    "chunk": chunk,
                    "matched_endpoints": matched_endpoints
                })
    
    return handlers


def trace_http_calls(
    cadashboardbe_index: Dict[str, Any],
    other_repo_indexes: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Trace HTTP calls from cadashboardbe to handlers in other repos.
    """
    cadashboardbe_chunks = cadashboardbe_index.get("chunks", [])
    
    # Find all HTTP clients in cadashboardbe
    print("🔍 Finding HTTP clients in cadashboardbe...")
    clients = find_http_clients(cadashboardbe_chunks)
    
    print(f"   Found {len(clients)} HTTP client chunks")
    
    # Collect all HTTP calls
    all_calls = []
    for client_info in clients:
        all_calls.extend(client_info["http_calls"])
    
    # Group by service
    calls_by_service = {}
    for call in all_calls:
        service = call.get("service", "unknown")
        if service not in calls_by_service:
            calls_by_service[service] = []
        calls_by_service[service].append(call)
    
    print(f"   Found {len(all_calls)} HTTP calls")
    print(f"   Calls to {len(calls_by_service)} services: {', '.join(sorted(calls_by_service.keys()))}")
    
    # Find handlers in other repos
    traced_chunks = {
        "cadashboardbe": {
            "clients": [c["chunk"] for c in clients],
            "http_calls": all_calls
        }
    }
    
    for repo_name, repo_index in other_repo_indexes.items():
        print(f"\n🔍 Searching for handlers in {repo_name}...")
        repo_chunks = repo_index.get("chunks", [])
        handlers = find_http_handlers(all_calls, repo_chunks)
        
        if handlers:
            print(f"   Found {len(handlers)} matching handler chunks")
            traced_chunks[repo_name] = {
                "handlers": [h["chunk"] for h in handlers],
                "matched_calls": [
                    ep for h in handlers for ep in h["matched_endpoints"]
                ]
            }
        else:
            print(f"   No handlers found for HTTP calls")
    
    return {
        "total_calls": len(all_calls),
        "total_clients": len(clients),
        "total_handlers": sum(
            len(traced_chunks.get(repo, {}).get("handlers", []))
            for repo in other_repo_indexes.keys()
        ),
        "traced_chunks": traced_chunks
    }


def main():
    parser = argparse.ArgumentParser(
        description="Trace HTTP calls from cadashboardbe to other repos"
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
        default="artifacts/http-traced-chunks.json",
        help="Output file path (default: artifacts/http-traced-chunks.json)"
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
    
    # Trace HTTP calls
    result = trace_http_calls(cadashboardbe_index, other_repo_indexes)
    
    # Save results
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📊 Summary:")
    print(f"   Total HTTP calls: {result['total_calls']}")
    print(f"   Total clients: {result['total_clients']}")
    print(f"   Total handlers: {result['total_handlers']}")
    print(f"\n📄 Traced chunks saved to: {args.output}")


if __name__ == "__main__":
    main()


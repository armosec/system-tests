#!/usr/bin/env python3
"""
Extract call chains from handler code.

This script analyzes handler code chunks to find called functions, then
extracts service/repository chunks to build call chains.

Usage:
    python extract_call_chain.py \
      --handler-chunk-id chunk_123 \
      --index code-index.json \
      --max-depth 3 \
      --output artifacts/call-chains.json
"""

import argparse
import json
import os
import re
import sys
from collections import deque
from typing import Dict, List, Optional, Set, Any, Tuple


def load_code_index(index_path: str) -> Dict[str, Any]:
    """Load code index JSON file."""
    if not os.path.exists(index_path):
        print(f"Error: Code index file not found: {index_path}", file=sys.stderr)
        sys.exit(1)
    
    with open(index_path, 'r') as f:
        return json.load(f)


def find_chunk_by_id(chunk_id: str, chunks: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Find a chunk by its ID."""
    for chunk in chunks:
        if chunk.get("id") == chunk_id:
            return chunk
    return None


def find_chunks_by_name(name: str, chunks: List[Dict[str, Any]], package: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Find chunks by name (and optionally package).
    
    Returns:
        List of matching chunks
    """
    matches = []
    for chunk in chunks:
        chunk_name = chunk.get("name", "")
        chunk_package = chunk.get("package", "")
        
        if chunk_name == name:
            if package is None or chunk_package == package:
                matches.append(chunk)
    
    return matches


def extract_repo_from_import(import_path: str) -> Optional[str]:
    """
    Extract repository name from Go import path.
    
    Examples:
        github.com/armosec/postgres-connector/dal -> postgres-connector
        github.com/kubescape/storage/pkg/apis -> storage
    
    Returns:
        Repository name or None if not armosec/kubescape package
    """
    match = re.match(r'github\.com/(armosec|kubescape)/([^/]+)', import_path)
    return match.group(2) if match else None


def parse_imports(code: str) -> Dict[str, str]:
    """
    Parse Go import statements to build alias -> repo mapping.
    
    Returns:
        Dict mapping package alias to repository name
    """
    imports = {}
    
    # Match: import "github.com/armosec/postgres-connector/dal"
    # Match: import pc "github.com/armosec/postgres-connector/dal"
    # Also handle multi-line import blocks
    import_pattern = r'import\s+(?:(\w+)\s+)?"([^"]+)"'
    
    for match in re.finditer(import_pattern, code):
        alias = match.group(1)
        path = match.group(2)
        repo = extract_repo_from_import(path)
        
        if repo:
            # If no alias, use last part of path
            if not alias:
                alias = path.split('/')[-1]
            imports[alias] = repo
    
    return imports


def extract_function_calls(code: str, package: str) -> List[Tuple[str, Optional[str]]]:
    """
    Extract function calls from code.
    
    This is a simplified parser that looks for common patterns:
    - obj.Method()
    - package.Function()
    - Function()
    
    Args:
        code: Source code string
        package: Current package name
    
    Returns:
        List of tuples (function_name, package_name)
    """
    calls = []
    
    # Pattern 1: obj.Method() or obj.field.Method()
    # Matches: handler.bl.GetWorkflows(), service.repo.GetData()
    method_pattern = r'(\w+(?:\.\w+)*)\.(\w+)\s*\('
    for match in re.finditer(method_pattern, code):
        obj_path = match.group(1)
        method_name = match.group(2)
        
        # Skip common Go patterns that aren't function calls
        if obj_path in ['fmt', 'log', 'errors', 'context', 'http', 'json', 'time']:
            continue
        
        # Extract package from object path (e.g., "bl.WorkflowsBL" -> "bl")
        parts = obj_path.split('.')
        if len(parts) > 1:
            # Likely a package.method pattern
            calls.append((method_name, parts[0]))
        else:
            # Method call on an object
            calls.append((method_name, None))
    
    # Pattern 2: package.Function() (direct package calls)
    # Matches: bl.GetWorkflows(), repository.GetData()
    package_func_pattern = r'(\w+)\.(\w+)\s*\('
    for match in re.finditer(package_func_pattern, code):
        pkg_name = match.group(1)
        func_name = match.group(2)
        
        # Skip common Go standard library packages
        if pkg_name in ['fmt', 'log', 'errors', 'context', 'http', 'json', 'time', 'os', 'io', 'strings', 'strconv']:
            continue
        
        # Skip if it's the current package (likely a local function)
        if pkg_name == package:
            continue
        
        calls.append((func_name, pkg_name))
    
    # Pattern 3: Function() (local function calls - BOTH exported and unexported)
    # Matches: GetWorkflows(), ProcessData(), getVulnerabilitySummary(), newTicketsEnricher()
    local_func_pattern = r'\b([a-zA-Z]\w+)\s*\('
    for match in re.finditer(local_func_pattern, code):
        func_name = match.group(1)
        
        # Skip common Go keywords and built-ins
        if func_name in ['if', 'for', 'switch', 'select', 'return', 'break', 'continue',
                         'New', 'Make', 'Error', 'String', 'Int', 'Bool', 'Float',
                         'make', 'new', 'append', 'delete', 'len', 'cap', 'copy',
                         'panic', 'recover', 'defer', 'close', 'range']:
            continue
        
        # Skip common variable assignments (e.g., "err := func()")
        # This is heuristic - might need refinement
        if func_name in ['err', 'ok', 'res', 'result', 'value', 'data', 'item', 'i', 'j', 'k']:
            continue
        
        calls.append((func_name, None))
    
    # Remove duplicates
    return list(set(calls))


def classify_chunk_pattern(chunk: Dict[str, Any]) -> Optional[str]:
    """
    Classify chunk pattern (handler, service, repository, etc.).
    
    Returns:
        Pattern type or None
    """
    pattern = chunk.get("pattern", "").lower()
    chunk_type = chunk.get("type", "").lower()
    name = chunk.get("name", "").lower()
    package = chunk.get("package", "").lower()
    
    # Check explicit pattern
    if "handler" in pattern:
        return "handler"
    if "service" in pattern:
        return "service"
    if "repository" in pattern or "repo" in pattern:
        return "repository"
    if "connector" in pattern:
        return "connector"
    if "enricher" in pattern or "enrich" in pattern:
        return "enricher"
    if "validator" in pattern or "validate" in pattern:
        return "validator"
    if "helper" in pattern or "util" in pattern:
        return "helper"
    
    # Infer from package name
    if "handler" in package or "http" in package:
        return "handler"
    if "service" in package or "bl" in package or "business" in package:
        return "service"
    if "repository" in package or "repo" in package or "dal" in package:
        return "repository"
    if "connector" in package or "client" in package:
        return "connector"
    if "enricher" in package or "enrich" in package:
        return "enricher"
    if "validator" in package or "validate" in package:
        return "validator"
    if "helper" in package or "util" in package:
        return "helper"
    
    # Infer from name
    if "handler" in name:
        return "handler"
    if "service" in name or "bl" in name:
        return "service"
    if "repository" in name or "repo" in name:
        return "repository"
    if "enricher" in name or "enrich" in name:
        return "enricher"
    if "validator" in name or "validate" in name:
        return "validator"
    if "helper" in name or "util" in name:
        return "helper"
    
    return None


def extract_call_chain(
    handler_chunk_id: str,
    code_index: Dict[str, Any],
    max_depth: int = 3,
    visited: Optional[Set[str]] = None,
    all_chunks: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Extract call chain starting from a handler chunk.
    
    Args:
        handler_chunk_id: ID of the handler chunk
        code_index: Code index dict (main repository)
        max_depth: Maximum depth to traverse (default: 3)
        visited: Set of already visited chunk IDs (to prevent cycles)
        all_chunks: Optional list of all chunks from all repos (with _repo tag)
    
    Returns:
        Dict with call chain information
    """
    if visited is None:
        visited = set()
    
    # Use provided all_chunks if available, otherwise just use main index
    if all_chunks is None:
        chunks = code_index.get("chunks", [])
    else:
        chunks = all_chunks
    handler_chunk = find_chunk_by_id(handler_chunk_id, chunks)
    
    if not handler_chunk:
        return {
            "error": f"Handler chunk not found: {handler_chunk_id}",
            "chain": []
        }
    
    # Prevent cycles
    if handler_chunk_id in visited:
        return {
            "handler_chunk_id": handler_chunk_id,
            "handler_name": handler_chunk.get("name"),
            "circular": True,
            "chain": []
        }
    
    visited.add(handler_chunk_id)
    
    # Extract function calls from handler code
    handler_code = handler_chunk.get("code", "")
    handler_package = handler_chunk.get("package", "")
    
    # Parse imports to build alias -> repo mapping
    import_to_repo = parse_imports(handler_code)
    
    function_calls = extract_function_calls(handler_code, handler_package)
    
    # Track cross-repo calls and repositories in chain
    cross_repo_calls = []
    repositories_in_chain = set(["cadashboardbe"])  # Start with main repo
    
    # Build call chain
    chain = []
    current_level = [{
        "chunk_id": handler_chunk_id,
        "name": handler_chunk.get("name"),
        "type": handler_chunk.get("type"),
        "pattern": classify_chunk_pattern(handler_chunk),
        "package": handler_package,
        "file": handler_chunk.get("file")
    }]
    
    level = 0
    while level < max_depth and current_level:
        next_level = []
        
        for item in current_level:
            # Find the chunk for this item
            chunk = find_chunk_by_id(item["chunk_id"], chunks)
            if not chunk:
                continue
            
            chunk_code = chunk.get("code", "")
            chunk_package = chunk.get("package", "")
            
            # Extract calls from this chunk
            calls = extract_function_calls(chunk_code, chunk_package)
            
            # Find matching chunks for each call
            for func_name, pkg_name in calls:
                # Check if this is a cross-repo call
                if pkg_name and pkg_name in import_to_repo:
                    repo_name = import_to_repo[pkg_name]
                    cross_repo_calls.append({
                        "repo": repo_name,
                        "package": pkg_name,
                        "function": func_name,
                        "called_from_chunk": item["chunk_id"]
                    })
                    repositories_in_chain.add(repo_name)
                
                # Try to find chunk by name and package
                matching_chunks = find_chunks_by_name(func_name, chunks, pkg_name)
                
                # If no package specified, try without package constraint
                if not matching_chunks and pkg_name is None:
                    matching_chunks = find_chunks_by_name(func_name, chunks)
                
                for called_chunk in matching_chunks:
                    called_chunk_id = called_chunk.get("id")
                    called_pattern = classify_chunk_pattern(called_chunk)
                    
                    # Only follow service/repository/enricher/helper patterns (skip handlers, connectors at deeper levels)
                    if level == 0:
                        # First level: can be anything
                        pass
                    elif level == 1:
                        # Second level: prefer service/repository, but allow enrichers/validators/helpers
                        if called_pattern and called_pattern not in ["service", "repository", "enricher", "validator", "helper", None]:
                            continue
                    elif level == 2:
                        # Third level: repository, enricher, validator, helper, or unknown functions
                        if called_pattern and called_pattern not in ["repository", "enricher", "validator", "helper", "dal", None]:
                            continue
                    else:
                        # Fourth level and beyond: repository, enricher, dal, or unknown functions
                        if called_pattern and called_pattern not in ["repository", "enricher", "dal", None]:
                            continue
                    
                    # Skip if already visited
                    if called_chunk_id in visited:
                        continue
                    
                    visited.add(called_chunk_id)
                    
                    next_item = {
                        "chunk_id": called_chunk_id,
                        "name": called_chunk.get("name"),
                        "type": called_chunk.get("type"),
                        "pattern": called_pattern,
                        "package": called_chunk.get("package"),
                        "file": called_chunk.get("file"),
                        "called_from": item["chunk_id"],
                        "function_name": func_name
                    }
                    
                    next_level.append(next_item)
                    chain.append(next_item)
        
        current_level = next_level
        level += 1
    
    return {
        "handler_chunk_id": handler_chunk_id,
        "handler_name": handler_chunk.get("name"),
        "max_depth": max_depth,
        "chain": chain,
        "total_chunks": len(chain) + 1,  # +1 for handler itself
        "cross_repo_calls": cross_repo_calls,
        "repositories_in_chain": list(repositories_in_chain)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extract call chains from handler code"
    )
    parser.add_argument(
        "--handler-chunk-id",
        required=True,
        help="ID of the handler chunk to start from"
    )
    parser.add_argument(
        "--index",
        required=True,
        help="Path to code index JSON file"
    )
    parser.add_argument(
        "--dependency-indexes",
        help="JSON string mapping repo names to index paths: {\"postgres-connector\": \"path/to/index.json\"}"
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=3,
        help="Maximum depth to traverse (default: 3)"
    )
    parser.add_argument(
        "--output",
        default="artifacts/call-chains.json",
        help="Path to save call chain JSON (default: artifacts/call-chains.json)"
    )
    
    args = parser.parse_args()
    
    # Load code index
    print(f"Loading code index from: {args.index}")
    code_index = load_code_index(args.index)
    main_chunks = code_index.get('chunks', [])
    
    # Load dependency indexes if provided
    all_chunks = []
    dependency_chunks = {}
    
    if args.dependency_indexes:
        try:
            dep_indexes = json.loads(args.dependency_indexes)
            print(f"Loading {len(dep_indexes)} dependency indexes...")
            
            for repo_name, index_path in dep_indexes.items():
                if os.path.exists(index_path):
                    dep_index = load_code_index(index_path)
                    dep_chunks = dep_index.get('chunks', [])
                    dependency_chunks[repo_name] = dep_chunks
                    print(f"  Loaded {len(dep_chunks)} chunks from {repo_name}")
                else:
                    print(f"  ⚠️  Index not found: {index_path}")
        except json.JSONDecodeError as e:
            print(f"⚠️  Warning: Failed to parse dependency-indexes JSON: {e}")
        except Exception as e:
            print(f"⚠️  Warning: Error loading dependency indexes: {e}")
    
    # Combine all chunks with repo tags
    for chunk in main_chunks:
        chunk['_repo'] = 'cadashboardbe'  # Tag with source repo
        all_chunks.append(chunk)
    
    for repo_name, chunks in dependency_chunks.items():
        for chunk in chunks:
            chunk['_repo'] = repo_name
            all_chunks.append(chunk)
    
    if dependency_chunks:
        print(f"Total chunks available: {len(all_chunks)} (from {1 + len(dependency_chunks)} repos)")
    
    # Extract call chain
    print(f"Extracting call chain for handler chunk: {args.handler_chunk_id}")
    print(f"Max depth: {args.max_depth}")
    
    result = extract_call_chain(
        handler_chunk_id=args.handler_chunk_id,
        code_index=code_index,
        max_depth=args.max_depth,
        all_chunks=all_chunks if all_chunks else None
    )
    
    if "error" in result:
        print(f"❌ Error: {result['error']}", file=sys.stderr)
        sys.exit(1)
    
    # Print summary
    print(f"\n📊 Call Chain Summary:")
    print(f"   Handler: {result.get('handler_name')}")
    print(f"   Total chunks in chain: {result.get('total_chunks')}")
    print(f"   Chain depth: {len(result.get('chain', []))}")
    
    # Group by pattern
    patterns = {}
    for item in result.get("chain", []):
        pattern = item.get("pattern", "unknown")
        if pattern not in patterns:
            patterns[pattern] = 0
        patterns[pattern] += 1
    
    if patterns:
        print(f"\n   Chunks by pattern:")
        for pattern, count in patterns.items():
            print(f"     {pattern}: {count}")
    
    # Save results
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📄 Call chain saved to: {args.output}")


if __name__ == "__main__":
    main()


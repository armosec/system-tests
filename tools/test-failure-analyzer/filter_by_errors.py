#!/usr/bin/env python3
"""
Filter code chunks by error logs from Loki.

This script parses Loki error logs for function names, matches them against code chunks,
and prioritizes matched chunks to add to context.

Usage:
    python filter_by_errors.py \
      --error-logs artifacts/loki-errors.txt \
      --code-indexes cadashboardbe:cadashboardbe-index.json,event-ingester:event-ingester-index.json \
      --output artifacts/error-filtered-chunks.json
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


def extract_function_names_from_errors(error_logs: str) -> Set[str]:
    """
    Extract function names from error logs.
    
    Looks for patterns like:
    - "function_name: error message"
    - "at function_name (file.go:123)"
    - "panic: function_name"
    - Stack traces
    """
    function_names = set()
    
    # Pattern 1: Go stack traces
    # e.g., "at github.com/armosec/cadashboardbe/handler.WorkflowsHandler (file.go:123)"
    stack_trace_pattern = r'at\s+[^\s]+\/([^/\s]+)\.(\w+)\s*\('
    matches = re.finditer(stack_trace_pattern, error_logs, re.IGNORECASE)
    for match in matches:
        package = match.group(1)
        func_name = match.group(2)
        # Store as "package.FunctionName" and just "FunctionName"
        function_names.add(f"{package}.{func_name}")
        function_names.add(func_name)
    
    # Pattern 2: Function names in error messages
    # e.g., "WorkflowsHandler: failed to process"
    error_func_pattern = r'(\w+Handler|\w+Service|\w+Repository|\w+Connector)\s*[:\(]'
    matches = re.finditer(error_func_pattern, error_logs, re.IGNORECASE)
    for match in matches:
        func_name = match.group(1)
        function_names.add(func_name)
    
    # Pattern 3: Panic messages
    # e.g., "panic: WorkflowsHandler"
    panic_pattern = r'panic:\s*(\w+)'
    matches = re.finditer(panic_pattern, error_logs, re.IGNORECASE)
    for match in matches:
        func_name = match.group(1)
        function_names.add(func_name)
    
    # Pattern 4: Error context
    # e.g., "error in WorkflowsHandler"
    error_context_pattern = r'(?:error|failed|panic)\s+(?:in|at|from)\s+(\w+)'
    matches = re.finditer(error_context_pattern, error_logs, re.IGNORECASE)
    for match in matches:
        func_name = match.group(1)
        function_names.add(func_name)
    
    return function_names


def match_chunks_to_functions(
    function_names: Set[str],
    code_indexes: Dict[str, Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Match function names to code chunks.
    
    Returns dict mapping repo name to list of matched chunks.
    """
    matched_chunks = {}
    
    for repo_name, code_index in code_indexes.items():
        chunks = code_index.get("chunks", [])
        repo_matches = []
        
        for chunk in chunks:
            chunk_name = chunk.get("name", "")
            chunk_package = chunk.get("package", "")
            chunk_signature = chunk.get("signature", "")
            
            # Try exact match
            if chunk_name in function_names:
                repo_matches.append({
                    "chunk": chunk,
                    "match_type": "exact_name",
                    "matched_function": chunk_name
                })
            # Try package.function match
            elif f"{chunk_package}.{chunk_name}" in function_names:
                repo_matches.append({
                    "chunk": chunk,
                    "match_type": "package_function",
                    "matched_function": f"{chunk_package}.{chunk_name}"
                })
            # Try substring match (for partial function names)
            else:
                for func_name in function_names:
                    if func_name.lower() in chunk_name.lower() or chunk_name.lower() in func_name.lower():
                        repo_matches.append({
                            "chunk": chunk,
                            "match_type": "substring",
                            "matched_function": func_name
                        })
                        break
        
        if repo_matches:
            matched_chunks[repo_name] = repo_matches
    
    return matched_chunks


def prioritize_chunks(
    matched_chunks: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Prioritize chunks by match type and pattern.
    
    Priority order:
    1. Handlers (exact match)
    2. Services (exact match)
    3. Repositories (exact match)
    4. Connectors (exact match)
    5. Others (substring match)
    """
    prioritized = {}
    
    for repo_name, chunks in matched_chunks.items():
        # Sort by priority
        priority_order = {
            "handler": 1,
            "service": 2,
            "repository": 3,
            "connector": 4,
            "other": 5
        }
        
        def get_priority(chunk_info):
            chunk = chunk_info["chunk"]
            pattern = chunk.get("pattern", "").lower()
            match_type = chunk_info["match_type"]
            
            # Exact matches get higher priority
            base_priority = 0 if match_type == "exact_name" else 100
            
            # Pattern-based priority
            pattern_priority = priority_order.get(pattern, 5)
            
            return base_priority + pattern_priority
        
        sorted_chunks = sorted(chunks, key=get_priority)
        prioritized[repo_name] = sorted_chunks
    
    return prioritized


def filter_by_errors(
    error_logs_path: str,
    code_indexes: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Filter code chunks by error logs.
    """
    print(f"📖 Reading error logs from: {error_logs_path}")
    if not os.path.exists(error_logs_path):
        print(f"⚠️  Error logs file not found: {error_logs_path}")
        return {
            "total_functions": 0,
            "total_matched_chunks": 0,
            "filtered_chunks": {}
        }
    
    with open(error_logs_path, 'r') as f:
        error_logs = f.read()
    
    # Extract function names
    print("🔍 Extracting function names from error logs...")
    function_names = extract_function_names_from_errors(error_logs)
    print(f"   Found {len(function_names)} unique function names")
    if len(function_names) <= 20:
        print(f"   Functions: {', '.join(sorted(function_names))}")
    
    # Match to chunks
    print("\n🔍 Matching functions to code chunks...")
    matched_chunks = match_chunks_to_functions(function_names, code_indexes)
    
    total_matched = sum(len(chunks) for chunks in matched_chunks.values())
    print(f"   Matched {total_matched} chunks across {len(matched_chunks)} repos")
    
    # Prioritize
    print("\n📊 Prioritizing matched chunks...")
    prioritized_chunks = prioritize_chunks(matched_chunks)
    
    return {
        "total_functions": len(function_names),
        "function_names": list(function_names),
        "total_matched_chunks": total_matched,
        "filtered_chunks": {
            repo: [c["chunk"] for c in chunks]
            for repo, chunks in prioritized_chunks.items()
        },
        "match_details": prioritized_chunks
    }


def main():
    parser = argparse.ArgumentParser(
        description="Filter code chunks by error logs"
    )
    parser.add_argument(
        "--error-logs",
        required=True,
        help="Path to error logs file (from Loki or workflow logs)"
    )
    parser.add_argument(
        "--code-indexes",
        required=True,
        help="Comma-separated list of code index JSON files (format: repo1:path1,repo2:path2)"
    )
    parser.add_argument(
        "--output",
        default="artifacts/error-filtered-chunks.json",
        help="Output file path (default: artifacts/error-filtered-chunks.json)"
    )
    
    args = parser.parse_args()
    
    # Parse and load code indexes
    code_indexes = {}
    for repo_spec in args.code_indexes.split(','):
        if ':' in repo_spec:
            repo_name, index_path = repo_spec.split(':', 1)
        else:
            index_path = repo_spec
            repo_name = os.path.basename(index_path).replace('-index.json', '').replace('_index.json', '')
        
        print(f"Loading {repo_name} index from: {index_path}")
        repo_index = load_code_index(index_path, required=False)
        if repo_index:
            code_indexes[repo_name] = repo_index
        else:
            print(f"   Skipping {repo_name} (index not found)")
    
    # Filter by errors
    result = filter_by_errors(args.error_logs, code_indexes)
    
    # Save results
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📊 Summary:")
    print(f"   Total functions found: {result['total_functions']}")
    print(f"   Total matched chunks: {result['total_matched_chunks']}")
    for repo, chunks in result['filtered_chunks'].items():
        print(f"   {repo}: {len(chunks)} chunks")
    print(f"\n📄 Filtered chunks saved to: {args.output}")


if __name__ == "__main__":
    main()


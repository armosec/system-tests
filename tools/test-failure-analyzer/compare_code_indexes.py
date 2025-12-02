#!/usr/bin/env python3
"""
Compare code indexes to generate diffs.

Compares deployed vs RC/latest versions for dashboard and dependencies,
identifying changed functions, new/removed endpoints, and modified code.

Usage:
    python compare_code_indexes.py \
        --found-indexes artifacts/found-indexes.json \
        --output artifacts/code-diffs.json \
        --max-changes 100
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Any, Optional


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare code indexes to generate diffs")
    parser.add_argument("--found-indexes", required=True, help="Path to found-indexes.json from find_indexes.py")
    parser.add_argument("--output", required=True, help="Output JSON file path")
    parser.add_argument("--max-changes", type=int, default=100, help="Maximum changes to include in diff (default: 100)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def load_code_index(path: str) -> Dict:
    """Load code index from JSON file."""
    if not path or not Path(path).exists():
        return {}
    
    with open(path, 'r') as f:
        return json.load(f)


def extract_functions(index: Dict) -> Set[str]:
    """Extract function signatures from code index."""
    functions = set()
    
    chunks = index.get('chunks', [])
    for chunk in chunks:
        chunk_type = chunk.get('type', '')
        if chunk_type in ['function', 'method']:
            # Create signature: file:function_name
            file_path = chunk.get('file', '')
            func_name = chunk.get('name', '')
            if file_path and func_name:
                signature = f"{file_path}:{func_name}"
                functions.add(signature)
    
    return functions


def extract_endpoints(index: Dict) -> Set[tuple]:
    """Extract HTTP endpoints from code index."""
    endpoints = set()
    
    chunks = index.get('chunks', [])
    for chunk in chunks:
        # Look for HTTP handler metadata
        metadata = chunk.get('metadata', {})
        http_method = metadata.get('http_method')
        http_path = metadata.get('http_path')
        
        if http_method and http_path:
            endpoints.add((http_method, http_path))
    
    return endpoints


def get_function_details(index: Dict, signature: str) -> Optional[Dict]:
    """Get details for a specific function."""
    file_path, func_name = signature.rsplit(':', 1)
    
    chunks = index.get('chunks', [])
    for chunk in chunks:
        if chunk.get('file') == file_path and chunk.get('name') == func_name:
            return {
                "name": func_name,
                "file": file_path,
                "type": chunk.get('type', ''),
                "lines": chunk.get('lines', 0),
                "start_line": chunk.get('start_line', 0),
                "end_line": chunk.get('end_line', 0)
            }
    
    return None


def compare_indexes(old_index: Dict, new_index: Dict, old_label: str, new_label: str, max_changes: int = 100) -> Dict:
    """
    Compare two code indexes and generate diff.
    
    Returns:
        Dict with diff summary and details
    """
    # Extract functions from both indexes
    old_functions = extract_functions(old_index)
    new_functions = extract_functions(new_index)
    
    # Compute differences
    added_functions = new_functions - old_functions
    removed_functions = old_functions - new_functions
    unchanged_functions = old_functions & new_functions
    
    # Extract endpoints
    old_endpoints = extract_endpoints(old_index)
    new_endpoints = extract_endpoints(new_index)
    
    added_endpoints = new_endpoints - old_endpoints
    removed_endpoints = old_endpoints - new_endpoints
    
    # Limit to max_changes
    added_functions_list = sorted(list(added_functions))[:max_changes]
    removed_functions_list = sorted(list(removed_functions))[:max_changes]
    
    # Get details for changed functions
    added_details = []
    for sig in added_functions_list:
        details = get_function_details(new_index, sig)
        if details:
            added_details.append(details)
    
    removed_details = []
    for sig in removed_functions_list:
        details = get_function_details(old_index, sig)
        if details:
            removed_details.append(details)
    
    # Convert endpoints to dicts
    added_endpoints_list = [{"method": m, "path": p} for m, p in sorted(added_endpoints)]
    removed_endpoints_list = [{"method": m, "path": p} for m, p in sorted(removed_endpoints)]
    
    # Build result
    result = {
        "old_version": old_label,
        "new_version": new_label,
        "changed": len(added_functions) > 0 or len(removed_functions) > 0 or len(added_endpoints) > 0 or len(removed_endpoints) > 0,
        "summary": {
            "total_functions_added": len(added_functions),
            "total_functions_removed": len(removed_functions),
            "total_functions_unchanged": len(unchanged_functions),
            "total_endpoints_added": len(added_endpoints),
            "total_endpoints_removed": len(removed_endpoints),
            "showing_up_to": max_changes
        },
        "functions": {
            "added": added_details,
            "removed": removed_details,
            "truncated": len(added_functions) > max_changes or len(removed_functions) > max_changes
        },
        "endpoints": {
            "added": added_endpoints_list,
            "removed": removed_endpoints_list
        }
    }
    
    return result


def main():
    args = parse_args()
    
    if args.debug:
        print("="*70)
        print("  Code Index Comparison")
        print("="*70)
        print()
    
    # Load found indexes
    with open(args.found_indexes, 'r') as f:
        found_indexes = json.load(f)
    
    triggering_repo = found_indexes.get('triggering_repo', 'unknown')
    indexes_info = found_indexes.get('indexes', {})
    
    results = {}
    
    # Compare dashboard (RC vs deployed)
    if triggering_repo in indexes_info:
        dashboard_info = indexes_info[triggering_repo]
        
        rc_info = dashboard_info.get('rc', {})
        deployed_info = dashboard_info.get('deployed', {})
        
        if rc_info.get('found') and deployed_info.get('found'):
            if args.debug:
                print(f"📊 Comparing {triggering_repo}...")
                print(f"   Deployed: {deployed_info.get('version')}")
                print(f"   RC: {rc_info.get('version')}")
            
            deployed_index = load_code_index(deployed_info.get('index_path'))
            rc_index = load_code_index(rc_info.get('index_path'))
            
            diff = compare_indexes(
                deployed_index,
                rc_index,
                deployed_info.get('version', 'deployed'),
                rc_info.get('version', 'rc'),
                args.max_changes
            )
            
            diff['rc_commit'] = rc_info.get('version', '')
            results[triggering_repo] = diff
            
            if args.debug:
                print(f"   ✅ Changes: {diff['summary']['total_functions_added']} added, {diff['summary']['total_functions_removed']} removed")
                print()
        else:
            if args.debug:
                print(f"⏭️  Skipping {triggering_repo} (missing RC or deployed index)")
                print()
    
    # Compare dependencies (deployed vs latest)
    for repo, repo_info in indexes_info.items():
        if repo == triggering_repo:
            continue
        
        # Check if this is a dependency (has deployed_version and latest_index_path)
        deployed_version = repo_info.get('deployed_version')
        deployed_path = repo_info.get('deployed_index_path')
        latest_path = repo_info.get('latest_index_path')
        
        if deployed_path and latest_path:
            if args.debug:
                print(f"📊 Comparing {repo}...")
                print(f"   Deployed: {deployed_version}")
                print(f"   Latest: main")
            
            deployed_index = load_code_index(deployed_path)
            latest_index = load_code_index(latest_path)
            
            diff = compare_indexes(
                deployed_index,
                latest_index,
                deployed_version or 'deployed',
                'latest',
                args.max_changes
            )
            
            diff['deployed_version'] = deployed_version
            diff['latest_version'] = 'latest'
            results[repo] = diff
            
            if args.debug:
                print(f"   ✅ Changes: {diff['summary']['total_functions_added']} added, {diff['summary']['total_functions_removed']} removed")
                print()
        else:
            if args.debug:
                print(f"⏭️  Skipping {repo} (missing indexes)")
                print()
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    total_repos = len(results)
    changed_repos = sum(1 for r in results.values() if r.get('changed'))
    
    print(f"✅ Comparison complete")
    print(f"   Repos compared: {total_repos}")
    print(f"   Repos with changes: {changed_repos}")
    print(f"   Output: {args.output}")
    
    if args.debug:
        print()
        print("📋 Change Summary:")
        for repo, diff in results.items():
            if diff.get('changed'):
                added = diff['summary']['total_functions_added']
                removed = diff['summary']['total_functions_removed']
                endpoints = diff['summary']['total_endpoints_added'] + diff['summary']['total_endpoints_removed']
                print(f"  📦 {repo}: +{added} -{removed} functions, {endpoints} endpoint changes")


if __name__ == '__main__':
    main()


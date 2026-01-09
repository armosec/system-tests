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
import subprocess
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
    # Note: "changed" means either code changes OR version changes (dependencies can have new versions without code changes)
    has_code_changes = len(added_functions) > 0 or len(removed_functions) > 0 or len(added_endpoints) > 0 or len(removed_endpoints) > 0
    has_version_change = old_label != new_label and old_label != "unknown" and new_label != "unknown"
    result = {
        "old_version": old_label,
        "new_version": new_label,
        "changed": has_code_changes or has_version_change,
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


def get_git_compare(org: str, repo: str, base: str, head: str, max_changes: int = 100, debug: bool = False) -> Dict[str, Any]:
    """
    Fetch git compare info (including file patches) using GitHub's compare API via gh CLI.
    Returns a stable structure compatible with generate_github_summary.py expectations.
    """
    git_diff: Dict[str, Any] = {
        "deployed_commit": base or "",
        "rc_commit": head or "",
        "total_commits": 0,
        "files": []
    }

    if not org or not repo or not base or not head or base == head:
        return git_diff

    endpoint = f"repos/{org}/{repo}/compare/{base}...{head}"
    cmd = ["gh", "api", endpoint]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            if debug:
                print(f"⚠️  gh api compare failed for {org}/{repo}: {proc.stderr.strip()}", file=sys.stderr)
            return git_diff

        data = json.loads(proc.stdout or "{}")
        commits = data.get("commits") or []
        files = data.get("files") or []

        git_diff["total_commits"] = len(commits)
        git_diff["files"] = [
            {
                "filename": f.get("filename", ""),
                "status": f.get("status", ""),
                "additions": f.get("additions", 0),
                "deletions": f.get("deletions", 0),
                "changes": f.get("changes", 0),
                "patch": f.get("patch", ""),
            }
            for f in files[:max_changes]
            if isinstance(f, dict)
        ]
        return git_diff
    except Exception as e:
        if debug:
            print(f"⚠️  Failed to parse git compare for {org}/{repo}: {e}", file=sys.stderr)
        return git_diff


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
            
            # Store commits (not versions) for git diff URLs
            diff['rc_commit'] = rc_info.get('commit', '')
            diff['deployed_commit'] = deployed_info.get('commit', '')
            
            # Add git_diff section (includes patches) for compatibility with generate_github_summary.py and LLM context
            org = deployed_info.get("github_org") or rc_info.get("github_org") or "armosec"
            diff['git_diff'] = get_git_compare(
                org=org,
                repo=triggering_repo,
                base=deployed_info.get('commit', '') or "",
                head=rc_info.get('commit', '') or "",
                max_changes=args.max_changes,
                debug=args.debug
            )
            
            results[triggering_repo] = diff
            
            if args.debug:
                print(f"   ✅ Changes: {diff['summary']['total_functions_added']} added, {diff['summary']['total_functions_removed']} removed")
                print()
        else:
            if args.debug:
                print(f"⏭️  Skipping {triggering_repo} (missing RC or deployed index)")
                print()
    
    # Compare dependencies
    #
    # Current found-indexes schema (preferred):
    #   indexes.<repo>.deployed.index_path + indexes.<repo>.rc.index_path
    #
    # Legacy schema (fallback):
    #   deployed_index_path + latest_index_path
    for repo, repo_info in indexes_info.items():
        if repo == triggering_repo:
            continue

        deployed_info = repo_info.get("deployed") if isinstance(repo_info, dict) else {}
        rc_info = repo_info.get("rc") if isinstance(repo_info, dict) else {}

        # Preferred path: deployed vs rc (matches go.mod analysis versions when available)
        if isinstance(deployed_info, dict) and isinstance(rc_info, dict) and deployed_info.get("found") and rc_info.get("found"):
            if args.debug:
                print(f"📊 Comparing {repo}...")
                print(f"   Deployed: {deployed_info.get('version')}")
                print(f"   RC: {rc_info.get('version')}")

            deployed_index = load_code_index(deployed_info.get("index_path"))
            rc_index = load_code_index(rc_info.get("index_path"))

            diff = compare_indexes(
                deployed_index,
                rc_index,
                deployed_info.get("version", "deployed"),
                rc_info.get("version", "rc"),
                args.max_changes
            )

            diff["deployed_commit"] = deployed_info.get("commit", "") or ""
            diff["rc_commit"] = rc_info.get("commit", "") or ""

            org = deployed_info.get("github_org") or rc_info.get("github_org") or "armosec"
            diff["git_diff"] = get_git_compare(
                org=org,
                repo=repo,
                base=diff["deployed_commit"],
                head=diff["rc_commit"],
                max_changes=args.max_changes,
                debug=args.debug
            )

            results[repo] = diff

            if args.debug:
                print(f"   ✅ Changes: {diff['summary']['total_functions_added']} added, {diff['summary']['total_functions_removed']} removed")
                print()
            continue

        # Legacy fallback: deployed vs latest (old schema)
        deployed_version = repo_info.get('deployed_version') if isinstance(repo_info, dict) else None
        deployed_path = repo_info.get('deployed_index_path') if isinstance(repo_info, dict) else None
        latest_path = repo_info.get('latest_index_path') if isinstance(repo_info, dict) else None

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


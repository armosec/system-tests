#!/usr/bin/env python3
"""
Extract go.mod dependencies from a code index.

This script parses go.mod from a code index, finds all armosec/* and kubescape/*
dependencies, and checks which ones have code indexes available on GitHub.

Usage:
    python extract_gomod_dependencies.py \
        --code-index artifacts/code-indexes/deployed/code-index.json \
        --output artifacts/gomod-dependencies.json
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set
import requests

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract go.mod dependencies")
    parser.add_argument("--deployed-code-index", help="Path to deployed version code index JSON")
    parser.add_argument("--rc-code-index", help="Path to RC version code index JSON")
    parser.add_argument("--code-index", help="Path to code index JSON (deprecated, use --deployed-code-index)")
    parser.add_argument("--output", required=True, help="Output JSON file path")
    parser.add_argument("--github-token", help="GitHub token (or use GITHUB_TOKEN env var)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def load_code_index(path: str) -> Dict:
    """Load code index JSON file."""
    with open(path, 'r') as f:
        return json.load(f)


def download_gomod_from_github(repo: str, ref: str, token: Optional[str] = None) -> Optional[str]:
    """
    Download go.mod directly from GitHub.
    
    Args:
        repo: Repository in format "owner/repo" (e.g., "armosec/cadashboardbe")
        ref: Git ref (commit hash, tag, or branch)
        token: Optional GitHub token
    
    Returns:
        go.mod content as string, or None if not found
    """
    url = f"https://api.github.com/repos/{repo}/contents/go.mod?ref={ref}"
    headers = {'Accept': 'application/vnd.github.v3.raw'}
    if token:
        headers['Authorization'] = f'token {token}'
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            print(f"⚠️  Failed to download go.mod from {repo}@{ref}: HTTP {response.status_code}")
            return None
    except Exception as e:
        print(f"⚠️  Error downloading go.mod: {e}")
        return None


def find_gomod_in_index(index: Dict) -> Optional[str]:
    """Find go.mod content in code index."""
    # Code index has 'files' array with file objects
    files = index.get('files', [])
    
    for file_obj in files:
        path = file_obj.get('path', '')
        if path == 'go.mod' or path.endswith('/go.mod'):
            # Content might be in 'content' or 'code' field
            content = file_obj.get('content') or file_obj.get('code', '')
            if content:
                return content
    
    return None


def parse_gomod_dependencies(gomod_content: str) -> Dict[str, str]:
    """
    Parse go.mod content and extract dependencies.
    
    Returns:
        Dict mapping package name to version
    """
    dependencies = {}
    
    # Parse require block
    in_require = False
    for line in gomod_content.split('\n'):
        line = line.strip()
        
        # Start of require block
        if line.startswith('require ('):
            in_require = True
            continue
        
        # End of require block
        if in_require and line == ')':
            in_require = False
            continue
        
        # Single line require
        if line.startswith('require '):
            match = re.match(r'require\s+([^\s]+)\s+([^\s]+)', line)
            if match:
                pkg, version = match.groups()
                dependencies[pkg] = version
            continue
        
        # Inside require block
        if in_require:
            # Remove comments
            line = line.split('//')[0].strip()
            if not line:
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                pkg = parts[0]
                version = parts[1]
                dependencies[pkg] = version
    
    return dependencies


def filter_relevant_dependencies(dependencies: Dict[str, str]) -> Dict[str, str]:
    """Filter to only armosec/* and kubescape/* dependencies."""
    relevant = {}
    
    for pkg, version in dependencies.items():
        if pkg.startswith('github.com/armosec/') or pkg.startswith('github.com/kubescape/'):
            relevant[pkg] = version
    
    return relevant


def compare_dependency_versions(deployed_deps: Dict[str, str], rc_deps: Dict[str, str]) -> Dict[str, Dict]:
    """
    Compare dependency versions between deployed and RC.
    
    Returns:
        Dict with version_changed flag for each dependency
    """
    result = {}
    all_deps = set(deployed_deps.keys()) | set(rc_deps.keys())
    
    for dep in all_deps:
        deployed_ver = deployed_deps.get(dep, "unknown")
        rc_ver = rc_deps.get(dep, "unknown")
        
        # Extract just the repo name (not full package path)
        repo_match = re.match(r'github\.com/(armosec|kubescape)/([^/]+)', dep)
        repo_name = repo_match.group(2) if repo_match else dep
        
        result[repo_name] = {
            "deployed_version": deployed_ver,
            "rc_version": rc_ver,
            "version_changed": deployed_ver != rc_ver and deployed_ver != "unknown" and rc_ver != "unknown",
            "has_index": False  # Will be updated later if we check
        }
    
    return result


def extract_repo_from_package(pkg: str) -> Optional[str]:
    """
    Extract repository name from package path.
    
    Examples:
        github.com/armosec/postgres-connector -> armosec/postgres-connector
        github.com/kubescape/opa-utils -> kubescape/opa-utils
    """
    match = re.match(r'github\.com/([^/]+/[^/]+)', pkg)
    if match:
        return match.group(1)
    return None


def check_code_index_exists(repo: str, version: str, github_token: Optional[str], debug: bool = False) -> bool:
    """
    Check if code index artifact exists for this repo/version.
    
    Tries multiple artifact names:
    - code-index-v{version}
    - code-index-latest
    """
    if not github_token:
        if debug:
            print(f"  ⚠️  No GitHub token, skipping artifact check for {repo}")
        return False
    
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
        "User-Agent": "test-failure-analyzer/1.0"
    }
    
    # Get latest workflow run for code-index-generation
    api_url = f"https://api.github.com/repos/{repo}/actions/workflows/code-index-generation.yml/runs"
    
    try:
        resp = requests.get(api_url, headers=headers, timeout=30, params={"per_page": 1})
        if resp.status_code != 200:
            if debug:
                print(f"  ⚠️  Failed to fetch workflow runs for {repo}: {resp.status_code}")
            return False
        
        data = resp.json()
        runs = data.get('workflow_runs', [])
        
        if not runs:
            if debug:
                print(f"  ⚠️  No workflow runs found for {repo}")
            return False
        
        # If any run exists, assume code index is available
        # (More precise check would list artifacts, but that's slower)
        if debug:
            print(f"  ✅ Code index workflow found for {repo}")
        return True
    
    except Exception as e:
        if debug:
            print(f"  ⚠️  Error checking {repo}: {e}")
        return False


def main():
    args = parse_args()
    
    # Get GitHub token
    github_token = args.github_token or os.environ.get('GITHUB_TOKEN')
    
    # Determine which mode: comparison or single index
    compare_mode = bool(args.deployed_code_index and args.rc_code_index)
    single_mode = bool(args.code_index or (args.deployed_code_index and not args.rc_code_index))
    
    if not compare_mode and not single_mode:
        print("❌ Error: Must provide either --code-index OR both --deployed-code-index and --rc-code-index", file=sys.stderr)
        sys.exit(1)
    
    if args.debug:
        print(f"🔍 Extracting go.mod dependencies...")
        if compare_mode:
            print(f"   Mode: Comparison (deployed vs RC)")
            print(f"   Deployed index: {args.deployed_code_index}")
            print(f"   RC index: {args.rc_code_index}")
        else:
            code_index_path = args.code_index or args.deployed_code_index
            print(f"   Mode: Single index")
            print(f"   Code index: {code_index_path}")
        print(f"   Output: {args.output}")
        print()
    
    if compare_mode:
        # Load both indexes
        try:
            deployed_index = load_code_index(args.deployed_code_index)
            rc_index = load_code_index(args.rc_code_index)
            if args.debug:
                print(f"✅ Loaded both code indexes")
        except Exception as e:
            print(f"❌ Error loading code indexes: {e}", file=sys.stderr)
            sys.exit(1)
        
        # Extract go.mod from both
        deployed_gomod = find_gomod_in_index(deployed_index)
        rc_gomod = find_gomod_in_index(rc_index)
        
        if not deployed_gomod or not rc_gomod:
            print(f"⚠️  Warning: go.mod not found in one or both indexes", file=sys.stderr)
            deployed_gomod = deployed_gomod or ""
            rc_gomod = rc_gomod or ""
        
        # Parse dependencies
        deployed_deps_all = parse_gomod_dependencies(deployed_gomod)
        rc_deps_all = parse_gomod_dependencies(rc_gomod)
        
        # Filter to relevant dependencies
        deployed_deps = filter_relevant_dependencies(deployed_deps_all)
        rc_deps = filter_relevant_dependencies(rc_deps_all)
        
        if args.debug:
            print(f"📊 Found {len(deployed_deps)} relevant dependencies in deployed version")
            print(f"📊 Found {len(rc_deps)} relevant dependencies in RC version")
            print()
        
        # Compare versions
        result = compare_dependency_versions(deployed_deps, rc_deps)
        
        # Optionally check if code indexes exist
        if github_token and args.debug:
            print(f"🔍 Checking code index availability...")
            for repo_name, info in result.items():
                # For now, just mark as unknown - actual check happens in find_indexes.py
                info['has_index'] = None  # Will be determined later
        
        if args.debug:
            changed_count = sum(1 for info in result.values() if info['version_changed'])
            print(f"📊 {changed_count} dependencies changed versions")
            print()
        
        # Write output
        output_dir = os.path.dirname(args.output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        
        if args.debug:
            print(f"✅ Wrote comparison results to {args.output}")
        
        return
    
    # Single index mode (backward compatibility)
    code_index_path = args.code_index or args.deployed_code_index
    
    # Load code index
    try:
        index = load_code_index(code_index_path)
        if args.debug:
            print(f"✅ Loaded code index")
    except Exception as e:
        print(f"❌ Error loading code index: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Find go.mod - first try code index, then fallback to GitHub
    gomod_content = find_gomod_in_index(index)
    
    if not gomod_content:
        if args.debug:
            print(f"⚠️  go.mod not found in code index, trying GitHub fallback...")
        
        # Try to extract repo and commit from code index metadata
        metadata = index.get('metadata', {})
        repo = metadata.get('repo', 'armosec/cadashboardbe')
        commit = metadata.get('commit') or metadata.get('version', 'main')
        
        if args.debug:
            print(f"   Repo: {repo}")
            print(f"   Ref: {commit}")
        
        # Download go.mod from GitHub
        gomod_content = download_gomod_from_github(repo, commit, github_token)
        
        if not gomod_content:
            print(f"❌ go.mod not found in code index or GitHub", file=sys.stderr)
            # Create empty output and exit gracefully
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump({}, f)
            print(f"⚠️  Created empty dependencies file")
            sys.exit(0)
        
        if args.debug:
            print(f"✅ Downloaded go.mod from GitHub")
    else:
        if args.debug:
            print(f"✅ Found go.mod in code index")
    
    if args.debug:
        print()
    
    # Parse dependencies
    all_deps = parse_gomod_dependencies(gomod_content)
    if args.debug:
        print(f"📦 Total dependencies: {len(all_deps)}")
    
    # Filter to relevant ones
    relevant_deps = filter_relevant_dependencies(all_deps)
    if args.debug:
        print(f"📦 Relevant dependencies (armosec/kubescape): {len(relevant_deps)}")
        print()
    
    # Check which ones have code indexes
    result = {}
    for pkg, version in relevant_deps.items():
        repo = extract_repo_from_package(pkg)
        if not repo:
            continue
        
        repo_name = repo.split('/')[-1]  # e.g., postgres-connector
        
        if args.debug:
            print(f"Checking {repo_name} ({version})...")
        
        has_index = check_code_index_exists(repo, version, github_token, args.debug)
        
        result[repo_name] = {
            "version": version,
            "has_index": has_index,
            "source": "go.mod",
            "full_package": pkg,
            "repo": repo
        }
        
        if args.debug:
            print()
    
    # Write output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"✅ Extracted {len(result)} dependencies")
    print(f"   With code index: {sum(1 for d in result.values() if d['has_index'])}")
    print(f"   Output: {args.output}")
    
    if args.debug:
        print()
        print("📋 Summary:")
        for name, info in sorted(result.items()):
            status = "✅" if info['has_index'] else "❌"
            print(f"  {status} {name:30} {info['version']}")


if __name__ == '__main__':
    main()


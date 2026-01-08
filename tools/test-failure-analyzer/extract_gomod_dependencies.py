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
    parser.add_argument("--triggering-repo", help="Name of triggering repo to exclude from dependencies (e.g., cadashboardbe)")
    parser.add_argument("--deployed-version", help="Deployed version tag (e.g., v0.0.223) - used to fetch correct go.mod instead of PR commit")
    parser.add_argument("--rc-version", help="RC version tag (e.g., rc-v0.0.224-2435) - used to fetch correct RC go.mod instead of code index commit")
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
    # Check metadata first (new format)
    metadata = index.get('metadata', {})
    gomod_content = metadata.get('goModContent') or metadata.get('go_mod_content')
    if gomod_content:
        return gomod_content
    
    # Fallback: check 'files' array (old format - may not exist in current indexes)
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


def filter_relevant_dependencies(dependencies: Dict[str, str], triggering_repo: Optional[str] = None, debug: bool = False) -> Dict[str, str]:
    """
    Filter to only armosec/* and kubescape/* dependencies, excluding triggering repo.
    
    Args:
        dependencies: Dict mapping package name to version
        triggering_repo: Name of triggering repo to exclude (e.g., "cadashboardbe")
        debug: Enable debug logging
    
    Returns:
        Filtered dependencies dict
    """
    relevant = {}
    excluded_count = 0
    
    for pkg, version in dependencies.items():
        if pkg.startswith('github.com/armosec/') or pkg.startswith('github.com/kubescape/'):
            # Extract repo name to check if it's the triggering repo
            repo_match = re.match(r'github\.com/(armosec|kubescape)/([^/]+)', pkg)
            if repo_match:
                repo_name = repo_match.group(2)
                # Skip if this is the triggering repo (case-insensitive match)
                if triggering_repo and repo_name.lower() == triggering_repo.lower():
                    if debug:
                        print(f"🚫 Excluding triggering repo '{repo_name}' (matches '{triggering_repo}') from dependencies")
                    excluded_count += 1
                    continue
            # Only add if we didn't skip it
            relevant[pkg] = version
    
    if debug and excluded_count > 0:
        print(f"📊 Excluded {excluded_count} dependency(ies) matching triggering repo '{triggering_repo}'")
    
    return relevant


def extract_base_version(version: str) -> str:
    """
    Extract base version from pseudo-version or regular version.
    
    Examples:
        v0.0.1182-0.20251225061625-832fbea140cc -> v0.0.1182
        v0.0.1182 -> v0.0.1182
        v1.2.3-0.20240101120000-abc123 -> v1.2.3
    """
    if not version or version == "unknown":
        return "unknown"
    
    # Pseudo-version format: v0.0.1182-0.20251225061625-832fbea140cc
    # Extract base version before the first dash after version number
    match = re.match(r'^(v\d+\.\d+\.\d+)(?:-|$)', version)
    if match:
        return match.group(1)
    
    # If no match, return as-is (might be a commit hash or other format)
    return version


def compare_dependency_versions(deployed_deps: Dict[str, str], rc_deps: Dict[str, str]) -> Dict[str, Dict]:
    """
    Compare dependency versions between deployed and RC.
    
    Returns:
        Dict with version_changed flag for each dependency
    """
    result = {}
    all_deps = set(deployed_deps.keys()) | set(rc_deps.keys())
    
    for dep in all_deps:
        deployed_ver_raw = deployed_deps.get(dep, "unknown")
        rc_ver_raw = rc_deps.get(dep, "unknown")
        
        # Use EXACT versions from go.mod (don't extract base versions)
        # The versions shown should match exactly what's in go.mod
        deployed_ver = deployed_ver_raw
        rc_ver = rc_ver_raw
        
        # Extract base versions ONLY for comparison (to detect version changes)
        # Pseudo-versions like v0.0.1182-0.20251225061625-832fbea140cc should be compared
        # against base version v0.0.1182 to detect if they're the same base version
        deployed_base = extract_base_version(deployed_ver_raw)
        rc_base = extract_base_version(rc_ver_raw)
        
        # Extract org and repo name
        repo_match = re.match(r'github\.com/(armosec|kubescape)/([^/]+)', dep)
        github_org = repo_match.group(1) if repo_match else "armosec"
        repo_name = repo_match.group(2) if repo_match else dep
        
        # Version changed if base versions differ (pseudo-version vs tag of same base = not changed)
        version_changed = deployed_base != rc_base and deployed_base != "unknown" and rc_base != "unknown"
        
        result[repo_name] = {
            "deployed_version": deployed_ver,  # Exact version from go.mod
            "rc_version": rc_ver,  # Exact version from go.mod (may include pseudo-version)
            "version_changed": version_changed,
            "github_org": github_org,
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
        
        # Extract go.mod from both - prefer GitHub download (actual repo file) over code index content
        # Code index go.mod might have pseudo-versions if index was generated from commit after tag
        deployed_gomod = None
        rc_gomod = None
        
        # Try to download from GitHub first (more accurate - actual repo file)
        deployed_metadata = deployed_index.get('metadata', {})
        rc_metadata = rc_index.get('metadata', {})
        
        deployed_repo = deployed_metadata.get('repo', 'armosec/cadashboardbe')
        deployed_commit = deployed_metadata.get('commit') or deployed_metadata.get('version', 'main')
        rc_repo = rc_metadata.get('repo', 'armosec/cadashboardbe')
        rc_commit = rc_metadata.get('commit') or rc_metadata.get('version', 'main')
        
        if args.debug:
            print(f"📥 Attempting to download go.mod from GitHub...")
            print(f"   Deployed: {deployed_repo}@{deployed_commit}")
            print(f"   RC: {rc_repo}@{rc_commit}")
        
        # Download deployed go.mod from GitHub
        # IMPORTANT: Use deployed version tag if provided, not commit from code index
        # This ensures we get the actual deployed go.mod, not from a PR commit
        deployed_ref = args.deployed_version or deployed_commit
        if args.deployed_version and args.debug:
            print(f"📌 Using deployed version tag for go.mod: {args.deployed_version} (instead of commit {deployed_commit})")
        
        deployed_gomod = download_gomod_from_github(deployed_repo, deployed_ref, github_token)
        if deployed_gomod:
            if args.debug:
                print(f"✅ Downloaded deployed go.mod from GitHub")
        else:
            print(f"⚠️  Failed to download deployed go.mod from GitHub (tag '{deployed_ref}' may not exist)")
            print(f"   Will fall back to code index go.mod (may not reflect deployed baseline)")
        
        # Download RC go.mod from GitHub
        # IMPORTANT: Prefer RC tag if available; the RC index may fall back to code-index-latest,
        # which can point to a non-RC commit and cause false "version_changed" for many deps.
        rc_ref = rc_commit
        if args.rc_version and args.rc_version not in ("unknown", "null", ""):
            rc_ref = args.rc_version
            if args.debug:
                print(f"📌 Using RC version tag for go.mod: {args.rc_version} (instead of commit {rc_commit})")
        rc_gomod = download_gomod_from_github(rc_repo, rc_ref, github_token)
        if rc_gomod and args.debug:
            print(f"✅ Downloaded RC go.mod from GitHub")
        
        # Fallback to code index go.mod if GitHub download failed
        if not deployed_gomod:
            deployed_gomod = find_gomod_in_index(deployed_index)
            if deployed_gomod and args.debug:
                print(f"⚠️  Using deployed go.mod from code index (GitHub download failed)")
        
        if not rc_gomod:
            rc_gomod = find_gomod_in_index(rc_index)
            if rc_gomod and args.debug:
                print(f"⚠️  Using RC go.mod from code index (GitHub download failed)")
        
        if not deployed_gomod or not rc_gomod:
            print(f"⚠️  Warning: go.mod not found in one or both indexes", file=sys.stderr)
            deployed_gomod = deployed_gomod or ""
            rc_gomod = rc_gomod or ""
        
        # Parse dependencies
        deployed_deps_all = parse_gomod_dependencies(deployed_gomod)
        rc_deps_all = parse_gomod_dependencies(rc_gomod)
        
        # Filter to relevant dependencies (excluding triggering repo)
        deployed_deps = filter_relevant_dependencies(deployed_deps_all, args.triggering_repo, args.debug)
        rc_deps = filter_relevant_dependencies(rc_deps_all, args.triggering_repo, args.debug)
        
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
    
    # Find go.mod.
    #
    # IMPORTANT:
    # When snapshotting the *deployed* baseline, we want the go.mod that matches the deployed TAG,
    # not whatever commit the code index was generated from (often RC commit).
    # So if --deployed-version is provided, prefer downloading go.mod from GitHub by that ref
    # even if go.mod is present inside the code index.
    gomod_content = None
    metadata = index.get('metadata', {})
    repo = metadata.get('repo', 'armosec/cadashboardbe')
    commit = metadata.get('commit') or metadata.get('version', 'main')
    if args.deployed_version and github_token:
        if args.debug:
            print(f"📥 Attempting to download go.mod baseline from GitHub by deployed tag: {repo}@{args.deployed_version}")
        gomod_content = download_gomod_from_github(repo, args.deployed_version, github_token)
        if gomod_content and args.debug:
            print("✅ Downloaded go.mod from GitHub (deployed baseline)")
    if not gomod_content:
        gomod_content = find_gomod_in_index(index)
    
    if not gomod_content:
        if args.debug:
            print(f"⚠️  go.mod not found in code index, trying GitHub fallback...")
        
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
    
    # Filter to relevant ones (excluding triggering repo)
    relevant_deps = filter_relevant_dependencies(all_deps, args.triggering_repo, args.debug)
    if args.debug:
        print(f"📦 Relevant dependencies (armosec/kubescape): {len(relevant_deps)}")
        print()
    
    # NOTE:
    # In single-index mode this script is used for snapshotting go.mod (baseline/RC) and for display.
    # Code-index availability is resolved later by find_indexes.py (which checks actual artifacts).
    # Probing GitHub workflow runs here is redundant and can be slow/noisy (404s are common).
    result = {}
    for pkg, version in relevant_deps.items():
        repo = extract_repo_from_package(pkg)
        if not repo:
            continue
        
        repo_name = repo.split('/')[-1]  # e.g., postgres-connector
        
        if args.debug:
            print(f"Found dependency {repo_name} ({version})")

        result[repo_name] = {
            "version": version,
            "has_index": None,  # resolved later by find_indexes.py
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
    print(f"   Output: {args.output}")
    
    if args.debug:
        print()
        print("📋 Summary:")
        for name, info in sorted(result.items()):
            print(f"  - {name:30} {info['version']}")


if __name__ == '__main__':
    main()


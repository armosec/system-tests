#!/usr/bin/env python3
"""
Find and download code indexes from GitHub artifacts.

Supports multiple resolution strategies:
1. PR-based resolution (for RC versions like rc-v0.0.224-2435)
2. Version tag resolution (code-index-v0.0.223)
3. Commit hash resolution (code-index-abc123...)
4. Latest fallback (code-index-latest)

Usage:
    python find_indexes.py \
      --triggering-repo cadashboardbe \
      --triggering-commit abc123... \
      --rc-version rc-v0.0.224-2435 \
      --deployed-version v0.0.223 \
      --gomod-dependencies artifacts/gomod-dependencies.json \
      --output artifacts/found-indexes.json
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import requests

# Cache artifact listings per (org, repo) to reduce API calls and rate-limit pressure.
# Key: (github_org, repo) -> dict(name -> artifact_json)
_ARTIFACTS_CACHE: Dict[Tuple[str, str], Dict[str, Any]] = {}

# Always include these repositories (fallback for critical dependencies)
ALWAYS_INCLUDE_REPOS = [
    ('armosec', 'armosec-infra'),      # Always needed for notifications, utils
    ('armosec', 'postgres-connector'),  # Database layer
]

GITHUB_ORGS_TO_CHECK = ['armosec', 'kubescape']  # Check both orgs (fallback only)

# Default list of repos to fetch code indexes for (most commonly used)
# This reduces time by not fetching indexes for rarely-used dependencies
# Note: Repos in ALWAYS_INCLUDE_REPOS will be fetched regardless of this list
DEFAULT_REPOS_TO_FETCH = [
    'armosec-infra',           # Already in ALWAYS_INCLUDE, but explicit here for clarity
    'postgres-connector',      # Already in ALWAYS_INCLUDE, but explicit here for clarity
    'event-ingester-service',  # Frequently used in test failures
    'config-service',          # Frequently used in test failures
    'users-notification-service',  # Frequently used in test failures
    'messaging',               # Infrastructure dependency (also in detect_dependencies.py ALWAYS_INCLUDE)
]

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Find and download code indexes")
    
    # Dashboard (triggering repo) arguments
    parser.add_argument("--triggering-repo", required=True, help="Name of triggering repository (e.g., cadashboardbe)")
    parser.add_argument("--dashboard-repo", default="cadashboardbe", help="Name of dashboard repository for API mapping")
    parser.add_argument("--triggering-commit", help="Workflow commit SHA")
    parser.add_argument("--rc-version", help="RC version tag (e.g., rc-v0.0.224-2435)")
    parser.add_argument("--deployed-version", help="Deployed version (e.g., v0.0.223)")
    
    # Dependencies
    parser.add_argument("--gomod-dependencies", help="Path to gomod-dependencies.json")
    parser.add_argument("--default-repos", help="Comma-separated list of repos to fetch (defaults to built-in list)")
    
    # Output
    parser.add_argument("--output", required=True, help="Output JSON file path")
    parser.add_argument("--output-dir", default="artifacts/code-indexes", help="Directory to download indexes to")
    
    # GitHub config
    parser.add_argument("--github-token", help="GitHub token (or use GITHUB_TOKEN env var)")
    parser.add_argument("--github-orgs", default="armosec,kubescape", help="Comma-separated GitHub organizations to check")
    
    # Options
    parser.add_argument("--images", help="Path to test-deployed-services.json or running-images.json (for triggering repo)")
    parser.add_argument("--services-only", help="Path to services-only.json (filtered services, excludes triggering repo)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    return parser.parse_args()


def extract_pr_from_rc(rc_version: str) -> Optional[int]:
    """
    Extract PR number from RC version.
    
    NOTE: RC versions can have either PR numbers or workflow run IDs as suffix.
    - PR numbers are typically < 10,000,000
    - Workflow run IDs are typically >= 10,000,000 (10+ digits)
    
    Examples:
        rc-v0.0.224-2435 -> 2435 (PR number)
        rc-v1.2.3-999 -> 999 (PR number)
        rc-v0.0.394-20549238574 -> None (workflow run ID, not a PR)
    """
    match = re.match(r'rc-v\d+\.\d+\.\d+-(\d+)', rc_version)
    if match:
        number = int(match.group(1))
        # Workflow run IDs are typically 10+ digits (>= 10,000,000,000)
        # PR numbers are typically smaller. Use 10,000,000 as threshold.
        if number >= 10000000:
            # Likely a workflow run ID, not a PR number
            return None
        return number
    return None


def get_pr_head_commit(repo: str, pr_number: int, github_token: str, github_org: str, debug: bool = False) -> Optional[str]:
    """Get PR head commit SHA from GitHub API."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
        "User-Agent": "test-failure-analyzer/1.0"
    }
    
    api_url = f"https://api.github.com/repos/{github_org}/{repo}/pulls/{pr_number}"
    
    if debug:
        print(f"  📡 Fetching PR #{pr_number} metadata from GitHub...")
    
    try:
        resp = requests.get(api_url, headers=headers, timeout=30)
        if resp.status_code != 200:
            if debug:
                print(f"  ❌ Failed to fetch PR: {resp.status_code}")
            return None
        
        data = resp.json()
        commit = data.get('head', {}).get('sha')
        
        if debug and commit:
            print(f"  ✅ PR head commit: {commit[:8]}")
        
        return commit
    
    except Exception as e:
        if debug:
            print(f"  ❌ Error fetching PR: {e}")
        return None


def download_artifact(repo: str, artifact_name: str, output_dir: str, github_token: str, github_org: str, debug: bool = False) -> Optional[str]:
    """
    Download artifact from GitHub Actions.
    
    Returns:
        Path to downloaded index file, or None if not found
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
        "User-Agent": "test-failure-analyzer/1.0"
    }
    
    if debug:
        print(f"  📡 Searching for artifact: {artifact_name}")
    
    try:
        cache_key = (github_org, repo)
        repo_cache = _ARTIFACTS_CACHE.get(cache_key)
        if repo_cache is None:
            # List artifacts once per repo/org and cache
            api_url = f"https://api.github.com/repos/{github_org}/{repo}/actions/artifacts"
            resp = requests.get(api_url, headers=headers, params={"per_page": 100}, timeout=30)
            if resp.status_code != 200:
                if debug:
                    print(f"  ❌ Failed to list artifacts: {resp.status_code}")
                return None
            data = resp.json()
            artifacts = data.get('artifacts', []) or []
            repo_cache = {a.get('name'): a for a in artifacts if isinstance(a, dict) and a.get('name')}
            _ARTIFACTS_CACHE[cache_key] = repo_cache
            if debug:
                print(f"  📦 Cached {len(repo_cache)} artifacts for {github_org}/{repo}")

        artifact = repo_cache.get(artifact_name) if repo_cache else None
        if not artifact:
            if debug:
                print(f"  ❌ Artifact not found: {artifact_name}")
            return None

        artifact_id = artifact.get('id')
        
        if debug:
            print(f"  ✅ Found artifact (ID: {artifact_id})")
            print(f"  📥 Downloading...")
        
        # Download artifact
        download_url = f"https://api.github.com/repos/{github_org}/{repo}/actions/artifacts/{artifact_id}/zip"
        download_resp = requests.get(download_url, headers=headers, timeout=120, allow_redirects=True)
        
        if download_resp.status_code != 200:
            if debug:
                print(f"  ❌ Download failed: {download_resp.status_code}")
            return None
        
        # Save ZIP
        os.makedirs(output_dir, exist_ok=True)
        zip_path = Path(output_dir) / f"{artifact_name}.zip"
        
        with open(zip_path, 'wb') as f:
            f.write(download_resp.content)
        
        # Extract ZIP
        import zipfile
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(output_dir)
        
        # Find the code-index.json file
        index_path = Path(output_dir) / "docs" / "indexes" / "code-index.json"
        if not index_path.exists():
            # Try alternate location
            index_path = Path(output_dir) / "code-index.json"
        
        if not index_path.exists():
            if debug:
                print(f"  ❌ code-index.json not found in artifact")
            return None
        
        if debug:
            size = index_path.stat().st_size / 1024 / 1024
            print(f"  ✅ Downloaded: {index_path} ({size:.1f} MB)")
        
        return str(index_path)
    
    except Exception as e:
        if debug:
            print(f"  ❌ Error downloading artifact: {e}")
        return None


def get_commit_for_tag(repo_full_name: str, tag: str, github_token: str, debug: bool = False) -> Optional[str]:
    """Get commit SHA for a Git tag using GitHub API."""
    try:
        headers = {'Authorization': f'token {github_token}'} if github_token else {}
        url = f"https://api.github.com/repos/{repo_full_name}/git/ref/tags/{tag}"
        
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            # For lightweight tags, object.sha is the commit
            # For annotated tags, we need to follow the tag object
            object_type = data.get('object', {}).get('type')
            sha = data.get('object', {}).get('sha')
            
            if object_type == 'commit':
                if debug:
                    print(f"   📌 Found commit for tag {tag}: {sha[:8]}")
                return sha
            elif object_type == 'tag':
                # Annotated tag - need to dereference
                tag_url = f"https://api.github.com/repos/{repo_full_name}/git/tags/{sha}"
                tag_response = requests.get(tag_url, headers=headers, timeout=10)
                if tag_response.status_code == 200:
                    tag_data = tag_response.json()
                    commit_sha = tag_data.get('object', {}).get('sha')
                    if debug:
                        print(f"   📌 Found commit for annotated tag {tag}: {commit_sha[:8]}")
                    return commit_sha
        
        if debug:
            print(f"   ⚠️  Could not find commit for tag {tag} (status: {response.status_code})")
        return None
    except Exception as e:
        if debug:
            print(f"   ⚠️  Failed to get commit for tag {tag}: {e}")
        return None


def extract_commit_from_index(index_path: str, debug: bool = False) -> Optional[str]:
    """Extract commit SHA from code index metadata."""
    if not index_path or not os.path.exists(index_path):
        return None
    
    try:
        with open(index_path, 'r') as f:
            index = json.load(f)
        
        # Check metadata for commit/commitHash
        metadata = index.get('metadata', {})
        commit = metadata.get('commit') or metadata.get('commitHash')
        
        if commit and debug:
            print(f"   📌 Extracted commit from index: {commit[:8]}")
        
        return commit
    except Exception as e:
        if debug:
            print(f"   ⚠️  Failed to extract commit: {e}")
        return None


def resolve_rc_index(repo: str, rc_version: str, output_dir: str, github_token: str, github_org: str, triggering_commit: Optional[str] = None, debug: bool = False) -> Tuple[Optional[str], str]:
    """
    Resolve RC code index using multiple strategies.
    
    Args:
        repo: Repository name
        rc_version: RC version tag (e.g., rc-v0.0.224-2435)
        output_dir: Directory to download index to
        github_token: GitHub token
        github_org: GitHub organization
        triggering_commit: Optional commit hash from workflow context
        debug: Enable debug logging
    
    Returns:
        (index_path, strategy_used)
    """
    if debug:
        print(f"\n🔍 Resolving RC index for {repo}...")
        print(f"   RC version: {rc_version}")
        if triggering_commit:
            print(f"   Triggering commit: {triggering_commit}")
    
    # Strategy 1: RC tag artifact (preferred when available)
    # After moving to merge-only + workflow_call generation, we expect code-index-{rc_version} to exist.
    if rc_version:
        if debug:
            print(f"\n📋 Strategy 1: RC tag artifact (code-index-{rc_version})")
        artifact_name = f"code-index-{rc_version}"
        index_path = download_artifact(repo, artifact_name, f"{output_dir}/{repo}-rc", github_token, github_org, debug)
        if index_path:
            return index_path, "rc_tag"

    # Strategy 2: Try triggering commit directly (if provided from workflow context)
    # This is the most reliable fallback since it's the actual commit that triggered the workflow
    if triggering_commit and len(triggering_commit) >= 7:
        if debug:
            print(f"\n📋 Strategy 2: Commit-based resolution (commit {triggering_commit[:8]})")
        
        artifact_name = f"code-index-{triggering_commit}"
        index_path = download_artifact(repo, artifact_name, f"{output_dir}/{repo}-rc", github_token, github_org, debug)
        if index_path:
            return index_path, "commit_direct"
    
    # NOTE: Removed PR-based and latest fallbacks for determinism.
    # If we couldn't resolve by tag or commit, fail explicitly.
    return None, "failed"


def resolve_deployed_index(repo: str, version: str, output_dir: str, github_token: str, github_org: str, debug: bool = False) -> Tuple[Optional[str], str]:
    """
    Resolve deployed version code index.
    
    Returns:
        (index_path, strategy_used)
    """
    if debug:
        print(f"\n🔍 Resolving deployed index for {repo}...")
        print(f"   Version: {version}")
    
    # Strategy 1: Version tag
    if debug:
        print(f"\n📋 Strategy 1: Version tag")
    
    artifact_name = f"code-index-{version}"
    index_path = download_artifact(repo, artifact_name, f"{output_dir}/{repo}-deployed", github_token, github_org, debug)
    if index_path:
        return index_path, "version_tag"
    
    # Strategy 2: Get commit from Git tag and try code-index-{commit}
    if debug:
        print(f"\n📋 Strategy 2: Getting commit from Git tag and trying code-index-{{commit}}")
    
    repo_full_name = f"{github_org}/{repo}"
    tag_commit = get_commit_for_tag(repo_full_name, version, github_token, debug)
    if tag_commit:
        artifact_name = f"code-index-{tag_commit}"
        index_path = download_artifact(repo, artifact_name, f"{output_dir}/{repo}-deployed", github_token, github_org, debug)
        if index_path:
            if debug:
                print(f"  ✅ Found code index for commit {tag_commit[:8]} (from tag {version})")
            return index_path, "tag_commit"
    
    # DO NOT FALL BACK TO LATEST - deployed version must have exact code index
    # Falling back to latest could use a PR commit, which would give wrong go.mod dependencies
    if debug:
        print(f"\n❌ No code index found for deployed version {version}")
        print(f"   Tried: code-index-{version}, code-index-{tag_commit[:8] if tag_commit else 'N/A'}")
        print(f"   Will NOT use code-index-latest (must match deployed version exactly)")
        print(f"   This ensures go.mod dependencies match the actual deployed version")
    
    return None, "failed"


def find_dependency_index(
    repo: str, 
    version: str, 
    github_orgs: List[str],  # Changed from single github_org
    github_token: str,
    output_dir: str, 
    debug: bool = False,
    github_org_hint: Optional[str] = None  # NEW: Use this org first, skip others if found
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Find dependency index, checking GitHub organizations.
    
    If github_org_hint is provided, ONLY check that org (don't check others).
    This saves time by avoiding unnecessary API calls.
    
    Tries multiple strategies:
    1. Get commit from Git tag and try code-index-{commit}
    2. Latest: code-index-latest (only if commit resolution fails)
    
    Returns:
        (index_path, github_org_found, strategy_used)
    """
    # If we have an org hint, ONLY check that org (saves time)
    orgs_to_check = [github_org_hint] if github_org_hint else github_orgs
    
    # Strategy 1: Get commit from Git tag and try code-index-{commit}
    # This is the correct approach since artifacts are named by commit hash, not version tag
    if version and version != "unknown" and version != "latest":
        if debug:
            print(f"  🔍 Getting commit for tag: {version}")
        
        # Try each org to find the tag
        tag_commit = None
        tag_org = None
        for github_org in orgs_to_check:
            repo_full_name = f"{github_org}/{repo}"
            tag_commit = get_commit_for_tag(repo_full_name, version, github_token, debug)
            if tag_commit:
                tag_org = github_org
                break
        
        if tag_commit:
            if debug:
                print(f"  📌 Found commit for tag {version}: {tag_commit[:8]}")
            
            artifact_name = f"code-index-{tag_commit}"
            for github_org in orgs_to_check:
                if debug:
                    print(f"  Checking {github_org}/{repo} with {artifact_name}")
                
                index_path = download_artifact(
                    repo, 
                    artifact_name,
                    output_dir,
                    github_token,
                    github_org,
                    debug
                )
                
                if index_path:
                    if debug:
                        print(f"  ✅ Found in {github_org}/{repo}")
                    return index_path, github_org, "tag_commit"
        elif debug:
            print(f"  ⚠️  Could not resolve commit for tag {version}")
    
    # Strategy 2: Fallback to latest (only if we couldn't get commit from tag)
    if debug:
        print(f"  🔄 Falling back to code-index-latest")
    
    artifact_name = "code-index-latest"
    for github_org in orgs_to_check:
        if debug:
            print(f"  Checking {github_org}/{repo} with {artifact_name}")
        
        index_path = download_artifact(
            repo, 
            artifact_name,
            output_dir,
            github_token,
            github_org,
            debug
        )
        
        if index_path:
            if debug:
                print(f"  ✅ Found in {github_org}/{repo}")
                print(f"  ⚠️  Using latest index (may not match version {version} exactly)")
            return index_path, github_org, "latest_fallback"
    
    # Not found in any org
    if debug:
        print(f"  ⚠️  Not found in any organization: {orgs_to_check}")
    return None, None, "not_found"


def resolve_dependency_indexes(dependencies: Dict[str, Any], output_dir: str, github_token: str, github_orgs: List[str], debug: bool = False, default_repos: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Resolve code indexes for all dependencies from multiple GitHub organizations.
    
    NEW: Only fetches indexes for repos in default_repos list (plus always-include repos).
    This significantly reduces resolution time by skipping rarely-used dependencies.
    
    New format handles version comparison and multi-org discovery:
    {
      "postgres-connector": {
        "deployed_version": "v0.0.1160",
        "rc_version": "v0.0.1165",
        "version_changed": true,
        "github_org": "armosec"  # Use this org ONLY, don't check both
      }
    }
    
    Args:
        default_repos: List of repo names to fetch. If None, uses DEFAULT_REPOS_TO_FETCH.
                      Dependencies not in this list are skipped (unless in ALWAYS_INCLUDE_REPOS).
    
    Returns:
        Dict mapping dependency name to index info
    """
    if default_repos is None:
        default_repos = DEFAULT_REPOS_TO_FETCH
    
    # Combine default repos with always-include repos (remove duplicates)
    repos_to_fetch = set(default_repos)
    for _, repo in ALWAYS_INCLUDE_REPOS:
        repos_to_fetch.add(repo)
    
    results = {}

    # Filter dependencies up-front (avoid iterating/logging "skipped" for every go.mod dep)
    # We only attempt to resolve indexes for:
    # 1) repos in default_repos (plus always-include), OR
    # 2) repos that changed between deployed vs RC (version_changed=True)
    selected_dependencies: Dict[str, Any] = {}
    for dep_name, dep_info in dependencies.items():
        try:
            version_changed = bool(dep_info.get('version_changed', False)) if isinstance(dep_info, dict) else False
        except Exception:
            version_changed = False
        if dep_name in repos_to_fetch or version_changed:
            selected_dependencies[dep_name] = dep_info

    if debug:
        total_in = len(dependencies) if isinstance(dependencies, dict) else 0
        total_selected = len(selected_dependencies)
        changed_selected = sum(
            1 for v in selected_dependencies.values()
            if isinstance(v, dict) and v.get('version_changed', False)
        )
        print(f"\n🧮 go.mod dependency filtering:")
        print(f"   - Total go.mod deps (input): {total_in}")
        print(f"   - Selected for resolution:   {total_selected}")
        print(f"     - In default repos list:  {sum(1 for k in selected_dependencies.keys() if k in repos_to_fetch)}")
        print(f"     - Version-changed extras: {max(changed_selected - sum(1 for k,v in selected_dependencies.items() if k in repos_to_fetch and isinstance(v, dict) and v.get('version_changed', False)), 0)}")
    
    # First, process gomod dependencies
    # Include repos that are:
    # 1. In the default repos list (repos_to_fetch), OR
    # 2. Have version_changed=True (even if not in default list)
    for dep_name, dep_info in selected_dependencies.items():
        # Handle both formats:
        # - Compare mode: has deployed_version, rc_version, version_changed
        # - Single-index mode: has just version
        version_changed = dep_info.get('version_changed', False)
        deployed_ver_raw = dep_info.get('deployed_version')
        rc_ver_raw = dep_info.get('rc_version')
        
        # Fallback to single-index format (just 'version' field)
        if deployed_ver_raw is None and rc_ver_raw is None:
            single_version = dep_info.get('version')
            if single_version:
                # In single-index mode, we don't know if version changed
                # So only include if in default list
                deployed_ver_raw = single_version
                rc_ver_raw = 'unknown'
                version_changed = False
            else:
                deployed_ver_raw = 'unknown'
                rc_ver_raw = 'unknown'
        else:
            # Compare mode - use defaults if missing
            if deployed_ver_raw is None:
                deployed_ver_raw = 'unknown'
            if rc_ver_raw is None:
                rc_ver_raw = 'unknown'
        
        if debug:
            print(f"\n📦 Processing dependency: {dep_name}")
            if version_changed and dep_name not in repos_to_fetch:
                print(f"   ✅ Version changed - including even though not in default list")
        
        github_org_hint = dep_info.get('github_org')  # This tells us which org to use
        
        # Extract base versions for index resolution (indexes are tagged with base versions)
        # But keep raw versions for display
        def extract_base_version(version: str) -> str:
            """Extract base version from pseudo-version for index resolution."""
            if not version or version == "unknown":
                return "unknown"
            # Pseudo-version format: v0.0.1182-0.20251225061625-832fbea140cc -> v0.0.1182
            match = re.match(r'^(v\d+\.\d+\.\d+)(?:-|$)', version)
            return match.group(1) if match else version
        
        deployed_ver_base = extract_base_version(deployed_ver_raw) if deployed_ver_raw != 'unknown' else 'unknown'
        rc_ver_base = extract_base_version(rc_ver_raw) if rc_ver_raw != 'unknown' else 'unknown'
        
        # Use ONLY the org hint if available (don't check both orgs)
        # This saves significant time by avoiding unnecessary API calls
        
        if deployed_ver_raw == 'unknown' and rc_ver_raw == 'unknown':
            if debug:
                print(f"  ⏭️  Skipping {dep_name} (no version info)")
            results[dep_name] = {
                "deployed": {"found": False, "reason": "no_version"},
                "rc": {"found": False, "reason": "no_version"},
                "version_changed": False
            }
            continue
        
        # Resolve deployed version (use base version for index lookup)
        deployed_index = None
        deployed_org = None
        deployed_strategy = None
        deployed_found = False
        if deployed_ver_base != 'unknown':
            if debug:
                print(f"  🔍 Resolving deployed version: {deployed_ver_raw} (using base {deployed_ver_base} for index lookup)")
                if github_org_hint:
                    print(f"  📌 Using org hint: {github_org_hint} (skipping other orgs)")
            
            # Pass org hint to avoid checking both orgs
            deployed_index, deployed_org, deployed_strategy = find_dependency_index(
                dep_name, deployed_ver_base, github_orgs,  # Still pass list for fallback
                github_token, f"{output_dir}/{dep_name}-deployed", debug,
                github_org_hint=github_org_hint  # NEW: Use this org ONLY
            )
            deployed_found = deployed_index is not None
            
            if deployed_found:
                if debug:
                    print(f"  ✅ Found deployed index in {deployed_org}")
            else:
                if debug:
                    print(f"  ⚠️  Deployed index not found")
        
        # Resolve RC version (use base version for index lookup)
        # NOTE: We resolve RC even if version didn't change, so we can compute commit-level diffs
        rc_index = None
        rc_org = None
        rc_strategy = None
        rc_found = False
        if rc_ver_base != 'unknown':
            if debug:
                print(f"  🔍 Resolving RC version: {rc_ver_raw} (using base {rc_ver_base} for index lookup)")
                if github_org_hint:
                    print(f"  📌 Using org hint: {github_org_hint} (skipping other orgs)")
            
            # Pass org hint to avoid checking both orgs
            rc_index, rc_org, rc_strategy = find_dependency_index(
                dep_name, rc_ver_base, github_orgs,  # Still pass list for fallback
                github_token, f"{output_dir}/{dep_name}-rc", debug,
                github_org_hint=github_org_hint  # NEW: Use this org ONLY
            )
            rc_found = rc_index is not None
            
            if rc_found:
                if debug:
                    print(f"  ✅ Found RC index in {rc_org}")
            else:
                if debug:
                    print(f"  ⚠️  RC index not found")
        
        # Extract commits from downloaded indexes
        deployed_commit = None
        if deployed_index and deployed_org:
            deployed_commit = extract_commit_from_index(deployed_index, debug)
            # Fallback: Get commit from Git tag if index has no metadata (use base version for tag lookup)
            if not deployed_commit and deployed_ver_base != 'unknown':
                repo_full_name = f"{deployed_org}/{dep_name}"
                deployed_commit = get_commit_for_tag(repo_full_name, deployed_ver_base, github_token, debug)
        
        rc_commit = None
        if rc_index and rc_org:
            rc_commit = extract_commit_from_index(rc_index, debug)
            # Fallback: Get commit from Git tag if index has no metadata (use base version for tag lookup)
            if not rc_commit and rc_ver_base != 'unknown':
                repo_full_name = f"{rc_org}/{dep_name}"
                rc_commit = get_commit_for_tag(repo_full_name, rc_ver_base, github_token, debug)
        
        # Use org hint if still not found, otherwise default to armosec
        if not deployed_org:
            deployed_org = github_org_hint or 'armosec'
        if not rc_org and version_changed:
            rc_org = github_org_hint or 'armosec'
        
        results[dep_name] = {
            "deployed": {
                "version": deployed_ver_raw,  # Store exact version from go.mod
                "commit": deployed_commit,
                "index_path": deployed_index,
                "found": deployed_found,
                "github_org": deployed_org,
                "strategy": deployed_strategy,
                "source": "gomod"  # Mark as coming from go.mod
            },
            "rc": {
                "version": rc_ver_raw,  # Store exact version from go.mod (may include pseudo-version)
                "commit": rc_commit,
                "index_path": rc_index,
                "found": rc_found,
                "github_org": rc_org,
                "strategy": rc_strategy
            },
            "version_changed": version_changed
        }
    
    # NEW: Add always-include repos as fallback (only if not already in go.mod dependencies)
    if debug:
        print("\n📌 Adding always-include repositories (if not in go.mod)...")
    for org, repo in ALWAYS_INCLUDE_REPOS:
        # Skip if already processed from go.mod dependencies (will have version-tagged artifacts)
        if repo in results:
            if debug:
                print(f"  ⏭️  Skipping {org}/{repo} - already in go.mod dependencies with version {results[repo].get('deployed', {}).get('version', 'unknown')}")
            continue
        
        if debug:
            print(f"  Adding fallback: {org}/{repo} (not in go.mod, using latest)")
        # Get latest release (only used if not in go.mod)
        # Use specific org (don't check both)
        index_path, found_org, strategy = find_dependency_index(
            repo, "latest", github_orgs,  # Pass list for fallback
            github_token, f"{output_dir}/{repo}-fallback", debug,
            github_org_hint=org  # NEW: Use specific org ONLY
        )
        if index_path:
            # Extract commit
            commit = extract_commit_from_index(index_path, debug)
            results[repo] = {
                "deployed": {
                    "version": "latest",
                    "commit": commit,
                    "index_path": index_path,
                    "found": True,
                    "github_org": found_org or org,  # Use found_org or default to specified org
                    "strategy": "always_include_fallback",
                    "source": "service"  # Mark as service dependency
                },
                "rc": {"found": False},
                "version_changed": False
            }
        else:
            # Even if not found, add placeholder with org
            results[repo] = {
                "deployed": {
                    "version": "latest",
                    "commit": None,
                    "index_path": None,
                    "found": False,
                    "github_org": org,  # Use specified org
                    "strategy": "always_include_fallback",
                    "source": "service"  # Mark as service dependency
                },
                "rc": {"found": False},
                "version_changed": False
            }
    
    return results


def main():
    args = parse_args()
    
    # Get GitHub token
    github_token = args.github_token or os.environ.get('GITHUB_TOKEN')
    if not github_token:
        print("❌ Error: GitHub token required (use --github-token or GITHUB_TOKEN env var)", file=sys.stderr)
        sys.exit(1)
    
    # Parse GitHub orgs (comma-separated)
    github_orgs = [org.strip() for org in args.github_orgs.split(',')]
    if args.debug:
        print(f"🔍 Checking GitHub organizations: {', '.join(github_orgs)}")
    
    if args.debug:
        print("="*70)
        print("  Code Index Resolution")
        print("="*70)
        print()
    
    results = {
        "triggering_repo": args.triggering_repo,
        "indexes": {},
        "dependencies_summary": {
            "total": 0,
            "indexes_found": 0,
            "indexes_missing": 0,
            "version_changes": []
        }
    }
    
    # Resolve dashboard indexes (both RC and deployed)
    dashboard_indexes = {}
    
    # Discovery triggering org (usually armosec, but could be kubescape)
    # We check both orgs for the triggering repo index
    triggering_org = None
    rc_path = None
    rc_strategy = None
    deployed_path = None
    deployed_strategy = None

    if args.rc_version:
        for org in github_orgs:
            rc_path, rc_strategy = resolve_rc_index(
                args.triggering_repo,
                args.rc_version,
                args.output_dir,
                github_token,
                org,
                args.triggering_commit,  # Pass triggering commit for Strategy 2
                args.debug
            )
            if rc_path:
                triggering_org = org
                break
    
    if args.deployed_version:
        # If we already found the org from RC, use it. Otherwise discover.
        if triggering_org:
            deployed_path, deployed_strategy = resolve_deployed_index(
                args.triggering_repo,
                args.deployed_version,
                args.output_dir,
                github_token,
                triggering_org,
                args.debug
            )
        else:
            for org in github_orgs:
                deployed_path, deployed_strategy = resolve_deployed_index(
                    args.triggering_repo,
                    args.deployed_version,
                    args.output_dir,
                    github_token,
                    org,
                    args.debug
                )
                if deployed_path:
                    triggering_org = org
                    break
                
    # Fallback to first org if not found
    if not triggering_org:
        triggering_org = github_orgs[0]
    
    # RC version metadata
    if args.rc_version:
        # Extract commit from downloaded index
        rc_commit = None
        if rc_path:
            rc_commit = extract_commit_from_index(rc_path, args.debug)
        
        # Fallback to triggering_commit if not in index OR if index wasn't found
        # This ensures we always have a commit when triggering_commit is available
        if not rc_commit and args.triggering_commit and args.triggering_commit != 'unknown':
            rc_commit = args.triggering_commit
            if args.debug:
                print(f"   📌 Using triggering commit as fallback: {rc_commit[:8]}")
        
        dashboard_indexes["rc"] = {
            "version": args.rc_version,
            "commit": rc_commit,  # Can be None if no index found and no triggering_commit
            "index_path": rc_path,
            "strategy": rc_strategy,
            "found": rc_path is not None,
            "github_org": triggering_org,
            "source": "service"  # Triggering repo is a service, not a go.mod dependency
        }
    
    # Deployed version metadata
    if args.deployed_version:
        # Extract commit from downloaded index
        deployed_commit = None
        if deployed_path:
            deployed_commit = extract_commit_from_index(deployed_path, args.debug)
        
        # Fallback: Get commit from Git tag if index has no metadata OR if index wasn't found
        # This ensures we try to get commit even when index download failed
        if not deployed_commit and args.deployed_version and args.deployed_version != 'unknown':
            repo_full_name = f"{triggering_org}/{args.triggering_repo}"
            deployed_commit = get_commit_for_tag(repo_full_name, args.deployed_version, github_token, args.debug)
            if deployed_commit and args.debug:
                print(f"   📌 Using Git tag commit as fallback: {deployed_commit[:8]}")
        
        dashboard_indexes["deployed"] = {
            "version": args.deployed_version,
            "commit": deployed_commit,  # Can be None if no index found and tag lookup fails
            "index_path": deployed_path,
            "strategy": deployed_strategy,
            "found": deployed_path is not None,
            "github_org": triggering_org,
            "source": "service"  # Triggering repo is a service, not a go.mod dependency
        }
    
    results["indexes"][args.triggering_repo] = dashboard_indexes
    
    # Resolve dependencies
    if args.gomod_dependencies:
        if args.debug:
            print("\n" + "="*70)
            print("  Resolving Dependencies")
            print("="*70)
        
        with open(args.gomod_dependencies, 'r') as f:
            dependencies = json.load(f)
        
        # Parse default repos if provided
        default_repos = None
        if args.default_repos:
            default_repos = [repo.strip() for repo in args.default_repos.split(',')]
            if args.debug:
                print(f"📋 Using custom default repos: {', '.join(default_repos)}")
        
        dep_results = resolve_dependency_indexes(
            dependencies,
            args.output_dir,
            github_token,
            github_orgs,  # Pass list of orgs
            args.debug,
            default_repos=default_repos or DEFAULT_REPOS_TO_FETCH  # Use custom or default
        )
        
        # Add dependencies to results and calculate summary
        for dep_name, dep_info in dep_results.items():
            results["indexes"][dep_name] = dep_info
            
            # Update summary
            results["dependencies_summary"]["total"] += 1
            
            if dep_info.get("deployed", {}).get("found") or dep_info.get("rc", {}).get("found"):
                results["dependencies_summary"]["indexes_found"] += 1
            else:
                results["dependencies_summary"]["indexes_missing"] += 1
            
            if dep_info.get("version_changed"):
                results["dependencies_summary"]["version_changes"].append(dep_name)
    
    # Resolve service indexes from services-only.json (excludes triggering repo)
    if args.services_only and os.path.exists(args.services_only):
        if args.debug:
            print("\n" + "="*70)
            print("  Resolving Service Indexes")
            print("="*70)
        
        try:
            with open(args.services_only, 'r') as f:
                services_data = json.load(f)
            
            # Process each service repo
            for repo_name, repo_info in services_data.items():
                images = repo_info.get("images", [])
                if not images:
                    if args.debug:
                        print(f"\n⚠️  No images found for service {repo_name}")
                    continue
                
                # Filter out dataPurger service_key (already filtered in normalization, but double-check)
                filtered_images = [img for img in images if img.get('service_key') != 'dataPurger']
                if not filtered_images:
                    if args.debug:
                        print(f"\n⏭️  Skipping {repo_name} (only dataPurger images, excluded from analysis)")
                    continue
                
                # For event-ingester-service and other repos with multiple services:
                # Process ALL images to show all service versions
                # Group by unique tags to avoid duplicates
                unique_tags = {}
                for img in filtered_images:
                    tag = img.get("tag", "")
                    service_key = img.get("service_key", "")
                    if tag and tag != "unknown":
                        if tag not in unique_tags:
                            unique_tags[tag] = {
                                "tag": tag,
                                "service_keys": [],
                                "image": img
                            }
                        if service_key and service_key not in unique_tags[tag]["service_keys"]:
                            unique_tags[tag]["service_keys"].append(service_key)
                
                if not unique_tags:
                    if args.debug:
                        print(f"\n⚠️  No valid deployed version tags for service {repo_name}")
                    continue
                
                # Process each unique tag (for repos with multiple services using different versions)
                for tag, tag_info in unique_tags.items():
                    service_keys_str = ", ".join(tag_info["service_keys"]) if tag_info["service_keys"] else "unknown"
                    
                    if args.debug:
                        print(f"\n📦 Processing service: {repo_name}")
                        print(f"   Deployed version: {tag}")
                        if len(unique_tags) > 1:
                            print(f"   Service keys: {service_keys_str}")
                    
                    # Resolve deployed index for this service version
                    service_index_path = None
                    service_org = None
                    service_strategy = None
                    
                    # Try each org
                    for org in github_orgs:
                        service_index_path, service_org, service_strategy = find_dependency_index(
                            repo_name,
                            tag,
                            [org],  # Check one org at a time
                            github_token,
                            f"{args.output_dir}/{repo_name}-service-{tag}",
                            args.debug
                        )
                        if service_index_path:
                            break
                    
                    # Extract commit from tag or index
                    service_commit = None
                    if service_index_path:
                        service_commit = extract_commit_from_index(service_index_path, args.debug)
                        # Fallback: Get commit from Git tag
                        if not service_commit:
                            repo_full_name = f"{service_org or github_orgs[0]}/{repo_name}"
                            service_commit = get_commit_for_tag(repo_full_name, tag, github_token, args.debug)
                    
                    # Use repo_name as key, but if multiple versions exist, append tag
                    result_key = repo_name
                    if len(unique_tags) > 1:
                        result_key = f"{repo_name}-{tag}"
                    
                    # Add to results
                    results["indexes"][result_key] = {
                        "deployed": {
                            "version": tag,
                            "commit": service_commit,
                            "index_path": service_index_path,
                            "strategy": service_strategy,
                            "found": service_index_path is not None,
                            "github_org": service_org or github_orgs[0],
                            "source": "service",
                            "service_keys": tag_info["service_keys"] if len(unique_tags) > 1 else None
                        },
                        "rc": {"found": False},  # Services don't use RC versions
                        "version_changed": False
                    }
                
                # Update summary
                results["dependencies_summary"]["total"] += 1
                if service_index_path:
                    results["dependencies_summary"]["indexes_found"] += 1
                else:
                    results["dependencies_summary"]["indexes_missing"] += 1
                
                if args.debug:
                    status = "✅" if service_index_path else "❌"
                    print(f"   {status} Index: {service_index_path or 'not found'}")
        except Exception as e:
            if args.debug:
                print(f"\n⚠️  Error processing services-only.json: {e}")
            # Non-fatal, continue
    
    # Resolve dashboard indexes if different from triggering repo
    if args.dashboard_repo != args.triggering_repo:
        if args.debug:
            print(f"\n🔍 Resolving dashboard index for {args.dashboard_repo} (required for API mapping)...")
        
        # Dashboard repo usually uses latest index for mapping
        # We don't try to resolve RC version for dashboard if it's not the triggering repo
        dash_deployed_ver = "latest"
        
        dash_path, dash_strategy = resolve_deployed_index(
            args.dashboard_repo,
            dash_deployed_ver,
            args.output_dir,
            github_token,
            triggering_org,  # Use same org as triggering repo
            args.debug
        )
        
        dash_commit = extract_commit_from_index(dash_path, args.debug) if dash_path else None
        
        results["indexes"][args.dashboard_repo] = {
            "deployed": {
                "version": dash_deployed_ver,
                "commit": dash_commit,
                "index_path": dash_path,
                "strategy": dash_strategy,
                "found": dash_path is not None
            }
        }
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    if args.debug:
        print("\n" + "="*70)
        print("  Summary")
        print("="*70)
    
    total = len(results["indexes"])
    found = sum(1 for idx in results["indexes"].values() if isinstance(idx, dict) and (idx.get("found") or idx.get("rc", {}).get("found") or idx.get("deployed", {}).get("found")))
    
    print(f"\n✅ Resolution complete")
    print(f"   Total repos: {total}")
    print(f"   Indexes found: {found}")
    print(f"   Output: {args.output}")
    
    if args.debug:
        print()
        for repo, idx_info in results["indexes"].items():
            print(f"\n📦 {repo}:")
            if isinstance(idx_info, dict):
                for key, val in idx_info.items():
                    if isinstance(val, dict):
                        status = "✅" if val.get("found") else "❌"
                        print(f"  {status} {key}: {val.get('strategy', 'N/A')}")


if __name__ == '__main__':
    main()

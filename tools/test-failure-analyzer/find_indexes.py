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

# Always include these repositories (fallback for critical dependencies)
ALWAYS_INCLUDE_REPOS = [
    ('armosec', 'armosec-infra'),      # Always needed for notifications, utils
    ('armosec', 'postgres-connector'),  # Database layer
]

GITHUB_ORGS_TO_CHECK = ['armosec', 'kubescape']  # Check both orgs

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
    
    Examples:
        rc-v0.0.224-2435 -> 2435
        rc-v1.2.3-999 -> 999
    """
    match = re.match(r'rc-v\d+\.\d+\.\d+-(\d+)', rc_version)
    if match:
        return int(match.group(1))
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
    
    # List artifacts
    api_url = f"https://api.github.com/repos/{github_org}/{repo}/actions/artifacts"
    
    if debug:
        print(f"  📡 Searching for artifact: {artifact_name}")
    
    try:
        resp = requests.get(api_url, headers=headers, params={"per_page": 100}, timeout=30)
        if resp.status_code != 200:
            if debug:
                print(f"  ❌ Failed to list artifacts: {resp.status_code}")
            return None
        
        data = resp.json()
        artifacts = data.get('artifacts', [])
        
        # Find matching artifact
        matching = [a for a in artifacts if a.get('name') == artifact_name]
        if not matching:
            if debug:
                print(f"  ❌ Artifact not found: {artifact_name}")
            return None
        
        artifact = matching[0]
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


def resolve_rc_index(repo: str, rc_version: str, output_dir: str, github_token: str, github_org: str, debug: bool = False) -> Tuple[Optional[str], str]:
    """
    Resolve RC code index using PR-based strategy.
    
    Returns:
        (index_path, strategy_used)
    """
    if debug:
        print(f"\n🔍 Resolving RC index for {repo}...")
        print(f"   RC version: {rc_version}")
    
    # Strategy 1: PR-based resolution
    pr_number = extract_pr_from_rc(rc_version)
    if pr_number:
        if debug:
            print(f"\n📋 Strategy 1: PR-based resolution (PR #{pr_number})")
        
        commit = get_pr_head_commit(repo, pr_number, github_token, github_org, debug)
        if commit:
            artifact_name = f"code-index-{commit}"
            index_path = download_artifact(repo, artifact_name, f"{output_dir}/{repo}-rc", github_token, github_org, debug)
            if index_path:
                return index_path, "pr_commit"
    
    # Strategy 2: Try RC commit directly (if provided)
    # This would require extracting commit from workflow context
    
    # Strategy 3: Fallback to latest
    if debug:
        print(f"\n📋 Strategy 3: Falling back to latest")
    
    artifact_name = "code-index-latest"
    index_path = download_artifact(repo, artifact_name, f"{output_dir}/{repo}-rc", github_token, github_org, debug)
    if index_path:
        if debug:
            print(f"  ⚠️  Using latest index (may not match RC exactly)")
        return index_path, "latest_fallback"
    
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
    
    # Strategy 2: Fallback to latest
    if debug:
        print(f"\n📋 Strategy 2: Falling back to latest")
    
    artifact_name = "code-index-latest"
    index_path = download_artifact(repo, artifact_name, f"{output_dir}/{repo}-deployed", github_token, github_org, debug)
    if index_path:
        if debug:
            print(f"  ⚠️  Using latest index (may not match deployed version)")
        return index_path, "latest_fallback"
    
    return None, "failed"


def find_dependency_index(
    repo: str, 
    version: str, 
    github_orgs: List[str],  # Changed from single github_org
    github_token: str,
    output_dir: str, 
    debug: bool = False
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Find dependency index, checking multiple GitHub organizations.
    
    Tries multiple strategies:
    1. Version tag: code-index-v0.0.1160
    2. Latest: code-index-latest
    
    Returns:
        (index_path, github_org_found, strategy_used)
    """
    strategies = [
        f"code-index-{version}",  # Try version tag first
        "code-index-latest"       # Fallback to latest
    ]
    
    for artifact_name in strategies:
        for github_org in github_orgs:
            if debug:
                print(f"  Checking {github_org}/{repo} with {artifact_name}")
            
            # Try finding in this org
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
                strategy = "version_tag" if artifact_name == f"code-index-{version}" else "latest_fallback"
                return index_path, github_org, strategy
    
    # Not found in any org
    if debug:
        print(f"  ⚠️  Not found in any organization: {github_orgs}")
    return None, None, "not_found"


def resolve_dependency_indexes(dependencies: Dict[str, Any], output_dir: str, github_token: str, github_orgs: List[str], debug: bool = False) -> Dict[str, Any]:
    """
    Resolve code indexes for all dependencies from multiple GitHub organizations.
    
    New format handles version comparison and multi-org discovery:
    {
      "postgres-connector": {
        "deployed_version": "v0.0.1160",
        "rc_version": "v0.0.1165",
        "version_changed": true
      }
    }
    
    Returns:
        Dict mapping dependency name to index info
    """
    results = {}
    
    # First, process gomod dependencies
    for dep_name, dep_info in dependencies.items():
        if debug:
            print(f"\n📦 Processing dependency: {dep_name}")
        
        deployed_ver_raw = dep_info.get('deployed_version', 'unknown')
        rc_ver_raw = dep_info.get('rc_version', 'unknown')
        version_changed = dep_info.get('version_changed', False)
        github_org_hint = dep_info.get('github_org')
        
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
        
        # If we have an org hint, prioritize it in the orgs list
        check_orgs = github_orgs
        if github_org_hint and github_org_hint in github_orgs:
            # Move the hinted org to the front
            check_orgs = [github_org_hint] + [o for o in github_orgs if o != github_org_hint]
        
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
            
            deployed_index, deployed_org, deployed_strategy = find_dependency_index(
                dep_name, deployed_ver_base, check_orgs,  # Use base version for index lookup
                github_token, f"{output_dir}/{dep_name}-deployed", debug
            )
            deployed_found = deployed_index is not None
            
            if deployed_found:
                if debug:
                    print(f"  ✅ Found deployed index in {deployed_org}")
            else:
                if debug:
                    print(f"  ⚠️  Deployed index not found")
        
        # Resolve RC version if changed (use base version for index lookup)
        rc_index = None
        rc_org = None
        rc_strategy = None
        rc_found = False
        if version_changed and rc_ver_base != 'unknown':
            if debug:
                print(f"  🔍 Resolving RC version: {rc_ver_raw} (using base {rc_ver_base} for index lookup)")
            
            rc_index, rc_org, rc_strategy = find_dependency_index(
                dep_name, rc_ver_base, check_orgs,  # Use base version for index lookup
                github_token, f"{output_dir}/{dep_name}-rc", debug
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
    
    # NEW: Add always-include repos as fallback
    if debug:
        print("\n📌 Adding always-include repositories...")
    for org, repo in ALWAYS_INCLUDE_REPOS:
        if repo not in results:
            if debug:
                print(f"  Adding fallback: {org}/{repo}")
            # Get latest release
            index_path, found_org, strategy = find_dependency_index(
                repo, "latest", [org],  # Just check specific org
                github_token, f"{output_dir}/{repo}-fallback", debug
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
            # Fallback to triggering_commit if not in index
            if not rc_commit and args.triggering_commit:
                rc_commit = args.triggering_commit
                if args.debug:
                    print(f"   📌 Using triggering commit as fallback: {rc_commit[:8]}")
        
        dashboard_indexes["rc"] = {
            "version": args.rc_version,
            "commit": rc_commit,
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
            # Fallback: Get commit from Git tag if index has no metadata
            if not deployed_commit and args.deployed_version:
                repo_full_name = f"{triggering_org}/{args.triggering_repo}"
                deployed_commit = get_commit_for_tag(repo_full_name, args.deployed_version, github_token, args.debug)
                if deployed_commit and args.debug:
                    print(f"   📌 Using Git tag commit as fallback: {deployed_commit[:8]}")
        
        dashboard_indexes["deployed"] = {
            "version": args.deployed_version,
            "commit": deployed_commit,
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
        
        dep_results = resolve_dependency_indexes(
            dependencies,
            args.output_dir,
            github_token,
            github_orgs,  # Pass list of orgs
            args.debug
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

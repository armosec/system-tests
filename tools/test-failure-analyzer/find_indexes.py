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
    parser.add_argument("--github-org", default="armosec", help="GitHub organization")
    
    # Options
    parser.add_argument("--images", help="Path to running-images.json to resolve dashboard version")
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


def find_dependency_index(repo: str, version: str, github_org: str, 
                          github_token: str, output_dir: str, debug: bool) -> Optional[str]:
    """
    Find and download code index for a dependency.
    
    Tries multiple strategies:
    1. Version tag: code-index-v0.0.1160
    2. Commit hash: code-index-{commit}
    3. Latest: code-index-latest
    
    Returns:
        Path to downloaded index or None if not found
    """
    strategies = [
        f"code-index-{version}",  # Try version tag first
        "code-index-latest"       # Fallback to latest
    ]
    
    for artifact_name in strategies:
        if debug:
            print(f"  Trying {repo}: {artifact_name}")
        
        index_path = download_artifact(repo, artifact_name, output_dir, 
                                       github_token, github_org, debug)
        if index_path:
            return index_path
    
    return None


def resolve_dependency_indexes(dependencies: Dict[str, Any], output_dir: str, github_token: str, github_org: str, debug: bool = False) -> Dict[str, Any]:
    """
    Resolve code indexes for all dependencies.
    
    New format handles version comparison:
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
    
    for dep_name, dep_info in dependencies.items():
        if debug:
            print(f"\n📦 Processing dependency: {dep_name}")
        
        deployed_ver = dep_info.get('deployed_version', 'unknown')
        rc_ver = dep_info.get('rc_version', 'unknown')
        version_changed = dep_info.get('version_changed', False)
        
        if deployed_ver == 'unknown' and rc_ver == 'unknown':
            if debug:
                print(f"  ⏭️  Skipping {dep_name} (no version info)")
            results[dep_name] = {
                "deployed": {"found": False, "reason": "no_version"},
                "rc": {"found": False, "reason": "no_version"},
                "version_changed": False
            }
            continue
        
        # Resolve deployed version
        deployed_index = None
        deployed_found = False
        if deployed_ver != 'unknown':
            if debug:
                print(f"  🔍 Resolving deployed version: {deployed_ver}")
            
            deployed_index = find_dependency_index(
                dep_name, deployed_ver, github_org, 
                github_token, f"{output_dir}/{dep_name}-deployed", debug
            )
            deployed_found = deployed_index is not None
            
            if deployed_found:
                if debug:
                    print(f"  ✅ Found deployed index")
            else:
                if debug:
                    print(f"  ⚠️  Deployed index not found")
        
        # Resolve RC version if changed
        rc_index = None
        rc_found = False
        if version_changed and rc_ver != 'unknown':
            if debug:
                print(f"  🔍 Resolving RC version: {rc_ver}")
            
            rc_index = find_dependency_index(
                dep_name, rc_ver, github_org,
                github_token, f"{output_dir}/{dep_name}-rc", debug
            )
            rc_found = rc_index is not None
            
            if rc_found:
                if debug:
                    print(f"  ✅ Found RC index")
            else:
                if debug:
                    print(f"  ⚠️  RC index not found")
        
        # Extract commits from downloaded indexes
        deployed_commit = None
        if deployed_index:
            deployed_commit = extract_commit_from_index(deployed_index, debug)
            # Fallback: Get commit from Git tag if index has no metadata
            if not deployed_commit and deployed_ver != 'unknown':
                repo_full_name = f"{github_org}/{dep_name}"
                deployed_commit = get_commit_for_tag(repo_full_name, deployed_ver, github_token, debug)
        
        rc_commit = None
        if rc_index:
            rc_commit = extract_commit_from_index(rc_index, debug)
            # Fallback: Get commit from Git tag if index has no metadata
            if not rc_commit and rc_ver != 'unknown':
                repo_full_name = f"{github_org}/{dep_name}"
                rc_commit = get_commit_for_tag(repo_full_name, rc_ver, github_token, debug)
        
        results[dep_name] = {
            "deployed": {
                "version": deployed_ver,
                "commit": deployed_commit,
                "index_path": deployed_index,
                "found": deployed_found
            },
            "rc": {
                "version": rc_ver,
                "commit": rc_commit,
                "index_path": rc_index,
                "found": rc_found
            },
            "version_changed": version_changed
        }
    
    return results


def main():
    args = parse_args()
    
    # Get GitHub token
    github_token = args.github_token or os.environ.get('GITHUB_TOKEN')
    if not github_token:
        print("❌ Error: GitHub token required (use --github-token or GITHUB_TOKEN env var)", file=sys.stderr)
        sys.exit(1)
    
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
    
    # RC version
    if args.rc_version:
        rc_path, rc_strategy = resolve_rc_index(
            args.triggering_repo,
            args.rc_version,
            args.output_dir,
            github_token,
            args.github_org,
            args.debug
        )
        
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
            "found": rc_path is not None
        }
    
    # Deployed version
    if args.deployed_version:
        deployed_path, deployed_strategy = resolve_deployed_index(
            args.triggering_repo,
            args.deployed_version,
            args.output_dir,
            github_token,
            args.github_org,
            args.debug
        )
        
        # Extract commit from downloaded index
        deployed_commit = None
        if deployed_path:
            deployed_commit = extract_commit_from_index(deployed_path, args.debug)
            # Fallback: Get commit from Git tag if index has no metadata
            if not deployed_commit and args.deployed_version:
                repo_full_name = f"{args.github_org}/{args.triggering_repo}"
                deployed_commit = get_commit_for_tag(repo_full_name, args.deployed_version, github_token, args.debug)
                if deployed_commit and args.debug:
                    print(f"   📌 Using Git tag commit as fallback: {deployed_commit[:8]}")
        
        dashboard_indexes["deployed"] = {
            "version": args.deployed_version,
            "commit": deployed_commit,
            "index_path": deployed_path,
            "strategy": deployed_strategy,
            "found": deployed_path is not None
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
            args.github_org,
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
    
    # Resolve dashboard indexes if different from triggering repo
    if args.dashboard_repo != args.triggering_repo:
        if args.debug:
            print(f"\n🔍 Resolving dashboard index for {args.dashboard_repo} (required for API mapping)...")
        
        # Try to resolve actual version for dashboard if available in running-images
        dash_deployed_ver = "latest"
        if args.images and os.path.exists(args.images):
            try:
                with open(args.images, 'r') as f:
                    running_images = json.load(f)
                    repos = running_images.get('repos', {})
                    dash_data = repos.get(args.dashboard_repo, {})
                    images = dash_data.get('images', [])
                    if images:
                        dash_deployed_ver = images[0].get('tag', 'latest')
            except Exception:
                pass

        dash_path, dash_strategy = resolve_deployed_index(
            args.dashboard_repo,
            dash_deployed_ver,
            args.output_dir,
            github_token,
            args.github_org,
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

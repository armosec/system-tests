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
            index_path = download_artifact(repo, artifact_name, f"{output_dir}/rc", github_token, github_org, debug)
            if index_path:
                return index_path, "pr_commit"
    
    # Strategy 2: Try RC commit directly (if provided)
    # This would require extracting commit from workflow context
    
    # Strategy 3: Fallback to latest
    if debug:
        print(f"\n📋 Strategy 3: Falling back to latest")
    
    artifact_name = "code-index-latest"
    index_path = download_artifact(repo, artifact_name, f"{output_dir}/rc", github_token, github_org, debug)
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
    index_path = download_artifact(repo, artifact_name, f"{output_dir}/deployed", github_token, github_org, debug)
    if index_path:
        return index_path, "version_tag"
    
    # Strategy 2: Fallback to latest
    if debug:
        print(f"\n📋 Strategy 2: Falling back to latest")
    
    artifact_name = "code-index-latest"
    index_path = download_artifact(repo, artifact_name, f"{output_dir}/deployed", github_token, github_org, debug)
    if index_path:
        if debug:
            print(f"  ⚠️  Using latest index (may not match deployed version)")
        return index_path, "latest_fallback"
    
    return None, "failed"


def resolve_dependency_indexes(dependencies: Dict[str, Any], output_dir: str, github_token: str, github_org: str, debug: bool = False) -> Dict[str, Any]:
    """
    Resolve code indexes for all dependencies.
    
    Returns:
        Dict mapping dependency name to index info
    """
    results = {}
    
    for dep_name, dep_info in dependencies.items():
        if not dep_info.get('has_index'):
            if debug:
                print(f"\n⏭️  Skipping {dep_name} (no code index available)")
            results[dep_name] = {
                "found": False,
                "reason": "no_index_workflow"
            }
            continue
        
        version = dep_info.get('version', '')
        repo = dep_info.get('repo', '')
        
        if not repo:
            if debug:
                print(f"\n⏭️  Skipping {dep_name} (no repo info)")
            results[dep_name] = {
                "found": False,
                "reason": "no_repo_info"
            }
            continue
        
        # Extract repo name from full path (e.g., armosec/postgres-connector -> postgres-connector)
        repo_name = repo.split('/')[-1]
        
        if debug:
            print(f"\n🔍 Resolving dependency: {dep_name}")
            print(f"   Deployed version: {version}")
        
        # Get deployed version index
        deployed_path, deployed_strategy = resolve_deployed_index(
            repo_name, version, f"{output_dir}/{dep_name}", github_token, github_org, debug
        )
        
        # Get latest version index
        if debug:
            print(f"\n🔍 Resolving latest version for {dep_name}")
        
        latest_path = download_artifact(
            repo_name, "code-index-latest", f"{output_dir}/{dep_name}/latest", github_token, github_org, debug
        )
        
        results[dep_name] = {
            "found": deployed_path is not None,
            "deployed_version": version,
            "deployed_index_path": deployed_path,
            "deployed_strategy": deployed_strategy,
            "latest_index_path": latest_path,
            "repo": repo
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
        "indexes": {}
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
        dashboard_indexes["rc"] = {
            "version": args.rc_version,
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
        dashboard_indexes["deployed"] = {
            "version": args.deployed_version,
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
        
        for dep_name, dep_info in dep_results.items():
            results["indexes"][dep_name] = dep_info
    
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

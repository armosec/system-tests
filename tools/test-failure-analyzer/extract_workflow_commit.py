#!/usr/bin/env python3
"""
Extract git commit from GitHub Actions workflow run.

This script extracts the git commit SHA from a GitHub Actions workflow run.
It supports multiple methods:
1. GitHub API (preferred) - uses workflow run metadata
2. Log parsing (fallback) - extracts commit from workflow logs

Usage:
    python extract_workflow_commit.py <run_url_or_id> [--output artifacts/workflow-commit.txt]
    python extract_workflow_commit.py --run-id 12345678 --repo armosec/shared-workflows
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def extract_commit_from_api(run_id: str, repo: str, token: Optional[str] = None) -> Optional[str]:
    """
    Extract commit SHA from GitHub API.
    
    Args:
        run_id: GitHub Actions run ID (numeric)
        repo: Repository in format 'owner/repo'
        token: GitHub token (or use GITHUB_TOKEN env var)
        
    Returns:
        Commit SHA if found, None otherwise
    """
    if not HAS_REQUESTS:
        return None
    
    token = token or os.environ.get('GITHUB_TOKEN')
    if not token:
        return None
    
    api_url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Try head_sha first (for workflow_run events)
        commit_sha = data.get('head_sha') or data.get('head_commit', {}).get('id')
        
        if commit_sha:
            return commit_sha
        
        # Fallback to workflow run head commit
        head_branch = data.get('head_branch')
        if head_branch:
            # Try to get commit from head branch
            commits_url = f"https://api.github.com/repos/{repo}/commits/{head_branch}"
            commit_response = requests.get(commits_url, headers=headers, timeout=10)
            if commit_response.status_code == 200:
                commit_data = commit_response.json()
                return commit_data.get('sha')
        
    except Exception as e:
        print(f"API error: {e}", file=sys.stderr)
        return None
    
    return None


def extract_commit_from_logs(logs_text: str) -> Optional[str]:
    """
    Extract commit SHA from workflow logs.
    
    Looks for patterns like:
    - "HEAD is now at <sha>"
    - "Checking out <sha>"
    - "commit <sha>"
    - Full SHA (40 hex chars)
    
    Args:
        logs_text: Workflow log text
        
    Returns:
        Commit SHA if found, None otherwise
    """
    if not logs_text:
        return None
    
    # Pattern 1: "HEAD is now at <sha>"
    pattern1 = re.compile(r'HEAD\s+is\s+now\s+at\s+([0-9a-f]{40})', re.IGNORECASE)
    match = pattern1.search(logs_text)
    if match:
        return match.group(1)
    
    # Pattern 2: "Checking out <sha>"
    pattern2 = re.compile(r'Checking\s+out\s+([0-9a-f]{40})', re.IGNORECASE)
    match = pattern2.search(logs_text)
    if match:
        return match.group(1)
    
    # Pattern 3: "commit <sha>"
    pattern3 = re.compile(r'commit\s+([0-9a-f]{40})', re.IGNORECASE)
    match = pattern3.search(logs_text)
    if match:
        return match.group(1)
    
    # Pattern 4: Standalone full SHA (40 hex chars, not part of another word)
    pattern4 = re.compile(r'\b([0-9a-f]{40})\b', re.IGNORECASE)
    matches = pattern4.findall(logs_text)
    if matches:
        # Return the first one found (usually the checkout commit)
        return matches[0]
    
    return None


def parse_run_url(url: str) -> tuple[Optional[str], Optional[str]]:
    """
    Parse GitHub Actions run URL to extract repo and run ID.
    
    Args:
        url: GitHub Actions run URL
        
    Returns:
        Tuple of (repo, run_id) or (None, None) if parsing fails
    """
    # Examples:
    # https://github.com/armosec/shared-workflows/actions/runs/123456789
    # https://github.com/owner/repo/actions/runs/123456789
    
    try:
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) >= 4 and path_parts[-2] == 'runs':
            repo = f"{path_parts[0]}/{path_parts[1]}"
            run_id = path_parts[-1]
            return repo, run_id
    except Exception:
        pass
    
    return None, None


def main():
    parser = argparse.ArgumentParser(
        description='Extract git commit from GitHub Actions workflow run',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # From run URL
    python extract_workflow_commit.py https://github.com/armosec/shared-workflows/actions/runs/123456789
    
    # From run ID and repo
    python extract_workflow_commit.py --run-id 123456789 --repo armosec/shared-workflows
    
    # From logs file
    python extract_workflow_commit.py --logs workflow-logs.txt
    
    # Save to file
    python extract_workflow_commit.py --run-id 123456789 --repo armosec/shared-workflows --output artifacts/workflow-commit.txt
        """
    )
    parser.add_argument(
        'run_url_or_id',
        nargs='?',
        help='GitHub Actions run URL or numeric run ID'
    )
    parser.add_argument(
        '--run-id',
        type=str,
        help='GitHub Actions run ID (numeric)'
    )
    parser.add_argument(
        '--repo',
        type=str,
        help='Repository in format owner/repo (required if using --run-id)'
    )
    parser.add_argument(
        '--logs',
        type=argparse.FileType('r'),
        help='Workflow logs file (for fallback parsing)'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Output file path (default: print to stdout)'
    )
    parser.add_argument(
        '--token',
        type=str,
        help='GitHub token (or use GITHUB_TOKEN env var)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print verbose output'
    )
    
    args = parser.parse_args()
    
    commit_sha = None
    run_id = None
    repo = None
    
    # Parse input
    if args.run_url_or_id:
        # Try parsing as URL first
        repo, run_id = parse_run_url(args.run_url_or_id)
        if not run_id:
            # Assume it's a run ID
            run_id = args.run_url_or_id
    
    if args.run_id:
        run_id = args.run_id
    
    if args.repo:
        repo = args.repo
    
    # Method 1: Try GitHub API
    if run_id and repo:
        if args.verbose:
            print(f"Attempting to extract commit from GitHub API...", file=sys.stderr)
            print(f"  Repo: {repo}", file=sys.stderr)
            print(f"  Run ID: {run_id}", file=sys.stderr)
        
        commit_sha = extract_commit_from_api(run_id, repo, args.token)
        
        if commit_sha and args.verbose:
            print(f"Found commit via API: {commit_sha}", file=sys.stderr)
    
    # Method 2: Parse logs (fallback)
    if not commit_sha and args.logs:
        if args.verbose:
            print("Attempting to extract commit from logs...", file=sys.stderr)
        
        try:
            logs_text = args.logs.read()
            commit_sha = extract_commit_from_logs(logs_text)
            
            if commit_sha and args.verbose:
                print(f"Found commit via log parsing: {commit_sha}", file=sys.stderr)
        except Exception as e:
            print(f"Error reading logs: {e}", file=sys.stderr)
    
    # Output result
    if commit_sha:
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(commit_sha + '\n')
            if args.verbose:
                print(f"Saved to: {output_path}", file=sys.stderr)
        else:
            print(commit_sha)
        
        sys.exit(0)
    else:
        if args.verbose:
            print("No commit SHA found", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()


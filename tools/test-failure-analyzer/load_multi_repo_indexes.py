#!/usr/bin/env python3
"""
Load code indexes for multiple repositories.

This script loads indexes for all repositories listed in target_repositories
from system_test_mapping.json, handling different commits per repo.

Usage:
    python load_multi_repo_indexes.py \
      --test-name jira_integration \
      --mapping system_test_mapping.json \
      --registry index-registry.json \
      --workflow-commit 7e920e4d90e390f2d2f8736e8608ea4c8647a4bf \
      --output artifacts/loaded-indexes.json
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any

# Import find_indexes function
from find_indexes import find_indexes, load_registry


def load_test_mapping(mapping_path: str) -> Dict[str, Any]:
    """Load system_test_mapping.json."""
    if not os.path.exists(mapping_path):
        print(f"Error: Test mapping file not found: {mapping_path}", file=sys.stderr)
        sys.exit(1)
    
    with open(mapping_path, 'r') as f:
        return json.load(f)


def get_target_repositories(test_mapping: Dict[str, Any], test_name: str) -> List[str]:
    """
    Get target repositories for a specific test.
    
    Returns:
        List of repository names
    """
    if test_name not in test_mapping:
        print(f"Warning: Test '{test_name}' not found in mapping", file=sys.stderr)
        return []
    
    test_config = test_mapping[test_name]
    target_repos = test_config.get("target_repositories", [])
    
    if not target_repos:
        print(f"Warning: No target_repositories specified for test '{test_name}'", file=sys.stderr)
    
    return target_repos


def resolve_repo_commits(
    target_repos: List[str],
    workflow_commit: str,
    commit_overrides: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    """
    Resolve git commits for each repository.
    
    For now, uses the workflow commit for all repos. In Phase 6, this will
    be enhanced to resolve actual commits from kubernetes-deployment.
    
    Args:
        target_repos: List of repository names
        workflow_commit: Default commit to use (from workflow)
        commit_overrides: Optional dict mapping repo -> commit
    
    Returns:
        Dict mapping repo names to commit SHAs
    """
    repo_commits = {}
    overrides = commit_overrides or {}
    
    for repo in target_repos:
        # Use override if provided, otherwise use workflow commit
        repo_commits[repo] = overrides.get(repo, workflow_commit)
    
    return repo_commits


def load_indexes_for_repos(
    registry_path: str,
    repo_commits: Dict[str, str],
    generate_missing: bool = False
) -> Dict[str, Any]:
    """
    Load indexes for multiple repositories.
    
    Args:
        registry_path: Path to registry JSON file
        repo_commits: Dict mapping repo names to commit SHAs
        generate_missing: If True, generate indexes on-the-fly if missing
    
    Returns:
        Dict mapping repo names to loaded index data (or error info)
    """
    # Find indexes using find_indexes
    index_results = find_indexes(
        registry_path=registry_path,
        repo_commits=repo_commits,
        generate_missing=generate_missing
    )
    
    # Load actual index files for found indexes
    loaded_indexes = {}
    
    for repo, result in index_results.items():
        if result.get("found"):
            index_path = result.get("index_path")
            
            # Try to load the index file
            if index_path and os.path.exists(index_path):
                try:
                    with open(index_path, 'r') as f:
                        index_data = json.load(f)
                    loaded_indexes[repo] = {
                        "commit": result.get("commit"),
                        "index_data": index_data,
                        "source": result.get("source", "registry")
                    }
                    print(f"✅ Loaded index for {repo}@{result.get('commit', '')[:8]}")
                except Exception as e:
                    print(f"⚠️  Failed to load index file for {repo}: {e}", file=sys.stderr)
                    loaded_indexes[repo] = {
                        "commit": result.get("commit"),
                        "error": f"Failed to load index file: {e}",
                        "index_path": index_path
                    }
            elif index_path and index_path.startswith(("http://", "https://", "s3://")):
                # Remote index - store metadata but don't load
                loaded_indexes[repo] = {
                    "commit": result.get("commit"),
                    "index_url": result.get("index_url") or index_path,
                    "index_path": index_path,
                    "source": result.get("source", "registry"),
                    "note": "Remote index - not loaded"
                }
                print(f"✅ Found remote index for {repo}@{result.get('commit', '')[:8]}: {index_path}")
            else:
                loaded_indexes[repo] = {
                    "commit": result.get("commit"),
                    "error": f"Index file not found: {index_path}",
                    "index_path": index_path
                }
                print(f"⚠️  Index file not found for {repo}: {index_path}", file=sys.stderr)
        else:
            # Index not found
            loaded_indexes[repo] = {
                "commit": result.get("commit"),
                "error": result.get("error", "Index not found"),
                "found": False
            }
    
    return loaded_indexes


def main():
    parser = argparse.ArgumentParser(
        description="Load code indexes for multiple repositories"
    )
    parser.add_argument(
        "--test-name",
        help="Test name from system_test_mapping.json"
    )
    parser.add_argument(
        "--mapping",
        default="system_test_mapping.json",
        help="Path to system_test_mapping.json (default: system_test_mapping.json)"
    )
    parser.add_argument(
        "--registry",
        default="index-registry.json",
        help="Path to registry JSON file (default: index-registry.json)"
    )
    parser.add_argument(
        "--workflow-commit",
        required=True,
        help="Git commit SHA from workflow (used as default for all repos)"
    )
    parser.add_argument(
        "--commit-overrides",
        help="JSON dict of repo->commit overrides (e.g., '{\"cadashboardbe\":\"abc123...\"}')"
    )
    parser.add_argument(
        "--repos",
        nargs="+",
        help="Explicit list of repositories (overrides test-name)"
    )
    parser.add_argument(
        "--generate-missing",
        action="store_true",
        help="Generate indexes on-the-fly if not found"
    )
    parser.add_argument(
        "--output",
        help="Path to save loaded indexes JSON file"
    )
    
    args = parser.parse_args()
    
    # Determine target repositories
    if args.repos:
        target_repos = args.repos
    elif args.test_name:
        test_mapping = load_test_mapping(args.mapping)
        target_repos = get_target_repositories(test_mapping, args.test_name)
        if not target_repos:
            print(f"Error: No target repositories found for test '{args.test_name}'", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: Must specify either --test-name or --repos", file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    
    # Parse commit overrides
    commit_overrides = {}
    if args.commit_overrides:
        try:
            commit_overrides = json.loads(args.commit_overrides)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in --commit-overrides: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Resolve commits for each repo
    repo_commits = resolve_repo_commits(
        target_repos=target_repos,
        workflow_commit=args.workflow_commit,
        commit_overrides=commit_overrides
    )
    
    print(f"📦 Loading indexes for {len(repo_commits)} repositories:")
    for repo, commit in repo_commits.items():
        print(f"   {repo}@{commit[:8]}")
    
    # Load indexes
    loaded_indexes = load_indexes_for_repos(
        registry_path=args.registry,
        repo_commits=repo_commits,
        generate_missing=args.generate_missing
    )
    
    # Save results
    if args.output:
        os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(loaded_indexes, f, indent=2)
        print(f"\n📄 Loaded indexes saved to: {args.output}")
    
    # Print summary
    loaded_count = sum(1 for idx in loaded_indexes.values() if "index_data" in idx or "index_url" in idx)
    total_count = len(loaded_indexes)
    print(f"\n📊 Summary: {loaded_count}/{total_count} indexes loaded")
    
    # Exit with error if any indexes failed to load
    failed_count = sum(1 for idx in loaded_indexes.values() if "error" in idx and idx.get("error"))
    if failed_count > 0:
        print(f"⚠️  {failed_count} indexes failed to load", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


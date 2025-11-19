#!/usr/bin/env python3
"""
Find code indexes by git commit for multiple repositories.

This script queries the index registry to find code indexes for specific
git commits. It supports per-repo commit resolution and can generate
indexes on-the-fly if missing.

Usage:
    python find_indexes.py \
      --registry index-registry.json \
      --repo cadashboardbe --commit abc123... \
      --repo event-ingester-service --commit def456... \
      --output artifacts/found-indexes.json
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any


def load_registry(registry_path: str) -> Dict[str, Any]:
    """Load the index registry from file."""
    if not os.path.exists(registry_path):
        print(f"Warning: Registry file not found: {registry_path}", file=sys.stderr)
        return {}
    
    with open(registry_path, 'r') as f:
        return json.load(f)


def find_index_in_registry(
    registry: Dict[str, Any],
    repo: str,
    commit: str
) -> Optional[Dict[str, Any]]:
    """
    Find index entry in registry for a specific repo and commit.
    
    Returns:
        Index entry dict if found, None otherwise
    """
    if repo not in registry:
        return None
    
    repo_registry = registry[repo]
    if commit not in repo_registry:
        return None
    
    return repo_registry[commit]


def generate_index_on_the_fly(
    repo: str,
    commit: str,
    output_dir: str = "artifacts/generated-indexes"
) -> Optional[str]:
    """
    Generate index on-the-fly by checking out the commit and running indexgen.
    
    This is a fallback when index is not found in registry.
    
    Returns:
        Path to generated index file, or None if generation failed
    """
    print(f"⚠️  Index not found in registry for {repo}@{commit[:8]}", file=sys.stderr)
    print(f"   Attempting to generate index on-the-fly...", file=sys.stderr)
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # For now, return None - actual implementation would:
    # 1. Clone/checkout the repo at the specific commit
    # 2. Run indexgen to generate the index
    # 3. Return the path to the generated index
    
    print(f"   On-the-fly generation not yet implemented", file=sys.stderr)
    return None


def find_indexes(
    registry_path: str,
    repo_commits: Dict[str, str],
    generate_missing: bool = False,
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Find indexes for multiple repositories and commits.
    
    Args:
        registry_path: Path to registry JSON file
        repo_commits: Dict mapping repo names to commit SHAs
        generate_missing: If True, generate indexes on-the-fly if missing
        output_file: Optional path to save results JSON
    
    Returns:
        Dict mapping repo names to index info (or None if not found)
    """
    registry = load_registry(registry_path)
    results = {}
    
    for repo, commit in repo_commits.items():
        # Validate commit format
        if len(commit) != 40 or not all(c in '0123456789abcdef' for c in commit.lower()):
            print(f"Warning: Invalid commit format for {repo}: {commit}", file=sys.stderr)
            results[repo] = {
                "found": False,
                "error": "Invalid commit format"
            }
            continue
        
        # Try to find in registry
        index_entry = find_index_in_registry(registry, repo, commit)
        
        if index_entry:
            results[repo] = {
                "found": True,
                "commit": commit,
                "index_path": index_entry.get("index_path"),
                "index_url": index_entry.get("index_url"),
                "source": "registry"
            }
            print(f"✅ Found index for {repo}@{commit[:8]}: {index_entry.get('index_path')}")
        else:
            # Try to generate on-the-fly if requested
            if generate_missing:
                generated_path = generate_index_on_the_fly(repo, commit)
                if generated_path:
                    results[repo] = {
                        "found": True,
                        "commit": commit,
                        "index_path": generated_path,
                        "source": "generated"
                    }
                    print(f"✅ Generated index for {repo}@{commit[:8]}: {generated_path}")
                else:
                    results[repo] = {
                        "found": False,
                        "commit": commit,
                        "error": "Generation failed"
                    }
                    print(f"❌ Failed to generate index for {repo}@{commit[:8]}")
            else:
                results[repo] = {
                    "found": False,
                    "commit": commit,
                    "error": "Not found in registry"
                }
                print(f"❌ Index not found for {repo}@{commit[:8]}")
    
    # Save results if output file specified
    if output_file:
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n📄 Results saved to: {output_file}")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Find code indexes by git commit for multiple repositories"
    )
    parser.add_argument(
        "--registry",
        default="index-registry.json",
        help="Path to registry JSON file (default: index-registry.json)"
    )
    parser.add_argument(
        "--repo",
        action="append",
        dest="repos",
        metavar="REPO",
        help="Repository name (can be specified multiple times)"
    )
    parser.add_argument(
        "--commit",
        action="append",
        dest="commits",
        metavar="COMMIT",
        help="Git commit SHA (must match --repo order, can be specified multiple times)"
    )
    parser.add_argument(
        "--repo-commit",
        action="append",
        dest="repo_commits",
        metavar="REPO:COMMIT",
        help="Repository and commit in format 'repo:commit' (can be specified multiple times)"
    )
    parser.add_argument(
        "--generate-missing",
        action="store_true",
        help="Generate indexes on-the-fly if not found in registry"
    )
    parser.add_argument(
        "--output",
        help="Path to save results JSON file"
    )
    
    args = parser.parse_args()
    
    # Build repo_commits dict
    repo_commits = {}
    
    # Method 1: Using --repo-commit pairs
    if args.repo_commits:
        for pair in args.repo_commits:
            if ':' not in pair:
                print(f"Error: Invalid format for --repo-commit: {pair}", file=sys.stderr)
                print("Expected format: repo:commit", file=sys.stderr)
                sys.exit(1)
            repo, commit = pair.split(':', 1)
            repo_commits[repo] = commit
    
    # Method 2: Using --repo and --commit lists
    elif args.repos and args.commits:
        if len(args.repos) != len(args.commits):
            print("Error: Number of --repo and --commit arguments must match", file=sys.stderr)
            sys.exit(1)
        for repo, commit in zip(args.repos, args.commits):
            repo_commits[repo] = commit
    
    else:
        print("Error: Must specify either --repo-commit pairs or --repo/--commit lists", file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    
    if not repo_commits:
        print("Error: No repositories specified", file=sys.stderr)
        sys.exit(1)
    
    # Find indexes
    results = find_indexes(
        registry_path=args.registry,
        repo_commits=repo_commits,
        generate_missing=args.generate_missing,
        output_file=args.output
    )
    
    # Print summary
    found_count = sum(1 for r in results.values() if r.get("found"))
    total_count = len(results)
    print(f"\n📊 Summary: {found_count}/{total_count} indexes found")
    
    # Exit with error if any indexes not found
    if found_count < total_count:
        sys.exit(1)


if __name__ == "__main__":
    main()


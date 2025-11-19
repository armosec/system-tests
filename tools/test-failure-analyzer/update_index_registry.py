#!/usr/bin/env python3
"""
Update the index registry with a new index entry.

This script adds or updates an entry in the index registry for a specific
repository and git commit.

Usage:
    python update_index_registry.py \
      --repo cadashboardbe \
      --commit 7e920e4d90e390f2d2f8736e8608ea4c8647a4bf \
      --index-path s3://code-indexes/cadashboardbe/7e920e4/code-index.json \
      --registry-file index-registry.json
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


def load_registry(registry_path: str) -> Dict[str, Any]:
    """Load the index registry from file."""
    if os.path.exists(registry_path):
        with open(registry_path, 'r') as f:
            return json.load(f)
    return {}


def save_registry(registry_path: str, registry: Dict[str, Any]) -> None:
    """Save the index registry to file."""
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(registry_path) if os.path.dirname(registry_path) else '.', exist_ok=True)
    
    with open(registry_path, 'w') as f:
        json.dump(registry, f, indent=2, sort_keys=True)


def update_registry(
    registry_path: str,
    repo: str,
    commit: str,
    index_path: str,
    index_url: str = None,
    branch: str = None,
    tag: str = None,
    build_time: str = None
) -> None:
    """
    Update the registry with a new index entry.
    
    Args:
        registry_path: Path to registry JSON file
        repo: Repository name (e.g., cadashboardbe)
        commit: Full git commit SHA (40 characters)
        index_path: Path to the index file
        index_url: Optional URL to download the index
        branch: Git branch name
        tag: Git tag (if applicable)
        build_time: Build time from index metadata
    """
    # Validate commit format (should be 40-character hex)
    if len(commit) != 40 or not all(c in '0123456789abcdef' for c in commit.lower()):
        print(f"Error: Invalid commit SHA format: {commit}", file=sys.stderr)
        print("Expected 40-character hexadecimal string", file=sys.stderr)
        sys.exit(1)
    
    registry = load_registry(registry_path)
    
    # Initialize repo entry if it doesn't exist
    if repo not in registry:
        registry[repo] = {}
    
    # Create or update commit entry
    registry[repo][commit] = {
        "index_path": index_path,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    
    # Add optional fields
    if index_url:
        registry[repo][commit]["index_url"] = index_url
    if branch:
        registry[repo][commit]["branch"] = branch
    if tag:
        registry[repo][commit]["tag"] = tag
    if build_time:
        registry[repo][commit]["build_time"] = build_time
    
    save_registry(registry_path, registry)
    print(f"✅ Updated registry: {repo}@{commit[:8]} -> {index_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Update index registry with a new index entry"
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Repository name (e.g., cadashboardbe)"
    )
    parser.add_argument(
        "--commit",
        required=True,
        help="Full git commit SHA (40 characters)"
    )
    parser.add_argument(
        "--index-path",
        required=True,
        help="Path to the index file (S3 URL, GitHub artifact, or local path)"
    )
    parser.add_argument(
        "--index-url",
        help="Optional URL to download the index"
    )
    parser.add_argument(
        "--branch",
        help="Git branch name"
    )
    parser.add_argument(
        "--tag",
        help="Git tag (if applicable)"
    )
    parser.add_argument(
        "--build-time",
        help="Build time from index metadata"
    )
    parser.add_argument(
        "--registry-file",
        default="index-registry.json",
        help="Path to registry JSON file (default: index-registry.json)"
    )
    
    args = parser.parse_args()
    
    update_registry(
        registry_path=args.registry_file,
        repo=args.repo,
        commit=args.commit,
        index_path=args.index_path,
        index_url=args.index_url,
        branch=args.branch,
        tag=args.tag,
        build_time=args.build_time
    )


if __name__ == "__main__":
    main()


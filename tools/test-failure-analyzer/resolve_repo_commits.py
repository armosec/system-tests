#!/usr/bin/env python3
"""
Resolve git commits for each repository using a hierarchy of sources.

This script resolves the final commit SHA for each repository by combining:
1. Image tag to commit mappings (from map_tag_to_commit.py)
2. Workflow commit (fallback for repos without tag mappings)
3. Triggering repo handling (may use workflow commit directly)

The hierarchy for commit resolution:
1. If repo has commit from map_tag_to_commit.py -> use it
2. If triggering repo and no tag mapping -> use workflow commit
3. If non-triggering repo and no tag mapping -> use workflow commit (fallback)

Usage:
    python resolve_repo_commits.py \
      --running-images artifacts/running-images.json \
      --repo-commits artifacts/repo-commits.json \
      --workflow-commit artifacts/workflow-commit.txt \
      --output artifacts/resolved-repo-commits.json
"""

import argparse
import json
import os
import sys
from typing import Dict, Optional, Any
from pathlib import Path


def load_json_file(file_path: str) -> Dict[str, Any]:
    """Load JSON file."""
    if not os.path.exists(file_path):
        print(f"Warning: File not found: {file_path}", file=sys.stderr)
        return {}
    
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {file_path}: {e}", file=sys.stderr)
        sys.exit(1)


def load_text_file(file_path: str) -> Optional[str]:
    """Load text file and return content as string."""
    if not os.path.exists(file_path):
        return None
    
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            return content if content else None
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
        return None


def normalize_repo_name(repo_name: str) -> str:
    """Normalize repo name (remove org prefix if present)."""
    return repo_name.split('/')[-1]


def resolve_repo_commits(
    running_images: Dict[str, Any],
    repo_commits: Dict[str, Any],
    workflow_commit: Optional[str] = None
) -> Dict[str, str]:
    """
    Resolve git commits for each repository using hierarchy.
    
    Args:
        running_images: Output from extract_image_tags.py
        repo_commits: Output from map_tag_to_commit.py
        workflow_commit: Workflow commit SHA (fallback)
    
    Returns:
        Dictionary mapping repo names to commit SHAs
    """
    resolved: Dict[str, str] = {}
    
    # Extract triggering repo info
    triggering_repo_normalized = None
    if running_images.get("triggering_repo_normalized"):
        triggering_repo_normalized = running_images["triggering_repo_normalized"].lower()
    
    # Extract repo commits from map_tag_to_commit.py output
    tag_mapped_commits: Dict[str, str] = {}
    for repo_name, commit_info in repo_commits.items():
        if isinstance(commit_info, dict) and commit_info.get("commit"):
            tag_mapped_commits[repo_name.lower()] = commit_info["commit"]
    
    # Get list of repos from running_images
    repos_data = running_images.get("repos", {})
    
    print(f"🔍 Resolving commits for {len(repos_data)} repositories...")
    if workflow_commit:
        print(f"   Workflow commit (fallback): {workflow_commit[:8]}")
    if triggering_repo_normalized:
        print(f"   Triggering repo: {triggering_repo_normalized}")
    
    for repo_name, repo_data in repos_data.items():
        repo_normalized = repo_name.lower()
        is_triggering_repo = (triggering_repo_normalized and 
                             repo_normalized == triggering_repo_normalized)
        
        # Strategy 1: Use commit from tag mapping if available
        if repo_normalized in tag_mapped_commits:
            resolved[repo_name] = tag_mapped_commits[repo_normalized]
            source = "tag_mapping"
            print(f"   ✅ {repo_name}: {resolved[repo_name][:8]} (from tag mapping)")
        
        # Strategy 2: Fallback to workflow commit
        elif workflow_commit:
            resolved[repo_name] = workflow_commit
            source = "workflow_commit_fallback"
            trigger_note = " (triggering repo)" if is_triggering_repo else ""
            print(f"   ⚠️  {repo_name}: {resolved[repo_name][:8]} (workflow commit fallback{trigger_note})")
        
        # Strategy 3: No commit found
        else:
            print(f"   ❌ {repo_name}: No commit found (no tag mapping or workflow commit)", file=sys.stderr)
            # Still add it with None to indicate missing commit
            resolved[repo_name] = None
    
    return resolved


def main():
    parser = argparse.ArgumentParser(
        description="Resolve git commits for each repository using hierarchy."
    )
    parser.add_argument(
        "--running-images",
        required=True,
        help="Path to running-images.json (from extract_image_tags.py)"
    )
    parser.add_argument(
        "--repo-commits",
        required=True,
        help="Path to repo-commits.json (from map_tag_to_commit.py)"
    )
    parser.add_argument(
        "--workflow-commit",
        help="Path to workflow-commit.txt or commit SHA directly"
    )
    parser.add_argument(
        "--output",
        default="artifacts/resolved-repo-commits.json",
        help="Output file path (default: artifacts/resolved-repo-commits.json)"
    )
    
    args = parser.parse_args()
    
    # Load input files
    print(f"📖 Loading input files...")
    running_images = load_json_file(args.running_images)
    repo_commits = load_json_file(args.repo_commits)
    
    # Load workflow commit
    workflow_commit = None
    if args.workflow_commit:
        if os.path.exists(args.workflow_commit):
            # It's a file path
            workflow_commit = load_text_file(args.workflow_commit)
        else:
            # It's a commit SHA directly
            workflow_commit = args.workflow_commit.strip()
    
    # Fallback: Try to load from default location
    if not workflow_commit:
        default_workflow_commit_path = Path("artifacts/workflow-commit.txt")
        if default_workflow_commit_path.exists():
            workflow_commit = load_text_file(str(default_workflow_commit_path))
            if workflow_commit:
                print(f"   Loaded workflow commit from default location: {workflow_commit[:8]}")
    
    if not workflow_commit:
        print("   Warning: No workflow commit provided. Some repos may not have commits.", file=sys.stderr)
    
    # Resolve commits
    resolved_commits = resolve_repo_commits(
        running_images=running_images,
        repo_commits=repo_commits,
        workflow_commit=workflow_commit
    )
    
    # Calculate metadata
    tag_mapped_repo_names = {k.lower() for k, v in repo_commits.items() 
                             if isinstance(v, dict) and v.get("commit")}
    
    repos_with_tag_mapping = sum(1 for repo, commit in resolved_commits.items() 
                                 if commit and repo.lower() in tag_mapped_repo_names)
    repos_with_workflow_fallback = sum(1 for repo, commit in resolved_commits.items() 
                                       if commit and repo.lower() not in tag_mapped_repo_names)
    repos_without_commit = sum(1 for commit in resolved_commits.values() if not commit)
    
    # Prepare result with metadata
    result = {
        "workflow_commit": workflow_commit,
        "triggering_repo": running_images.get("triggering_repo"),
        "triggering_repo_normalized": running_images.get("triggering_repo_normalized"),
        "resolved_commits": resolved_commits,
        "metadata": {
            "total_repos": len(resolved_commits),
            "repos_with_tag_mapping": repos_with_tag_mapping,
            "repos_with_workflow_fallback": repos_with_workflow_fallback,
            "repos_without_commit": repos_without_commit
        }
    }
    
    # Save result
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📊 Summary:")
    print(f"   Total repos: {result['metadata']['total_repos']}")
    print(f"   With tag mapping: {result['metadata']['repos_with_tag_mapping']}")
    print(f"   With workflow fallback: {result['metadata']['repos_with_workflow_fallback']}")
    if result['metadata']['repos_without_commit'] > 0:
        print(f"   ⚠️  Without commit: {result['metadata']['repos_without_commit']}", file=sys.stderr)
    
    print(f"\n📄 Resolved commits saved to: {args.output}")
    
    # Exit with error if any repos are missing commits
    if result['metadata']['repos_without_commit'] > 0:
        print(f"\n❌ Error: {result['metadata']['repos_without_commit']} repo(s) have no commit", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


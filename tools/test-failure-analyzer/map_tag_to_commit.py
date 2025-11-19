#!/usr/bin/env python3
"""
Map image tags to git commits for backend components.

This script attempts to map image tags (e.g., "rc-v0.0.385-1452") to git commit SHAs
using multiple strategies in order of priority:

1. Container registry metadata (if available)
   - Query container registry API for image labels/annotations
   - Many registries store git commit in image metadata
2. Parse tag format (if standardized)
   - If tags contain commit hash: "rc-v0.0.385-1452-abc1234" -> "abc1234"
   - Extract commit from tag using regex patterns
3. Deployment manifest/metadata
   - Check if kubernetes-deployment tracks commits per component
   - Use deployment workflow artifacts if available
4. Fallback: Use workflow commit
   - Assume all repos from same deployment use same commit
   - Less accurate but better than nothing

Usage:
    python map_tag_to_commit.py --image-tags artifacts/running-images.json --workflow-commit <sha> --output artifacts/repo-commits.json
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Any
from pathlib import Path


def parse_commit_from_tag(tag: str) -> Optional[str]:
    """
    Try to extract git commit SHA from image tag format.
    
    Examples:
        "rc-v0.0.385-1452-abc1234" -> "abc1234" (if commit is at end)
        "v0.0.385-abc1234" -> "abc1234"
        "abc1234" -> "abc1234" (if tag is just commit)
    
    Args:
        tag: Image tag string
    
    Returns:
        Git commit SHA (7-40 hex characters) or None if not found
    """
    # Pattern 1: Commit hash at the end (7-40 hex chars)
    # e.g., "rc-v0.0.385-1452-abc1234" -> "abc1234"
    match = re.search(r'-([0-9a-f]{7,40})$', tag, re.IGNORECASE)
    if match:
        commit = match.group(1)
        # Validate it looks like a commit (at least 7 chars, all hex)
        if len(commit) >= 7 and all(c in '0123456789abcdef' for c in commit.lower()):
            return commit
    
    # Pattern 2: Commit hash anywhere in tag (if it's a full 40-char SHA)
    match = re.search(r'([0-9a-f]{40})', tag, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    
    # Pattern 3: Short commit hash (7 chars) anywhere
    match = re.search(r'([0-9a-f]{7})', tag, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    
    return None


def query_registry_metadata(image_string: str, registry_type: str = "quay") -> Optional[str]:
    """
    Query container registry for image metadata to extract git commit.
    
    This is a placeholder implementation. In practice, this would:
    - Use registry API (Quay.io, Docker Hub, ECR, GCR, etc.)
    - Query image labels/annotations
    - Extract git commit from labels like "io.quay.image.commit" or "git.commit"
    
    Args:
        image_string: Full image string (e.g., "quay.io/armosec/cadashboardbe:rc-v0.0.385-1452")
        registry_type: Type of registry ("quay", "docker", "ecr", "gcr")
    
    Returns:
        Git commit SHA or None if not found
    """
    # Placeholder: In real implementation, would query registry API
    # For now, return None to indicate this method is not available
    return None


def get_commit_from_deployment_metadata(repo_name: str, image_tag: str, deployment_metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Try to get commit from deployment metadata if available.
    
    Args:
        repo_name: Repository name
        image_tag: Image tag
        deployment_metadata: Optional deployment metadata dict
    
    Returns:
        Git commit SHA or None if not found
    """
    if not deployment_metadata:
        return None
    
    # Check if deployment metadata tracks commits per component
    if "components" in deployment_metadata:
        component_data = deployment_metadata["components"].get(repo_name, {})
        if "git_commit" in component_data:
            return component_data["git_commit"]
        if "commit" in component_data:
            return component_data["commit"]
    
    # Check if there's a mapping by image tag
    if "image_tag_to_commit" in deployment_metadata:
        mapping = deployment_metadata["image_tag_to_commit"]
        if repo_name in mapping:
            repo_mapping = mapping[repo_name]
            if image_tag in repo_mapping:
                return repo_mapping[image_tag]
    
    return None


def map_image_tag_to_commit(
    repo_name: str,
    image_string: str,
    image_tag: str,
    workflow_commit: Optional[str] = None,
    deployment_metadata: Optional[Dict[str, Any]] = None,
    registry_type: str = "quay"
) -> Dict[str, Any]:
    """
    Map an image tag to a git commit using multiple strategies.
    
    Args:
        repo_name: Repository name
        image_string: Full image string
        image_tag: Image tag (e.g., "rc-v0.0.385-1452")
        workflow_commit: Workflow commit SHA (fallback)
        deployment_metadata: Optional deployment metadata
        registry_type: Container registry type
    
    Returns:
        Dictionary with commit info and source
    """
    result = {
        "repo_name": repo_name,
        "image_string": image_string,
        "image_tag": image_tag,
        "commit": None,
        "source": None,
        "methods_tried": []
    }
    
    # Strategy 1: Try to parse commit from tag format
    parsed_commit = parse_commit_from_tag(image_tag)
    if parsed_commit:
        result["commit"] = parsed_commit
        result["source"] = "tag_parsing"
        result["methods_tried"].append("tag_parsing")
        return result
    result["methods_tried"].append("tag_parsing")
    
    # Strategy 2: Query container registry metadata
    registry_commit = query_registry_metadata(image_string, registry_type)
    if registry_commit:
        result["commit"] = registry_commit
        result["source"] = "registry_metadata"
        result["methods_tried"].append("registry_metadata")
        return result
    result["methods_tried"].append("registry_metadata")
    
    # Strategy 3: Check deployment metadata
    deployment_commit = get_commit_from_deployment_metadata(repo_name, image_tag, deployment_metadata)
    if deployment_commit:
        result["commit"] = deployment_commit
        result["source"] = "deployment_metadata"
        result["methods_tried"].append("deployment_metadata")
        return result
    result["methods_tried"].append("deployment_metadata")
    
    # Strategy 4: Fallback to workflow commit
    if workflow_commit:
        result["commit"] = workflow_commit
        result["source"] = "workflow_commit_fallback"
        result["methods_tried"].append("workflow_commit_fallback")
        return result
    result["methods_tried"].append("workflow_commit_fallback")
    
    # No commit found
    result["source"] = "not_found"
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Map image tags to git commits for backend components."
    )
    parser.add_argument(
        "--image-tags",
        required=True,
        help="Path to running-images.json file (output from extract_image_tags.py)"
    )
    parser.add_argument(
        "--workflow-commit",
        help="Workflow commit SHA (used as fallback if tag parsing fails)"
    )
    parser.add_argument(
        "--deployment-metadata",
        help="Path to deployment metadata JSON file (optional)"
    )
    parser.add_argument(
        "--registry-type",
        default="quay",
        choices=["quay", "docker", "ecr", "gcr"],
        help="Container registry type (default: quay)"
    )
    parser.add_argument(
        "--output",
        default="artifacts/repo-commits.json",
        help="Output file path (default: artifacts/repo-commits.json)"
    )
    
    args = parser.parse_args()
    
    # Create output directory if needed
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Load image tags
    print(f"📖 Loading image tags from: {args.image_tags}")
    if not os.path.exists(args.image_tags):
        print(f"Error: Image tags file not found: {args.image_tags}", file=sys.stderr)
        sys.exit(1)
    
    with open(args.image_tags, 'r') as f:
        image_tags_data = json.load(f)
    
    # Load deployment metadata if provided
    deployment_metadata = None
    if args.deployment_metadata:
        print(f"📖 Loading deployment metadata from: {args.deployment_metadata}")
        if os.path.exists(args.deployment_metadata):
            with open(args.deployment_metadata, 'r') as f:
                deployment_metadata = json.load(f)
        else:
            print(f"   Warning: Deployment metadata file not found: {args.deployment_metadata}", file=sys.stderr)
    
    # Load workflow commit if provided
    workflow_commit = args.workflow_commit
    if not workflow_commit:
        # Try to load from artifacts/workflow-commit.txt
        workflow_commit_path = Path("artifacts/workflow-commit.txt")
        if workflow_commit_path.exists():
            with open(workflow_commit_path, 'r') as f:
                workflow_commit = f.read().strip()
            print(f"📖 Loaded workflow commit from artifacts/workflow-commit.txt: {workflow_commit}")
    
    print(f"\n🔍 Mapping image tags to git commits...")
    print(f"   Registry type: {args.registry_type}")
    if workflow_commit:
        print(f"   Workflow commit (fallback): {workflow_commit}")
    
    # Map each repo's images to commits
    repo_commits: Dict[str, Dict[str, Any]] = {}
    repos_data = image_tags_data.get("repos", {})
    
    for repo_name, repo_data in repos_data.items():
        images = repo_data.get("images", [])
        if not images:
            continue
        
        # Use the first image (or could use latest/most recent)
        primary_image = images[0]
        image_string = primary_image.get("full_image", primary_image.get("image", ""))
        image_tag = primary_image.get("tag", "")
        
        print(f"\n   {repo_name}:")
        print(f"     Image: {image_string}")
        print(f"     Tag: {image_tag}")
        
        # Map tag to commit
        commit_info = map_image_tag_to_commit(
            repo_name=repo_name,
            image_string=image_string,
            image_tag=image_tag,
            workflow_commit=workflow_commit,
            deployment_metadata=deployment_metadata,
            registry_type=args.registry_type
        )
        
        repo_commits[repo_name] = commit_info
        
        if commit_info["commit"]:
            print(f"     ✅ Commit: {commit_info['commit']} (source: {commit_info['source']})")
        else:
            print(f"     ⚠️  No commit found (tried: {', '.join(commit_info['methods_tried'])})")
    
    # Prepare result
    result = {
        "workflow_commit": workflow_commit,
        "registry_type": args.registry_type,
        "source_image_tags_file": args.image_tags,
        "repos": repo_commits
    }
    
    # Save result
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    # Summary
    print(f"\n📊 Summary:")
    total_repos = len(repo_commits)
    found_commits = sum(1 for r in repo_commits.values() if r["commit"])
    print(f"   Total repositories: {total_repos}")
    print(f"   Commits found: {found_commits}")
    print(f"   Commits not found: {total_repos - found_commits}")
    
    if found_commits < total_repos:
        print(f"\n   ⚠️  Some repositories could not be mapped to commits.")
        print(f"   They will use workflow commit fallback: {workflow_commit or 'N/A'}")
    
    print(f"\n📄 Results saved to: {args.output}")


if __name__ == "__main__":
    main()


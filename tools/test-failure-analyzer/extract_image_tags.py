#!/usr/bin/env python3
"""
Extract image tags for backend components from deployment configuration files.

This script extracts image tags for backend components (cadashboardbe, config-service,
users-notification-service, event-ingester-service) from:
1. Event-sourcing-chart values files (RECOMMENDED)
   - YAML files from kubernetes-deployment/event-sourcing-chart/
   - stage-env-values.yaml, prod-env-values.yaml, prod-ohio-env-values.yaml
   - Contains image tags for all backend services deployed in each environment
2. Deployment workflow artifacts (GitHub Actions)
   - Artifacts from the deployment workflow that deployed the services being tested
   - Looks for image-tags.json, deployment-images.json, etc. in artifacts directory
3. Deployment manifests (if manually provided)
   - Kubernetes YAML/JSON files from kubernetes-deployment repo
4. Image tag files (if manually provided)
   - Direct JSON file with image tag mappings

Focus: Backend components only (not frontend, operators, or other services).

IMPORTANT: The system test workflow does NOT deploy services - it tests against already-deployed services.
Image tags must come from the DEPLOYMENT configuration that defines what's running in each environment.

IMPORTANT DISTINCTION:
- Triggering repos: The repository that triggered the test (e.g., cadashboardbe, event-ingester-service)
- Services: Actual services running in the environment (may be colloquially called "ingesters" but could come from any repo)

The actual source repository for each service is ALWAYS determined from the image.repository field,
NOT from service naming conventions or service keys. Services called "ingesters" might come from
event-ingester-service repo, but could also come from other repos - always check the image name.

Usage:
    # From event-sourcing-chart values file (RECOMMENDED - contains all backend service images)
    python extract_image_tags.py --event-sourcing-values event-sourcing-chart/stage-env-values.yaml --test-run-id <id> --output artifacts/running-images.json
    
    # From deployment workflow artifacts
    # Download artifacts from the deployment workflow run first, then:
    python extract_image_tags.py --workflow-artifacts artifacts/ --test-run-id <id> --output artifacts/running-images.json
    
    # From manually downloaded deployment manifest
    python extract_image_tags.py --deployment-manifest path/to/deployment.yaml --test-run-id <id> --output artifacts/running-images.json
    
    # From image tags file
    python extract_image_tags.py --image-tags image-tags.json --test-run-id <id> --output artifacts/running-images.json
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Any
from pathlib import Path

# Backend components only - focus on services that have code indexes
BACKEND_REPOS = {
    "cadashboardbe": {
        "aliases": ["dashboard-be", "dashboardbe", "ca-dashboard-be", "ca-dashboardbe"],
        "image_patterns": ["cadashboardbe", "dashboard-be", "dashboardbe"]
    },
    "config-service": {
        "aliases": ["configservice", "portal", "config"],
        "image_patterns": ["config-service", "configservice", "portal"]
    },
    "users-notification-service": {
        "aliases": ["users-notifications-service", "usersnotification", "users-notification"],
        "image_patterns": ["users-notification-service", "users-notifications-service", "usersnotification"]
    },
    "event-ingester-service": {
        "aliases": ["event-ingester", "eventingester", "event-ingester-service"],
        "image_patterns": ["event-ingester", "event-ingester-service", "eventingester"]
    }
}


def map_image_to_repo(image_string: str) -> Optional[str]:
    """
    Map an image string to a backend repository name.
    
    Args:
        image_string: Full image string (e.g., "registry.io/armosec/cadashboardbe:tag")
    
    Returns:
        Repository name or None if not a backend component
    """
    image_lower = image_string.lower()
    
    # Check each backend repo's image patterns
    for repo_name, repo_info in BACKEND_REPOS.items():
        for pattern in repo_info["image_patterns"]:
            if pattern.lower() in image_lower:
                return repo_name
    
    return None


def extract_image_tag(image_string: str) -> str:
    """
    Extract image tag from full image string.
    
    Examples:
        "registry.io/repo/image:tag" -> "tag"
        "registry.io/repo/image@sha256:abc123" -> "sha256:abc123"
        "registry.io/repo/image" -> "latest" (default)
    """
    if "@" in image_string:
        # Digest format: image@sha256:abc123
        return image_string.split("@")[1]
    elif ":" in image_string:
        # Tag format: image:tag
        return image_string.split(":")[-1]
    else:
        return "latest"


def extract_from_event_sourcing_values(values_file_path: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract image tags from event-sourcing-chart values YAML files.
    
    These files are in kubernetes-deployment/event-sourcing-chart/:
    - stage-env-values.yaml
    - prod-env-values.yaml
    - prod-ohio-env-values.yaml
    
    Args:
        values_file_path: Path to the values YAML file
    
    Returns:
        Dictionary mapping repo names to image info
    """
    repo_images: Dict[str, List[Dict[str, Any]]] = {}
    
    try:
        import yaml
        with open(values_file_path, 'r') as f:
            data = yaml.safe_load(f)
        
        if not data:
            return repo_images
        
        # Map of service keys in YAML to repo names
        # These are top-level keys in the YAML file (case-insensitive matching)
        # 
        # IMPORTANT DISTINCTION:
        # - Triggering repos: The repository that triggered the test (e.g., cadashboardbe, event-ingester-service)
        # - Services: Actual services running in the environment (may be colloquially called "ingesters" but could come from any repo)
        # 
        # Services may be colloquially called "ingesters" but they might NOT always come from 
        # event-ingester-service repo. The actual source repo is ALWAYS determined by the image.repository 
        # field, NOT by service naming conventions or service keys.
        # 
        # This mapping is only used as an initial hint - the final repo assignment comes from 
        # map_image_to_repo() which analyzes the actual image repository name.
        service_keys = {
            "dashboardBE": "cadashboardbe",
            "dashboard-be": "cadashboardbe",
            "dashboardBackend": "cadashboardbe",
            "configService": "config-service",
            "config-service": "config-service",
            "kubescapeConfigService": "config-service",  # camelCase version
            "kubescape-config-service": "config-service",
            "usersNotificationService": "users-notification-service",
            "users-notification-service": "users-notification-service",
            "eventIngester": "event-ingester-service",
            "event-ingester": "event-ingester-service",
            "event-ingester-service": "event-ingester-service",
            "dataPurger": "event-ingester-service",  # Common case, but actual repo determined from image.repository
            # Note: Services colloquially called "ingesters" may come from event-ingester-service repo,
            # but could also come from other repos. Always check image.repository to determine actual source.
        }
        
        def extract_from_nested_dict(obj: dict, parent_key: str = "") -> None:
            """Recursively extract image tags from nested YAML structure."""
            for key, value in obj.items():
                current_key = key
                full_path = f"{parent_key}.{key}" if parent_key else key
                
                # Check if this is a service we care about
                repo_name = None
                for service_key, repo in service_keys.items():
                    if key == service_key or key.lower() == service_key.lower():
                        repo_name = repo
                        break
                
                # If this is a service key, look for image.repository and image.tag
                if repo_name and isinstance(value, dict):
                    image_section = value.get("image", {})
                    if isinstance(image_section, dict):
                        repository = image_section.get("repository", "")
                        tag = image_section.get("tag", "")
                        if repository and tag:
                            image_string = f"{repository}:{tag}"
                            
                            # CRITICAL: Determine actual repo from image repository name, NOT from service key or naming
                            # Services may be colloquially called "ingesters" but could come from any repo.
                            # The image.repository field is the source of truth for determining the actual source repo.
                            actual_repo = map_image_to_repo(repository)
                            if not actual_repo:
                                # Fallback to service key mapping only if image doesn't match any known patterns
                                actual_repo = repo_name
                            
                            if actual_repo not in repo_images:
                                repo_images[actual_repo] = []
                            
                            # Build note explaining the mapping
                            note_parts = [f"Service key '{key}' initially mapped to '{repo_name}'"]
                            if actual_repo != repo_name:
                                note_parts.append(f"but actual repo is '{actual_repo}' (determined from image '{repository}')")
                            else:
                                note_parts.append(f"confirmed as '{actual_repo}' from image '{repository}'")
                            
                            repo_images[actual_repo].append({
                                "image": image_string,
                                "tag": tag,
                                "full_image": image_string,
                                "repository": repository,
                                "source": f"event_sourcing_values:{os.path.basename(values_file_path)}",
                                "yaml_path": full_path,
                                "service_key": key,  # Service key from YAML (e.g., "dataPurger", "dashboardBE")
                                "service_key_mapped_to_repo": repo_name,  # Initial mapping from service key (hint only)
                                "actual_repo": actual_repo,  # Actual repo determined from image.repository (source of truth)
                                "note": " | ".join(note_parts)
                            })
                
                # Recurse into nested dicts
                if isinstance(value, dict):
                    extract_from_nested_dict(value, full_path)
        
        extract_from_nested_dict(data)
        
    except ImportError:
        print("   Warning: PyYAML not installed. Install with: pip install pyyaml", file=sys.stderr)
    except Exception as e:
        print(f"   Error reading event-sourcing values file: {e}", file=sys.stderr)
    
    return repo_images


def extract_from_deployment_manifest(manifest_path: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract image tags from Kubernetes deployment manifest (YAML or JSON).
    
    Args:
        manifest_path: Path to deployment manifest file
    
    Returns:
        Dictionary mapping repo names to image info
    """
    repo_images: Dict[str, List[Dict[str, Any]]] = {}
    
    try:
        with open(manifest_path, 'r') as f:
            content = f.read()
        
        # Try JSON first
        try:
            data = json.loads(content)
            manifests = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            # Try YAML
            try:
                import yaml
                manifests = yaml.safe_load_all(content) if '---' in content else [yaml.safe_load(content)]
            except ImportError:
                print("   Warning: PyYAML not installed. Install with: pip install pyyaml", file=sys.stderr)
                return {}
        
        for manifest in manifests:
            if not manifest:
                continue
            
            # Extract images from containers
            containers = []
            if manifest.get("spec", {}).get("template", {}).get("spec", {}).get("containers"):
                containers.extend(manifest["spec"]["template"]["spec"]["containers"])
            if manifest.get("spec", {}).get("template", {}).get("spec", {}).get("initContainers"):
                containers.extend(manifest["spec"]["template"]["spec"]["initContainers"])
            
            for container in containers:
                image_string = container.get("image", "")
                if not image_string:
                    continue
                
                repo_name = map_image_to_repo(image_string)
                if not repo_name:
                    continue  # Skip non-backend components
                
                image_tag = extract_image_tag(image_string)
                
                if repo_name not in repo_images:
                    repo_images[repo_name] = []
                
                repo_images[repo_name].append({
                    "image": image_string,
                    "tag": image_tag,
                    "full_image": image_string,
                    "container_name": container.get("name", "unknown"),
                    "source": "deployment_manifest"
                })
    
    except Exception as e:
        print(f"   Error reading deployment manifest: {e}", file=sys.stderr)
    
    return repo_images


def extract_from_image_tags_file(tags_file: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract image tags from a JSON file with image tag mappings.
    
    Expected format:
    {
        "cadashboardbe": "registry.io/armosec/cadashboardbe:tag",
        "config-service": "registry.io/armosec/config-service:tag",
        ...
    }
    
    Args:
        tags_file: Path to JSON file with image tags
    
    Returns:
        Dictionary mapping repo names to image info
    """
    repo_images: Dict[str, List[Dict[str, Any]]] = {}
    
    try:
        with open(tags_file, 'r') as f:
            data = json.load(f)
        
        for repo_name, image_string in data.items():
            if repo_name not in BACKEND_REPOS:
                continue  # Skip non-backend components
            
            image_tag = extract_image_tag(image_string)
            
            repo_images[repo_name] = [{
                "image": image_string,
                "tag": image_tag,
                "full_image": image_string,
                "source": "image_tags_file"
            }]
    
    except Exception as e:
        print(f"   Error reading image tags file: {e}", file=sys.stderr)
    
    return repo_images


def extract_from_workflow_artifacts(artifacts_dir: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract image tags from workflow artifacts directory.
    
    Looks for files like:
    - image-tags.json
    - deployment-images.json
    - *.image-tags
    
    Args:
        artifacts_dir: Path to workflow artifacts directory
    
    Returns:
        Dictionary mapping repo names to image info
    """
    repo_images: Dict[str, List[Dict[str, Any]]] = {}
    artifacts_path = Path(artifacts_dir)
    
    if not artifacts_path.exists():
        return repo_images
    
    # Look for common artifact file names
    artifact_patterns = [
        "image-tags.json",
        "deployment-images.json",
        "*.image-tags",
        "images.json"
    ]
    
    for pattern in artifact_patterns:
        for artifact_file in artifacts_path.glob(pattern):
            try:
                with open(artifact_file, 'r') as f:
                    data = json.load(f)
                
                # Try different data structures
                if isinstance(data, dict):
                    # Direct mapping: {"cadashboardbe": "image:tag"}
                    for repo_name, image_string in data.items():
                        if repo_name in BACKEND_REPOS and isinstance(image_string, str):
                            image_tag = extract_image_tag(image_string)
                            if repo_name not in repo_images:
                                repo_images[repo_name] = []
                            repo_images[repo_name].append({
                                "image": image_string,
                                "tag": image_tag,
                                "full_image": image_string,
                                "source": f"workflow_artifact:{artifact_file.name}"
                            })
                    # Nested structure: {"repos": {"cadashboardbe": {"image": "..."}}}
                    if "repos" in data:
                        for repo_name, repo_data in data["repos"].items():
                            if repo_name in BACKEND_REPOS and isinstance(repo_data, dict):
                                image_string = repo_data.get("image") or repo_data.get("image_string")
                                if image_string:
                                    image_tag = extract_image_tag(image_string)
                                    if repo_name not in repo_images:
                                        repo_images[repo_name] = []
                                    repo_images[repo_name].append({
                                        "image": image_string,
                                        "tag": image_tag,
                                        "full_image": image_string,
                                        "source": f"workflow_artifact:{artifact_file.name}"
                                    })
            except Exception as e:
                print(f"   Warning: Could not parse {artifact_file}: {e}", file=sys.stderr)
    
    return repo_images


def main():
    parser = argparse.ArgumentParser(
        description="Extract image tags for backend components from deployment configuration files."
    )
    parser.add_argument(
        "--event-sourcing-values",
        help="Path to event-sourcing-chart values YAML file (e.g., stage-env-values.yaml, prod-env-values.yaml)"
    )
    parser.add_argument(
        "--deployment-manifest",
        help="Path to Kubernetes deployment manifest (YAML or JSON)"
    )
    parser.add_argument(
        "--workflow-artifacts",
        help="Path to workflow artifacts directory"
    )
    parser.add_argument(
        "--image-tags",
        help="Path to JSON file with image tag mappings"
    )
    parser.add_argument(
        "--test-run-id",
        help="Test run ID (for identification)"
    )
    parser.add_argument(
        "--triggering-repo",
        help="Repository that triggered the test (e.g., 'armosec/cadashboardbe' or 'cadashboardbe'). Used to distinguish triggering repo from services."
    )
    parser.add_argument(
        "--rc-version",
        help="Release candidate version tag (e.g., rc-v0.0.224-2437) - for test failure analysis"
    )
    parser.add_argument(
        "--output",
        default="artifacts/running-images.json",
        help="Output file path (default: artifacts/running-images.json)"
    )
    
    args = parser.parse_args()
    
    # Create output directory if needed
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"🔍 Extracting backend component image tags...")
    print(f"   Focus: Backend services only (cadashboardbe, config-service, users-notification-service, event-ingester-service)")
    
    # Normalize triggering repo (remove org prefix if present)
    triggering_repo_normalized = None
    if args.triggering_repo:
        triggering_repo_normalized = args.triggering_repo.split('/')[-1]  # e.g., "armosec/cadashboardbe" -> "cadashboardbe"
        print(f"   Triggering repo: {args.triggering_repo} (normalized: {triggering_repo_normalized})")
    
    repo_images: Dict[str, List[Dict[str, Any]]] = {}
    
    # Try event-sourcing values file first (recommended for backend services)
    if args.event_sourcing_values:
        print(f"   Reading event-sourcing values file: {args.event_sourcing_values}")
        values_images = extract_from_event_sourcing_values(args.event_sourcing_values)
        for repo_name, images in values_images.items():
            if repo_name not in repo_images:
                repo_images[repo_name] = []
            repo_images[repo_name].extend(images)
    
    # Try deployment manifest
    if args.deployment_manifest:
        print(f"   Reading deployment manifest: {args.deployment_manifest}")
        manifest_images = extract_from_deployment_manifest(args.deployment_manifest)
        for repo_name, images in manifest_images.items():
            if repo_name not in repo_images:
                repo_images[repo_name] = []
            repo_images[repo_name].extend(images)
    
    # Try workflow artifacts
    if args.workflow_artifacts:
        print(f"   Reading workflow artifacts: {args.workflow_artifacts}")
        artifact_images = extract_from_workflow_artifacts(args.workflow_artifacts)
        for repo_name, images in artifact_images.items():
            if repo_name not in repo_images:
                repo_images[repo_name] = []
            repo_images[repo_name].extend(images)
    
    # Try image tags file
    if args.image_tags:
        print(f"   Reading image tags file: {args.image_tags}")
        tags_images = extract_from_image_tags_file(args.image_tags)
        for repo_name, images in tags_images.items():
            if repo_name not in repo_images:
                repo_images[repo_name] = []
            repo_images[repo_name].extend(images)
    
    if not repo_images:
        print("   Warning: No backend component images found.", file=sys.stderr)
        print("   Provide --event-sourcing-values, --deployment-manifest, --workflow-artifacts, or --image-tags", file=sys.stderr)
        # Create empty result
        result = {
            "test_run_id": args.test_run_id,
            "rc_version": args.rc_version,
            "source": "none",
            "repos": {}
        }
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"   Empty result saved to: {args.output}")
        sys.exit(0)
    
    # Prepare result - deduplicate images per repo
    # Debug logging
    print(f"🔍 Debug - Received RC_VERSION: '{args.rc_version}'", file=sys.stderr)
    print(f"🔍 Debug - Triggering repo: '{args.triggering_repo}'", file=sys.stderr)
    
    result = {
        "test_run_id": args.test_run_id,
        "rc_version": args.rc_version,  # Release candidate version tag (e.g., rc-v0.0.224-2437)
        "triggering_repo": args.triggering_repo,  # Full repo name (e.g., "armosec/cadashboardbe")
        "triggering_repo_normalized": triggering_repo_normalized,  # Normalized name (e.g., "cadashboardbe")
        "source": "event_sourcing_values" if args.event_sourcing_values else "deployment_manifest" if args.deployment_manifest else "workflow_artifacts" if args.workflow_artifacts else "image_tags_file",
        "repos": {}
    }
    
    for repo_name, images in repo_images.items():
        # Deduplicate by full_image
        unique_images = {}
        for image_info in images:
            image_key = image_info["full_image"]
            if image_key not in unique_images:
                unique_images[image_key] = image_info
        
        # Mark if this repo is the triggering repo
        is_triggering_repo = (triggering_repo_normalized and 
                             repo_name.lower() == triggering_repo_normalized.lower())
        
        result["repos"][repo_name] = {
            "images": list(unique_images.values()),
            "is_triggering_repo": is_triggering_repo,  # True if this repo triggered the test
            "note": "This is the triggering repo" if is_triggering_repo else 
                   f"Service from {repo_name} repo (not the triggering repo)"
        }
    
    # Save result
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📊 Summary:")
    print(f"   Backend repositories found: {len(repo_images)}")
    for repo_name, images in repo_images.items():
        unique_tags = set(img["tag"] for img in images)
        print(f"     {repo_name}: {len(images)} image(s), {len(unique_tags)} unique tag(s)")
        for img in images:
            print(f"       - {img['tag']} ({img.get('source', 'unknown')})")
    
    print(f"\n📄 Results saved to: {args.output}")


if __name__ == "__main__":
    main()


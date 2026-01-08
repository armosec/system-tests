#!/usr/bin/env python3
"""
Detect actual dependencies used in code chunks.

This script analyzes import statements in code chunks to determine which
dependencies are actually referenced, enabling smart filtering of code indexes.

Usage:
    python detect_dependencies.py \
      --chunks artifacts/filtered-chunks.json \
      --available-indexes artifacts/found-indexes.json \
      --output artifacts/detected-dependencies.json
"""

import argparse
import json
import os
import re
import sys
from collections import Counter
from typing import Dict, List, Set, Any, Tuple


def extract_repo_from_import(import_path: str) -> Tuple[str, str]:
    """
    Extract GitHub org and repository name from Go import path.
    
    Examples:
        github.com/armosec/postgres-connector/dal -> ('armosec', 'postgres-connector')
        github.com/kubescape/storage/pkg/apis -> ('kubescape', 'storage')
        github.com/armosec/utils-go/httputils -> ('armosec', 'utils-go')
    
    Returns:
        Tuple of (org, repo) or (None, None) if not github.com/armosec|kubescape
    """
    match = re.match(r'github\.com/(armosec|kubescape)/([^/]+)', import_path)
    if match:
        return match.group(1), match.group(2)
    return None, None


def analyze_imports_in_chunk(chunk: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    Extract all armosec/kubescape imports from a chunk's code.
    
    Args:
        chunk: Code chunk dict with 'code' field
    
    Returns:
        List of (org, repo) tuples
    """
    code = chunk.get("code", "")
    if not code:
        return []
    
    imports = []
    
    # Pattern 1: Single import statement
    # import "github.com/armosec/postgres-connector/dal"
    single_import_pattern = r'import\s+"([^"]+)"'
    for match in re.finditer(single_import_pattern, code):
        import_path = match.group(1)
        org, repo = extract_repo_from_import(import_path)
        if org and repo:
            imports.append((org, repo))
    
    # Pattern 2: Import with alias
    # import pc "github.com/armosec/postgres-connector/dal"
    alias_import_pattern = r'import\s+\w+\s+"([^"]+)"'
    for match in re.finditer(alias_import_pattern, code):
        import_path = match.group(1)
        org, repo = extract_repo_from_import(import_path)
        if org and repo:
            imports.append((org, repo))
    
    # Pattern 3: Multi-line import block
    # import (
    #     "github.com/armosec/postgres-connector/dal"
    #     pc "github.com/armosec/storage/pkg/apis"
    # )
    import_block_pattern = r'import\s+\((.*?)\)'
    for match in re.finditer(import_block_pattern, code, re.DOTALL):
        block = match.group(1)
        # Extract all quoted paths from block
        path_pattern = r'"([^"]+)"'
        for path_match in re.finditer(path_pattern, block):
            import_path = path_match.group(1)
            org, repo = extract_repo_from_import(import_path)
            if org and repo:
                imports.append((org, repo))
    
    return imports


def analyze_all_chunks(chunks: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Analyze imports across all chunks from all repos.
    
    Args:
        chunks: Dict mapping repo_name -> list of chunks
    
    Returns:
        Dict with detected dependencies and statistics
    """
    # Track import counts
    import_counts = Counter()
    chunks_by_repo = {}
    total_chunks = 0
    
    # Analyze each repo's chunks
    for repo_name, chunk_list in chunks.items():
        chunks_by_repo[repo_name] = len(chunk_list)
        total_chunks += len(chunk_list)
        
        for chunk in chunk_list:
            imports = analyze_imports_in_chunk(chunk)
            for org, repo in imports:
                # Use full name org/repo
                import_counts[(org, repo)] += 1
    
    # Build dependency list
    detected_dependencies = []
    for (org, repo), count in import_counts.most_common():
        detected_dependencies.append({
            "github_org": org,
            "repository": repo,
            "import_count": count,
            "priority": "high" if count >= 10 else "medium" if count >= 3 else "low"
        })
    
    return {
        "total_chunks_analyzed": total_chunks,
        "chunks_by_repo": chunks_by_repo,
        "detected_dependencies": detected_dependencies,
        "total_unique_dependencies": len(detected_dependencies)
    }


def filter_available_indexes(
    detected_deps: List[Dict[str, Any]],
    available_indexes: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Filter available indexes to only include detected dependencies.
    
    Args:
        detected_deps: List of detected dependencies with import counts
        available_indexes: Dict from found-indexes.json
    
    Returns:
        Filtered index info with priorities
    """
    indexes = available_indexes.get('indexes', {})
    filtered = {}
    
    # Create lookup for detected deps
    detected_set = {(dep['github_org'], dep['repository']): dep for dep in detected_deps}
    
    for repo_name, repo_info in indexes.items():
        # Check if this repo was detected in imports
        # Try both orgs (might be in either)
        detected_info = None
        for org in ['armosec', 'kubescape']:
            if (org, repo_name) in detected_set:
                detected_info = detected_set[(org, repo_name)]
                break
        
        if detected_info:
            # Include this repo with priority
            filtered[repo_name] = {
                **repo_info,
                "import_count": detected_info['import_count'],
                "priority": detected_info['priority'],
                "reason": "detected_in_imports"
            }
    
    # Always include critical infrastructure repos even if not detected
    ALWAYS_INCLUDE = [
        'armosec-infra',
        'postgres-connector',
        'messaging'
    ]
    
    for repo_name in ALWAYS_INCLUDE:
        if repo_name in indexes and repo_name not in filtered:
            filtered[repo_name] = {
                **indexes[repo_name],
                "import_count": 0,
                "priority": "critical",
                "reason": "always_include"
            }
    
    return {
        "triggering_repo": available_indexes.get('triggering_repo'),
        "indexes": filtered,
        "filtering_summary": {
            "total_available": len(indexes),
            "after_filtering": len(filtered),
            "removed": len(indexes) - len(filtered),
            "detected_dependencies": len([r for r in filtered.values() if r.get('reason') == 'detected_in_imports']),
            "always_included": len([r for r in filtered.values() if r.get('reason') == 'always_include'])
        }
    }


def main():
    parser = argparse.ArgumentParser(
        description="Detect dependencies used in code chunks"
    )
    parser.add_argument(
        "--chunks",
        required=True,
        help="Path to filtered chunks JSON (output from filter_by_errors.py)"
    )
    parser.add_argument(
        "--available-indexes",
        required=True,
        help="Path to found-indexes.json"
    )
    parser.add_argument(
        "--output",
        default="artifacts/detected-dependencies.json",
        help="Path to save detected dependencies JSON"
    )
    parser.add_argument(
        "--output-filtered-indexes",
        help="Optional: Path to save filtered indexes JSON"
    )
    
    args = parser.parse_args()
    
    # Load chunks
    print(f"📖 Loading chunks from: {args.chunks}")
    if not os.path.exists(args.chunks):
        print(f"❌ Error: Chunks file not found: {args.chunks}", file=sys.stderr)
        sys.exit(1)
    
    with open(args.chunks, 'r') as f:
        chunks_data = json.load(f)
    
    # Extract chunks (handle different formats)
    if isinstance(chunks_data, dict) and 'filtered_chunks' in chunks_data:
        chunks = chunks_data['filtered_chunks']
    elif isinstance(chunks_data, dict):
        chunks = chunks_data
    else:
        print(f"❌ Error: Unexpected chunks format", file=sys.stderr)
        sys.exit(1)
    
    # Analyze imports
    print(f"\n🔍 Analyzing imports in code chunks...")
    analysis = analyze_all_chunks(chunks)
    
    print(f"   Total chunks analyzed: {analysis['total_chunks_analyzed']}")
    print(f"   Unique dependencies detected: {analysis['total_unique_dependencies']}")
    
    # Show top dependencies
    if analysis['detected_dependencies']:
        print(f"\n   📦 Top dependencies by import count:")
        for dep in analysis['detected_dependencies'][:10]:
            org = dep['github_org']
            repo = dep['repository']
            count = dep['import_count']
            priority = dep['priority']
            print(f"     {org}/{repo}: {count} imports ({priority} priority)")
        
        if len(analysis['detected_dependencies']) > 10:
            print(f"     ... and {len(analysis['detected_dependencies']) - 10} more")
    
    # Save detected dependencies
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(analysis, f, indent=2)
    print(f"\n📄 Detected dependencies saved to: {args.output}")
    
    # Filter available indexes if provided
    if args.available_indexes and os.path.exists(args.available_indexes):
        print(f"\n🔍 Filtering available indexes...")
        with open(args.available_indexes, 'r') as f:
            available_indexes = json.load(f)
        
        filtered_indexes = filter_available_indexes(
            analysis['detected_dependencies'],
            available_indexes
        )
        
        summary = filtered_indexes['filtering_summary']
        print(f"   Available indexes: {summary['total_available']}")
        print(f"   After filtering: {summary['after_filtering']}")
        print(f"   Removed: {summary['removed']}")
        print(f"   Detected deps: {summary['detected_dependencies']}")
        print(f"   Always included: {summary['always_included']}")
        
        # Save filtered indexes
        if args.output_filtered_indexes:
            with open(args.output_filtered_indexes, 'w') as f:
                json.dump(filtered_indexes, f, indent=2)
            print(f"\n📄 Filtered indexes saved to: {args.output_filtered_indexes}")
        
        # Show token savings estimate
        removed_repos = summary['removed']
        if removed_repos > 0:
            estimated_savings = removed_repos * 5000  # Rough estimate: 5K tokens per repo index
            print(f"\n💰 Estimated token savings: ~{estimated_savings:,} tokens")
            print(f"   (Removed {removed_repos} unused dependency indexes)")


if __name__ == "__main__":
    main()








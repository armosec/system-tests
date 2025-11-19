#!/usr/bin/env python3
"""
Apply size limits and prioritization to code chunks.

This script takes chunks from multiple sources (API mapping, Pulsar tracing, HTTP tracing, etc.)
and applies size limits (max 30 chunks per repo) with prioritization.

Usage:
    python apply_size_limits.py \
      --chunks artifacts/api-code-map-with-chains.json,artifacts/pulsar-traced-chunks.json \
      --max-chunks-per-repo 30 \
      --output artifacts/final-context-chunks.json
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Set, Optional, Any
from collections import defaultdict


def load_chunks_from_file(file_path: str) -> Dict[str, Any]:
    """Load chunks from various file formats."""
    if not os.path.exists(file_path):
        print(f"⚠️  File not found: {file_path}", file=sys.stderr)
        return {}
    
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Handle different file formats
    chunks_by_repo = {}
    
    # Format 1: API mapping with call chains
    if "api_mappings" in data or "mappings" in data:
        mappings = data.get("api_mappings") or data.get("mappings", {})
        repo_chunks = defaultdict(list)
        
        for api_key, mapping in mappings.items():
            if mapping.get("matched"):
                handler_chunk = mapping.get("handler_chunk")
                if handler_chunk:
                    repo = handler_chunk.get("package", "").split("/")[0] or "cadashboardbe"
                    repo_chunks[repo].append({
                        "chunk": handler_chunk,
                        "source": "api_mapping",
                        "priority": 1  # High priority - directly tested
                    })
                
                # Add call chain chunks
                call_chain = mapping.get("call_chain", {})
                chain_list = call_chain.get("chain", [])
                for chain_item in chain_list:
                    if isinstance(chain_item, dict) and chain_item.get("chunk_id"):
                        chunk_id = chain_item.get("chunk_id")
                        # Extract repo from chunk_id
                        repo = chunk_id.split("/")[0] if "/" in chunk_id else "cadashboardbe"
                        repo_chunks[repo].append({
                            "chunk": chain_item,
                            "source": "call_chain",
                            "priority": 2  # Medium priority - related to tested API
                        })
        
        chunks_by_repo.update(repo_chunks)
    
    # Format 2: Pulsar traced chunks
    if "traced_chunks" in data:
        traced = data["traced_chunks"]
        for repo_name, repo_data in traced.items():
            if repo_name not in chunks_by_repo:
                chunks_by_repo[repo_name] = []
            
            # Add producers (from cadashboardbe)
            for producer in repo_data.get("producers", []):
                chunks_by_repo[repo_name].append({
                    "chunk": producer,
                    "source": "pulsar_producer",
                    "priority": 3
                })
            
            # Add consumers (from other repos)
            for consumer in repo_data.get("consumers", []):
                chunks_by_repo[repo_name].append({
                    "chunk": consumer,
                    "source": "pulsar_consumer",
                    "priority": 2  # Higher priority - directly called
                })
    
    # Format 3: HTTP traced chunks
    if "traced_chunks" in data and "clients" in data.get("traced_chunks", {}).get("cadashboardbe", {}):
        traced = data["traced_chunks"]
        for repo_name, repo_data in traced.items():
            if repo_name == "cadashboardbe":
                continue  # Skip cadashboardbe clients
            
            if repo_name not in chunks_by_repo:
                chunks_by_repo[repo_name] = []
            
            for handler in repo_data.get("handlers", []):
                chunks_by_repo[repo_name].append({
                    "chunk": handler,
                    "source": "http_handler",
                    "priority": 2  # High priority - directly called via HTTP
                })
    
    # Format 4: Connector traced chunks
    if "traced_chunks" in data and "connectors" in data.get("traced_chunks", {}).get("cadashboardbe", {}):
        traced = data["traced_chunks"]
        for repo_name, repo_data in traced.items():
            if repo_name == "cadashboardbe":
                continue
            
            if repo_name not in chunks_by_repo:
                chunks_by_repo[repo_name] = []
            
            for handler in repo_data.get("handlers", []):
                chunks_by_repo[repo_name].append({
                    "chunk": handler,
                    "source": "connector_handler",
                    "priority": 2  # High priority - directly called via connector
                })
    
    # Format 5: Error-filtered chunks
    if "filtered_chunks" in data:
        for repo_name, chunks in data["filtered_chunks"].items():
            if repo_name not in chunks_by_repo:
                chunks_by_repo[repo_name] = []
            
            for chunk in chunks:
                chunks_by_repo[repo_name].append({
                    "chunk": chunk,
                    "source": "error_logs",
                    "priority": 1  # Highest priority - mentioned in errors
                })
    
    return chunks_by_repo


def deduplicate_chunks(chunks_by_repo: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    """Remove duplicate chunks (same chunk ID)."""
    deduplicated = {}
    
    for repo_name, chunks in chunks_by_repo.items():
        seen_ids = set()
        unique_chunks = []
        
        for chunk_info in chunks:
            chunk = chunk_info["chunk"]
            chunk_id = chunk.get("id") or chunk.get("chunk_id") or f"{chunk.get('package', '')}/{chunk.get('name', '')}"
            
            if chunk_id not in seen_ids:
                seen_ids.add(chunk_id)
                unique_chunks.append(chunk_info)
            else:
                # If duplicate, keep the one with higher priority
                for i, existing in enumerate(unique_chunks):
                    existing_chunk = existing["chunk"]
                    existing_id = existing_chunk.get("id") or existing_chunk.get("chunk_id") or f"{existing_chunk.get('package', '')}/{existing_chunk.get('name', '')}"
                    if existing_id == chunk_id:
                        if chunk_info["priority"] < existing["priority"]:
                            unique_chunks[i] = chunk_info
                        break
        
        deduplicated[repo_name] = unique_chunks
    
    return deduplicated


def apply_size_limits(
    chunks_by_repo: Dict[str, List[Dict[str, Any]]],
    max_chunks_per_repo: int = 30
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Apply size limits with prioritization.
    
    Priority order:
    1. Error logs (priority 1)
    2. API mapping handlers (priority 1)
    3. Direct calls (HTTP/connector/Pulsar consumers) (priority 2)
    4. Call chains (priority 2)
    5. Producers (priority 3)
    """
    limited_chunks = {}
    
    for repo_name, chunks in chunks_by_repo.items():
        # Sort by priority (lower number = higher priority)
        sorted_chunks = sorted(chunks, key=lambda x: (
            x.get("priority", 999),
            (x.get("chunk", {}).get("pattern") or "").lower()  # Secondary sort by pattern
        ))
        
        # Take top N chunks
        limited = sorted_chunks[:max_chunks_per_repo]
        limited_chunks[repo_name] = limited
        
        if len(chunks) > max_chunks_per_repo:
            print(f"   {repo_name}: Limited from {len(chunks)} to {len(limited)} chunks")
    
    return limited_chunks


def calculate_context_size(chunks_by_repo: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
    """Calculate total context size in chunks and lines."""
    total_chunks = 0
    total_lines = 0
    
    for repo_name, chunks in chunks_by_repo.items():
        repo_chunks = len(chunks)
        repo_lines = 0
        
        for chunk_info in chunks:
            chunk = chunk_info["chunk"]
            code = chunk.get("code", "")
            if code:
                repo_lines += len(code.split('\n'))
        
        total_chunks += repo_chunks
        total_lines += repo_lines
        
        print(f"   {repo_name}: {repo_chunks} chunks, ~{repo_lines} lines")
    
    return {
        "total_chunks": total_chunks,
        "total_lines": total_lines
    }


def main():
    parser = argparse.ArgumentParser(
        description="Apply size limits and prioritization to code chunks"
    )
    parser.add_argument(
        "--chunks",
        required=True,
        help="Comma-separated list of chunk JSON files (from various tracers)"
    )
    parser.add_argument(
        "--max-chunks-per-repo",
        type=int,
        default=30,
        help="Maximum chunks per repository (default: 30)"
    )
    parser.add_argument(
        "--max-total-chunks",
        type=int,
        default=200,
        help="Maximum total chunks across all repos (default: 200)"
    )
    parser.add_argument(
        "--max-total-lines",
        type=int,
        default=10000,
        help="Maximum total lines across all chunks (default: 10000)"
    )
    parser.add_argument(
        "--output",
        default="artifacts/final-context-chunks.json",
        help="Output file path (default: artifacts/final-context-chunks.json)"
    )
    
    args = parser.parse_args()
    
    # Load chunks from all sources
    print("📖 Loading chunks from multiple sources...")
    all_chunks_by_repo = defaultdict(list)
    
    for chunk_file in args.chunks.split(','):
        print(f"   Loading: {chunk_file}")
        file_chunks = load_chunks_from_file(chunk_file)
        for repo_name, chunks in file_chunks.items():
            all_chunks_by_repo[repo_name].extend(chunks)
    
    print(f"\n📊 Before deduplication:")
    for repo_name, chunks in all_chunks_by_repo.items():
        print(f"   {repo_name}: {len(chunks)} chunks")
    
    # Deduplicate
    print("\n🔍 Deduplicating chunks...")
    deduplicated = deduplicate_chunks(dict(all_chunks_by_repo))
    
    print(f"\n📊 After deduplication:")
    for repo_name, chunks in deduplicated.items():
        print(f"   {repo_name}: {len(chunks)} chunks")
    
    # Apply size limits
    print(f"\n📏 Applying size limits (max {args.max_chunks_per_repo} per repo)...")
    limited = apply_size_limits(deduplicated, args.max_chunks_per_repo)
    
    # Check total limits
    size_info = calculate_context_size(limited)
    
    if size_info["total_chunks"] > args.max_total_chunks:
        print(f"\n⚠️  Total chunks ({size_info['total_chunks']}) exceeds limit ({args.max_total_chunks})")
        print("   Applying global limit...")
        # Flatten and re-sort all chunks
        all_chunks_flat = []
        for repo_name, chunks in limited.items():
            for chunk_info in chunks:
                chunk_info["repo"] = repo_name
                all_chunks_flat.append(chunk_info)
        
        all_chunks_flat.sort(key=lambda x: (x.get("priority", 999), (x.get("chunk", {}).get("pattern") or "").lower()))
        all_chunks_flat = all_chunks_flat[:args.max_total_chunks]
        
        # Re-group by repo
        limited = defaultdict(list)
        for chunk_info in all_chunks_flat:
            repo = chunk_info.pop("repo")
            limited[repo].append(chunk_info)
        
        size_info = calculate_context_size(limited)
    
    if size_info["total_lines"] > args.max_total_lines:
        print(f"\n⚠️  Total lines ({size_info['total_lines']}) exceeds limit ({args.max_total_lines})")
        print("   Note: Line limit exceeded, but chunk limit takes precedence")
    
    # Prepare output
    result = {
        "total_chunks": size_info["total_chunks"],
        "total_lines": size_info["total_lines"],
        "max_chunks_per_repo": args.max_chunks_per_repo,
        "chunks_by_repo": {
            repo: [c["chunk"] for c in chunks]
            for repo, chunks in limited.items()
        },
        "chunks_with_metadata": limited
    }
    
    # Save results
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📊 Final Summary:")
    print(f"   Total chunks: {size_info['total_chunks']}")
    print(f"   Total lines: ~{size_info['total_lines']}")
    print(f"   Repositories: {len(limited)}")
    print(f"\n📄 Final context chunks saved to: {args.output}")


if __name__ == "__main__":
    main()


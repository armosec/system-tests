#!/usr/bin/env python3
"""
Extract connected repos context - Master script for Phase 5.

This script orchestrates all Phase 5 tracers to extract ONLY relevant code from connected repos:
1. Trace Pulsar topics
2. Trace HTTP calls
3. Trace service connectors
4. Filter by errors (optional)
5. Apply size limits and prioritization

Usage:
    python extract_connected_context.py \
      --cadashboardbe-index cadashboardbe-index.json \
      --other-repo-indexes event-ingester-service:event-ingester-index.json,config-service:config-service-index.json \
      --api-mapping artifacts/api-code-map-with-chains.json \
      --error-logs artifacts/loki-errors.txt \
      --output artifacts/connected-context.json
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Any


def run_script(script_name: str, args: List[str]) -> Dict[str, Any]:
    """Run a Python script and return its output."""
    script_path = Path(__file__).parent / script_name
    if not script_path.exists():
        print(f"⚠️  Script not found: {script_name}", file=sys.stderr)
        return {}
    
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)] + args,
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode != 0:
            print(f"⚠️  {script_name} failed: {result.stderr}", file=sys.stderr)
            return {}
        
        # Try to parse JSON output if available
        output_file = None
        for arg in args:
            if arg == "--output" and args.index(arg) + 1 < len(args):
                output_file = args[args.index(arg) + 1]
                break
        
        if output_file and os.path.exists(output_file):
            with open(output_file, 'r') as f:
                return json.load(f)
        
        return {}
    except Exception as e:
        print(f"⚠️  Error running {script_name}: {e}", file=sys.stderr)
        return {}


def extract_connected_context(
    cadashboardbe_index: str,
    other_repo_indexes: str,
    api_mapping_file: str = None,
    error_logs_file: str = None,
    max_chunks_per_repo: int = 30,
    max_total_chunks: int = 200
) -> Dict[str, Any]:
    """
    Extract connected repos context using all Phase 5 tracers.
    """
    print("🚀 Phase 5: Extracting Connected Repos Context\n")
    
    # Temporary files for intermediate results
    temp_dir = tempfile.mkdtemp(prefix="phase5_")
    pulsar_output = os.path.join(temp_dir, "pulsar-traced.json")
    http_output = os.path.join(temp_dir, "http-traced.json")
    connector_output = os.path.join(temp_dir, "connector-traced.json")
    error_output = os.path.join(temp_dir, "error-filtered.json") if error_logs_file else None
    
    chunk_files = []
    
    # Step 1: Trace Pulsar topics
    print("📡 Step 1: Tracing Pulsar topics...")
    print(f"   Using cadashboardbe index: {cadashboardbe_index}")
    run_script("trace_pulsar_topics.py", [
        "--cadashboardbe-index", os.path.abspath(cadashboardbe_index),
        "--other-repo-indexes", other_repo_indexes,
        "--output", pulsar_output
    ])
    if os.path.exists(pulsar_output):
        chunk_files.append(pulsar_output)
        print("   ✅ Pulsar tracing completed")
    
    # Step 2: Trace HTTP calls
    print("\n🌐 Step 2: Tracing HTTP calls...")
    run_script("trace_http_calls.py", [
        "--cadashboardbe-index", os.path.abspath(cadashboardbe_index),
        "--other-repo-indexes", other_repo_indexes,
        "--output", http_output
    ])
    if os.path.exists(http_output):
        chunk_files.append(http_output)
        print("   ✅ HTTP tracing completed")
    
    # Step 3: Trace connectors
    print("\n🔌 Step 3: Tracing service connectors...")
    run_script("trace_connectors.py", [
        "--cadashboardbe-index", os.path.abspath(cadashboardbe_index),
        "--other-repo-indexes", other_repo_indexes,
        "--output", connector_output
    ])
    if os.path.exists(connector_output):
        chunk_files.append(connector_output)
        print("   ✅ Connector tracing completed")
    
    # Step 4: Filter by errors (if provided)
    if error_logs_file and os.path.exists(error_logs_file):
        print("\n🔍 Step 4: Filtering by error logs...")
        run_script("filter_by_errors.py", [
            "--error-logs", error_logs_file,
            "--code-indexes", f"cadashboardbe:{cadashboardbe_index},{other_repo_indexes}",
            "--output", error_output
        ])
        if os.path.exists(error_output):
            chunk_files.append(error_output)
            print("   ✅ Error filtering completed")
    
    # Add API mapping if provided
    if api_mapping_file and os.path.exists(api_mapping_file):
        chunk_files.append(api_mapping_file)
        print(f"\n📋 Including API mapping: {api_mapping_file}")
    
    # Step 5: Apply size limits
    print(f"\n📏 Step 5: Applying size limits (max {max_chunks_per_repo} per repo, {max_total_chunks} total)...")
    final_output = os.path.join(temp_dir, "final-context.json")
    
    run_script("apply_size_limits.py", [
        "--chunks", ",".join(chunk_files),
        "--max-chunks-per-repo", str(max_chunks_per_repo),
        "--max-total-chunks", str(max_total_chunks),
        "--output", final_output
    ])
    
    if os.path.exists(final_output):
        with open(final_output, 'r') as f:
            result = json.load(f)
        print("   ✅ Size limits applied")
        return result
    
    return {}


def main():
    parser = argparse.ArgumentParser(
        description="Extract connected repos context (Phase 5 master script)"
    )
    parser.add_argument(
        "--cadashboardbe-index",
        required=True,
        help="Path to cadashboardbe code index JSON file"
    )
    parser.add_argument(
        "--other-repo-indexes",
        required=True,
        help="Comma-separated list of code index JSON files (format: repo1:path1,repo2:path2)"
    )
    parser.add_argument(
        "--api-mapping",
        help="Path to API mapping with call chains JSON file (from Phase 4)"
    )
    parser.add_argument(
        "--error-logs",
        help="Path to error logs file (from Loki or workflow logs)"
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
        "--output",
        default="artifacts/connected-context.json",
        help="Output file path (default: artifacts/connected-context.json)"
    )
    
    args = parser.parse_args()
    
    # Extract connected context
    result = extract_connected_context(
        cadashboardbe_index=args.cadashboardbe_index,
        other_repo_indexes=args.other_repo_indexes,
        api_mapping_file=args.api_mapping,
        error_logs_file=args.error_logs,
        max_chunks_per_repo=args.max_chunks_per_repo,
        max_total_chunks=args.max_total_chunks
    )
    
    if not result:
        print("❌ Failed to extract connected context", file=sys.stderr)
        sys.exit(1)
    
    # Save results
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n✅ Connected context extraction completed!")
    print(f"📄 Results saved to: {args.output}")
    print(f"\n📊 Final Summary:")
    print(f"   Total chunks: {result.get('total_chunks', 0)}")
    print(f"   Total lines: ~{result.get('total_lines', 0)}")
    print(f"   Repositories: {len(result.get('chunks_by_repo', {}))}")


if __name__ == "__main__":
    main()


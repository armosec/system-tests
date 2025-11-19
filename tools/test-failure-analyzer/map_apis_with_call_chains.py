#!/usr/bin/env python3
"""
Map tested APIs to code chunks with call chains.

This script combines API mapping and call chain extraction to create
a complete mapping of tested APIs to their handler code and related chunks.

Usage:
    python map_apis_with_call_chains.py \
      --test-name jira_integration \
      --mapping system_test_mapping.json \
      --index code-index.json \
      --max-depth 3 \
      --output artifacts/api-code-map-with-chains.json
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Any

# Import functions from other modules
from map_apis_to_code import map_apis_to_code
from extract_call_chain import extract_call_chain, load_code_index as load_code_index_from_call_chain


def map_apis_with_call_chains(
    test_name: str,
    test_mapping: Dict[str, Any],
    code_index: Dict[str, Any],
    max_depth: int = 3
) -> Dict[str, Any]:
    """
    Map tested APIs to code chunks with call chains.
    
    Args:
        test_name: Test name from system_test_mapping.json
        test_mapping: Full test mapping dict
        code_index: Code index dict
        max_depth: Maximum call chain depth
    
    Returns:
        Dict with API mappings and call chains
    """
    # First, map APIs to handlers
    api_mapping_result = map_apis_to_code(test_name, test_mapping, code_index)
    
    if not api_mapping_result or "mappings" not in api_mapping_result:
        return {
            "test_name": test_name,
            "error": "Failed to map APIs to code",
            "api_mappings": {}
        }
    
    mappings = api_mapping_result["mappings"]
    
    # Extract call chains for each matched handler
    all_chunk_ids = set()
    api_results = {}
    
    for api_key, mapping in mappings.items():
        if not mapping.get("matched"):
            api_results[api_key] = mapping
            continue
        
        handler_chunk = mapping.get("handler_chunk")
        if not handler_chunk:
            api_results[api_key] = mapping
            continue
        
        handler_chunk_id = handler_chunk.get("id")
        if not handler_chunk_id:
            api_results[api_key] = mapping
            continue
        
        # Extract call chain
        call_chain_result = extract_call_chain(
            handler_chunk_id=handler_chunk_id,
            code_index=code_index,
            max_depth=max_depth
        )
        
        # Collect chunk IDs from call chain
        chain_chunk_ids = set()
        # extract_call_chain returns a dict with "chain" key containing list of chunk IDs
        chain_list = call_chain_result.get("chain", [])
        for item in chain_list:
            # Each item is a dict with "chunk_id" or just a string chunk_id
            chunk_id = item.get("chunk_id") if isinstance(item, dict) else item
            if chunk_id:
                chain_chunk_ids.add(chunk_id)
                all_chunk_ids.add(chunk_id)
        
        # Add call chain to mapping
        api_results[api_key] = {
            **mapping,
            "call_chain": call_chain_result,
            "related_chunk_ids": list(chain_chunk_ids)
        }
    
    return {
        "test_name": test_name,
        "total_apis": api_mapping_result.get("total_apis", 0),
        "matched_count": api_mapping_result.get("matched_count", 0),
        "unmatched_count": api_mapping_result.get("unmatched_count", 0),
        "max_depth": max_depth,
        "total_related_chunks": len(all_chunk_ids),
        "mappings": api_results
    }


def main():
    parser = argparse.ArgumentParser(
        description="Map tested APIs to code chunks with call chains"
    )
    parser.add_argument(
        "--test-name",
        required=True,
        help="Test name from system_test_mapping.json"
    )
    parser.add_argument(
        "--mapping",
        default="system_test_mapping.json",
        help="Path to system_test_mapping.json (default: system_test_mapping.json)"
    )
    parser.add_argument(
        "--index",
        required=True,
        help="Path to code index JSON file"
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=3,
        help="Maximum call chain depth (default: 3)"
    )
    parser.add_argument(
        "--output",
        default="artifacts/api-code-map-with-chains.json",
        help="Path to save mapping JSON (default: artifacts/api-code-map-with-chains.json)"
    )
    
    args = parser.parse_args()
    
    # Load test mapping and code index
    print(f"Loading test mapping from: {args.mapping}")
    from map_apis_to_code import load_test_mapping, load_code_index
    test_mapping = load_test_mapping(args.mapping)
    
    print(f"Loading code index from: {args.index}")
    code_index = load_code_index(args.index)
    
    # Map APIs with call chains
    print(f"\nMapping APIs with call chains for test: {args.test_name}")
    print(f"Max depth: {args.max_depth}")
    
    result = map_apis_with_call_chains(
        test_name=args.test_name,
        test_mapping=test_mapping,
        code_index=code_index,
        max_depth=args.max_depth
    )
    
    # Print summary
    print(f"\n📊 Summary:")
    print(f"   Total APIs: {result.get('total_apis', 0)}")
    print(f"   Matched: {result.get('matched_count', 0)}")
    print(f"   Unmatched: {result.get('unmatched_count', 0)}")
    print(f"   Total related chunks: {result.get('total_related_chunks', 0)}")
    
    # Save results
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📄 API-code mapping with call chains saved to: {args.output}")
    
    # Exit with error if any APIs unmatched
    if result.get("unmatched_count", 0) > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()


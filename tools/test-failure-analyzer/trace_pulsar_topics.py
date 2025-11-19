#!/usr/bin/env python3
"""
Trace Pulsar topics from cadashboardbe producers to consumers in other repos.

This script analyzes cadashboardbe code to find Pulsar producers, extracts topic names,
and then finds matching consumers in other repositories to extract only relevant handler chunks.

Usage:
    python trace_pulsar_topics.py \
      --cadashboardbe-index cadashboardbe-index.json \
      --other-repo-indexes event-ingester-index.json,config-service-index.json \
      --output artifacts/pulsar-traced-chunks.json
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Set, Optional, Any


def load_code_index(index_path: str, required: bool = True) -> Optional[Dict[str, Any]]:
    """Load code index JSON file."""
    if not os.path.exists(index_path):
        if required:
            print(f"Error: Code index file not found: {index_path}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"⚠️  Code index file not found (skipping): {index_path}", file=sys.stderr)
            return None
    
    with open(index_path, 'r') as f:
        return json.load(f)


def find_pulsar_producers(chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Find Pulsar producer code chunks in cadashboardbe.
    
    Looks for patterns like:
    - p.Produce(topic, message)
    - producer.Send(topic, message)
    - pulsar.Producer.Send(...)
    """
    producers = []
    
    for chunk in chunks:
        code = chunk.get("code", "")
        pattern = chunk.get("pattern", "").lower()
        name = chunk.get("name", "").lower()
        
        # Check if it's a producer-related chunk
        is_producer = (
            "producer" in pattern or
            "producer" in name or
            "pulsar" in pattern or
            re.search(r'\.(Produce|Send|Publish)', code, re.IGNORECASE) is not None
        )
        
        if is_producer:
            # Extract topic names from code
            topics = extract_topics_from_code(code)
            if topics:
                producers.append({
                    "chunk": chunk,
                    "topics": topics
                })
    
    return producers


def extract_topics_from_code(code: str) -> List[str]:
    """
    Extract Pulsar topic names from code.
    
    Looks for patterns like:
    - createPulsarProducer(client, common.TopicName) or createPulsarProducer(client, "topic-name")
    - NewProducer(pulsarCon.WithProducerTopic(common.TopicName))
    - producer.Send(context, &pulsar.ProducerMessage{...})
    - const topic = "topic-name"
    """
    topics = []
    
    # Pattern 1: createPulsarProducer calls with topic argument
    # e.g., createPulsarProducer(client, common.AttackChainStateScanStateTopic)
    # e.g., createPulsarProducer(client, "analytics")
    create_producer_pattern = r'createPulsarProducer\s*\([^,]+,\s*([^)]+)\)'
    matches = re.finditer(create_producer_pattern, code, re.IGNORECASE)
    for match in matches:
        topic_arg = match.group(1).strip()
        # Extract topic name from constant (e.g., common.AttackChainStateScanStateTopic -> AttackChainStateScanStateTopic)
        if '.' in topic_arg:
            topic_name = topic_arg.split('.')[-1].strip()
            # Convert CamelCase to kebab-case (e.g., AttackChainStateScanStateTopic -> attack-chain-state-scan-state-topic)
            # But first check if it's a string literal
            if topic_name.startswith('"') or topic_name.startswith("'"):
                topic = topic_name.strip('"\'')
            else:
                # Try to infer topic name from constant name
                # Remove common suffixes like "Topic"
                if topic_name.endswith('Topic'):
                    topic_name = topic_name[:-5]
                # Convert CamelCase to kebab-case
                import re as re_module
                topic = re_module.sub(r'([a-z0-9])([A-Z])', r'\1-\2', topic_name).lower()
            if topic and len(topic) > 2 and topic not in topics:
                topics.append(topic)
        elif topic_arg.startswith('"') or topic_arg.startswith("'"):
            topic = topic_arg.strip('"\'')
            if topic and len(topic) > 2 and topic not in topics:
                topics.append(topic)
    
    # Pattern 2: NewProducer with WithProducerTopic
    # e.g., client.NewProducer(pulsarCon.WithProducerTopic(common.TopicName))
    with_topic_pattern = r'WithProducerTopic\s*\(\s*([^)]+)\)'
    matches = re.finditer(with_topic_pattern, code, re.IGNORECASE)
    for match in matches:
        topic_arg = match.group(1).strip()
        if '.' in topic_arg:
            topic_name = topic_arg.split('.')[-1].strip()
            if topic_name.endswith('Topic'):
                topic_name = topic_name[:-5]
            import re as re_module
            topic = re_module.sub(r'([a-z0-9])([A-Z])', r'\1-\2', topic_name).lower()
            if topic and len(topic) > 2 and topic not in topics:
                topics.append(topic)
        elif topic_arg.startswith('"') or topic_arg.startswith("'"):
            topic = topic_arg.strip('"\'')
            if topic and len(topic) > 2 and topic not in topics:
                topics.append(topic)
    
    # Pattern 3: String literal constants
    # e.g., const topic = "analytics"
    # e.g., const userInputTopic = "user-input"
    const_patterns = [
        r'const\s+\w+[Tt]opic\s*=\s*["\']([^"\']+)["\']',
        r'const\s+topic\s*=\s*["\']([^"\']+)["\']',
    ]
    for pattern in const_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            topic = match.group(1)
            if topic and len(topic) > 2 and topic not in topics:
                topics.append(topic)
    
    # Pattern 4: Topic variable assignments (more specific)
    # e.g., topic := "analytics"
    topic_var_patterns = [
        r'\w+[Tt]opic\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    for pattern in topic_var_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            topic = match.group(1)
            # Filter out common false positives
            if topic and len(topic) > 2 and topic not in ['commandName', 'context', 'message'] and topic not in topics:
                topics.append(topic)
    
    return topics


def find_pulsar_consumers(topics: List[str], chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Find Pulsar consumer handlers that match the given topics.
    
    Looks for patterns like:
    - consumer.Subscribe("topic-name", handler)
    - pulsar.Consumer.Subscribe(...)
    """
    consumers = []
    
    for chunk in chunks:
        code = chunk.get("code", "")
        pattern = chunk.get("pattern", "").lower()
        name = chunk.get("name", "").lower()
        
        # Check if it's a consumer-related chunk
        is_consumer = (
            "consumer" in pattern or
            "consumer" in name or
            "pulsar" in pattern or
            re.search(r'\.(Subscribe|Consume|Receive)', code, re.IGNORECASE) is not None
        )
        
        if is_consumer:
            # Extract topics from consumer code
            consumer_topics = extract_topics_from_code(code)
            
            # Check if any consumer topics match our producer topics
            matching_topics = [t for t in consumer_topics if t in topics]
            
            if matching_topics:
                consumers.append({
                    "chunk": chunk,
                    "topics": matching_topics
                })
    
    return consumers


def trace_pulsar_topics(
    cadashboardbe_index: Dict[str, Any],
    other_repo_indexes: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Trace Pulsar topics from cadashboardbe producers to consumers in other repos.
    
    Args:
        cadashboardbe_index: Code index for cadashboardbe
        other_repo_indexes: Dict mapping repo names to their code indexes
    
    Returns:
        Dict with traced chunks organized by repo
    """
    cadashboardbe_chunks = cadashboardbe_index.get("chunks", [])
    
    # Find all producers in cadashboardbe
    print("🔍 Finding Pulsar producers in cadashboardbe...")
    producers = find_pulsar_producers(cadashboardbe_chunks)
    
    print(f"   Found {len(producers)} producer chunks")
    
    # Collect all unique topics
    all_topics = set()
    for producer_info in producers:
        all_topics.update(producer_info["topics"])
    
    print(f"   Found {len(all_topics)} unique topics: {', '.join(sorted(all_topics))}")
    
    # Find consumers in other repos
    traced_chunks = {
        "cadashboardbe": {
            "producers": [p["chunk"] for p in producers],
            "topics": list(all_topics)
        }
    }
    
    for repo_name, repo_index in other_repo_indexes.items():
        print(f"\n🔍 Searching for consumers in {repo_name}...")
        repo_chunks = repo_index.get("chunks", [])
        consumers = find_pulsar_consumers(list(all_topics), repo_chunks)
        
        if consumers:
            print(f"   Found {len(consumers)} consumer chunks")
            traced_chunks[repo_name] = {
                "consumers": [c["chunk"] for c in consumers],
                "matched_topics": list(set(topic for c in consumers for topic in c["topics"]))
            }
        else:
            print(f"   No consumers found for topics: {', '.join(sorted(all_topics))}")
    
    return {
        "total_topics": len(all_topics),
        "total_producers": len(producers),
        "total_consumers": sum(
            len(traced_chunks.get(repo, {}).get("consumers", []))
            for repo in other_repo_indexes.keys()
        ),
        "traced_chunks": traced_chunks
    }


def main():
    parser = argparse.ArgumentParser(
        description="Trace Pulsar topics from cadashboardbe to other repos"
    )
    parser.add_argument(
        "--cadashboardbe-index",
        required=True,
        help="Path to cadashboardbe code index JSON file"
    )
    parser.add_argument(
        "--other-repo-indexes",
        required=True,
        help="Comma-separated list of code index JSON files for other repos (format: repo1:path1,repo2:path2)"
    )
    parser.add_argument(
        "--output",
        default="artifacts/pulsar-traced-chunks.json",
        help="Output file path (default: artifacts/pulsar-traced-chunks.json)"
    )
    
    args = parser.parse_args()
    
    # Load cadashboardbe index
    print(f"Loading cadashboardbe index from: {args.cadashboardbe_index}")
    cadashboardbe_index = load_code_index(args.cadashboardbe_index)
    
    # Parse and load other repo indexes
    other_repo_indexes = {}
    for repo_spec in args.other_repo_indexes.split(','):
        if ':' in repo_spec:
            repo_name, index_path = repo_spec.split(':', 1)
        else:
            # If no repo name specified, use filename
            index_path = repo_spec
            repo_name = os.path.basename(index_path).replace('-index.json', '').replace('_index.json', '')
        
        print(f"Loading {repo_name} index from: {index_path}")
        repo_index = load_code_index(index_path, required=False)
        if repo_index:
            other_repo_indexes[repo_name] = repo_index
        else:
            print(f"   Skipping {repo_name} (index not found)")
    
    # Trace Pulsar topics
    result = trace_pulsar_topics(cadashboardbe_index, other_repo_indexes)
    
    # Save results
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📊 Summary:")
    print(f"   Total topics: {result['total_topics']}")
    print(f"   Total producers: {result['total_producers']}")
    print(f"   Total consumers: {result['total_consumers']}")
    print(f"\n📄 Traced chunks saved to: {args.output}")


if __name__ == "__main__":
    main()


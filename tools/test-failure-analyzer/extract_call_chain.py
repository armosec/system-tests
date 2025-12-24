#!/usr/bin/env python3
"""
Extract call chains from handler code.

This script analyzes handler code chunks to find called functions, then
extracts service/repository chunks to build call chains.

Usage:
    python extract_call_chain.py \
      --handler-chunk-id chunk_123 \
      --index code-index.json \
      --max-depth 3 \
      --output artifacts/call-chains.json
"""

import argparse
import json
import os
import re
import sys
from collections import deque
from typing import Dict, List, Optional, Set, Any, Tuple


def load_code_index(index_path: str) -> Dict[str, Any]:
    """Load code index JSON file."""
    if not os.path.exists(index_path):
        print(f"Error: Code index file not found: {index_path}", file=sys.stderr)
        sys.exit(1)
    
    with open(index_path, 'r') as f:
        return json.load(f)


def find_chunk_by_id(chunk_id: str, chunks: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Find a chunk by its ID."""
    for chunk in chunks:
        if chunk.get("id") == chunk_id:
            return chunk
    return None


def find_chunks_by_name(name: str, chunks: List[Dict[str, Any]], package: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Find chunks by name (and optionally package).
    
    Returns:
        List of matching chunks
    """
    matches = []
    for chunk in chunks:
        chunk_name = chunk.get("name", "")
        chunk_package = chunk.get("package", "")
        
        if chunk_name == name:
            if package is None or chunk_package == package:
                matches.append(chunk)
    
    return matches


def extract_repo_from_import(import_path: str) -> Optional[str]:
    """
    Extract repository name from Go import path.
    
    Examples:
        github.com/armosec/postgres-connector/dal -> postgres-connector
        github.com/kubescape/storage/pkg/apis -> storage
    
    Returns:
        Repository name or None if not armosec/kubescape package
    """
    match = re.match(r'github\.com/(armosec|kubescape)/([^/]+)', import_path)
    return match.group(2) if match else None


def parse_imports(code: str) -> Dict[str, str]:
    """
    Parse Go import statements to build alias -> repo mapping.
    
    Returns:
        Dict mapping package alias to repository name
    """
    imports = {}
    
    # Match: import "github.com/armosec/postgres-connector/dal"
    # Match: import pc "github.com/armosec/postgres-connector/dal"
    # Also handle multi-line import blocks
    import_pattern = r'import\s+(?:(\w+)\s+)?"([^"]+)"'
    
    for match in re.finditer(import_pattern, code):
        alias = match.group(1)
        path = match.group(2)
        repo = extract_repo_from_import(path)
        
        if repo:
            # If no alias, use last part of path
            if not alias:
                alias = path.split('/')[-1]
            imports[alias] = repo
    
    return imports


def detect_pulsar_producers(code: str) -> List[Dict[str, Any]]:
    """
    Detect Pulsar message producers (functions that send messages to topics).
    
    Enhanced patterns to catch:
    - producer.Send(...) - simple
    - pc.userInputPulsarProducer.Send(...) - nested field access
    - handler.messagingProducer.SendAsync(...) - multi-level
    - PublishMessage(...) - direct calls
    
    Returns:
        List of dicts with topic, message_type info
    """
    producers = []
    seen_positions = set()  # Deduplicate by position
    
    # Pattern 1: Nested producer field access (NEW - catches pc.userInputPulsarProducer.Send)
    # Matches: pc.userInputPulsarProducer.Send, handler.producer.SendAsync, etc.
    nested_producer_pattern = r'(\w+(?:\.\w+)*[Pp]roducer)\.(?:Send(?:Async)?)\s*\('
    for match in re.finditer(nested_producer_pattern, code):
        if match.start() in seen_positions:
            continue
        seen_positions.add(match.start())
        
        producer_path = match.group(1)
        method = "Send" if "SendAsync" not in match.group(0) else "SendAsync"
        
        # Try to extract topic from nearby context (400 chars for nested calls)
        start_pos = max(0, match.start() - 400)
        end_pos = min(len(code), match.end() + 200)
        context = code[start_pos:end_pos]
        
        topic = extract_topic_from_context(context)
        
        producers.append({
            "type": "producer",
            "method": method,
            "variable": producer_path,
            "topic": topic,
            "position": match.start(),
            "pattern": "nested_producer"
        })
    
    # Pattern 2: Simple producer.Send() (catches simple cases)
    send_pattern = r'(\w+)\.(Send(?:Async)?)\s*\([^)]*\)'
    for match in re.finditer(send_pattern, code):
        if match.start() in seen_positions:
            continue
        seen_positions.add(match.start())
        
        producer_var = match.group(1)
        method = match.group(2)
        
        # Skip if producer_var is not actually a producer variable
        if not re.search(r'[Pp]roducer|[Mm]essaging|[Cc]lient', producer_var):
            continue
        
        # Try to extract topic from nearby context
        start_pos = max(0, match.start() - 200)
        end_pos = min(len(code), match.end() + 100)
        context = code[start_pos:end_pos]
        
        topic = extract_topic_from_context(context)
        
        producers.append({
            "type": "producer",
            "method": method,
            "variable": producer_var,
            "topic": topic,
            "position": match.start(),
            "pattern": "simple_producer"
        })
    
    # Pattern 3: Direct Publish() calls
    publish_pattern = r'Publish(?:Message|Event)?\s*\([^)]*["\']([^"\']+)["\']'
    for match in re.finditer(publish_pattern, code):
        if match.start() in seen_positions:
            continue
        seen_positions.add(match.start())
        
        topic = match.group(1)
        producers.append({
            "type": "producer",
            "method": "Publish",
            "topic": topic,
            "position": match.start(),
            "pattern": "publish_call"
        })
    
    # Pattern 4: Topic constants in the file (NEW - look for topic definitions)
    # userInputTopic = "user-input", const TopicName = "persistent://..."
    topic_const_pattern = r'(?:const|var)?\s*(\w*[Tt]opic)\s*=\s*["\']([^"\']+)["\']'
    topic_constants = {}
    for match in re.finditer(topic_const_pattern, code):
        const_name = match.group(1)
        topic_value = match.group(2)
        topic_constants[const_name] = topic_value
    
    # Enrich existing producers with topic constants
    for producer in producers:
        if not producer.get("topic") and topic_constants:
            # Look for topic constant usage near the producer
            context_start = max(0, producer["position"] - 500)
            context_end = min(len(code), producer["position"] + 500)
            context = code[context_start:context_end]
            
            for const_name, topic_value in topic_constants.items():
                if const_name in context:
                    producer["topic"] = topic_value
                    producer["topic_source"] = "constant:" + const_name
                    break
    
    return producers


def extract_topic_from_context(context: str) -> Optional[str]:
    """
    Extract topic name from code context using multiple patterns.
    
    Returns topic string or None if not found.
    """
    # Pattern 1: topic assignment (topic = "...", topic: "...")
    topic_pattern = r'topic[:\s=]+["\']([^"\']+)["\']'
    match = re.search(topic_pattern, context, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Pattern 2: Topic literal in string (look for "user-input", "persistent://...")
    # Must be at least 5 chars and look like a topic name
    literal_pattern = r'["\']([a-zA-Z][\w\-:/]{4,60})["\']'
    for match in re.finditer(literal_pattern, context):
        potential_topic = match.group(1)
        # Check if it looks like a Pulsar topic
        if ('persistent://' in potential_topic or 
            '-' in potential_topic or  # user-input, user-output style
            '/' in potential_topic):   # path-like topics
            # Avoid false positives (error messages, file paths)
            if not any(skip in potential_topic.lower() for skip in 
                      ['error', 'failed', 'invalid', '.go', '.json', 'http://']):
                return potential_topic
    
    return None


def is_pulsar_sender(chunk: Dict[str, Any]) -> bool:
    """
    Check if a chunk sends Pulsar messages (contains .Send() or .SendAsync() calls).
    
    This is used to exempt Pulsar-sending functions from pattern filtering,
    since they are critical for cross-service communication tracing.
    
    Args:
        chunk: Code chunk dictionary with 'code' field
    
    Returns:
        True if chunk contains Pulsar producer .Send() calls
    """
    code = chunk.get("code", "")
    
    # Pattern 1: producer.Send() or producer.SendAsync()
    if re.search(r'\w+Producer\s*\.\s*Send(?:Async)?\s*\(', code):
        return True
    
    # Pattern 2: pc.xxxProducer.Send()
    if re.search(r'\w+\.\w+Producer\s*\.\s*Send(?:Async)?\s*\(', code):
        return True
    
    # Pattern 3: Direct producer variable usage: myProducer.Send()
    if re.search(r'\w+\s*\.\s*Send(?:Async)?\s*\([^)]*(?:Message|Event|Payload)', code):
        return True
    
    return False


def detect_pulsar_consumers(chunk: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Detect if a chunk is a Pulsar message consumer/handler.
    
    Patterns:
    - Function implementing Consumer interface
    - Function with "Handle", "Process", "Consume" in name
    - Function taking Message/Event parameter
    - Subscribe() calls in code
    
    Returns:
        Dict with consumer info or None
    """
    code = chunk.get("code", "")
    name = chunk.get("name", "")
    chunk_type = chunk.get("type", "")
    
    consumer_info = {
        "is_consumer": False,
        "topics": [],
        "message_type": None
    }
    
    # Pattern 1: Function name indicates message handling
    if re.search(r'(Handle|Process|Consume|Ingest|Listen)', name, re.IGNORECASE):
        consumer_info["is_consumer"] = True
        consumer_info["handler_type"] = "name_pattern"
    
    # Pattern 2: Subscribe() call in code
    subscribe_pattern = r'Subscribe\s*\([^)]*["\']([^"\']+)["\']'
    for match in re.finditer(subscribe_pattern, code):
        topic = match.group(1)
        consumer_info["is_consumer"] = True
        consumer_info["topics"].append(topic)
        consumer_info["handler_type"] = "explicit_subscribe"
    
    # Pattern 3: Implements Consumer interface or has Receive method
    if re.search(r'func\s+\([^)]+\)\s+(?:Receive|Consume|Handle)\s*\(', code):
        consumer_info["is_consumer"] = True
        consumer_info["handler_type"] = "interface_implementation"
    
    # Pattern 4: Parameter type indicates message
    param_pattern = r'func\s+\w+\s*\([^)]*(?:Message|Event|Payload)\s+(\w+)'
    match = re.search(param_pattern, code)
    if match:
        consumer_info["is_consumer"] = True
        consumer_info["message_type"] = match.group(1)
        consumer_info["handler_type"] = "message_parameter"
    
    return consumer_info if consumer_info["is_consumer"] else None


def match_pulsar_producers_to_consumers(
    producer_calls: List[Dict[str, Any]],
    all_chunks: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Match Pulsar message producers to their consumer handlers.
    
    Args:
        producer_calls: List of detected producer calls (from detect_pulsar_producers)
        all_chunks: All code chunks from all repos
    
    Returns:
        List of matched producer->consumer pairs
    """
    matches = []
    
    # Build consumer index by topic
    consumers_by_topic = {}
    for chunk in all_chunks:
        consumer_info = detect_pulsar_consumers(chunk)
        if consumer_info:
            for topic in consumer_info.get("topics", []):
                if topic not in consumers_by_topic:
                    consumers_by_topic[topic] = []
                consumers_by_topic[topic].append({
                    "chunk": chunk,
                    "consumer_info": consumer_info
                })
    
    # Match producers to consumers by topic
    for producer in producer_calls:
        topic = producer.get("topic")
        if topic and topic in consumers_by_topic:
            for consumer_data in consumers_by_topic[topic]:
                matches.append({
                    "producer": producer,
                    "consumer_chunk": consumer_data["chunk"],
                    "consumer_info": consumer_data["consumer_info"],
                    "topic": topic,
                    "match_type": "topic_exact"
                })
        elif topic:
            # Try fuzzy matching for partial topic names
            for consumer_topic, consumer_list in consumers_by_topic.items():
                if topic in consumer_topic or consumer_topic in topic:
                    for consumer_data in consumer_list:
                        matches.append({
                            "producer": producer,
                            "consumer_chunk": consumer_data["chunk"],
                            "consumer_info": consumer_data["consumer_info"],
                            "topic": topic,
                            "consumer_topic": consumer_topic,
                            "match_type": "topic_partial"
                        })
    
    return matches


def extract_function_calls(code: str, package: str) -> List[Tuple[str, Optional[str]]]:
    """
    Extract function calls from code.
    
    This is a simplified parser that looks for common patterns:
    - obj.Method()
    - package.Function()
    - Function()
    
    Args:
        code: Source code string
        package: Current package name
    
    Returns:
        List of tuples (function_name, package_name)
    """
    calls = []
    
    # Pattern 1: obj.Method() or obj.field.Method()
    # Matches: handler.bl.GetWorkflows(), service.repo.GetData()
    method_pattern = r'(\w+(?:\.\w+)*)\.(\w+)\s*\('
    for match in re.finditer(method_pattern, code):
        obj_path = match.group(1)
        method_name = match.group(2)
        
        # Skip common Go patterns that aren't function calls
        if obj_path in ['fmt', 'log', 'errors', 'context', 'http', 'json', 'time']:
            continue
        
        # Extract package from object path (e.g., "bl.WorkflowsBL" -> "bl")
        parts = obj_path.split('.')
        if len(parts) > 1:
            # Likely a package.method pattern
            calls.append((method_name, parts[0]))
        else:
            # Method call on an object
            calls.append((method_name, None))
    
    # Pattern 2: package.Function() (direct package calls)
    # Matches: bl.GetWorkflows(), repository.GetData()
    package_func_pattern = r'(\w+)\.(\w+)\s*\('
    for match in re.finditer(package_func_pattern, code):
        pkg_name = match.group(1)
        func_name = match.group(2)
        
        # Skip common Go standard library packages
        if pkg_name in ['fmt', 'log', 'errors', 'context', 'http', 'json', 'time', 'os', 'io', 'strings', 'strconv']:
            continue
        
        # Skip if it's the current package (likely a local function)
        if pkg_name == package:
            continue
        
        calls.append((func_name, pkg_name))
    
    # Pattern 3: Function() (local function calls - BOTH exported and unexported)
    # Matches: GetWorkflows(), ProcessData(), getVulnerabilitySummary(), newTicketsEnricher()
    local_func_pattern = r'\b([a-zA-Z]\w+)\s*\('
    for match in re.finditer(local_func_pattern, code):
        func_name = match.group(1)
        
        # Skip common Go keywords and built-ins
        if func_name in ['if', 'for', 'switch', 'select', 'return', 'break', 'continue',
                         'New', 'Make', 'Error', 'String', 'Int', 'Bool', 'Float',
                         'make', 'new', 'append', 'delete', 'len', 'cap', 'copy',
                         'panic', 'recover', 'defer', 'close', 'range']:
            continue
        
        # Skip common variable assignments (e.g., "err := func()")
        # This is heuristic - might need refinement
        if func_name in ['err', 'ok', 'res', 'result', 'value', 'data', 'item', 'i', 'j', 'k']:
            continue
        
        calls.append((func_name, None))
    
    # Remove duplicates
    return list(set(calls))


def classify_chunk_pattern(chunk: Dict[str, Any]) -> Optional[str]:
    """
    Classify chunk pattern (handler, service, repository, etc.).
    
    Returns:
        Pattern type or None
    """
    pattern = chunk.get("pattern", "").lower()
    chunk_type = chunk.get("type", "").lower()
    name = chunk.get("name", "").lower()
    package = chunk.get("package", "").lower()
    
    # Check explicit pattern
    if "handler" in pattern:
        return "handler"
    if "service" in pattern:
        return "service"
    if "repository" in pattern or "repo" in pattern:
        return "repository"
    if "connector" in pattern:
        return "connector"
    if "enricher" in pattern or "enrich" in pattern:
        return "enricher"
    if "validator" in pattern or "validate" in pattern:
        return "validator"
    if "helper" in pattern or "util" in pattern:
        return "helper"
    
    # Infer from package name
    if "handler" in package or "http" in package:
        return "handler"
    if "service" in package or "bl" in package or "business" in package:
        return "service"
    if "repository" in package or "repo" in package or "dal" in package:
        return "repository"
    if "connector" in package or "client" in package:
        return "connector"
    if "enricher" in package or "enrich" in package:
        return "enricher"
    if "validator" in package or "validate" in package:
        return "validator"
    if "helper" in package or "util" in package:
        return "helper"
    
    # Infer from name
    if "handler" in name:
        return "handler"
    if "service" in name or "bl" in name:
        return "service"
    if "repository" in name or "repo" in name:
        return "repository"
    if "enricher" in name or "enrich" in name:
        return "enricher"
    if "validator" in name or "validate" in name:
        return "validator"
    if "helper" in name or "util" in name:
        return "helper"
    
    return None


def extract_call_chain(
    handler_chunk_id: str,
    code_index: Dict[str, Any],
    max_depth: int = 3,
    visited: Optional[Set[str]] = None,
    all_chunks: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Extract call chain starting from a handler chunk.
    
    Args:
        handler_chunk_id: ID of the handler chunk
        code_index: Code index dict (main repository)
        max_depth: Maximum depth to traverse (default: 3)
        visited: Set of already visited chunk IDs (to prevent cycles)
        all_chunks: Optional list of all chunks from all repos (with _repo tag)
    
    Returns:
        Dict with call chain information
    """
    if visited is None:
        visited = set()
    
    # Use provided all_chunks if available, otherwise just use main index
    if all_chunks is None:
        chunks = code_index.get("chunks", [])
    else:
        chunks = all_chunks
    handler_chunk = find_chunk_by_id(handler_chunk_id, chunks)
    
    if not handler_chunk:
        return {
            "error": f"Handler chunk not found: {handler_chunk_id}",
            "chain": []
        }
    
    # Prevent cycles
    if handler_chunk_id in visited:
        return {
            "handler_chunk_id": handler_chunk_id,
            "handler_name": handler_chunk.get("name"),
            "circular": True,
            "chain": []
        }
    
    visited.add(handler_chunk_id)
    
    # Extract function calls from handler code
    handler_code = handler_chunk.get("code", "")
    handler_package = handler_chunk.get("package", "")
    
    # Parse imports to build alias -> repo mapping (will be updated per chunk)
    import_to_repo = parse_imports(handler_code)
    
    # Detect Pulsar message producers in handler
    pulsar_producers = detect_pulsar_producers(handler_code)
    
    # Match producers to consumers (if all_chunks available)
    pulsar_matches = []
    if all_chunks and pulsar_producers:
        pulsar_matches = match_pulsar_producers_to_consumers(pulsar_producers, all_chunks)
    
    function_calls = extract_function_calls(handler_code, handler_package)
    
    # Track cross-repo calls and repositories in chain
    cross_repo_calls = []
    repositories_in_chain = set([handler_chunk.get("_repo", "cadashboardbe")])  # Start with handler's repo
    
    # DEBUG: Log initial state
    if all_chunks:
        print(f"   🔍 DEBUG: all_chunks contains {len(all_chunks)} chunks from repos: {set(c.get('_repo', 'unknown') for c in all_chunks)}", file=sys.stderr)
        print(f"   🔍 DEBUG: Handler repo: {handler_chunk.get('_repo', 'cadashboardbe')}", file=sys.stderr)
    
    # Build call chain
    chain = []
    current_level = [{
        "chunk_id": handler_chunk_id,
        "name": handler_chunk.get("name"),
        "type": handler_chunk.get("type"),
        "pattern": classify_chunk_pattern(handler_chunk),
        "package": handler_package,
        "file": handler_chunk.get("file"),
        "repo": handler_chunk.get("_repo", "cadashboardbe")  # Include repo tag
    }]
    
    level = 0
    while level < max_depth and current_level:
        next_level = []
        
        for item in current_level:
            # Find the chunk for this item
            chunk = find_chunk_by_id(item["chunk_id"], chunks)
            if not chunk:
                continue
            
            chunk_code = chunk.get("code", "")
            chunk_package = chunk.get("package", "")
            chunk_repo = chunk.get("_repo", "cadashboardbe")
            
            # Parse imports from THIS chunk (update import_to_repo for this level)
            chunk_imports = parse_imports(chunk_code)
            if chunk_imports:
                import_to_repo.update(chunk_imports)  # Merge into global mapping
                print(f"   🔍 DEBUG Level {level}: Found {len(chunk_imports)} imports in chunk {chunk.get('name')} from repo {chunk_repo}", file=sys.stderr)
            
            # Detect Pulsar producers in this chunk
            chunk_pulsar_producers = detect_pulsar_producers(chunk_code)
            if chunk_pulsar_producers:
                pulsar_producers.extend(chunk_pulsar_producers)
                print(f"   🔍 DEBUG Level {level}: Found {len(chunk_pulsar_producers)} Pulsar producers in chunk {chunk.get('name')}", file=sys.stderr)
                # Match these producers to consumers
                if all_chunks:
                    new_matches = match_pulsar_producers_to_consumers(chunk_pulsar_producers, all_chunks)
                    pulsar_matches.extend(new_matches)
                    if new_matches:
                        print(f"   ✅ DEBUG Level {level}: Matched {len(new_matches)} Pulsar producer-consumer pairs", file=sys.stderr)
            
            # Extract calls from this chunk
            calls = extract_function_calls(chunk_code, chunk_package)
            
            # Find matching chunks for each call
            for func_name, pkg_name in calls:
                # Check if this is a cross-repo call
                if pkg_name and pkg_name in import_to_repo:
                    repo_name = import_to_repo[pkg_name]
                    if repo_name != chunk_repo:  # Only log if different repo
                        print(f"   🌐 DEBUG Level {level}: Cross-repo call detected: {chunk_repo}.{func_name} -> {repo_name}.{pkg_name}", file=sys.stderr)
                        cross_repo_calls.append({
                            "repo": repo_name,
                            "package": pkg_name,
                            "function": func_name,
                            "called_from_chunk": item["chunk_id"],
                            "called_from_repo": chunk_repo
                        })
                        repositories_in_chain.add(repo_name)
                
                # Try to find chunk by name and package
                matching_chunks = find_chunks_by_name(func_name, chunks, pkg_name)
                
                # If no package specified, try without package constraint
                if not matching_chunks and pkg_name is None:
                    matching_chunks = find_chunks_by_name(func_name, chunks)
                
                for called_chunk in matching_chunks:
                    called_chunk_id = called_chunk.get("id")
                    called_pattern = classify_chunk_pattern(called_chunk)
                    called_repo = called_chunk.get("_repo", "cadashboardbe")
                    
                    # Check if this chunk sends Pulsar messages (critical for cross-service tracing)
                    sends_pulsar = is_pulsar_sender(called_chunk)
                    
                    # Only follow service/repository/enricher/helper patterns (skip handlers, connectors at deeper levels)
                    # EXCEPTION: Always follow Pulsar-sending functions regardless of pattern
                    if sends_pulsar:
                        # Always follow Pulsar senders (e.g., handleUserInputOutput)
                        print(f"   🚀 DEBUG Level {level}: Following Pulsar sender: {called_chunk.get('name')} (pattern: {called_pattern})", file=sys.stderr)
                    elif level == 0:
                        # First level: can be anything
                        pass
                    elif level == 1:
                        # Second level: prefer service/repository, but allow enrichers/validators/helpers
                        if called_pattern and called_pattern not in ["service", "repository", "enricher", "validator", "helper", None]:
                            continue
                    elif level == 2:
                        # Third level: repository, enricher, validator, helper, or unknown functions
                        if called_pattern and called_pattern not in ["repository", "enricher", "validator", "helper", "dal", None]:
                            continue
                    else:
                        # Fourth level and beyond: repository, enricher, dal, or unknown functions
                        if called_pattern and called_pattern not in ["repository", "enricher", "dal", None]:
                            continue
                    
                    # Skip if already visited
                    if called_chunk_id in visited:
                        continue
                    
                    visited.add(called_chunk_id)
                    
                    next_item = {
                        "chunk_id": called_chunk_id,
                        "name": called_chunk.get("name"),
                        "type": called_chunk.get("type"),
                        "pattern": called_pattern,
                        "package": called_chunk.get("package"),
                        "file": called_chunk.get("file"),
                        "repo": called_repo,  # Include repo tag
                        "called_from": item["chunk_id"],
                        "function_name": func_name
                    }
                    
                    # Track repo in chain
                    repositories_in_chain.add(called_repo)
                    
                    # DEBUG: Log when adding chunk from different repo
                    if called_repo != chunk_repo:
                        print(f"   ✅ DEBUG Level {level}: Adding cross-repo chunk: {called_repo}/{called_chunk.get('name')} (called from {chunk_repo})", file=sys.stderr)
                    
                    next_level.append(next_item)
                    chain.append(next_item)
        
        current_level = next_level
        level += 1
    
    # Add Pulsar consumer chunks to chain if matched
    pulsar_consumer_chunks = []
    if pulsar_matches:
        for match in pulsar_matches:
            consumer_chunk = match["consumer_chunk"]
            consumer_chunk_id = consumer_chunk.get("id")
            if consumer_chunk_id and consumer_chunk_id not in visited:
                visited.add(consumer_chunk_id)
                consumer_item = {
                    "chunk_id": consumer_chunk_id,
                    "name": consumer_chunk.get("name"),
                    "type": consumer_chunk.get("type"),
                    "pattern": "pulsar_consumer",
                    "package": consumer_chunk.get("package"),
                    "file": consumer_chunk.get("file"),
                    "repo": consumer_chunk.get("_repo", "unknown"),
                    "pulsar_topic": match.get("topic"),
                    "match_type": match.get("match_type"),
                    "called_from": "pulsar_message"
                }
                chain.append(consumer_item)
                pulsar_consumer_chunks.append(consumer_item)
                
                # Track repo
                repo = consumer_chunk.get("_repo")
                if repo:
                    repositories_in_chain.add(repo)
    
    return {
        "handler_chunk_id": handler_chunk_id,
        "handler_name": handler_chunk.get("name"),
        "max_depth": max_depth,
        "chain": chain,
        "total_chunks": len(chain) + 1,  # +1 for handler itself
        "cross_repo_calls": cross_repo_calls,
        "repositories_in_chain": list(repositories_in_chain),
        "pulsar_producers": pulsar_producers,
        "pulsar_matches": pulsar_matches,
        "pulsar_consumer_chunks": pulsar_consumer_chunks
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extract call chains from handler code"
    )
    parser.add_argument(
        "--handler-chunk-id",
        required=True,
        help="ID of the handler chunk to start from"
    )
    parser.add_argument(
        "--index",
        required=True,
        help="Path to code index JSON file"
    )
    parser.add_argument(
        "--dependency-indexes",
        help="JSON string mapping repo names to index paths: {\"postgres-connector\": \"path/to/index.json\"}"
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=3,
        help="Maximum depth to traverse (default: 3)"
    )
    parser.add_argument(
        "--output",
        default="artifacts/call-chains.json",
        help="Path to save call chain JSON (default: artifacts/call-chains.json)"
    )
    
    args = parser.parse_args()
    
    # Load code index
    print(f"Loading code index from: {args.index}")
    code_index = load_code_index(args.index)
    main_chunks = code_index.get('chunks', [])
    
    # Load dependency indexes if provided
    all_chunks = []
    dependency_chunks = {}
    
    if args.dependency_indexes:
        try:
            dep_indexes = json.loads(args.dependency_indexes)
            print(f"Loading {len(dep_indexes)} dependency indexes...")
            
            for repo_name, index_path in dep_indexes.items():
                if os.path.exists(index_path):
                    dep_index = load_code_index(index_path)
                    dep_chunks = dep_index.get('chunks', [])
                    dependency_chunks[repo_name] = dep_chunks
                    print(f"  Loaded {len(dep_chunks)} chunks from {repo_name}")
                else:
                    print(f"  ⚠️  Index not found: {index_path}")
        except json.JSONDecodeError as e:
            print(f"⚠️  Warning: Failed to parse dependency-indexes JSON: {e}")
        except Exception as e:
            print(f"⚠️  Warning: Error loading dependency indexes: {e}")
    
    # Combine all chunks with repo tags
    for chunk in main_chunks:
        chunk['_repo'] = 'cadashboardbe'  # Tag with source repo
        all_chunks.append(chunk)
    
    for repo_name, chunks in dependency_chunks.items():
        for chunk in chunks:
            chunk['_repo'] = repo_name
            all_chunks.append(chunk)
    
    if dependency_chunks:
        print(f"Total chunks available: {len(all_chunks)} (from {1 + len(dependency_chunks)} repos)")
    
    # Extract call chain
    print(f"Extracting call chain for handler chunk: {args.handler_chunk_id}")
    print(f"Max depth: {args.max_depth}")
    
    result = extract_call_chain(
        handler_chunk_id=args.handler_chunk_id,
        code_index=code_index,
        max_depth=args.max_depth,
        all_chunks=all_chunks if all_chunks else None
    )
    
    if "error" in result:
        print(f"❌ Error: {result['error']}", file=sys.stderr)
        sys.exit(1)
    
    # Print summary
    print(f"\n📊 Call Chain Summary:")
    print(f"   Handler: {result.get('handler_name')}")
    print(f"   Total chunks in chain: {result.get('total_chunks')}")
    print(f"   Chain depth: {len(result.get('chain', []))}")
    
    # Group by pattern
    patterns = {}
    for item in result.get("chain", []):
        pattern = item.get("pattern", "unknown")
        if pattern not in patterns:
            patterns[pattern] = 0
        patterns[pattern] += 1
    
    if patterns:
        print(f"\n   Chunks by pattern:")
        for pattern, count in patterns.items():
            print(f"     {pattern}: {count}")
    
    # Print Pulsar detection summary
    pulsar_producers = result.get("pulsar_producers", [])
    pulsar_matches = result.get("pulsar_matches", [])
    pulsar_consumers = result.get("pulsar_consumer_chunks", [])
    
    if pulsar_producers:
        print(f"\n   📨 Pulsar Producers detected: {len(pulsar_producers)}")
        for prod in pulsar_producers[:5]:  # Show first 5
            topic = prod.get("topic", "unknown")
            method = prod.get("method", "unknown")
            print(f"     - {method} to topic: {topic}")
        if len(pulsar_producers) > 5:
            print(f"     ... and {len(pulsar_producers) - 5} more")
    
    if pulsar_matches:
        print(f"\n   🔗 Pulsar Producer→Consumer matches: {len(pulsar_matches)}")
        for match in pulsar_matches[:5]:  # Show first 5
            topic = match.get("topic", "unknown")
            consumer_name = match.get("consumer_chunk", {}).get("name", "unknown")
            consumer_repo = match.get("consumer_chunk", {}).get("_repo", "unknown")
            match_type = match.get("match_type", "unknown")
            print(f"     - Topic '{topic}' → {consumer_repo}/{consumer_name} ({match_type})")
        if len(pulsar_matches) > 5:
            print(f"     ... and {len(pulsar_matches) - 5} more")
    
    # Print cross-repo calls
    cross_repo_calls = result.get("cross_repo_calls", [])
    if cross_repo_calls:
        print(f"\n   🌐 Cross-repo calls detected: {len(cross_repo_calls)}")
        repos = set(call.get("repo") for call in cross_repo_calls)
        print(f"     Calling into: {', '.join(sorted(repos))}")
    
    repositories = result.get("repositories_in_chain", [])
    if len(repositories) > 1:
        print(f"\n   📦 Repositories in chain: {', '.join(sorted(repositories))}")
    
    # Save results
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📄 Call chain saved to: {args.output}")


if __name__ == "__main__":
    main()


#!/usr/bin/python3
# CRITICAL: Write to file BEFORE any imports to verify script execution
# Write to current directory since /tmp might have restrictions
try:
    import os
    log_dir = "artifacts"
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "script_start.log"), "w") as f:
        f.write("Script file is being read and executed\n")
        f.write(f"Working directory: {os.getcwd()}\n")
        f.flush()
        try:
            os.fsync(f.fileno())
        except:
            pass
except Exception as e:
    # Last resort - try /tmp with error handling
    try:
        with open("/tmp/build_llm_context_script_start_error.log", "w") as err_f:
            err_f.write(f"Error writing to artifacts: {e}\n")
            err_f.flush()
    except:
        pass

"""
Build LLM-ready context from all available sources.

This script combines:
1. Test code (from system-tests repository)
2. API handlers and call chains (from map_apis_with_call_chains.py)
3. Connected repos context (from extract_connected_context.py)
4. Error logs (from Loki or workflow logs)
5. Metadata (test name, test run ID, versions, etc.)

And formats everything into a single LLM-friendly JSON structure.

Usage:
    python build_llm_context.py \
      --test-name jira_integration \
      --test-run-id <id> \
      --workflow-commit <sha> \
      --api-mapping artifacts/api-code-map-with-chains.json \
      --connected-context artifacts/connected-context.json \
      --error-logs artifacts/loki-errors.txt \
      --resolved-commits artifacts/resolved-repo-commits.json \
      --output artifacts/llm-context.json
"""

# CRITICAL: Print at module load time to verify script is executing
import sys
import os

# Write to file immediately to verify script is loading
try:
    with open("/tmp/build_llm_context_module_load.log", "w") as f:
        try:
            file_path = __file__
        except NameError:
            file_path = "unknown"
        f.write(f"Module loading at {file_path}\n")
        f.write(f"sys.argv = {sys.argv}\n")
        f.write(f"Python version: {sys.version}\n")
        f.flush()
        os.fsync(f.fileno())
except Exception as e:
    # Try to write error to a different location
    try:
        with open("/tmp/build_llm_context_module_load_error.log", "w") as err_f:
            err_f.write(f"Error in module load logging: {e}\n")
            err_f.flush()
            os.fsync(err_f.fileno())
    except:
        pass

print("MODULE_LOAD: build_llm_context.py is being executed", file=sys.stderr)
sys.stderr.flush()

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


def load_json_file(file_path: str, required: bool = False) -> Optional[Dict[str, Any]]:
    """Load JSON file."""
    if not os.path.exists(file_path):
        if required:
            print(f"Error: Required file not found: {file_path}", file=sys.stderr)
            sys.exit(1)
        return None
    
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {file_path}: {e}", file=sys.stderr)
        if required:
            sys.exit(1)
        return None


def load_text_file(file_path: str) -> Optional[str]:
    """Load text file."""
    if not os.path.exists(file_path):
        return None
    
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
        return None


def load_analysis_prompts(prompts_file: str = None) -> Optional[str]:
    """Load analysis prompts from file."""
    if prompts_file and os.path.exists(prompts_file):
        with open(prompts_file, 'r') as f:
            return f.read()
    
    # Default prompts file
    default_path = os.path.join(os.path.dirname(__file__), "analysis_prompts.md")
    if os.path.exists(default_path):
        with open(default_path, 'r') as f:
            return f.read()
    
    return None


def calculate_dependency_impact(dep_name: str, code_diffs: Dict, 
                                call_chains: Dict, all_chunks: List[Dict]) -> tuple:
    """
    Calculate impact level for a dependency.
    
    Returns:
        (impact_level, list of changed+called functions)
    
    Impact levels:
        HIGH: Functions that both changed AND were called
        MEDIUM: Functions changed but not called
        LOW: Functions called but not changed
        NONE: Not changed and not called
    """
    if not code_diffs or dep_name not in code_diffs:
        return ("LOW", [])  # Called but not changed
    
    dep_diff = code_diffs[dep_name]
    
    # Skip if indexes were missing
    if dep_diff.get('indexes_missing'):
        return ("UNKNOWN", [])
    
    # Get changed functions
    changed_funcs = set()
    if 'functions' in dep_diff:
        changed_funcs.update(dep_diff['functions'].get('added', []))
        changed_funcs.update(dep_diff['functions'].get('removed', []))
        # If there's a 'modified' field, include it
        if 'modified' in dep_diff['functions']:
            changed_funcs.update(dep_diff['functions'].get('modified', []))
    
    # Get called functions from call chains
    called_funcs = set()
    for mapping in call_chains.get('mappings', {}).values():
        call_chain = mapping.get('call_chain', {})
        cross_repo_calls = call_chain.get('cross_repo_calls', [])
        
        for cross_call in cross_repo_calls:
            if cross_call.get('repo') == dep_name:
                called_funcs.add(cross_call.get('function', ''))
    
    # Also check chunks with _repo tag
    for chunk in all_chunks:
        if chunk.get('_repo') == dep_name:
            called_funcs.add(chunk.get('name', ''))
    
    # Calculate intersection
    intersection = changed_funcs & called_funcs
    
    if intersection:
        return ("HIGH", list(intersection))
    elif called_funcs:
        return ("LOW", [])
    elif changed_funcs:
        return ("MEDIUM", [])
    else:
        return ("NONE", [])


def extract_chunks_from_api_mapping(api_mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract code chunks from API mapping with call chains."""
    chunks = []
    mappings = api_mapping.get("mappings", {})
    
    for api_key, mapping in mappings.items():
        if not mapping.get("matched"):
            continue
        
        # Add handler chunk
        handler_chunk = mapping.get("handler_chunk")
        if handler_chunk:
            chunks.append({
                **handler_chunk,
                "source": "api_handler",
                "api_path": api_key,
                "priority": 1  # High priority - directly tested
            })
        
        # Add call chain chunks
        # Note: Call chain items may only have metadata (chunk_id, name, etc.) without full code
        # The code will need to be looked up from the code index if available
        call_chain = mapping.get("call_chain", {})
        chain_list = call_chain.get("chain", [])
        for chain_item in chain_list:
            if isinstance(chain_item, dict) and chain_item.get("chunk_id"):
                chunks.append({
                    **chain_item,
                    "source": "call_chain",
                    "api_path": api_key,
                    "priority": 2,  # Medium priority - related to tested API
                    # Note: code may be missing - will be looked up from code_index if provided
                    "code": chain_item.get("code", "")
                })
    
    return chunks


def extract_chunks_from_connected_context(connected_context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract code chunks from connected context."""
    chunks = []
    
    # Try different possible structures
    final_chunks = connected_context.get("final_context_chunks", [])
    if not final_chunks:
        # Try alternative structure from apply_size_limits.py
        chunks_by_repo = connected_context.get("chunks_by_repo", {})
        for repo_name, repo_chunks in chunks_by_repo.items():
            for chunk_info in repo_chunks:
                chunk = chunk_info.get("chunk", chunk_info)
                chunks.append({
                    **chunk,
                    "repo_name": repo_name,
                    "source": chunk_info.get("source", "connected_repo"),
                    "priority": chunk_info.get("priority", 3)  # Lower priority - connected but not directly tested
                })
        return chunks
    
    # Original structure
    for chunk in final_chunks:
        chunks.append({
            **chunk,
            "source": chunk.get("source", "connected_repo"),
            "priority": chunk.get("priority", 3)  # Lower priority - connected but not directly tested
        })
    
    return chunks


def format_chunk_for_llm(chunk: Dict[str, Any], repo_name: str = None) -> Dict[str, Any]:
    """Format a code chunk for LLM consumption."""
    formatted = {
        "id": chunk.get("id") or chunk.get("chunk_id"),
        "name": chunk.get("name"),
        "type": chunk.get("type"),  # function, method, type, interface, etc.
        "package": chunk.get("package"),
        "file": chunk.get("file"),
        "code": chunk.get("code", ""),
        "repo": repo_name or chunk.get("repo_name", "unknown"),
        "source": chunk.get("source", "unknown"),
        "priority": chunk.get("priority", 999)
    }
    
    # Add documentation if available
    if chunk.get("doc"):
        formatted["documentation"] = chunk.get("doc")
    
    # Add line numbers if available
    if chunk.get("line_start") and chunk.get("line_end"):
        formatted["line_range"] = {
            "start": chunk.get("line_start"),
            "end": chunk.get("line_end")
        }
    
    # Add API path if this chunk is related to an API
    if chunk.get("api_path"):
        formatted["api_path"] = chunk.get("api_path")
    
    # Add call chain info if available
    if chunk.get("depth") is not None:
        formatted["call_chain_depth"] = chunk.get("depth")
    
    return formatted


def format_context_as_text(context: Dict[str, Any]) -> str:
    """Format context as markdown text for LLM consumption."""
    lines = []
    metadata = context.get("metadata", {})
    
    # Header
    lines.append("# Test Failure Analysis Context\n")
    lines.append(f"**Test Name:** {metadata.get('test_name', 'unknown')}")
    lines.append(f"**Test Run ID:** {metadata.get('test_run_id', 'N/A')}")
    lines.append(f"**Workflow Commit:** {metadata.get('workflow_commit', 'N/A')}")
    lines.append(f"**Generated At:** {metadata.get('generated_at', 'N/A')}")
    lines.append("")
    
    # Repositories
    repos = metadata.get("repos", {})
    if repos:
        lines.append("## Repositories\n")
        for repo_name, repo_info in repos.items():
            commit = repo_info.get("commit", "N/A")
            is_triggering = repo_info.get("is_triggering_repo", False)
            trigger_note = " (triggering repo)" if is_triggering else ""
            lines.append(f"- **{repo_name}**: `{commit[:8]}`{trigger_note}")
        lines.append("")
    
    # Summary
    lines.append("## Summary\n")
    lines.append(f"- **Total Code Chunks:** {metadata.get('total_chunks', 0)}")
    lines.append(f"- **Total Lines of Code:** {metadata.get('total_lines_of_code', 0)}")
    lines.append("")
    
    chunks_by_source = metadata.get("chunks_by_source", {})
    if chunks_by_source:
        lines.append("### Chunks by Source\n")
        for source, count in sorted(chunks_by_source.items(), key=lambda x: -x[1]):
            lines.append(f"- {source}: {count}")
        lines.append("")
    
    chunks_by_repo = metadata.get("chunks_by_repo", {})
    if chunks_by_repo:
        lines.append("### Chunks by Repository\n")
        for repo, count in sorted(chunks_by_repo.items(), key=lambda x: -x[1]):
            lines.append(f"- {repo}: {count}")
        lines.append("")
    
    # Error logs
    if context.get("error_logs"):
        lines.append("## Error Logs\n")
        lines.append("```")
        error_logs = context.get("error_logs", "")
        # Limit to first 2000 chars for readability
        lines.append(error_logs[:2000] + ("..." if len(error_logs) > 2000 else ""))
        lines.append("```")
        lines.append("")
    
    # Test code
    if context.get("test_code"):
        lines.append("## Test Code\n")
        lines.append("```python")
        test_code = context.get("test_code", "")
        # Limit to first 3000 chars
        lines.append(test_code[:3000] + ("..." if len(test_code) > 3000 else ""))
        lines.append("```")
        lines.append("")
    
    # Code chunks
    lines.append("## Code Chunks\n")
    chunks = context.get("code_chunks", [])
    
    # Group by repo
    chunks_by_repo_grouped = {}
    for chunk in chunks:
        repo = chunk.get("repo", "unknown")
        if repo not in chunks_by_repo_grouped:
            chunks_by_repo_grouped[repo] = []
        chunks_by_repo_grouped[repo].append(chunk)
    
    for repo_name in sorted(chunks_by_repo_grouped.keys()):
        repo_chunks = chunks_by_repo_grouped[repo_name]
        lines.append(f"### Repository: {repo_name}\n")
        
        for i, chunk in enumerate(repo_chunks, 1):
            lines.append(f"#### Chunk {i}: {chunk.get('name', 'unnamed')}\n")
            
            # Metadata
            chunk_info = []
            if chunk.get("type"):
                chunk_info.append(f"Type: {chunk['type']}")
            if chunk.get("package"):
                chunk_info.append(f"Package: {chunk['package']}")
            if chunk.get("file"):
                chunk_info.append(f"File: {chunk['file']}")
            if chunk.get("line_range"):
                lines.append(f"Lines: {chunk['line_range']['start']}-{chunk['line_range']['end']}")
            if chunk.get("source"):
                chunk_info.append(f"Source: {chunk['source']}")
            if chunk.get("api_path"):
                chunk_info.append(f"API: {chunk['api_path']}")
            
            if chunk_info:
                lines.append(" | ".join(chunk_info))
                lines.append("")
            
            # Documentation
            if chunk.get("documentation"):
                lines.append(f"**Documentation:**\n{chunk['documentation']}\n")
            
            # Code
            lines.append("```go")
            code = chunk.get("code", "")
            # Limit each chunk to 500 lines for readability
            code_lines = code.splitlines()
            if len(code_lines) > 500:
                lines.append("\n".join(code_lines[:500]))
                lines.append(f"\n... ({len(code_lines) - 500} more lines)")
            else:
                lines.append(code)
            lines.append("```")
            lines.append("")
    
    return "\n".join(lines)


def deduplicate_chunks(chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate chunks (by ID)."""
    seen_ids = set()
    unique_chunks = []
    
    for chunk in chunks:
        chunk_id = chunk.get("id") or chunk.get("chunk_id")
        if chunk_id and chunk_id not in seen_ids:
            seen_ids.add(chunk_id)
            unique_chunks.append(chunk)
        elif not chunk_id:
            # If no ID, use name+package+file as key
            key = f"{chunk.get('name')}:{chunk.get('package')}:{chunk.get('file')}"
            if key not in seen_ids:
                seen_ids.add(key)
                unique_chunks.append(chunk)
    
    return unique_chunks


def lookup_chunk_code(chunk_id: str, code_index: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Look up full chunk code from code index using chunk_id."""
    if not code_index or not chunk_id:
        return None
    
    chunks = code_index.get("chunks", [])
    for chunk in chunks:
        if chunk.get("id") == chunk_id:
            return chunk.get("code", "")
    return None


def build_llm_context(
    test_name: str,
    test_run_id: Optional[str],
    workflow_commit: Optional[str],
    api_mapping: Optional[Dict[str, Any]] = None,
    connected_context: Optional[Dict[str, Any]] = None,
    error_logs: Optional[str] = None,
    resolved_commits: Optional[Dict[str, Any]] = None,
    code_diffs: Optional[Dict[str, Any]] = None,
    test_code: Optional[str] = None,
    code_index: Optional[Dict[str, Any]] = None,
    analysis_prompts: Optional[str] = None,
    incluster_logs: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    cross_test_interference: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Build LLM-ready context from all sources.
    
    Args:
        test_name: Name of the test
        test_run_id: Test run ID
        workflow_commit: Workflow commit SHA
        api_mapping: Output from map_apis_with_call_chains.py
        connected_context: Output from extract_connected_context.py
        code_diffs: Output from compare_code_indexes.py (multi-repo)
        error_logs: Error logs text
        resolved_commits: Output from resolve_repo_commits.py
        test_code: Test code (optional, if available)
        code_index: Code index for looking up chunk code
        analysis_prompts: Analysis instructions for the LLM
    
    Returns:
        Dictionary with LLM-ready context
    """
    all_chunks = []
    
    # 1. Extract chunks from API mapping (highest priority - directly tested APIs)
    if api_mapping:
        print("📋 Extracting chunks from API mapping...", file=sys.stderr)
        sys.stderr.flush()
        api_chunks = extract_chunks_from_api_mapping(api_mapping)
        all_chunks.extend(api_chunks)
        print(f"   Added {len(api_chunks)} chunks from API mapping", file=sys.stderr)
        sys.stderr.flush()
    
    # 2. Extract chunks from connected context (medium priority - related code)
    if connected_context:
        print("🔗 Extracting chunks from connected context...")
        connected_chunks = extract_chunks_from_connected_context(connected_context)
        all_chunks.extend(connected_chunks)
        print(f"   Added {len(connected_chunks)} chunks from connected context")
    
    # 3. Deduplicate chunks
    print("🧹 Deduplicating chunks...", file=sys.stderr)
    sys.stderr.flush()
    unique_chunks = deduplicate_chunks(all_chunks)
    print(f"   {len(unique_chunks)} unique chunks after deduplication (from {len(all_chunks)} total)", file=sys.stderr)
    sys.stderr.flush()
    
    # 4. Look up missing code for ALL chunks (if code_index provided)
    if code_index:
        print("🔍 Looking up missing chunk code from code index...", file=sys.stderr)
        sys.stderr.flush()
        looked_up = 0
        for chunk in unique_chunks:
            chunk_id = chunk.get("id") or chunk.get("chunk_id")
            # Look up code for ANY chunk that doesn't have it yet
            if chunk_id and not chunk.get("code"):
                code = lookup_chunk_code(chunk_id, code_index)
                if code:
                    chunk["code"] = code
                    looked_up += 1
        if looked_up > 0:
            print(f"   Looked up code for {looked_up} chunks", file=sys.stderr)
            sys.stderr.flush()
    
    # 5. Sort by priority (lower number = higher priority)
    unique_chunks.sort(key=lambda c: (
        c.get("priority", 999),
        c.get("source", ""),
        c.get("name", "")
    ))
    
    # 6. Determine repo names for chunks (try to infer from resolved_commits or use default)
    repo_mapping = {}
    if resolved_commits:
        resolved = resolved_commits.get("resolved_commits", {})
        # Use first repo as default (usually cadashboardbe)
        default_repo = list(resolved.keys())[0] if resolved else "cadashboardbe"
        repo_mapping["default"] = default_repo
    else:
        repo_mapping["default"] = "cadashboardbe"
    
    # 7. Format chunks for LLM
    formatted_chunks = []
    for chunk in unique_chunks:
        # Try to get repo name from chunk, or infer from package/file, or use default
        repo_name = chunk.get("repo_name") or chunk.get("repo")
        if not repo_name:
            # Try to infer from package (e.g., "httphandlerv2" -> likely cadashboardbe)
            package = chunk.get("package", "")
            if package and resolved_commits:
                # Check if any repo in resolved_commits matches
                resolved = resolved_commits.get("resolved_commits", {})
                # Default to first repo (usually cadashboardbe)
                repo_name = repo_mapping["default"]
            else:
                repo_name = repo_mapping.get("default", "cadashboardbe")
        
        formatted_chunk = format_chunk_for_llm(chunk, repo_name)
        formatted_chunks.append(formatted_chunk)
    
    # 8. Build metadata
    metadata = {
        "test_name": test_name,
        "test_run_id": test_run_id,
        "workflow_commit": workflow_commit,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "analysis_instructions": analysis_prompts,
        "total_chunks": len(formatted_chunks),
        "chunks_by_source": {},
        "chunks_by_repo": {},
        "repos": {}
    }
    
    # Count chunks by source and repo
    for chunk in formatted_chunks:
        source = chunk.get("source", "unknown")
        repo = chunk.get("repo", "unknown")
        
        metadata["chunks_by_source"][source] = metadata["chunks_by_source"].get(source, 0) + 1
        metadata["chunks_by_repo"][repo] = metadata["chunks_by_repo"].get(repo, 0) + 1
    
    # Build dependency analysis if code_diffs available
    if code_diffs and api_mapping:
        print("📊 Building dependency impact analysis...", file=sys.stderr)
        sys.stderr.flush()
        
        dependency_analysis = {}
        repositories_included = set()
        
        # Collect all repos from chunks
        for chunk in formatted_chunks:
            repo = chunk.get("_repo") or chunk.get("repo")
            if repo and repo != "cadashboardbe":
                repositories_included.add(repo)
        
        # Analyze each dependency
        for dep_name in repositories_included:
            # Calculate impact
            impact, critical_functions = calculate_dependency_impact(
                dep_name, code_diffs, api_mapping, formatted_chunks
            )
            
            # Get version info
            deployed_ver = "unknown"
            rc_ver = "unknown"
            version_changed = False
            
            if dep_name in code_diffs:
                deployed_ver = code_diffs[dep_name].get('old_version', 'unknown')
                rc_ver = code_diffs[dep_name].get('new_version', 'unknown')
                version_changed = code_diffs[dep_name].get('changed', False)
            
            # Count chunks from this dependency
            chunks_included = sum(1 for c in formatted_chunks if c.get('_repo') == dep_name or c.get('repo') == dep_name)
            
            # Get called functions
            functions_called = []
            if api_mapping:
                for mapping in api_mapping.get('mappings', {}).values():
                    call_chain = mapping.get('call_chain', {})
                    cross_repo_calls = call_chain.get('cross_repo_calls', [])
                    
                    for cross_call in cross_repo_calls:
                        if cross_call.get('repo') == dep_name:
                            func = cross_call.get('function', '')
                            if func and func not in functions_called:
                                functions_called.append(func)
            
            # Get changed functions
            functions_changed = []
            if dep_name in code_diffs and 'functions' in code_diffs[dep_name]:
                functions_changed = (
                    code_diffs[dep_name]['functions'].get('added', []) +
                    code_diffs[dep_name]['functions'].get('removed', []) +
                    code_diffs[dep_name]['functions'].get('modified', [])
                )
            
            dependency_analysis[dep_name] = {
                "deployed_version": deployed_ver,
                "rc_version": rc_ver,
                "version_changed": version_changed,
                "chunks_included": chunks_included,
                "functions_called": functions_called,
                "functions_changed": functions_changed,
                "functions_both_changed_and_called": critical_functions,
                "impact": impact
            }
        
        metadata["dependency_analysis"] = dependency_analysis
        metadata["repositories_included"] = ["cadashboardbe"] + list(repositories_included)
        
        print(f"   Analyzed {len(dependency_analysis)} dependencies", file=sys.stderr)
        sys.stderr.flush()
    
    # Add repo commit information
    if resolved_commits:
        resolved = resolved_commits.get("resolved_commits", {})
        triggering_repo = resolved_commits.get("triggering_repo_normalized", "")
        for repo_name, commit in resolved.items():
            # Handle None repo_name
            if not repo_name:
                continue
            is_triggering = False
            if triggering_repo and repo_name:
                is_triggering = (triggering_repo.lower() == repo_name.lower())
            metadata["repos"][repo_name] = {
                "commit": commit,
                "is_triggering_repo": is_triggering
            }
    
    # 9. Build final context
    # Smart truncation of error logs to preserve Loki excerpts
    truncated_error_logs = None
    if error_logs:
        # Check if we have both test errors and Loki excerpts
        if "=== Loki Excerpts ===" in error_logs:
            parts = error_logs.split("=== Loki Excerpts ===")
            test_errors = parts[0]
            loki_logs = parts[1] if len(parts) > 1 else ""
            
            # Truncate test errors to 3000 chars (they're often duplicated)
            truncated_errors = test_errors[:3000]
            if len(test_errors) > 3000:
                truncated_errors += "\n... (truncated) ..."
            
            # Keep first 7000 chars of Loki logs (most relevant are at start)
            truncated_loki = loki_logs[:7000]
            if len(loki_logs) > 7000:
                truncated_loki += "\n... (truncated) ..."
            
            truncated_error_logs = truncated_errors + "\n=== Loki Excerpts ===" + truncated_loki
        else:
            # No Loki logs, just truncate errors
            truncated_error_logs = error_logs[:5000]
            if len(error_logs) > 5000:
                truncated_error_logs += "\n... (truncated) ..."
    
    # Process in-cluster logs if available
    incluster_log_summary = {}
    if incluster_logs:
        total_incluster_lines = 0
        incluster_log_summary = {
            "components": list(incluster_logs.keys()),
            "total_components": len(incluster_logs),
            "lines_by_component": {},
            "errors_by_component": {},
            "warnings_by_component": {}
        }
        
        for component, logs in incluster_logs.items():
            line_count = len(logs)
            total_incluster_lines += line_count
            incluster_log_summary["lines_by_component"][component] = line_count
            
            # Count errors and warnings
            errors = sum(1 for log in logs if log.get("level") == "error")
            warnings = sum(1 for log in logs if log.get("level") == "warn")
            
            if errors > 0:
                incluster_log_summary["errors_by_component"][component] = errors
            if warnings > 0:
                incluster_log_summary["warnings_by_component"][component] = warnings
        
        incluster_log_summary["total_lines"] = total_incluster_lines
        metadata["incluster_log_summary"] = incluster_log_summary
    
    context = {
        "metadata": metadata,
        "error_logs": truncated_error_logs,
        "test_code": test_code[:10000] if test_code else None,  # Limit test code to 10000 chars
        "code_chunks": formatted_chunks,
        "incluster_logs": incluster_logs or {}
    }
    
    # Add cross-test interference data if available (this is INPUT context, not a conclusion)
    if cross_test_interference:
        context["cross_test_interference"] = cross_test_interference
        print(f"   ✅ Added cross-test interference data to context", file=sys.stderr)
        sys.stderr.flush()
    
    # Calculate total size
    total_lines = sum(len(chunk.get("code", "").splitlines()) for chunk in formatted_chunks)
    context["metadata"]["total_lines_of_code"] = total_lines
    
    return context


def main():
    parser = argparse.ArgumentParser(
        description="Build LLM-ready context from all available sources."
    )
    parser.add_argument(
        "--test-name",
        required=True,
        help="Name of the test (e.g., 'jira_integration')"
    )
    parser.add_argument(
        "--test-run-id",
        help="Test run ID"
    )
    parser.add_argument(
        "--workflow-commit",
        help="Workflow commit SHA"
    )
    parser.add_argument(
        "--api-mapping",
        help="Path to API mapping with call chains JSON (from map_apis_with_call_chains.py)"
    )
    parser.add_argument(
        "--connected-context",
        help="Path to connected context JSON (from extract_connected_context.py)"
    )
    parser.add_argument(
        "--error-logs",
        help="Path to error logs file"
    )
    parser.add_argument(
        "--resolved-commits",
        help="Path to resolved repo commits JSON (from resolve_repo_commits.py)"
    )
    parser.add_argument(
        "--code-diffs",
        help="Path to code diffs JSON (from compare_code_indexes.py)"
    )
    parser.add_argument(
        "--incluster-logs",
        help="Path to in-cluster component logs JSON (from analyzer.py report.json)"
    )
    parser.add_argument(
        "--test-code",
        help="Path to test code file (optional)"
    )
    parser.add_argument(
        "--code-index",
        help="Path to code index JSON (optional, used to look up full chunk code for call chains)"
    )
    parser.add_argument(
        "--prompts-file",
        type=str,
        help="Path to analysis prompts file (default: analysis_prompts.md)"
    )
    parser.add_argument(
        "--cross-test-interference",
        help="Path to cross-test interference data JSON (optional, from detect_cross_test_interference.py)"
    )
    parser.add_argument(
        "--output",
        default="artifacts/llm-context.json",
        help="Output file path (default: artifacts/llm-context.json)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "text", "both"],
        default="json",
        help="Output format: json (default), text (markdown), or both"
    )
    parser.add_argument(
        "--text-output",
        help="Path for text format output (if --format is 'text' or 'both')"
    )
    
    args = parser.parse_args()
    
    # Debug: Print immediately to verify we got here
    print("DEBUG: After parse_args", file=sys.stderr)
    sys.stderr.flush()
    print("DEBUG: args.test_name =", args.test_name, file=sys.stderr)
    sys.stderr.flush()
    
    try:
        print("🚀 Building LLM Context\n", file=sys.stderr)
        print("🚀 Building LLM Context\n", file=sys.stdout)
        sys.stderr.flush()
        sys.stdout.flush()
        
        # Load all input files
        print(f"DEBUG: Loading api_mapping from {args.api_mapping}", file=sys.stderr)
        sys.stderr.flush()
        api_mapping = load_json_file(args.api_mapping) if args.api_mapping else None
        if api_mapping:
            print(f"DEBUG: Loaded api_mapping: {len(api_mapping.get('mappings', {}))} APIs", file=sys.stderr)
        else:
            print(f"DEBUG: api_mapping is None", file=sys.stderr)
        sys.stderr.flush()
        
        print(f"DEBUG: Loading resolved_commits from {args.resolved_commits}", file=sys.stderr)
        sys.stderr.flush()
        resolved_commits = load_json_file(args.resolved_commits) if args.resolved_commits else None
        if resolved_commits:
            print(f"DEBUG: Loaded resolved_commits: {len(resolved_commits.get('resolved_commits', {}))} repos", file=sys.stderr)
        else:
            print(f"DEBUG: resolved_commits is None", file=sys.stderr)
        sys.stderr.flush()
        
        connected_context = load_json_file(args.connected_context) if args.connected_context else None
        code_diffs = load_json_file(args.code_diffs) if args.code_diffs else None
        error_logs = load_text_file(args.error_logs) if args.error_logs else None
        incluster_logs = load_json_file(args.incluster_logs) if args.incluster_logs else None
        test_code = load_text_file(args.test_code) if args.test_code else None
        code_index = load_json_file(args.code_index) if args.code_index else None
        analysis_prompts = load_analysis_prompts(args.prompts_file if hasattr(args, 'prompts_file') else None)
        
        # Load workflow commit if not provided
        workflow_commit = args.workflow_commit
        if not workflow_commit:
            workflow_commit_path = Path("artifacts/workflow-commit.txt")
            if workflow_commit_path.exists():
                workflow_commit = load_text_file(str(workflow_commit_path))
        
        # Load cross-test interference data if available
        cross_test_interference = None
        if args.cross_test_interference:
            cross_test_interference = load_json_file(args.cross_test_interference)
            if cross_test_interference:
                print(f"📖 Loaded cross-test interference data", file=sys.stderr)
                sys.stderr.flush()
        
        # Build context
        print(f"DEBUG: About to call build_llm_context()", file=sys.stderr)
        print(f"DEBUG: api_mapping is {'present' if api_mapping else 'None'}", file=sys.stderr)
        print(f"DEBUG: resolved_commits is {'present' if resolved_commits else 'None'}", file=sys.stderr)
        sys.stderr.flush()
        
        context = build_llm_context(
            test_name=args.test_name,
            test_run_id=args.test_run_id,
            workflow_commit=workflow_commit,
            api_mapping=api_mapping,
            connected_context=connected_context,
            error_logs=error_logs,
            code_diffs=code_diffs,
            resolved_commits=resolved_commits,
            test_code=test_code,
            code_index=code_index,
            analysis_prompts=analysis_prompts,
            incluster_logs=incluster_logs,
            cross_test_interference=cross_test_interference
        )
        
        print(f"DEBUG: build_llm_context() returned", file=sys.stderr)
        print(f"DEBUG: Context has {len(context.get('code_chunks', []))} chunks", file=sys.stderr)
        sys.stderr.flush()
        
        # Debug: Check context structure
        if not context:
            print("❌ Error: build_llm_context returned empty context", file=sys.stderr)
            sys.exit(1)
        
        if not context.get("metadata"):
            print("❌ Error: Context missing metadata", file=sys.stderr)
            sys.exit(1)
            
        if "code_chunks" not in context:
            print("❌ Error: Context missing code_chunks", file=sys.stderr)
            sys.exit(1)
        
        # Save output
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Debug: Write to log file as backup
        debug_log = Path("/tmp/build_llm_context_debug.log")
        try:
            with open(debug_log, 'w') as f:
                f.write(f"Output path: {output_path}\n")
                f.write(f"Context keys: {list(context.keys())}\n")
                f.write(f"Total chunks: {len(context.get('code_chunks', []))}\n")
                f.write(f"Metadata: {json.dumps(context.get('metadata', {}), indent=2)}\n")
        except:
            pass
        
        # Save JSON format
        if args.format in ["json", "both"]:
            try:
                print(f"DEBUG: Writing to {output_path}", file=sys.stderr)
                sys.stderr.flush()
                
                # Ensure output directory exists
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Write the file with explicit error handling
                try:
                    with open(output_path, 'w') as f:
                        json.dump(context, f, indent=2)
                        f.flush()
                        try:
                            os.fsync(f.fileno())
                        except:
                            pass
                except Exception as write_error:
                    # If write fails, try to write error info
                    try:
                        with open(output_path, 'w') as f:
                            json.dump({
                                "error": "Failed to write context",
                                "error_message": str(write_error),
                                "metadata": context.get("metadata", {}) if context else {}
                            }, f, indent=2)
                            f.flush()
                            os.fsync(f.fileno())
                    except:
                        pass
                    raise write_error
                
                # Verify file was written - CRITICAL CHECK
                if not output_path.exists():
                    # File doesn't exist - this is a critical error
                    # Try one more time with a simple write
                    try:
                        with open(output_path, 'w') as f:
                            json.dump({
                                "error": "Output file was not created",
                                "metadata": context.get("metadata", {}) if context else {}
                            }, f, indent=2)
                            f.flush()
                            os.fsync(f.fileno())
                    except Exception as final_error:
                        # Last resort - write to stderr and exit
                        print(f"CRITICAL: Cannot create output file: {final_error}", file=sys.stderr)
                        sys.stderr.flush()
                        sys.exit(1)
                
                file_size = output_path.stat().st_size
                print(f"DEBUG: File exists, size: {file_size} bytes", file=sys.stderr)
                sys.stderr.flush()
                
                if file_size > 0:
                    print(f"\n📄 LLM context (JSON) saved to: {args.output}", file=sys.stderr)
                    print(f"   File size: {file_size} bytes", file=sys.stderr)
                    sys.stderr.flush()
                else:
                    print(f"\n⚠️  Warning: File was created but appears empty: {args.output}", file=sys.stderr)
                    sys.stderr.flush()
                    # Write a minimal valid JSON to ensure file is not empty
                    with open(output_path, 'w') as f:
                        json.dump({
                            "error": "Context building failed - file was empty",
                            "metadata": context.get("metadata", {}) if context else {}
                        }, f, indent=2)
                        f.flush()
                        os.fsync(f.fileno())
            except Exception as e:
                print(f"\n❌ Error saving JSON file: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
                # Try to write error to output file before exiting
                try:
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(output_path, 'w') as f:
                        json.dump({
                            "error": "Failed to save context",
                            "error_message": str(e),
                            "traceback": traceback.format_exc()
                        }, f, indent=2)
                        f.flush()
                        os.fsync(f.fileno())
                except:
                    pass
                sys.exit(1)
        
        # Save text format (markdown)
        if args.format in ["text", "both"]:
            text_output_path = args.text_output or output_path.with_suffix('.md')
            text_content = format_context_as_text(context)
            with open(text_output_path, 'w') as f:
                f.write(text_content)
                f.flush()
                import os
                try:
                    os.fsync(f.fileno())
                except:
                    pass
            print(f"📄 LLM context (Text/Markdown) saved to: {text_output_path}", file=sys.stderr)
            sys.stderr.flush()
        
        # Print summary
        print(f"\n📊 Summary:", file=sys.stderr)
        print(f"   Test: {args.test_name}", file=sys.stderr)
        print(f"   Total chunks: {context['metadata']['total_chunks']}", file=sys.stderr)
        print(f"   Total lines of code: {context['metadata']['total_lines_of_code']}", file=sys.stderr)
        print(f"   Chunks by source:", file=sys.stderr)
        for source, count in context['metadata']['chunks_by_source'].items():
            print(f"     {source}: {count}", file=sys.stderr)
        print(f"   Chunks by repo:", file=sys.stderr)
        for repo, count in context['metadata']['chunks_by_repo'].items():
            print(f"     {repo}: {count}", file=sys.stderr)
        print(f"   Repositories: {len(context['metadata']['repos'])}", file=sys.stderr)
        sys.stderr.flush()
    
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    # Ensure we always write something to a log file for debugging
    import traceback
    error_log_path = "/tmp/build_llm_context_error.log"
    
    try:
        with open(error_log_path, "w") as log_file:
            log_file.write(f"Script started: {sys.argv}\n")
            log_file.flush()
            os.fsync(log_file.fileno())
        
        print("MAIN_BLOCK: Entering if __name__ == '__main__'", file=sys.stderr)
        sys.stderr.flush()
        print("MAIN_BLOCK: sys.argv =", sys.argv, file=sys.stderr)
        sys.stderr.flush()
        
        try:
            print("MAIN_BLOCK: About to call main()", file=sys.stderr)
            sys.stderr.flush()
            main()
            print("MAIN_BLOCK: main() returned successfully", file=sys.stderr)
            sys.stderr.flush()
            
            with open(error_log_path, "a") as log_file:
                log_file.write("Script completed successfully\n")
                log_file.flush()
                os.fsync(log_file.fileno())
                
        except SystemExit as e:
            with open(error_log_path, "a") as log_file:
                log_file.write(f"SystemExit with code {e.code}\n")
                log_file.flush()
                os.fsync(log_file.fileno())
            print(f"MAIN_BLOCK: SystemExit with code {e.code}", file=sys.stderr)
            sys.stderr.flush()
            raise
        except Exception as e:
            error_msg = f"MAIN_BLOCK: FATAL ERROR: {e}\n{traceback.format_exc()}"
            with open(error_log_path, "a") as log_file:
                log_file.write(error_msg + "\n")
                log_file.flush()
                os.fsync(log_file.fileno())
            print(error_msg, file=sys.stderr)
            sys.stderr.flush()
            sys.exit(1)
        
        print("MAIN_BLOCK: Script ending normally", file=sys.stderr)
        sys.stderr.flush()
    except Exception as outer_e:
        # Last resort error handling
        try:
            with open(error_log_path, "a") as log_file:
                log_file.write(f"Outer exception: {outer_e}\n{traceback.format_exc()}\n")
                log_file.flush()
                os.fsync(log_file.fileno())
        except:
            pass
        raise
else:
    print(f"MODULE_IMPORT: Script imported as module, __name__ = {__name__}", file=sys.stderr)
    sys.stderr.flush()


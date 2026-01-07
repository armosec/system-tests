#!/usr/bin/python3
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

import argparse
import base64
import json
import os
import shutil
import sys
import traceback
import re

# Import dependency detection functions
from detect_dependencies import analyze_all_chunks, filter_available_indexes
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set


def normalize_test_name(test_name: Optional[str]) -> Optional[str]:
    """Normalize test name for output/consistency (strip wrappers like 'ST (name)')."""
    if not test_name:
        return test_name
    s = str(test_name).strip()
    m = re.match(r"^ST\\s*\\(\\s*([^)]+?)\\s*\\)\\s*$", s)
    if m:
        return m.group(1).strip()
    return s


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


_TRACEBACK_FILE_LINE_RE = re.compile(r'File "([^"]+)", line (\d+)', re.MULTILINE)


def _candidate_paths_from_trace(trace_path: str) -> List[Path]:
    """
    Generate a list of relative path candidates from an absolute traceback path.

    This tries to handle common CI shapes like:
      /home/runner/_work/<repo>/<repo>/<subpath>
    and returns multiple possible suffixes for best-effort resolution.
    """
    p = Path(trace_path)
    parts = list(p.parts)
    candidates: List[Path] = []

    # 1) As-is (absolute)
    candidates.append(p)

    # 2) Try to strip common CI prefix: .../_work/<repo>/<repo>/...
    # Find "_work" segment
    if "_work" in parts:
        idx = parts.index("_work")
        suffix_parts = parts[idx + 1:]  # <repo>/<repo>/...
        if suffix_parts:
            # Drop leading <repo>
            suffix_parts = suffix_parts[1:]
        if suffix_parts and len(suffix_parts) >= 2 and suffix_parts[0] == suffix_parts[1]:
            # Drop duplicate repo name if present
            suffix_parts = suffix_parts[1:]
        if suffix_parts:
            candidates.append(Path(*suffix_parts))

    # 3) Add a few trailing slices (last 2..10 parts) to resolve regardless of repo root
    for k in range(2, min(10, len(parts)) + 1):
        candidates.append(Path(*parts[-k:]))

    # De-dup while preserving order
    seen = set()
    out: List[Path] = []
    for c in candidates:
        key = str(c)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _resolve_traceback_file(trace_path: str, search_roots: List[Path]) -> Optional[Path]:
    """
    Resolve a traceback file path against a set of repo roots.
    Returns the first existing file path found.
    """
    candidates = _candidate_paths_from_trace(trace_path)
    for cand in candidates:
        # Absolute candidate
        if cand.is_absolute() and cand.exists():
            return cand
        # Try relative to each root
        for root in search_roots:
            full = (root / cand)
            if full.exists():
                return full
    return None


def _extract_file_snippet(path: Path, line_no: int, context_lines: int = 60) -> str:
    """Extract a +/- context_lines snippet around line_no (1-based)."""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except Exception:
        return ""

    if line_no < 1:
        line_no = 1

    start = max(1, line_no - context_lines)
    end = min(len(lines), line_no + context_lines)

    snippet_lines = []
    for i in range(start, end + 1):
        prefix = ">>" if i == line_no else "  "
        snippet_lines.append(f"{prefix} {i:5d}: {lines[i - 1]}")
    return "\n".join(snippet_lines)


def build_test_code_from_traceback(
    error_logs: str,
    search_roots: Optional[List[Path]] = None,
    max_locations: int = 3,
    context_lines: int = 60
) -> Optional[str]:
    """
    Best-effort: build test_code snippets by parsing Python traceback file:line locations.
    This prevents `test_code` from being null when we have file:line evidence in logs.
    """
    if not error_logs:
        return None

    roots = search_roots or []

    # Add a couple sane defaults: repo root + current working dir
    try:
        roots.append(Path.cwd())
    except Exception:
        pass
    try:
        roots.append(Path(__file__).parents[2])  # system-tests repo root
    except Exception:
        pass
    roots = [r for r in roots if r and r.exists()]

    matches = list(_TRACEBACK_FILE_LINE_RE.finditer(error_logs))
    if not matches:
        return None

    snippets: List[str] = []
    used = 0
    for m in matches:
        if used >= max_locations:
            break
        file_path = m.group(1)
        line_no = int(m.group(2))

        resolved = _resolve_traceback_file(file_path, roots)
        if not resolved:
            continue

        snippet = _extract_file_snippet(resolved, line_no=line_no, context_lines=context_lines)
        if not snippet:
            continue

        snippets.append(f"# {resolved} (traceback: {file_path}:{line_no})\n{snippet}\n")
        used += 1

    if not snippets:
        return None

    return "\n".join(snippets)


def extract_dependency_chunks_from_diffs(
    code_diffs: Optional[Dict[str, Any]],
    extra_indexes: Optional[Dict[str, Dict[str, Any]]],
    max_total_chunks: int = 6
) -> List[Dict[str, Any]]:
    """
    Best-effort: if diffs show new imports/usages of dependency packages, pull the likely
    dependency implementation chunks even if call-chain extraction doesn't cross repos.
    """
    if not code_diffs or not extra_indexes:
        return []

    cadb = code_diffs.get("cadashboardbe") or {}
    git_diff = cadb.get("git_diff") or {}
    files = git_diff.get("files") or []
    if not isinstance(files, list):
        return []

    # Find github.com/armosec/<repo>/<path> imports/usages in patches
    import_re = re.compile(r'github\\.com/armosec/([^/\"\\s]+)/([^\"\\s]+)')

    candidates: List[Tuple[int, str, Dict[str, Any]]] = []  # (score, repo, chunk)

    for f in files:
        patch = (f or {}).get("patch") or ""
        if not patch:
            continue
        for repo, subpath in import_re.findall(patch):
            if repo not in extra_indexes:
                continue
            idx = extra_indexes.get(repo) or {}
            chunks = idx.get("chunks", [])
            if not isinstance(chunks, list):
                continue

            # Prefer chunks that live under the imported subpath and look like handlers/send-test-message
            for ch in chunks:
                file_path = (ch.get("file") or "")
                name = (ch.get("name") or "")
                score = 0
                if subpath and subpath in file_path:
                    score += 5
                lname = name.lower()
                if "sendtestmessage" in lname:
                    score += 10
                if "webhook" in lname:
                    score += 3
                if score > 0:
                    candidates.append((score, repo, ch))

    # Sort and pick top unique chunks
    candidates.sort(key=lambda t: t[0], reverse=True)
    out: List[Dict[str, Any]] = []
    seen_ids = set()
    for score, repo, ch in candidates:
        if len(out) >= max_total_chunks:
            break
        cid = ch.get("id") or f"{repo}:{ch.get('file')}:{ch.get('name')}"
        if cid in seen_ids:
            continue
        seen_ids.add(cid)
        out.append({
            **ch,
            "repo_name": repo,
            "source": "diff_dependency",
            "priority": 2,
        })

    return out


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
            # Default priority - may be bumped later if this is the failing API
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


_LOKI_REQ_RE = re.compile(r'"method":"([A-Z]+)".*?"requestURI":"([^"]+)"')
_PLAIN_REQ_RE = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH)\s+(/api/[^\\s]+)')
_API_KEY_RE = re.compile(r'^\s*([A-Z]+)\s+(.+?)\s*$')
_PARAM_SEGMENT_RE = re.compile(r"^(?:\{[^}]+\}|:[^/]+|<[^>]+>)$")


def _split_segments(path: str) -> List[str]:
    path = (path or "").split("?")[0].rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return [s for s in path.split("/") if s]


def _is_param(seg: str) -> bool:
    return bool(_PARAM_SEGMENT_RE.match(seg))


def _paths_equivalent(a: str, b: str) -> bool:
    aa = _split_segments(a)
    bb = _split_segments(b)
    if len(aa) != len(bb):
        return False
    for x, y in zip(aa, bb):
        if x == y:
            continue
        if _is_param(x) or _is_param(y):
            continue
        return False
    return True


def extract_failing_request_from_logs(error_logs: str) -> Optional[Dict[str, str]]:
    """
    Best-effort: extract a representative failing request from logs.
    Prefer Loki JSON lines (method + requestURI), fallback to plain 'METHOD /api/...' patterns.
    """
    if not error_logs:
        return None

    m = _LOKI_REQ_RE.search(error_logs)
    if m:
        method = m.group(1)
        uri = m.group(2)
        path = uri.split("?")[0]
        return {"method": method, "path": path, "request_uri": uri}

    m = _PLAIN_REQ_RE.search(error_logs)
    if m:
        method = m.group(1)
        uri = m.group(2)
        path = uri.split("?")[0]
        return {"method": method, "path": path, "request_uri": uri}

    return None


def bump_priority_for_failing_api(chunks: List[Dict[str, Any]], failing_req: Optional[Dict[str, str]]) -> None:
    """Mutate chunk priorities: failing API handler/call-chain gets priority 0."""
    if not failing_req:
        return
    req_method = (failing_req.get("method") or "").upper()
    req_path = failing_req.get("path") or ""

    for ch in chunks:
        api_keys: List[str] = []
        if ch.get("api_path"):
            api_keys.append(ch.get("api_path"))
        if isinstance(ch.get("api_paths"), list):
            api_keys.extend([x for x in ch.get("api_paths") if isinstance(x, str)])

        for api_key in api_keys:
            km = _API_KEY_RE.match(api_key)
            if not km:
                continue
            key_method = km.group(1).upper()
            key_path = km.group(2)
            if key_method == req_method and _paths_equivalent(req_path, key_path):
                # Most important: failing endpoint + its chain
                ch["priority"] = 0
                break


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
    if isinstance(chunk.get("api_paths"), list) and chunk.get("api_paths"):
        formatted["api_paths"] = chunk.get("api_paths")
    
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
    """
    Remove duplicate chunks (by ID) while preserving multi-API association.

    If the same chunk_id appears for multiple APIs, we merge:
    - **api_path** into **api_paths** list
    - keep the lowest priority
    - keep the first non-empty code
    - prefer "api_handler" source if any merged instance is an api handler
    """
    by_key: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    def chunk_key(c: Dict[str, Any]) -> str:
        cid = c.get("id") or c.get("chunk_id")
        if cid:
            return f"id:{cid}"
        return f"meta:{c.get('name')}:{c.get('package')}:{c.get('file')}"

    for chunk in chunks:
        key = chunk_key(chunk)
        if key not in by_key:
            merged = dict(chunk)
            api_path = chunk.get("api_path")
            if api_path:
                merged["api_paths"] = [api_path]
            by_key[key] = merged
            order.append(key)
            continue

        merged = by_key[key]

        # Merge api_path into api_paths
        api_path = chunk.get("api_path")
        if api_path:
            ap = merged.get("api_paths")
            if not isinstance(ap, list):
                ap = []
            if api_path not in ap:
                ap.append(api_path)
            merged["api_paths"] = ap

        # Keep lowest priority (higher importance)
        merged_pri = merged.get("priority", 999)
        new_pri = chunk.get("priority", 999)
        if isinstance(new_pri, int) and new_pri < merged_pri:
            merged["priority"] = new_pri

        # Prefer api_handler as source if any merged is api_handler
        if merged.get("source") != "api_handler" and chunk.get("source") == "api_handler":
            merged["source"] = "api_handler"

        # Fill code if missing
        if not merged.get("code") and chunk.get("code"):
            merged["code"] = chunk.get("code")

        by_key[key] = merged

    return [by_key[k] for k in order]


def lookup_chunk_code(chunk_id: str, code_index: Optional[Dict[str, Any]] = None, extra_indexes: Optional[Dict[str, Dict[str, Any]]] = None) -> Optional[str]:
    """Look up full chunk code from code index using chunk_id."""
    if not chunk_id:
        return None
    
    # Try main index
    if code_index:
        chunks = code_index.get("chunks", [])
        for chunk in chunks:
            if chunk.get("id") == chunk_id:
                return chunk.get("code", "")
    
    # Try extra indexes
    if extra_indexes:
        for repo_name, idx in extra_indexes.items():
            if not idx: continue
            chunks = idx.get("chunks", [])
            for chunk in chunks:
                if chunk.get("id") == chunk_id:
                    return chunk.get("code", "")
    
    return None


def _gh_env() -> Dict[str, str]:
    """
    Ensure gh CLI has a token in env. GitHub Actions often provides GITHUB_TOKEN,
    while gh prefers GH_TOKEN. Mirror if needed.
    """
    env = dict(os.environ)
    if not env.get("GH_TOKEN") and env.get("GITHUB_TOKEN"):
        env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    return env


def _gh_api(path: str) -> Optional[Any]:
    """Call `gh api <path>` and parse JSON output. Returns None on failure."""
    if not shutil.which("gh"):
        return None
    try:
        import subprocess
        proc = subprocess.run(
            ["gh", "api", path],
            capture_output=True,
            text=True,
            env=_gh_env(),
            check=False,
        )
        if proc.returncode != 0:
            return None
        return json.loads(proc.stdout or "null")
    except Exception:
        return None


def _extract_dependency_source_targets_from_code_diffs(code_diffs: Dict[str, Any]) -> Tuple[Dict[Tuple[str, str], Set[str]], Dict[Tuple[str, str], Set[str]]]:
    """
    Extract dependency source targets from code_diffs in two ways:
    1) **Directories** inferred from import paths inside patches (github.com/<org>/<repo>/<dir>/...)
    2) **Exact file paths** inferred from dependency repos' own git_diff.files[].filename

    Returns:
      (repo_dirs, repo_files)
        repo_dirs: (org, repo) -> set(dir paths)
        repo_files: (org, repo) -> set(file paths)
    """
    repo_dirs: Dict[Tuple[str, str], Set[str]] = {}
    repo_files: Dict[Tuple[str, str], Set[str]] = {}

    for repo_name, diff in (code_diffs or {}).items():
        if not isinstance(diff, dict):
            continue
        git_diff = diff.get("git_diff") or {}
        files = git_diff.get("files") or []
        if not isinstance(files, list):
            continue

        # 2) If this is a dependency repo, collect its changed Go files directly.
        # We don't know org here; infer from common cases. We'll also try to discover org via imports.
        # Default to armosec when unknown.
        default_org = "armosec"
        for f in files:
            if not isinstance(f, dict):
                continue
            filename = f.get("filename") or ""
            if filename.endswith(".go") and "/" in filename:
                repo_files.setdefault((default_org, repo_name), set()).add(filename)

            # 1) Scan patches for import paths into dependency repos
            patch = f.get("patch") or ""
            if not patch:
                continue
            for m in re.finditer(r"github\\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(/[A-Za-z0-9_./-]+)?", patch):
                org = m.group(1)
                repo = m.group(2)
                rest = (m.group(3) or "").lstrip("/")
                if not rest or "/" not in rest:
                    continue
                repo_dirs.setdefault((org, repo), set()).add(rest)

    return repo_dirs, repo_files


def _fetch_repo_dir_go_files(org: str, repo: str, dir_path: str, ref: str, max_files: int) -> List[str]:
    data = _gh_api(f"repos/{org}/{repo}/contents/{dir_path}?ref={ref}")
    if not isinstance(data, list):
        return []
    out: List[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "file":
            continue
        path = item.get("path") or ""
        if not path.endswith(".go"):
            continue
        out.append(path)
        if len(out) >= max_files:
            break
    return out


def _fetch_repo_file_content(org: str, repo: str, file_path: str, ref: str, max_lines: int) -> Optional[str]:
    data = _gh_api(f"repos/{org}/{repo}/contents/{file_path}?ref={ref}")
    if not isinstance(data, dict):
        return None
    content_b64 = data.get("content")
    encoding = data.get("encoding")
    if not content_b64 or encoding != "base64":
        return None
    try:
        raw = base64.b64decode(content_b64).decode("utf-8", errors="replace")
        lines = raw.splitlines()
        if len(lines) > max_lines:
            raw = "\n".join(lines[:max_lines]) + "\n// ... truncated ..."
        return raw
    except Exception:
        return None


def fetch_dependency_source_snippets(
    code_diffs: Optional[Dict[str, Any]],
    found_indexes: Optional[Dict[str, Any]],
    max_files_total: int = 6,
    max_lines_per_file: int = 200,
) -> List[Dict[str, Any]]:
    """
    Fetch small source snippets for dependency repos that appear in import diffs.
    This enables the LLM to propose concrete patches even when dependency code
    isn't present in local workspaces or extracted call chains.
    """
    if not code_diffs or not found_indexes:
        return []

    repo_dirs, repo_files = _extract_dependency_source_targets_from_code_diffs(code_diffs)
    if not repo_dirs and not repo_files:
        return []

    idx = found_indexes.get("indexes") or {}
    chunks: List[Dict[str, Any]] = []

    # Prefer fetching exact changed files from dependency repos (more reliable than imports).
    for (org, repo), files in repo_files.items():
        repo_info = idx.get(repo) or {}
        rc = repo_info.get("rc") or {}
        deployed = repo_info.get("deployed") or {}
        ref = (rc.get("commit") or "").strip() or (deployed.get("commit") or "").strip()
        if not ref:
            continue

        for fp in sorted(files):
            code = _fetch_repo_file_content(org, repo, fp, ref, max_lines=max_lines_per_file)
            if not code:
                continue
            chunks.append({
                "id": f"dependency_source/{repo}/{fp}@{ref}",
                "name": os.path.basename(fp),
                "type": "file",
                "package": os.path.dirname(fp),
                "file": fp,
                "code": code,
                "repo": repo,
                "source": "dependency_source",
                "priority": 1,
            })
            if len(chunks) >= max_files_total:
                return chunks

    # Fallback: fetch go files by directory derived from import paths
    for (org, repo), dirs in repo_dirs.items():
        repo_info = idx.get(repo) or {}
        rc = repo_info.get("rc") or {}
        deployed = repo_info.get("deployed") or {}
        ref = (rc.get("commit") or "").strip() or (deployed.get("commit") or "").strip()
        if not ref:
            continue

        for dir_path in sorted(dirs)[:2]:
            go_files = _fetch_repo_dir_go_files(org, repo, dir_path, ref, max_files=max_files_total)
            for fp in go_files:
                code = _fetch_repo_file_content(org, repo, fp, ref, max_lines=max_lines_per_file)
                if not code:
                    continue
                chunks.append({
                    "id": f"dependency_source/{repo}/{fp}@{ref}",
                    "name": os.path.basename(fp),
                    "type": "file",
                    "package": os.path.dirname(fp),
                    "file": fp,
                    "code": code,
                    "repo": repo,
                    "source": "dependency_source",
                    "priority": 1,
                })
                if len(chunks) >= max_files_total:
                    return chunks

    return chunks


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
    extra_indexes: Optional[Dict[str, Dict[str, Any]]] = None,
    analysis_prompts: Optional[str] = None,
    incluster_logs: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    cross_test_interference: Optional[Dict[str, Any]] = None,
    gomod_dependencies: Optional[Dict[str, Any]] = None,
    found_indexes_path: str = "artifacts/found-indexes.json",
    fetch_dependency_sources: bool = False,
    fetch_dependency_sources_max_files: int = 6,
    fetch_dependency_sources_max_lines: int = 200,
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
    test_name = normalize_test_name(test_name) or test_name
    all_chunks = []

    # 0. Ensure test_code isn't null if error logs contain traceback locations
    if not test_code and error_logs:
        derived = build_test_code_from_traceback(error_logs)
        if derived:
            test_code = derived
            print("🧩 Derived test_code from traceback locations in error logs", file=sys.stderr)
            sys.stderr.flush()

    # 0.5 Extract a representative failing request from logs (used to prioritize the most relevant API)
    failing_request = extract_failing_request_from_logs(error_logs) if error_logs else None
    
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

    # 2.5 Extract extra dependency chunks hinted by diffs (covers cases where call-chain doesn't cross repos)
    if code_diffs and extra_indexes:
        extra_diff_chunks = extract_dependency_chunks_from_diffs(code_diffs, extra_indexes)
        if extra_diff_chunks:
            all_chunks.extend(extra_diff_chunks)
            print(f"   ➕ Added {len(extra_diff_chunks)} dependency chunks hinted by diffs", file=sys.stderr)
            sys.stderr.flush()

    # 2.55 Fetch dependency source snippets (bounded) so we can propose concrete patches from LLM context
    if fetch_dependency_sources and code_diffs and found_indexes_path and os.path.exists(found_indexes_path):
        try:
            with open(found_indexes_path, "r") as f:
                found_indexes = json.load(f)
            dep_src_chunks = fetch_dependency_source_snippets(
                code_diffs=code_diffs,
                found_indexes=found_indexes,
                max_files_total=fetch_dependency_sources_max_files,
                max_lines_per_file=fetch_dependency_sources_max_lines,
            )
            if dep_src_chunks:
                all_chunks.extend(dep_src_chunks)
                print(f"   ➕ Added {len(dep_src_chunks)} dependency source file snippets (for patchable context)", file=sys.stderr)
                sys.stderr.flush()
        except Exception as e:
            print(f"⚠️  Failed to fetch dependency source snippets: {e}", file=sys.stderr)
            sys.stderr.flush()

    # 2.6 Prioritize failing API chunks (set priority=0 for matching api_path)
    bump_priority_for_failing_api(all_chunks, failing_request)
    
    # 3. Deduplicate chunks
    print("🧹 Deduplicating chunks...", file=sys.stderr)
    sys.stderr.flush()
    unique_chunks = deduplicate_chunks(all_chunks)
    print(f"   {len(unique_chunks)} unique chunks after deduplication (from {len(all_chunks)} total)", file=sys.stderr)
    sys.stderr.flush()
    
    # 4. Look up missing code for ALL chunks (if code_index or extra_indexes provided)
    if code_index or extra_indexes:
        print("🔍 Looking up missing chunk code from code indexes...", file=sys.stderr)
        sys.stderr.flush()
        looked_up = 0
        for chunk in unique_chunks:
            chunk_id = chunk.get("id") or chunk.get("chunk_id")
            # Look up code for ANY chunk that doesn't have it yet
            if chunk_id and not chunk.get("code"):
                code = lookup_chunk_code(chunk_id, code_index, extra_indexes)
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
        # Use triggering repo as default if available, otherwise first repo, otherwise cadashboardbe
        triggering_repo_normalized = resolved_commits.get("triggering_repo_normalized", "").lower()
        default_repo = None
        if triggering_repo_normalized:
            # Find matching repo key (case-insensitive match, but preserve original case)
            for repo_key in resolved.keys():
                if repo_key.lower() == triggering_repo_normalized:
                    default_repo = repo_key
                    print(f"   Using triggering repo as default: {default_repo}", file=sys.stderr)
                    break
        if not default_repo and resolved:
            default_repo = list(resolved.keys())[0]
            print(f"   Using first repo as default: {default_repo}", file=sys.stderr)
        if not default_repo:
            default_repo = "cadashboardbe"
            print(f"   No resolved repos, defaulting to cadashboardbe", file=sys.stderr)
        repo_mapping["default"] = default_repo
    else:
        repo_mapping["default"] = "cadashboardbe"  # Fallback for backward compatibility
    
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
    if failing_request:
        metadata["failing_request"] = failing_request
    
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
        
        # ALSO collect repos from api_mapping call chains
        if api_mapping:
            for mapping in api_mapping.get('mappings', {}).values():
                call_chain = mapping.get('call_chain', {})
                repos = call_chain.get('repositories_in_chain', [])
                if repos:
                    for repo in repos:
                        if repo and repo != "cadashboardbe":
                            repositories_included.add(repo)
        
        # Analyze each dependency
        # Load found_indexes as fallback for version info
        found_indexes = None
        if found_indexes_path and os.path.exists(found_indexes_path):
            try:
                with open(found_indexes_path, 'r') as f:
                    found_indexes = json.load(f)
            except Exception:
                pass
        
        for dep_name in repositories_included:
            # Calculate impact
            impact, critical_functions = calculate_dependency_impact(
                dep_name, code_diffs, api_mapping, formatted_chunks
            )
            
            # Get version info - try code_diffs first, then found_indexes as fallback
            deployed_ver = "unknown"
            rc_ver = "unknown"
            version_changed = False
            
            if dep_name in code_diffs:
                deployed_ver = code_diffs[dep_name].get('old_version', 'unknown')
                rc_ver = code_diffs[dep_name].get('new_version', 'unknown')
                version_changed = code_diffs[dep_name].get('changed', False)
            elif found_indexes:
                # Fallback: get version from found_indexes (for dependencies without version changes)
                dep_info = found_indexes.get('indexes', {}).get(dep_name, {})
                if dep_info:
                    deployed_info = dep_info.get('deployed', {})
                    rc_info = dep_info.get('rc', {})
                    deployed_ver = deployed_info.get('version', 'unknown')
                    rc_ver = rc_info.get('version', 'unknown')
                    version_changed = dep_info.get('version_changed', False)
            
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
    
    # Load dependency information from found-indexes.json
    dependencies_info = {}
    if os.path.exists(found_indexes_path):
        try:
            with open(found_indexes_path, 'r') as f:
                found_indexes = json.load(f)
                dependencies_info = {
                    "total_dependencies": len(found_indexes.get('indexes', {})),
                    "version_changes": [
                        {
                            "repository": repo_name,
                            "deployed_version": repo_info.get('deployed', {}).get('version', 'N/A'),
                            "rc_version": repo_info.get('rc', {}).get('version', 'N/A'),
                            "github_org": repo_info.get('deployed', {}).get('github_org', 'armosec'),
                            "source": repo_info.get('deployed', {}).get('source', 'gomod')
                        }
                        for repo_name, repo_info in found_indexes.get('indexes', {}).items()
                        if repo_info.get('version_changed', False)
                    ],
                    "missing_indexes": [
                        {
                            "repository": repo_name,
                            "github_org": repo_info.get('deployed', {}).get('github_org', 'armosec'),
                            "source": repo_info.get('deployed', {}).get('source', 'gomod')
                        }
                        for repo_name, repo_info in found_indexes.get('indexes', {}).items()
                        if not repo_info.get('deployed', {}).get('found', False)
                    ],
                    "discovered_repositories": [
                        {
                            "repository": repo_name,
                            "github_org": repo_info.get('deployed', {}).get('github_org', 
                                          repo_info.get('rc', {}).get('github_org', 'armosec')),
                            "has_deployed_index": repo_info.get('deployed', {}).get('found', False),
                            "has_rc_index": repo_info.get('rc', {}).get('found', False),
                            "strategy": repo_info.get('deployed', {}).get('strategy', 'unknown'),
                            "source": repo_info.get('deployed', {}).get('source', 'gomod')
                        }
                        for repo_name, repo_info in found_indexes.get('indexes', {}).items()
                    ]
                }
                print(f"   ✅ Added dependency information ({dependencies_info['total_dependencies']} deps)", file=sys.stderr)
                sys.stderr.flush()
        except Exception as e:
            print(f"   ⚠️  Failed to load dependency info: {e}", file=sys.stderr)
            sys.stderr.flush()
    
    # Merge go.mod dependency versions (from RC or deployed version)
    if gomod_dependencies:
        print(f"   📦 Merging go.mod versions into dependency info...", file=sys.stderr)
        sys.stderr.flush()
        
        # Create gomod_versions section with version information
        gomod_versions = {}
        for pkg_name, pkg_info in gomod_dependencies.items():
            gomod_versions[pkg_name] = {
                "version": pkg_info.get('version', 'unknown'),
                "source": pkg_info.get('source', 'go.mod'),
                "full_package": pkg_info.get('full_package', ''),
                "has_index": pkg_info.get('has_index', False)
            }
        
        dependencies_info["gomod_versions"] = gomod_versions
        print(f"   ✅ Added {len(gomod_versions)} go.mod package versions", file=sys.stderr)
        sys.stderr.flush()
    
    context = {
        "metadata": metadata,
        "dependencies": dependencies_info,  # NEW: Add dependencies section
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
    
    # Add dependency statistics to metadata
    context["metadata"]["dependencies_count"] = dependencies_info.get('total_dependencies', 0)
    context["metadata"]["version_changes_count"] = len(dependencies_info.get('version_changes', []))
    context["metadata"]["missing_indexes_count"] = len(dependencies_info.get('missing_indexes', []))
    
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
        "--dependency-indexes",
        help="JSON string or file mapping repo name to code index path"
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
        "--found-indexes",
        help="Path to found-indexes.json (for smart filtering)"
    )
    parser.add_argument(
        "--gomod-dependencies",
        help="Path to gomod-dependencies.json (go.mod versions from RC or deployed version)"
    )
    parser.add_argument(
        "--fetch-dependency-sources",
        action="store_true",
        help="Fetch bounded dependency source snippets from GitHub (based on import diffs) and embed them as chunks (enables concrete code fixes)."
    )
    parser.add_argument(
        "--fetch-dependency-sources-max-files",
        type=int,
        default=6,
        help="Max dependency source files to embed (default: 6)"
    )
    parser.add_argument(
        "--fetch-dependency-sources-max-lines",
        type=int,
        default=200,
        help="Max lines per fetched dependency source file (default: 200)"
    )
    parser.add_argument(
        "--smart-filter",
        action="store_true",
        help="Enable smart dependency filtering based on imports"
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
    
    try:
        print("🚀 Building LLM Context\n", file=sys.stderr)
        sys.stderr.flush()
        
        # Load all input files
        api_mapping = load_json_file(args.api_mapping) if args.api_mapping else None
        resolved_commits = load_json_file(args.resolved_commits) if args.resolved_commits else None
        
        connected_context = load_json_file(args.connected_context) if args.connected_context else None
        code_diffs = load_json_file(args.code_diffs) if args.code_diffs else None
        error_logs = load_text_file(args.error_logs) if args.error_logs else None
        incluster_logs = load_json_file(args.incluster_logs) if args.incluster_logs else None
        test_code = load_text_file(args.test_code) if args.test_code else None
        code_index = load_json_file(args.code_index) if args.code_index else None
        
        # Load extra indexes for dependencies
        extra_indexes = {}
        if args.dependency_indexes:
            if os.path.exists(args.dependency_indexes):
                with open(args.dependency_indexes, 'r') as f:
                    dep_map = json.load(f)
            else:
                try:
                    dep_map = json.loads(args.dependency_indexes)
                except:
                    dep_map = {}
            
            for repo_name, path in dep_map.items():
                if os.path.exists(path):
                    print(f"📖 Loading dependency index for {repo_name} from {path}", file=sys.stderr)
                    extra_indexes[repo_name] = load_json_file(path)
        
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
        
        # Load go.mod dependencies if available
        gomod_dependencies = None
        if args.gomod_dependencies:
            gomod_dependencies = load_json_file(args.gomod_dependencies)
            if gomod_dependencies:
                print(f"📖 Loaded go.mod dependencies ({len(gomod_dependencies)} packages)", file=sys.stderr)
                sys.stderr.flush()
        
        # Smart filtering: Analyze imports and filter dependency indexes
        if args.smart_filter and connected_context and args.found_indexes:
            print(f"\n🔍 Smart dependency filtering enabled...", file=sys.stderr)
            sys.stderr.flush()
            
            # Extract chunks from connected_context
            chunks_dict = connected_context.get('filtered_chunks', {})
            
            if chunks_dict:
                # Analyze imports
                analysis = analyze_all_chunks(chunks_dict)
                print(f"   Detected {analysis['total_unique_dependencies']} unique dependencies", file=sys.stderr)
                sys.stderr.flush()
                
                # Load found-indexes.json
                found_indexes = load_json_file(args.found_indexes)
                
                if found_indexes:
                    # Filter indexes based on detected dependencies
                    filtered_indexes = filter_available_indexes(
                        analysis['detected_dependencies'],
                        found_indexes
                    )
                    
                    summary = filtered_indexes['filtering_summary']
                    print(f"   Available indexes: {summary['total_available']}", file=sys.stderr)
                    print(f"   After filtering: {summary['after_filtering']}", file=sys.stderr)
                    print(f"   Removed: {summary['removed']} unused indexes", file=sys.stderr)
                    sys.stderr.flush()
                    
                    # Filter extra_indexes to only include detected dependencies
                    if extra_indexes:
                        original_count = len(extra_indexes)
                        filtered_extra_indexes = {
                            repo: index_data 
                            for repo, index_data in extra_indexes.items()
                            if repo in filtered_indexes['indexes']
                        }
                        extra_indexes = filtered_extra_indexes
                        removed = original_count - len(extra_indexes)
                        
                        if removed > 0:
                            estimated_savings = removed * 5000
                            print(f"   💰 Estimated token savings: ~{estimated_savings:,} tokens", file=sys.stderr)
                            print(f"      (Removed {removed} unused dependency indexes)", file=sys.stderr)
                            sys.stderr.flush()
        
        # Build context
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
            extra_indexes=extra_indexes,
            analysis_prompts=analysis_prompts,
            incluster_logs=incluster_logs,
            cross_test_interference=cross_test_interference,
            gomod_dependencies=gomod_dependencies,
            found_indexes_path=args.found_indexes or "artifacts/found-indexes.json",
            fetch_dependency_sources=args.fetch_dependency_sources,
            fetch_dependency_sources_max_files=args.fetch_dependency_sources_max_files,
            fetch_dependency_sources_max_lines=args.fetch_dependency_sources_max_lines,
        )
        
        # Save output
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save JSON format
        if args.format in ["json", "both"]:
            with open(output_path, 'w') as f:
                json.dump(context, f, indent=2)
            print(f"\n📄 LLM context (JSON) saved to: {args.output}", file=sys.stderr)
            sys.stderr.flush()
        
        # Save text format (markdown)
        if args.format in ["text", "both"]:
            text_output_path = args.text_output or output_path.with_suffix('.md')
            text_content = format_context_as_text(context)
            with open(text_output_path, 'w') as f:
                f.write(text_content)
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
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


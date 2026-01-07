#!/usr/bin/env python3
"""
Generate GitHub Job Summary from analyzer artifacts.

This script reads various artifact files and generates a comprehensive
markdown summary for the GitHub Actions job summary.
"""

import argparse
import json
import os
import re
import sys
import traceback
from pathlib import Path
from typing import Dict, Any, Optional


def load_json(path: str) -> Optional[Dict[str, Any]]:
    """Load JSON file, return None if not found."""
    if not path:
        return None
    if not os.path.exists(path):
        print(f"🔍 DEBUG: File does not exist: {path}", file=sys.stderr)
        return None
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            if isinstance(data, dict) and len(data) == 0:
                print(f"🔍 DEBUG: File {path} is empty dict {{}}", file=sys.stderr)
            return data
    except Exception as e:
        print(f"Warning: Failed to load {path}: {e}", file=sys.stderr)
        return None


def extract_chunk_stats_per_repo(llm_context: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """
    Extract chunk count and LOC per repository from LLM context.
    
    Returns:
        Dict mapping repo_name -> {"chunks": count, "loc": lines_of_code}
    """
    stats = {}
    
    if not llm_context:
        return stats
    
    code_chunks = llm_context.get('code_chunks', [])
    
    for chunk in code_chunks:
        # Get repo from either '_repo' or 'repo' field
        repo = chunk.get('_repo') or chunk.get('repo') or chunk.get('repo_name')
        
        if not repo:
            continue
        
        # Initialize stats for this repo if not seen
        if repo not in stats:
            stats[repo] = {"chunks": 0, "loc": 0}
        
        # Count this chunk
        stats[repo]["chunks"] += 1
        
        # Count LOC
        code = chunk.get('code', '')
        if code:
            loc = len([line for line in code.split('\n') if line.strip()])
            stats[repo]["loc"] += loc
    
    return stats


def format_dependencies_table(found_indexes: Dict[str, Any], chunk_stats: Optional[Dict[str, Dict[str, int]]] = None) -> str:
    """
    Generate markdown table showing discovered dependencies.
    Split by source (go.mod dependencies vs service dependencies).
    Ordered by: index available first, then missing.
    
    Columns: Repository | Deployed Version | RC Version | Changed | Index Available | Chunks | LOC
    """
    if not found_indexes or 'indexes' not in found_indexes:
        return "No dependency information available."
    
    if chunk_stats is None:
        chunk_stats = {}
    
    triggering_repo = found_indexes.get('triggering_repo', 'unknown')
    
    # Categorize dependencies
    gomod_deps = []
    service_deps = []
    
    for repo_name, repo_info in found_indexes['indexes'].items():
        # Skip triggering repo (shown separately)
        if repo_name == triggering_repo:
            continue
        
        deployed = repo_info.get('deployed', {})
        rc = repo_info.get('rc', {})
        source = deployed.get('source', 'gomod')  # Default to gomod if not specified
        
        # Calculate index availability score (for sorting)
        has_deployed_index = deployed.get('found', False)
        has_rc_index = rc.get('found', False)
        index_score = (2 if has_deployed_index else 0) + (1 if has_rc_index else 0)
        
        dep_data = {
            'name': repo_name,
            'deployed': deployed,
            'rc': rc,
            'version_changed': repo_info.get('version_changed', False),
            'index_score': index_score,
            'has_deployed_index': has_deployed_index,
            'has_rc_index': has_rc_index
        }
        
        if source == 'service':
            service_deps.append(dep_data)
        else:
            gomod_deps.append(dep_data)
    
    # Sort by index availability (available first, then alphabetical)
    gomod_deps.sort(key=lambda x: (-x['index_score'], x['name']))
    service_deps.sort(key=lambda x: (-x['index_score'], x['name']))
    
    table_lines = []
    
    # Go.mod Dependencies Section
    if gomod_deps:
        table_lines.append("### 📦 Go Module Dependencies (from go.mod)")
        table_lines.append("")
        table_lines.append("| Repository | Deployed Version | RC Version | Changed | Index Available | Code Index Type | Chunks | LOC | Diff |")
        table_lines.append("|-----------|------------------|------------|---------|-----------------|-----------------|--------|-----|------|")
        
        for dep in gomod_deps:
            deployed = dep['deployed']
            rc = dep['rc']
            
            deployed_ver = deployed.get('version', 'N/A')
            rc_ver = rc.get('version', 'N/A')
            
            changed_icon = "⚠️ Yes" if dep['version_changed'] else "✅ No"
            
            if dep['has_deployed_index'] and dep['has_rc_index']:
                index_status = "✅ Both"
            elif dep['has_deployed_index']:
                index_status = "✅ Deployed only"
            elif dep['has_rc_index']:
                index_status = "✅ RC only"
            else:
                index_status = "❌ Missing"
            
            # Get code index type/strategy
            deployed_strategy = deployed.get('strategy', 'unknown')
            rc_strategy = rc.get('strategy', 'unknown')
            
            # Format strategy display
            def format_strategy(strategy: str) -> str:
                """Format strategy for display."""
                if not strategy or strategy == 'unknown' or strategy == 'not_found':
                    return "-"
                strategy_map = {
                    'version_tag': '🏷️ version-tag',
                    'latest_fallback': '📌 latest',
                    'pr_commit': '🔀 PR commit',
                    'commit_direct': '🔀 commit',
                    'tag_commit': '🏷️ tag→commit',
                    'always_include_fallback': '📌 latest (fallback)'
                }
                return strategy_map.get(strategy, strategy)
            
            # Show deployed strategy, or RC strategy if deployed not available
            if dep['has_deployed_index']:
                index_type = format_strategy(deployed_strategy)
            elif dep['has_rc_index']:
                index_type = format_strategy(rc_strategy)
            else:
                index_type = "-"
            
            github_org = deployed.get('github_org') or rc.get('github_org') or 'armosec'
            repo_display = f"{github_org}/{dep['name']}" if github_org != 'unknown' else dep['name']
            
            # Get chunk/LOC stats for this repo
            stats = chunk_stats.get(dep['name'], {"chunks": 0, "loc": 0})
            chunks_count = stats["chunks"]
            loc_count = stats["loc"]
            
            # Format counts (0 means no chunks included)
            chunks_display = f"**{chunks_count}**" if chunks_count > 0 else "-"
            loc_display = f"{loc_count:,}" if loc_count > 0 else "-"
            
            # Generate diff link if version changed and we have commit info
            diff_display = "-"
            if dep['version_changed']:
                deployed_commit = deployed.get('commit')
                rc_commit = rc.get('commit')
                
                if deployed_commit and rc_commit:
                    compare_url = f"https://github.com/{github_org}/{dep['name']}/compare/{deployed_commit[:8]}...{rc_commit[:8]}"
                    diff_display = f"[View Diff]({compare_url})"
            
            table_lines.append(
                f"| {repo_display} | `{deployed_ver}` | `{rc_ver}` | {changed_icon} | {index_status} | {index_type} | {chunks_display} | {loc_display} | {diff_display} |"
            )
        
        table_lines.append("")
        total_gomod = len(gomod_deps)
        with_indexes = sum(1 for d in gomod_deps if d['index_score'] > 0)
        total_chunks = sum(chunk_stats.get(d['name'], {}).get('chunks', 0) for d in gomod_deps)
        total_loc = sum(chunk_stats.get(d['name'], {}).get('loc', 0) for d in gomod_deps)
        with_chunks = sum(1 for d in gomod_deps if chunk_stats.get(d['name'], {}).get('chunks', 0) > 0)
        table_lines.append(f"**Summary**: {total_gomod} go.mod dependencies, {with_indexes} with indexes, {with_chunks} contributed code ({total_chunks} chunks, {total_loc:,} LOC)")
        table_lines.append("")
    
    # Service Dependencies Section
    if service_deps:
        table_lines.append("### 🔧 Service Dependencies (runtime services)")
        table_lines.append("")
        table_lines.append("| Repository | Deployed Version | Index Available | Chunks | LOC |")
        table_lines.append("|-----------|------------------|-----------------|--------|-----|")
        
        for dep in service_deps:
            deployed = dep['deployed']
            deployed_ver = deployed.get('version', 'latest')
            
            if dep['has_deployed_index']:
                index_status = "✅ Available"
            else:
                index_status = "❌ Missing"
            
            github_org = deployed.get('github_org') or 'armosec'
            repo_display = f"{github_org}/{dep['name']}" if github_org != 'unknown' else dep['name']
            
            # Get chunk/LOC stats for this repo
            stats = chunk_stats.get(dep['name'], {"chunks": 0, "loc": 0})
            chunks_count = stats["chunks"]
            loc_count = stats["loc"]
            
            # Format counts
            chunks_display = f"**{chunks_count}**" if chunks_count > 0 else "-"
            loc_display = f"{loc_count:,}" if loc_count > 0 else "-"
            
            table_lines.append(
                f"| {repo_display} | `{deployed_ver}` | {index_status} | {chunks_display} | {loc_display} |"
            )
        
        table_lines.append("")
        total_services = len(service_deps)
        with_indexes = sum(1 for d in service_deps if d['index_score'] > 0)
        total_chunks = sum(chunk_stats.get(d['name'], {}).get('chunks', 0) for d in service_deps)
        total_loc = sum(chunk_stats.get(d['name'], {}).get('loc', 0) for d in service_deps)
        with_chunks = sum(1 for d in service_deps if chunk_stats.get(d['name'], {}).get('chunks', 0) > 0)
        table_lines.append(f"**Summary**: {total_services} service dependencies, {with_indexes} with indexes, {with_chunks} contributed code ({total_chunks} chunks, {total_loc:,} LOC)")
        table_lines.append("")
    
    if not gomod_deps and not service_deps:
        return "No dependencies found."
    
    return "\n".join(table_lines)


def generate_summary(
    llm_context_path: str,
    api_mapping_path: str,
    code_diffs_path: str,
    found_indexes_path: str,
    running_images_path: str,
    gomod_deps_path: str,
    gomod_deps_deployed_path: str,
    gomod_deps_rc_path: str,
    context_summary_path: str,
    environment: str,
    run_ref: str,
    actor: str = "",
    workflow_commit_path: str = None,
    llm_analysis_path: str = None,
    test_deployed_services_path: str = None,
    services_only_path: str = None
) -> str:
    """Generate markdown summary from artifacts."""
    
    lines = []
    
    # Load artifacts
    llm_context = load_json(llm_context_path)
    api_mapping = load_json(api_mapping_path)
    code_diffs = load_json(code_diffs_path)
    found_indexes = load_json(found_indexes_path)
    # Prefer new format, fallback to legacy
    test_deployed_services = load_json(test_deployed_services_path) if test_deployed_services_path else None
    running_images = load_json(running_images_path) if not test_deployed_services else None
    # Prefer services-only.json (already filtered) for services display
    print(f"🔍 DEBUG: services_only_path = {services_only_path}", file=sys.stderr)
    services_only = load_json(services_only_path) if services_only_path else None
    print(f"🔍 DEBUG: After load_json, services_only = {services_only is not None}, type={type(services_only) if services_only else 'None'}", file=sys.stderr)
    if services_only_path:
        print(f"🔍 DEBUG: Loaded services_only from {services_only_path}: {services_only is not None}, type={type(services_only)}, len={len(services_only) if isinstance(services_only, dict) else 'N/A'}", file=sys.stderr)
        if services_only and isinstance(services_only, dict):
            print(f"🔍 DEBUG: services_only keys: {list(services_only.keys())}", file=sys.stderr)
        elif services_only is None:
            print(f"🔍 DEBUG: services_only is None (file might not exist or failed to load)", file=sys.stderr)
        elif isinstance(services_only, dict) and len(services_only) == 0:
            print(f"🔍 DEBUG: services_only is empty dict {{}}", file=sys.stderr)
    # go.mod dependencies snapshots:
    # - deployed: baseline go.mod (prefer artifacts/gomod-dependencies-deployed.json)
    # - rc: go.mod for RC code (prefer artifacts/gomod-dependencies-rc.json)
    # Backward compat:
    # - artifacts/gomod-dependencies.json is treated as deployed snapshot when the new files are missing.
    gomod_deps = load_json(gomod_deps_path)
    gomod_deps_deployed = load_json(gomod_deps_deployed_path) if gomod_deps_deployed_path else None
    gomod_deps_rc = load_json(gomod_deps_rc_path) if gomod_deps_rc_path else None
    if not gomod_deps_deployed and gomod_deps:
        gomod_deps_deployed = gomod_deps
    context_summary = load_json(context_summary_path)
    llm_analysis = load_json(llm_analysis_path) if llm_analysis_path else None
    
    # Load workflow commit as fallback
    workflow_commit_fallback = None
    if workflow_commit_path and os.path.exists(workflow_commit_path):
        try:
            with open(workflow_commit_path, 'r') as f:
                workflow_commit_fallback = f.read().strip()
        except Exception:
            pass
    
    if not llm_context:
        return "⚠️  LLM context not available - cannot generate summary\n"
    
    # Resolved title (uses resolved environment/repo/test after analyzer ran)
    metadata = llm_context.get('metadata', {})
    test_name = metadata.get('test_name', 'unknown')

    # ========================================
    # LLM Context Summary
    # ========================================
    # NOTE: Triggering repo resolution happens below; we insert the title once triggering_repo_display is computed.
    lines.append("## 📊 LLM Context Summary\n")
    lines.append("")
    test_run_id = metadata.get('test_run_id', 'N/A')
    total_chunks = metadata.get('total_chunks', 0)
    total_lines = metadata.get('total_lines_of_code', 0)
    
    # Get triggering repo name for header (use normalized for matching chunks)
    triggering_repo = 'unknown'
    triggering_repo_normalized = 'unknown'  # For matching chunks
    triggering_repo_data = None
    
    if test_deployed_services and isinstance(test_deployed_services, dict):
        triggering_repo_data = test_deployed_services.get('triggering_repo')
        if triggering_repo_data and isinstance(triggering_repo_data, dict):
            triggering_repo = triggering_repo_data.get('name', triggering_repo_data.get('repo', 'unknown'))
            triggering_repo_normalized = triggering_repo_data.get('normalized', triggering_repo.split('/')[-1].lower())
        elif isinstance(triggering_repo_data, str):
            triggering_repo = triggering_repo_data
            triggering_repo_normalized = triggering_repo.split('/')[-1].lower()
    elif found_indexes and isinstance(found_indexes, dict):
        triggering_repo = found_indexes.get('triggering_repo', 'unknown')
        triggering_repo_normalized = triggering_repo.split('/')[-1].lower()
    
    # Format display name
    triggering_repo_display = 'unknown'
    if triggering_repo_data and isinstance(triggering_repo_data, dict):
        triggering_repo_display = triggering_repo_data.get('name', f'armosec/{triggering_repo_normalized}')
    elif triggering_repo and triggering_repo != 'unknown':
        if '/' in triggering_repo:
            triggering_repo_display = triggering_repo
        else:
            triggering_repo_display = f"armosec/{triggering_repo}"
    
    # Header section - Repository, Environment, Test
    resolved_actor = actor or os.environ.get("GITHUB_ACTOR") or "unknown"
    resolved_env = environment or "unknown"
    title = f"# {resolved_actor} | {triggering_repo_display} | {resolved_env} | {test_name}\n"
    # Put title above everything else (the "run title" can’t be changed after workflow start)
    lines.insert(0, "")
    lines.insert(0, title)

    lines.append(f"**Repository:** `{triggering_repo_display}`")
    lines.append(f"**Environment:** `{environment}`")
    lines.append(f"**Test:** `{test_name}`")
    lines.append(f"**Test Run ID:** `{test_run_id}`")
    
    # Format original test run link
    if run_ref.startswith('http'):
        lines.append(f"**Original Test Run:** [{run_ref}]({run_ref})")
    else:
        run_url = f"https://github.com/armosec/shared-workflows/actions/runs/{run_ref}"
        lines.append(f"**Original Test Run:** [Run #{run_ref}]({run_url})")
    
    # Code chunks and LOC - use extract_chunk_stats_per_repo for accurate counting
    chunk_stats = extract_chunk_stats_per_repo(llm_context)
    
    # Get triggering repo stats (case-insensitive match)
    triggering_repo_chunks = 0
    triggering_repo_loc = 0
    actual_triggering_repo_name = None
    
    for repo_name, stats in chunk_stats.items():
        if repo_name.lower() == triggering_repo_normalized.lower():
            triggering_repo_chunks = stats.get('chunks', 0)
            triggering_repo_loc = stats.get('loc', 0)
            actual_triggering_repo_name = repo_name  # Preserve actual case
            break
    
    # Calculate dependency stats (all non-triggering repos)
    # Break down into go.mod vs service dependencies
    dep_chunks = 0
    dep_loc = 0
    gomod_dep_chunks = 0
    gomod_dep_loc = 0
    service_dep_chunks = 0
    service_dep_loc = 0
    
    # Categorize dependencies if found_indexes is available
    if found_indexes and 'indexes' in found_indexes:
        for repo_name, stats in chunk_stats.items():
            if repo_name.lower() != triggering_repo_normalized.lower():
                repo_chunks = stats.get('chunks', 0)
                repo_loc = stats.get('loc', 0)
                dep_chunks += repo_chunks
                dep_loc += repo_loc
                
                # Check if this is a go.mod or service dependency
                repo_info = found_indexes['indexes'].get(repo_name, {})
                deployed = repo_info.get('deployed', {})
                source = deployed.get('source', 'gomod')  # Default to gomod
                
                if source == 'service':
                    service_dep_chunks += repo_chunks
                    service_dep_loc += repo_loc
                else:
                    gomod_dep_chunks += repo_chunks
                    gomod_dep_loc += repo_loc
    else:
        # Fallback: count all non-triggering repos as dependencies
        for repo_name, stats in chunk_stats.items():
            if repo_name.lower() != triggering_repo_normalized.lower():
                dep_chunks += stats.get('chunks', 0)
                dep_loc += stats.get('loc', 0)
    
    # Generate summary line with breakdown if available
    if found_indexes and gomod_dep_chunks + service_dep_chunks > 0:
        lines.append(f"**Total Code Chunks:** {total_chunks} ({triggering_repo_chunks} from triggering repo, {dep_chunks} from dependencies: {gomod_dep_chunks} from go.mod, {service_dep_chunks} from services)")
        lines.append(f"**Total Lines of Code:** {total_lines:,} ({triggering_repo_loc:,} from triggering repo, {dep_loc:,} from dependencies: {gomod_dep_loc:,} from go.mod, {service_dep_loc:,} from services)")
    else:
        lines.append(f"**Total Code Chunks:** {total_chunks} ({triggering_repo_chunks} from triggering repo, {dep_chunks} from dependencies)")
        lines.append(f"**Total Lines of Code:** {total_lines:,} ({triggering_repo_loc:,} from triggering repo, {dep_loc:,} from dependencies)")
    
    # Add Loki logs count - use consistent counting method
    loki_logs = llm_context.get('loki_logs', [])
    loki_logs_text = llm_context.get('error_logs', '')
    
    # Count Loki log lines consistently
    loki_line_count = 0
    if loki_logs:
        # Count structured log entries
        loki_line_count = len(loki_logs)
    elif loki_logs_text and '=== Loki Excerpts ===' in loki_logs_text:
        # Count lines in Loki excerpts section
        loki_section = loki_logs_text.split('=== Loki Excerpts ===')[1] if '=== Loki Excerpts ===' in loki_logs_text else ''
        loki_line_count = len([l for l in loki_section.split('\n') if l.strip()]) if loki_section else 0
    
    if loki_line_count > 0:
        lines.append(f"**Total Loki Log Lines:** {loki_line_count}")
    elif context_summary:
        # Fallback to context_summary if available
        loki_count = context_summary.get('loki_logs_count', 0)
        if loki_count > 0:
            lines.append(f"**Total Loki Log Lines:** {loki_count}")
    
    # Add in-cluster logs summary
    incluster_log_summary = metadata.get('incluster_log_summary', {})
    if incluster_log_summary and incluster_log_summary.get('total_lines', 0) > 0:
        total_incluster_lines = incluster_log_summary.get('total_lines', 0)
        total_components = incluster_log_summary.get('total_components', 0)
        components = incluster_log_summary.get('components', [])
        
        lines.append(f"**In-Cluster Log Lines:** {total_incluster_lines} (from {total_components} components)")
        
        # Show error/warning counts if present
        errors_by_comp = incluster_log_summary.get('errors_by_component', {})
        warnings_by_comp = incluster_log_summary.get('warnings_by_component', {})
        
        if errors_by_comp or warnings_by_comp:
            status_parts = []
            total_errors = sum(errors_by_comp.values())
            total_warnings = sum(warnings_by_comp.values())
            
            if total_errors > 0:
                status_parts.append(f"❌ {total_errors} errors")
            if total_warnings > 0:
                status_parts.append(f"⚠️  {total_warnings} warnings")
            
            if status_parts:
                lines.append(f"**In-Cluster Status:** {', '.join(status_parts)}")
        
        # Show components list
        lines.append(f"**Components:** {', '.join(f'`{c}`' for c in components)}")
    
    lines.append("")
    
    # ========================================
    # Pipeline Status
    # ========================================
    lines.append("### 📋 Pipeline Status\n")
    lines.append("")
    
    # Phase 3.5 status
    dep_count_deployed = len(gomod_deps_deployed) if isinstance(gomod_deps_deployed, dict) else 0
    dep_count_rc = len(gomod_deps_rc) if isinstance(gomod_deps_rc, dict) else 0
    if dep_count_deployed > 0 or dep_count_rc > 0:
        lines.append(f"- ✅ **Phase 3.5:** Extracted go.mod dependencies (deployed: {dep_count_deployed}, RC: {dep_count_rc})")
    else:
        lines.append("- ⚠️  **Phase 3.5:** No dependencies found (empty go.mod or extraction failed)")
    
    # Phase 4 status
    if api_mapping:
        api_count = api_mapping.get('total_apis', 0)
        matched = api_mapping.get('matched_count', 0)
        unmatched = api_mapping.get('unmatched_count', 0)
        lines.append(f"- ✅ **Phase 4:** Mapped {matched}/{api_count} APIs to code")
        lines.append("  **Source:** Downloaded from `test-mapping-latest` artifact (`system_test_mapping_artifact.json`)")
        lines.append("")
        
        # Show APIs
        if api_count > 0:
            lines.append(f"  <details><summary>All APIs from Test Mapping ({api_count} total)</summary>")
            lines.append("")
            
            mappings = api_mapping.get('mappings', {})
            matched_apis = [k for k, v in mappings.items() if v.get('matched')]
            unmatched_apis = [(k, v.get('error', 'not found')) for k, v in mappings.items() if not v.get('matched')]
            
            if matched_apis:
                lines.append(f"  **✅ Matched APIs ({len(matched_apis)}):**")
                for api in matched_apis[:10]:  # Limit to first 10
                    lines.append(f"  - `{api}`")
                if len(matched_apis) > 10:
                    lines.append(f"  ... and {len(matched_apis) - 10} more")
                lines.append("")
            
            if unmatched_apis:
                lines.append(f"  **❌ Unmatched APIs ({len(unmatched_apis)}):**")
                for api, error in unmatched_apis[:10]:
                    lines.append(f"  - `{api}` - {error}")
                if len(unmatched_apis) > 10:
                    lines.append(f"  ... and {len(unmatched_apis) - 10} more")
                lines.append("")
            
            lines.append("  </details>")
            lines.append("")
    else:
        lines.append("- ❌ **Phase 4:** API mapping skipped")
    
    # Phase 4.5 status
    if found_indexes:
        lines.append("- ✅ **Phase 4.5:** Code index resolution completed")
    else:
        lines.append("- ❌ **Phase 4.5:** Code index resolution skipped")
    
    # Phase 4.5 diff status
    if code_diffs:
        changed_repos = sum(1 for v in code_diffs.values() if isinstance(v, dict) and v.get('changed'))
        if changed_repos > 0:
            lines.append(f"- ✅ **Phase 4.5 (Diffs):** Found changes in {changed_repos} repositories")
        else:
            lines.append("- ⚠️  **Phase 4.5 (Diffs):** No code changes detected")
    else:
        lines.append("- ❌ **Phase 4.5 (Diffs):** Code diff generation skipped")
    
    lines.append(f"- ✅ **Phase 7:** LLM context built ({total_chunks} chunks, {total_lines} LOC)")
    lines.append("")
    
    # ========================================
    # Triggering Repository Data
    # ========================================
    triggering_repo = found_indexes.get('triggering_repo', 'cadashboardbe') if found_indexes else 'cadashboardbe'
    
    lines.append("## 🎯 Triggering Repository Data\n")
    lines.append("")
    
    # Extract triggering repo info from new format or legacy format
    triggering_repo_data = None
    if test_deployed_services:
        triggering_repo_data = test_deployed_services.get('triggering_repo', {})
        triggering_repo = triggering_repo_data.get('normalized', triggering_repo)
    elif running_images:
        # Legacy format - extract triggering repo info
        repos = running_images.get('repos', {})
        repo_data = repos.get(triggering_repo, {})
        images = repo_data.get('images', [])
        if images:
            triggering_repo_data = {
                'name': running_images.get('triggering_repo', f'armosec/{triggering_repo}'),
                'normalized': triggering_repo,
                'rc_version': running_images.get('rc_version', 'unknown'),
                'commit_hash': running_images.get('commit_hash', 'unknown'),
                'images': images
            }
    
    if triggering_repo_data:
        repo_name = triggering_repo_data.get('name', f'armosec/{triggering_repo}')
        rc_version = triggering_repo_data.get('rc_version', 'unknown')
        commit_hash = triggering_repo_data.get('commit_hash', 'unknown')
        images = triggering_repo_data.get('images', [])
        
        # Get RC commit from found_indexes if available
        rc_commit = 'unknown'
        if found_indexes:
            repo_info = found_indexes.get('indexes', {}).get(triggering_repo, {})
            rc_info = repo_info.get('rc', {})
            rc_commit = rc_info.get('commit') or commit_hash or 'unknown'
        
        # Use workflow_commit_fallback if RC commit is unknown or None
        if (not rc_commit or rc_commit == 'unknown') and workflow_commit_fallback:
            rc_commit = workflow_commit_fallback
        
        # Repository already shown in header, so skip here
        lines.append(f"- **RC Version:** `{rc_version}`")
        if rc_commit and rc_commit != 'unknown' and isinstance(rc_commit, str):
            lines.append(f"- **RC Commit:** `{rc_commit[:8]}`")
        else:
            lines.append(f"- **RC Commit:** `unknown`")
        
        # Get deployed version from found_indexes
        if found_indexes:
            repo_info = found_indexes.get('indexes', {}).get(triggering_repo, {})
            deployed_info = repo_info.get('deployed', {})
            deployed_version = deployed_info.get('version', 'unknown')
            deployed_commit = deployed_info.get('commit', 'unknown')
            
            if deployed_version and deployed_version != 'unknown':
                lines.append(f"- **Deployed Version:** `{deployed_version}`")
            if deployed_commit and deployed_commit != 'unknown' and isinstance(deployed_commit, str):
                lines.append(f"- **Deployed Commit:** `{deployed_commit[:8]}`")
        
        # Show PR info if available from pr-metadata.json
        # NOTE: DO NOT extract PR from RC version - the suffix is a run ID, not PR number!
        # RC format: rc-v0.0.232-{run_id}, not rc-v0.0.232-{pr_number}
        pr_metadata_path = Path("artifacts/pr-metadata.json")
        if pr_metadata_path.exists():
            try:
                with open(pr_metadata_path, 'r') as f:
                    pr_metadata = json.load(f)
                    pr_number = pr_metadata.get('number')
                    if pr_number:
                        pr_url = f"https://github.com/{repo_name}/pull/{pr_number}"
                        pr_title = pr_metadata.get('title', '')
                        if pr_title:
                            lines.append(f"- **PR:** [#{pr_number}: {pr_title}]({pr_url})")
                        else:
                            lines.append(f"- **PR:** [#{pr_number}]({pr_url})")
            except Exception as e:
                print(f"⚠️  Failed to read PR metadata: {e}", file=sys.stderr)
        
        lines.append("")
    
    # ========================================
    # Services Data
    # ========================================
    lines.append("## 📦 Services Data\n")
    lines.append("")
    lines.append("External services that were running when the test executed:\n")
    lines.append("")
    
    services_data = None
    # Prefer services-only.json (already filtered, excludes dataPurger and triggering repo)
    # services-only.json is a flat dict: {"repo-name": {"images": [...]}, ...}
    if services_only and isinstance(services_only, dict) and len(services_only) > 0:
        services_data = services_only
        print(f"🔍 DEBUG: Using services-only.json with {len(services_data)} services: {list(services_data.keys())}", file=sys.stderr)
    elif test_deployed_services and isinstance(test_deployed_services, dict):
        # Use services from test-deployed-services.json, but note that dataPurger filtering happens below
        services_data = test_deployed_services.get('services', {})
        if services_data and len(services_data) > 0:
            print(f"🔍 DEBUG: Using test-deployed-services.json with {len(services_data)} services: {list(services_data.keys())}", file=sys.stderr)
        else:
            print(f"🔍 DEBUG: test-deployed-services.json has no services (empty dict)", file=sys.stderr)
    elif running_images:
        # Legacy format - extract services (exclude triggering repo)
        repos = running_images.get('repos', {})
        services_data = {}
        triggering_repo_normalized = running_images.get('triggering_repo_normalized', triggering_repo)
        for repo_name, repo_info in repos.items():
            if not repo_info.get('is_triggering_repo', False) and repo_name.lower() != triggering_repo_normalized.lower():
                services_data[repo_name] = repo_info
        print(f"🔍 DEBUG: Using running-images.json (legacy) with {len(services_data)} services: {list(services_data.keys())}", file=sys.stderr)
    else:
        print(f"🔍 DEBUG: No services data source available (services_only={services_only is not None}, test_deployed_services={test_deployed_services is not None}, running_images={running_images is not None})", file=sys.stderr)
    
    if services_data and len(services_data) > 0:
        # Create table for services
        lines.append("| Service | Deployed Version | Index Available |")
        lines.append("|---------|------------------|-----------------|")
        
        # Collect all service entries (one per service_key, not per repo)
        service_entries = []
        
        for repo_name, repo_info in sorted(services_data.items()):
            images = repo_info.get('images', [])
            
            # Filter out dataPurger (should already be filtered, but double-check)
            filtered_images = [img for img in images if img.get('service_key') != 'dataPurger']
            
            if not filtered_images:
                continue
            
            # Group by unique tags to show all services
            # For repos with multiple services (like event-ingester-service), show each service
            unique_tags = {}
            for img in filtered_images:
                tag = img.get('tag', 'unknown')
                service_key = img.get('service_key', 'unknown')
                
                if tag not in unique_tags:
                    unique_tags[tag] = []
                if service_key not in unique_tags[tag]:
                    unique_tags[tag].append(service_key)
            
            # Create entries: one per unique tag, showing all service_keys using that tag
            for tag, service_keys in sorted(unique_tags.items()):
                # Format service display: repo name + service keys if multiple
                if len(service_keys) > 1:
                    service_display = f"{repo_name} ({', '.join(service_keys)})"
                elif len(service_keys) == 1 and service_keys[0] != 'unknown':
                    service_display = f"{repo_name} ({service_keys[0]})"
                else:
                    service_display = repo_name
                
                # Check if index is available - try multiple key formats
                index_available = "❌"
                if found_indexes:
                    indexes = found_indexes.get('indexes', {})
                    
                    # Try exact repo name match first
                    repo_idx = indexes.get(repo_name, {})
                    if repo_idx.get('deployed', {}).get('found', False):
                        index_available = "✅"
                    else:
                        # Try tag-suffixed key (for repos with multiple tags)
                        tag_key = f"{repo_name}-{tag}"
                        repo_idx = indexes.get(tag_key, {})
                        if repo_idx.get('deployed', {}).get('found', False):
                            index_available = "✅"
                        else:
                            # Try any key starting with repo_name (for multiple versions)
                            for key in indexes.keys():
                                if key.startswith(f"{repo_name}-") and indexes[key].get('deployed', {}).get('found', False):
                                    index_available = "✅"
                                    break
                
                service_entries.append({
                    'display': service_display,
                    'tag': tag,
                    'index_available': index_available
                })
        
        # Sort and display entries
        for entry in sorted(service_entries, key=lambda x: x['display']):
            lines.append(f"| `{entry['display']}` | `{entry['tag']}` | {entry['index_available']} |")
        
        lines.append("")
        lines.append(f"**Total Services:** {len(service_entries)}")
        lines.append("")
    else:
        lines.append("No service data available.\n")
        lines.append("")
    
    # ========================================
    # Go Mod Dependencies Data
    # ========================================
    lines.append("## 📚 Go Mod Dependencies Data\n")
    lines.append("")
    lines.append("Internal Go libraries and shared modules extracted from `go.mod`:\n")
    lines.append("")
    
    # Code Differences - Always show if we have commit info
    lines.append("### 🔄 Code Differences (RC vs Deployed)\n")
    lines.append("")
    
    # Try to get diff stats from code_diffs
    has_diff_stats = False
    if code_diffs and triggering_repo in code_diffs:
        repo_diff = code_diffs[triggering_repo]
        if repo_diff.get('changed'):
            summary = repo_diff.get('summary', {})
            funcs_added = summary.get('total_functions_added', 0)
            funcs_removed = summary.get('total_functions_removed', 0)
            endpoints_added = summary.get('total_endpoints_added', 0)
            endpoints_removed = summary.get('total_endpoints_removed', 0)
            
            git_diff = repo_diff.get('git_diff', {})
            total_commits = git_diff.get('total_commits', 0)
            files = git_diff.get('files', [])
            files_changed = len(files)
            
            lines.append(f"- **Functions:** +{funcs_added} / -{funcs_removed}")
            if triggering_repo == 'cadashboardbe':
                lines.append(f"- **Endpoints:** +{endpoints_added} / -{endpoints_removed}")
            lines.append(f"- **Files Changed:** {files_changed} ({total_commits} commits)")
            has_diff_stats = True
    
    # Always try to generate compare URL from found_indexes or fallbacks
    if found_indexes or code_diffs:
        deployed_commit = None
        rc_commit = None
        
        # Try to get commits from found_indexes
        if found_indexes:
            repo_info = found_indexes.get('indexes', {}).get(triggering_repo, {})
            deployed_commit = repo_info.get('deployed', {}).get('commit')
            rc_commit = repo_info.get('rc', {}).get('commit')
        
        # Fallback: Try code_diffs git_diff section
        if (not deployed_commit or deployed_commit == 'unknown') and code_diffs and triggering_repo in code_diffs:
            git_diff = code_diffs[triggering_repo].get('git_diff', {})
            deployed_commit = git_diff.get('deployed_commit')
            if not rc_commit or rc_commit == 'unknown':
                rc_commit = git_diff.get('rc_commit')
        
        # Fallback: Use workflow_commit_fallback for RC
        if (not rc_commit or rc_commit == 'unknown') and workflow_commit_fallback:
            rc_commit = workflow_commit_fallback
        
        # Validate commits are actual SHA hashes (not error messages)
        def is_valid_commit_hash(commit_str):
            """Check if commit string is a valid SHA hash."""
            if not commit_str or commit_str == 'unknown':
                return False
            # Check if it looks like a JSON error message
            if commit_str.startswith('{') or commit_str.startswith('['):
                return False
            # Check if it's a valid SHA (7-40 hex characters)
            return bool(re.match(r'^[0-9a-f]{7,40}$', commit_str, re.IGNORECASE))
        
        # Clean and validate commits
        if deployed_commit:
            deployed_commit = str(deployed_commit).strip()
            if not is_valid_commit_hash(deployed_commit):
                deployed_commit = None
        
        if rc_commit:
            rc_commit = str(rc_commit).strip()
            if not is_valid_commit_hash(rc_commit):
                rc_commit = None
        
        if deployed_commit and rc_commit:
            compare_url = f"https://github.com/armosec/{triggering_repo}/compare/{deployed_commit}...{rc_commit}"
            lines.append(f"- **[View Full Diff on GitHub]({compare_url})** (commit-to-commit)")
        elif not has_diff_stats:
            lines.append("- ⚠️  Code diff analysis unavailable (missing commit information)")
    elif not has_diff_stats:
        lines.append("- ⚠️  Code diff analysis unavailable (version info not found)")
    
    lines.append("")
    
    # Show go.mod dependencies table (versions from deployed + RC snapshots)
    if gomod_deps_deployed or gomod_deps_rc:
        # Extract chunk/LOC stats from LLM context
        chunk_stats = extract_chunk_stats_per_repo(llm_context)
        
        deployed_map = gomod_deps_deployed or {}
        rc_map = gomod_deps_rc or {}
        all_dep_names = sorted(set(deployed_map.keys()) | set(rc_map.keys()))
        
        def base_version(v: str) -> str:
            """Extract base semantic version for comparison (handles pseudo-versions)."""
            if not v:
                return ""
            v = str(v)
            m = re.match(r'^(v\d+\.\d+\.\d+)', v)
            return m.group(1) if m else v
        
        lines.append("### 📦 Go Module Dependencies (go.mod versions)\n")
        lines.append("")
        lines.append("| Repository | Deployed go.mod | RC go.mod | Changed | Has Index | Chunks | LOC | Diff |")
        lines.append("|-----------|------------------|-----------|---------|----------|--------|-----|------|")
        
        changed_count = 0
        for name in all_dep_names:
            dep_deployed = deployed_map.get(name, {}) if isinstance(deployed_map, dict) else {}
            dep_rc = rc_map.get(name, {}) if isinstance(rc_map, dict) else {}
            
            deployed_ver = dep_deployed.get('version', 'N/A') if isinstance(dep_deployed, dict) else 'N/A'
            rc_ver = dep_rc.get('version', 'N/A') if isinstance(dep_rc, dict) else 'N/A'
            
            changed = False
            if deployed_ver != 'N/A' and rc_ver != 'N/A':
                changed = base_version(deployed_ver) != base_version(rc_ver)
            if changed:
                changed_count += 1
            changed_icon = "⚠️ Yes" if changed else "✅ No"
            
            has_index = False
            if isinstance(dep_deployed, dict) and dep_deployed.get('has_index') is True:
                has_index = True
            if isinstance(dep_rc, dict) and dep_rc.get('has_index') is True:
                has_index = True
            has_index_icon = "✅" if has_index else "❌"
            
            stats = chunk_stats.get(name, {"chunks": 0, "loc": 0})
            chunks_count = stats.get("chunks", 0)
            loc_count = stats.get("loc", 0)
            chunks_display = f"**{chunks_count}**" if chunks_count > 0 else "-"
            loc_display = f"{loc_count:,}" if loc_count > 0 else "-"
            
            repo_display = name
            repo_field = None
            if isinstance(dep_deployed, dict):
                repo_field = dep_deployed.get('repo')
            if not repo_field and isinstance(dep_rc, dict):
                repo_field = dep_rc.get('repo')
            if isinstance(repo_field, str) and repo_field:
                repo_display = repo_field
            
            # Generate diff link if version changed and we have commit info
            diff_display = "-"
            if changed and found_indexes:
                dep_info = found_indexes.get('indexes', {}).get(name, {})
                deployed_commit = dep_info.get('deployed', {}).get('commit')
                rc_commit = dep_info.get('rc', {}).get('commit')
                github_org = dep_info.get('deployed', {}).get('github_org') or dep_info.get('rc', {}).get('github_org') or 'armosec'
                
                if deployed_commit and rc_commit:
                    compare_url = f"https://github.com/{github_org}/{name}/compare/{deployed_commit[:8]}...{rc_commit[:8]}"
                    diff_display = f"[View Diff]({compare_url})"
            
            lines.append(f"| `{repo_display}` | `{deployed_ver}` | `{rc_ver}` | {changed_icon} | {has_index_icon} | {chunks_display} | {loc_display} | {diff_display} |")
        
        lines.append("")
        lines.append(f"**Summary**: {len(all_dep_names)} go.mod dependencies, {changed_count} with version changes.")
        lines.append("")
        lines.append("> **Data sources:** deployed go.mod comes from the deployed tag baseline; RC go.mod comes from the RC code index (code being tested).")
        lines.append("")
    
    # ========================================
    # Dependency Analysis
    # ========================================
    dep_analysis = metadata.get('dependency_analysis', {})
    
    # Always show dependency section header
    lines.append("## 🔗 Dependency Analysis\n")
    lines.append("")
    
    if dep_analysis:
        # High impact dependencies
        high_impact = [(name, info) for name, info in dep_analysis.items() if info.get('impact') == 'HIGH']
        
        if high_impact:
            lines.append("### 🔴 High Impact Changes (Changed Functions Called by Test)\n")
            lines.append("")
            
            for dep_name, info in high_impact:
                old_ver = info.get('deployed_version', 'unknown')
                new_ver = info.get('rc_version', 'unknown')
                critical_funcs = info.get('functions_both_changed_and_called', [])
                chunks = info.get('chunks_included', 0)
                
                lines.append(f"**{dep_name}**: {old_ver} → {new_ver}")
                lines.append(f"- Changed functions called: {', '.join(critical_funcs) if critical_funcs else 'N/A'}")
                lines.append(f"- {chunks} code chunks included")
                
                # Add compare URL if possible
                if found_indexes:
                    dep_info = found_indexes.get('indexes', {}).get(dep_name, {})
                    deployed_commit = dep_info.get('deployed', {}).get('commit')
                    rc_commit = dep_info.get('rc', {}).get('commit')
                    
                    if deployed_commit and rc_commit:
                        compare_url = f"https://github.com/armosec/{dep_name}/compare/{deployed_commit}...{rc_commit}"
                        lines.append(f"- [View Diff on GitHub]({compare_url})")
                
                lines.append("")
        
        # All dependencies
        lines.append("### ✅ Dependencies Included in Analysis\n")
        lines.append("")
        
        for dep_name, info in dep_analysis.items():
            if info.get('impact') != 'HIGH':
                version = info.get('deployed_version', 'unknown')
                chunks = info.get('chunks_included', 0)
                impact = info.get('impact', 'NONE')
                ver_changed = info.get('version_changed', False)
                
                if ver_changed:
                    rc_ver = info.get('rc_version', 'unknown')
                    lines.append(f"- **{dep_name}**: {version} → {rc_ver} ({chunks} chunks, impact: {impact})")
                else:
                    lines.append(f"- **{dep_name}**: {version} ({chunks} chunks, impact: {impact})")
        
        if not dep_analysis:
            lines.append("- No dependencies found in call chain")
        
        lines.append("")
        
    # Missing indexes
    if found_indexes:
        indexes = found_indexes.get('indexes', {})
        missing = []
        
        for dep_name, dep_info in indexes.items():
            if dep_name != triggering_repo and dep_info.get('version_changed'):
                deployed_found = dep_info.get('deployed', {}).get('found', False)
                rc_found = dep_info.get('rc', {}).get('found', False)
                
                if not deployed_found or not rc_found:
                    missing.append((dep_name, dep_info))
        
        if missing:
            lines.append("### ⚠️  Changed Dependencies Without Code Indexes\n")
            lines.append("")
            
            for dep_name, dep_info in missing:
                old_ver = dep_info.get('deployed', {}).get('version', 'unknown')
                new_ver = dep_info.get('rc', {}).get('version', 'unknown')
                
                lines.append(f"- **{dep_name}**: {old_ver} → {new_ver}")
                lines.append("  - Code index not available")
                lines.append("  - Cannot determine if changes are related to failure")
                lines.append(f"  - Recommendation: Add code-index-generation workflow to {dep_name} repository")
            
            lines.append("")
    else:
        # No dependency analysis available - provide helpful context
        lines.append("### ℹ️  No Cross-Repository Dependencies Detected\n")
        lines.append("")
        lines.append(f"This test only calls code within the main `{triggering_repo}` repository.")
        lines.append("")
        lines.append("**Note:** Multi-repo code context is available when:")
        lines.append("1. The test calls functions in external dependencies")
        lines.append("2. Dependency versions can be detected from go.mod")
        lines.append("3. Dependencies have code index generation enabled")
        lines.append("")
    
    # ========================================
    # Code Context Statistics
    # ========================================
    chunks_by_source = metadata.get('chunks_by_source', {})
    if chunks_by_source:
        lines.append("### 📦 Code Chunks by Source\n")
        for source, count in chunks_by_source.items():
            lines.append(f"- **{source}**: {count}")
        lines.append("")
    
    chunks_by_repo = metadata.get('chunks_by_repo', {})
    if chunks_by_repo:
        lines.append("### 🗂️ Code Chunks by Repository\n")
        for repo, count in chunks_by_repo.items():
            lines.append(f"- **{repo}**: {count}")
        lines.append("")
    
    repos = metadata.get('repos', {})
    if repos:
        lines.append(f"### 🔗 Repositories in Context ({len(repos)})\n")
        for repo_name, repo_info in repos.items():
            commit = repo_info.get('commit', 'unknown')
            is_triggering = repo_info.get('is_triggering_repo', False)
            suffix = " (triggering)" if is_triggering else ""
            if commit and commit != 'unknown' and isinstance(commit, str):
                lines.append(f"- **{repo_name}**: `{commit[:8]}`{suffix}")
            else:
                lines.append(f"- **{repo_name}**: `unknown`{suffix}")
        lines.append("")
    
    # ========================================
    # LLM Context Artifact Info
    # ========================================
    lines.append("---\n")
    lines.append("")
    lines.append("### 📄 LLM Context Artifact (llm-context-phase7)\n")
    lines.append("")
    lines.append("This artifact contains the complete context for LLM analysis including:")
    lines.append("- **Error logs** from the test failure")
    lines.append("- **Code chunks** from relevant functions and API handlers")
    lines.append("- **Call chains** tracing execution paths")
    lines.append("- **Loki logs** from backend services")
    lines.append("- **Code diffs** between deployed and RC versions")
    lines.append("- **Metadata** (test info, timing, identifiers)")
    lines.append("")
    lines.append("📥 **Download:** Artifact `llm-context-phase7` from this workflow run")
    lines.append("")
    
    # ========================================
    # Action Required Section
    # ========================================
    lines.append("---\n")
    lines.append("")
    lines.append("## 🎯 **Action Required**\n")
    lines.append("")
    lines.append("### **Test Status:** ❌ FAILED\n")
    
    # Determine test info
    test_name = metadata.get('test_name', 'unknown')
    test_run_id = metadata.get('test_run_id', 'unknown')
    
    lines.append(f"**Test:** `{test_name}`")
    lines.append(f"**Run ID:** `{test_run_id}`")
    lines.append(f"**Environment:** `{environment}`")
    lines.append("")
    
    # Show LLM Analysis if available
    if llm_analysis:
        lines.append("### 🤖 **AI Analysis Summary**\n")
        
        # Show model used
        llm_metadata = llm_analysis.get('_metadata', {})
        if llm_metadata:
            model = llm_metadata.get('model', 'unknown')
            provider = llm_metadata.get('provider', 'unknown')
            lines.append(f"**Analyzed by:** {provider.title()} `{model}`")
            lines.append("")
        
        # Root Cause
        root_cause = llm_analysis.get('root_cause', '')
        if root_cause:
            lines.append("**Root Cause:**")
            lines.append(f"> {root_cause}")
            lines.append("")
        
        # Impact
        impact = llm_analysis.get('impact', {})
        severity = impact.get('severity', 'unknown')
        if severity:
            severity_emoji = {
                'low': '🟢',
                'medium': '🟡',
                'high': '🟠',
                'critical': '🔴'
            }.get(severity.lower(), '⚪')
            lines.append(f"**Severity:** {severity_emoji} {severity.upper()}")
            lines.append("")
        
        # Recommended Fix
        recommended_fix = llm_analysis.get('recommended_fix', [])
        if recommended_fix:
            lines.append("**Recommended Fix:**")
            for i, fix in enumerate(recommended_fix[:3], 1):  # Show top 3
                lines.append(f"{i}. {fix}")
            lines.append("")
        
        # Executive Verdict
        executive_verdict = llm_analysis.get('executive_verdict', '')
        if executive_verdict:
            lines.append("**Executive Verdict:**")
            lines.append(f"> {executive_verdict}")
            lines.append("")
        
        lines.append("📥 **Download full analysis:** Artifact `llm-analysis-reports-phase8`")
        lines.append("")
    else:
        lines.append("💡 **Tip:** Re-run with `use_llm_analysis: true` for AI-powered root cause analysis")
        lines.append("")
    
    # Key findings
    lines.append("### **Key Findings:**\n")
    
    # Show code changes if available
    if code_diffs and triggering_repo in code_diffs:
        repo_diff = code_diffs[triggering_repo]
        if repo_diff.get('changed'):
            summary = repo_diff.get('summary', {})
            funcs_added = summary.get('total_functions_added', 0)
            funcs_removed = summary.get('total_functions_removed', 0)
            lines.append(f"- 📝 **Code Changes:** +{funcs_added} / -{funcs_removed} functions")
        
        git_diff = repo_diff.get('git_diff', {})
        if git_diff:
            total_commits = git_diff.get('total_commits', 0)
            files = git_diff.get('files', [])
            if files:
                lines.append(f"- 📂 **Files Changed:** {len(files)} files ({total_commits} commits)")
    
    # Show API count
    total_apis = metadata.get('total_chunks', 0)
    total_loc = metadata.get('total_lines_of_code', 0)
    if total_apis > 0:
        lines.append(f"- 🔍 **Code Context:** {total_apis} chunks, {total_loc} lines of code")
    
    # Show Loki logs info
    loki_logs = llm_context.get('loki_logs', [])
    loki_logs_text = llm_context.get('error_logs', '')
    loki_has_content = bool(loki_logs) or (loki_logs_text and '=== Loki Excerpts ===' in loki_logs_text)
    
    if loki_has_content:
        if loki_logs:
            lines.append(f"- 📋 **Backend Logs:** {len(loki_logs)} Loki log entries captured")
        else:
            # Count lines in error_logs after Loki section
            loki_section = loki_logs_text.split('=== Loki Excerpts ===')[1] if '=== Loki Excerpts ===' in loki_logs_text else ''
            loki_line_count = len([l for l in loki_section.split('\n') if l.strip()]) if loki_section else 0
            lines.append(f"- 📋 **Backend Logs:** ~{loki_line_count} Loki log lines captured")
    else:
        lines.append(f"- ⚠️  **Backend Logs:** No Loki logs captured (may need investigation)")
    
    lines.append("")
    
    # Next steps (only show if no LLM analysis)
    if not llm_analysis:
        lines.append("### **Next Steps:**\n")
        lines.append("1. Review error logs in the test output above")
        lines.append("2. Check code differences and recent changes")
        if loki_has_content:
            lines.append("3. Analyze backend service logs (Loki excerpts in error_logs)")
        else:
            lines.append("3. ⚠️  Investigate why Loki logs are missing")
        lines.append("4. Download `llm-context-phase7` artifact for detailed analysis")
        lines.append("5. **Recommended:** Re-run with `use_llm_analysis: true` for AI-powered root cause analysis")
        lines.append("")
    
    # Quick links (always show)
    lines.append("### **📎 Quick Links:**\n")
    
    # GitHub diff link - reuse validation function from above
    def is_valid_commit_hash(commit_str):
        """Check if commit string is a valid SHA hash."""
        if not commit_str or commit_str == 'unknown':
            return False
        # Check if it looks like a JSON error message
        if commit_str.startswith('{') or commit_str.startswith('['):
            return False
        # Check if it's a valid SHA (7-40 hex characters)
        return bool(re.match(r'^[0-9a-f]{7,40}$', commit_str, re.IGNORECASE))
    
    if found_indexes or code_diffs:
        deployed_commit = None
        rc_commit = None
        
        if found_indexes:
            repo_info = found_indexes.get('indexes', {}).get(triggering_repo, {})
            deployed_commit = repo_info.get('deployed', {}).get('commit')
            rc_commit = repo_info.get('rc', {}).get('commit')
        
        if (not deployed_commit or deployed_commit == 'unknown') and code_diffs and triggering_repo in code_diffs:
            git_diff = code_diffs[triggering_repo].get('git_diff', {})
            deployed_commit = git_diff.get('deployed_commit')
            rc_commit = git_diff.get('rc_commit')
        
        # Validate commits before using them
        if deployed_commit:
            deployed_commit = str(deployed_commit).strip()
            if not is_valid_commit_hash(deployed_commit):
                deployed_commit = None
        
        if rc_commit:
            rc_commit = str(rc_commit).strip()
            if not is_valid_commit_hash(rc_commit):
                rc_commit = None
        
        if deployed_commit and rc_commit:
            compare_url = f"https://github.com/armosec/{triggering_repo}/compare/{deployed_commit}...{rc_commit}"
            lines.append(f"- [View Code Diff on GitHub]({compare_url})")
    
    # Original test run link
    if run_ref:
        if run_ref.startswith('http'):
            lines.append(f"- [Original Test Run]({run_ref})")
        else:
            run_url = f"https://github.com/armosec/shared-workflows/actions/runs/{run_ref}"
            lines.append(f"- [Original Test Run]({run_url})")
    
    lines.append("- [Download LLM Context](artifacts/llm-context-phase7)")
    
    # Show LLM analysis link if available
    if llm_analysis:
        lines.append("- [Download Full AI Analysis](artifacts/llm-analysis-reports-phase8)")
    
    lines.append("")
    
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate GitHub Job Summary")
    parser.add_argument('--llm-context', default='artifacts/llm-context.json')
    parser.add_argument('--api-mapping', default='artifacts/api-code-map-with-chains.json')
    parser.add_argument('--code-diffs', default='artifacts/code-diffs.json')
    parser.add_argument('--found-indexes', default='artifacts/found-indexes.json')
    parser.add_argument('--running-images', default='artifacts/running-images.json', help='Legacy format (backward compatibility)')
    parser.add_argument('--test-deployed-services', help='New format with separated triggering_repo and services sections')
    parser.add_argument('--services-only', help='Filtered services-only.json (excludes dataPurger and triggering repo)')
    parser.add_argument('--gomod-deps', default='artifacts/gomod-dependencies.json')
    parser.add_argument('--gomod-deps-deployed', default='artifacts/gomod-dependencies-deployed.json')
    parser.add_argument('--gomod-deps-rc', default='artifacts/gomod-dependencies-rc.json')
    parser.add_argument('--context-summary', default='artifacts/context/summary.json')
    parser.add_argument('--environment', default='unknown')
    parser.add_argument('--run-ref', default='')
    parser.add_argument('--actor', default='', help='GitHub actor (user) that triggered the analyzer run')
    parser.add_argument('--workflow-commit', help='Path to workflow-commit.txt (fallback for RC commit)')
    parser.add_argument('--llm-analysis', help='Path to llm-analysis.json (optional, for AI analysis summary)')
    parser.add_argument('--output', help='Output file (defaults to $GITHUB_STEP_SUMMARY)')
    
    args = parser.parse_args()
    
    # Debug: Print all args to see what's being parsed
    services_only_arg = getattr(args, 'services_only', None)
    print(f"🔍 DEBUG: Parsed args.services_only = {services_only_arg}", file=sys.stderr)
    print(f"🔍 DEBUG: All args: {vars(args)}", file=sys.stderr)
    print(f"🔍 DEBUG: About to call generate_summary with services_only_path = {services_only_arg}", file=sys.stderr)
    
    # Generate summary with error handling
    output_path = args.output or os.environ.get('GITHUB_STEP_SUMMARY')
    
    try:
        summary = generate_summary(
            args.llm_context,
            args.api_mapping,
            args.code_diffs,
            args.found_indexes,
            args.running_images,
            args.gomod_deps,
            args.gomod_deps_deployed,
            args.gomod_deps_rc,
            args.context_summary,
            args.environment,
            args.run_ref,
            args.actor,
            args.workflow_commit,  # workflow_commit_path (position 10)
            args.llm_analysis,      # llm_analysis_path (position 11)
            args.test_deployed_services,  # test_deployed_services_path (position 12)
            services_only_arg       # services_only_path (position 13)
        )
        
        # Write to output
        if output_path:
            # Ensure summary is not empty
            if not summary or len(summary.strip()) == 0:
                summary = "## ⚠️ Summary Generation Warning\n\n**Status:** Summary was generated but is empty.\n\nThis may indicate an issue with the data or the generation process. Please check the logs for details."
                print("⚠️  Warning: Generated summary is empty, writing placeholder", file=sys.stderr)
            
            # Use write mode ('w') to ensure file is created/overwritten properly
            # GitHub Actions GITHUB_STEP_SUMMARY should be empty at start of step
            try:
                with open(output_path, 'w') as f:  # Changed from 'a' to 'w'
                    f.write(summary)
                print(f"✅ Summary written to {output_path}")
                SUMMARY_SIZE = os.path.getsize(output_path) if os.path.exists(output_path) else 0
                print(f"   Summary file size: {SUMMARY_SIZE} bytes")
                
                # Verify content was actually written
                if SUMMARY_SIZE == 0:
                    print("❌ ERROR: Summary file is empty after writing!", file=sys.stderr)
                    # Try writing a minimal summary
                    with open(output_path, 'w') as f:
                        f.write("## ⚠️ Summary Generation Issue\n\nSummary file was created but is empty. Please check logs for details.")
            except Exception as write_error:
                print(f"❌ Failed to write summary to {output_path}: {write_error}", file=sys.stderr)
                raise  # Re-raise to trigger error handling
        else:
            print(summary)
            if not summary or len(summary.strip()) == 0:
                print("⚠️  Warning: Summary is empty", file=sys.stderr)
        
        return 0
        
    except Exception as e:
        error_msg = f"❌ Error generating summary: {e}\n\nTraceback:\n{traceback.format_exc()}"
        print(error_msg, file=sys.stderr)
        
        # Write error to output file so it's visible in GitHub Actions
        if output_path:
            try:
                with open(output_path, 'w') as f:  # Use write mode to ensure file is created
                    f.write(f"## ⚠️ Summary Generation Failed\n\n")
                    f.write(f"**Error:** {str(e)}\n\n")
                    f.write(f"```\n{traceback.format_exc()}\n```\n\n")
                    f.write(f"**Debug Info:**\n")
                    f.write(f"- LLM Context: {args.llm_context}\n")
                    f.write(f"- Test Deployed Services: {args.test_deployed_services}\n")
                    f.write(f"- Found Indexes: {args.found_indexes}\n")
                    f.write(f"- Environment: {args.environment}\n")
                    f.write(f"- Output Path: {output_path}\n")
                print(f"⚠️  Error details written to {output_path}")
            except Exception as write_error:
                print(f"❌ Failed to write error to output file: {write_error}", file=sys.stderr)
        
        # Return non-zero to trigger workflow error logging
        return 1


if __name__ == '__main__':
    sys.exit(main())


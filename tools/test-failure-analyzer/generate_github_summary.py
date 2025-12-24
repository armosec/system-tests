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
from pathlib import Path
from typing import Dict, Any, Optional


def load_json(path: str) -> Optional[Dict[str, Any]]:
    """Load JSON file, return None if not found."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load {path}: {e}", file=sys.stderr)
        return None


def generate_summary(
    llm_context_path: str,
    api_mapping_path: str,
    code_diffs_path: str,
    found_indexes_path: str,
    running_images_path: str,
    gomod_deps_path: str,
    context_summary_path: str,
    environment: str,
    run_ref: str,
    workflow_commit_path: str = None,
    llm_analysis_path: str = None
) -> str:
    """Generate markdown summary from artifacts."""
    
    lines = []
    
    # Load artifacts
    llm_context = load_json(llm_context_path)
    api_mapping = load_json(api_mapping_path)
    code_diffs = load_json(code_diffs_path)
    found_indexes = load_json(found_indexes_path)
    running_images = load_json(running_images_path)
    gomod_deps = load_json(gomod_deps_path)
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
    
    # ========================================
    # LLM Context Summary
    # ========================================
    lines.append("## 📊 LLM Context Summary\n")
    lines.append("")
    
    metadata = llm_context.get('metadata', {})
    test_name = metadata.get('test_name', 'unknown')
    test_run_id = metadata.get('test_run_id', 'N/A')
    total_chunks = metadata.get('total_chunks', 0)
    total_lines = metadata.get('total_lines_of_code', 0)
    
    lines.append(f"**Test:** `{test_name}`")
    lines.append(f"**Test Run ID:** `{test_run_id}`")
    lines.append(f"**Environment:** `{environment}`")
    
    # Format original test run link
    if run_ref.startswith('http'):
        lines.append(f"**Original Test Run:** [{run_ref}]({run_ref})")
    else:
        run_url = f"https://github.com/armosec/shared-workflows/actions/runs/{run_ref}"
        lines.append(f"**Original Test Run:** [Run #{run_ref}]({run_url})")
    
    lines.append(f"**Total Code Chunks:** {total_chunks}")
    lines.append(f"**Total Lines of Code:** {total_lines}")
    
    # Add Loki logs count
    if context_summary:
        loki_count = context_summary.get('loki_logs_count', 0)
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
    if gomod_deps:
        dep_count = len(gomod_deps)
        if dep_count > 0:
            lines.append(f"- ✅ **Phase 3.5:** Extracted {dep_count} go.mod dependencies")
        else:
            lines.append("- ⚠️  **Phase 3.5:** No dependencies found (empty go.mod or extraction failed)")
    else:
        lines.append("- ❌ **Phase 3.5:** Dependency extraction skipped (no code index)")
    
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
    # Version Information
    # ========================================
    triggering_repo = found_indexes.get('triggering_repo', 'cadashboardbe') if found_indexes else 'cadashboardbe'
    
    if found_indexes:
        lines.append("### 🎯 Triggering Repository Version\n")
        lines.append("")
        
        repo_info = found_indexes.get('indexes', {}).get(triggering_repo, {})
        rc_info = repo_info.get('rc', {})
        rc_version = rc_info.get('version', 'unknown')
        rc_commit = rc_info.get('commit', 'unknown')
        
        # Use workflow_commit_fallback if RC commit is unknown
        if rc_commit == 'unknown' and workflow_commit_fallback:
            rc_commit = workflow_commit_fallback
        
        lines.append(f"- **Repository:** `armosec/{triggering_repo}`")
        lines.append(f"- **RC Version:** `{rc_version}`")
        lines.append(f"- **RC Commit:** `{rc_commit[:8] if rc_commit != 'unknown' else 'unknown'}`")
        lines.append("")
    
    # Deployed Version
    if running_images:
        lines.append("### 📦 Deployed Version (Currently Running)\n")
        lines.append("")
        
        repos = running_images.get('repos', {})
        repo_data = repos.get(triggering_repo, {})
        images = repo_data.get('images', [])
        
        if images:
            deployed_tag = images[0].get('tag', 'unknown')
            
            # Get baseline version from found_indexes (if available)
            baseline_version = 'unknown'
            if found_indexes:
                repo_idx = found_indexes.get('indexes', {}).get(triggering_repo, {})
                baseline_version = repo_idx.get('deployed', {}).get('version', 'unknown')
            
            # Special handling for event-ingester-service: prefer baseline over cluster version
            if triggering_repo == 'event-ingester-service' and baseline_version != 'unknown':
                lines.append(f"- **Deployed Version:** `{baseline_version}` (derived from RC)")
                if deployed_tag != baseline_version:
                    lines.append(f"- **Cluster Version:** `{deployed_tag}` (for reference)")
            # Check if deployed is also an RC - if so, show both actual and baseline
            elif deployed_tag.startswith('rc-'):
                lines.append(f"- **Actual Deployed:** `{deployed_tag}` (RC in production)")
                
                if baseline_version != 'unknown' and baseline_version != deployed_tag:
                    lines.append(f"- **Baseline for Diff:** `{baseline_version}` (previous stable)")
            else:
                lines.append(f"- **Deployed Version:** `{deployed_tag}`")
            
            # Get previous stable commit from code-diffs
            if code_diffs and triggering_repo in code_diffs:
                git_diff = code_diffs[triggering_repo].get('git_diff', {})
                prev_commit = git_diff.get('deployed_commit', 'unknown')
                if prev_commit != 'unknown':
                    lines.append(f"- **Previous Stable Commit:** `{prev_commit[:8]}`")
        
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
            lines.append(f"- **{repo_name}**: `{commit[:8] if commit != 'unknown' else 'unknown'}`{suffix}")
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
    parser.add_argument('--running-images', default='artifacts/running-images.json')
    parser.add_argument('--gomod-deps', default='artifacts/gomod-dependencies.json')
    parser.add_argument('--context-summary', default='artifacts/context/summary.json')
    parser.add_argument('--environment', default='unknown')
    parser.add_argument('--run-ref', default='')
    parser.add_argument('--workflow-commit', help='Path to workflow-commit.txt (fallback for RC commit)')
    parser.add_argument('--llm-analysis', help='Path to llm-analysis.json (optional, for AI analysis summary)')
    parser.add_argument('--output', help='Output file (defaults to $GITHUB_STEP_SUMMARY)')
    
    args = parser.parse_args()
    
    # Generate summary
    summary = generate_summary(
        args.llm_context,
        args.api_mapping,
        args.code_diffs,
        args.found_indexes,
        args.running_images,
        args.gomod_deps,
        args.context_summary,
        args.environment,
        args.run_ref,
        args.workflow_commit,
        args.llm_analysis
    )
    
    # Write to output
    output_path = args.output or os.environ.get('GITHUB_STEP_SUMMARY')
    
    if output_path:
        with open(output_path, 'a') as f:
            f.write(summary)
        print(f"✅ Summary written to {output_path}")
    else:
        print(summary)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())


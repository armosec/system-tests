#!/usr/bin/env python3
"""
Generate executive summary and full analysis reports.

Takes LLM analysis and code diffs to generate human-readable reports
in Markdown format for both executives and engineers.

Usage:
    python generate_reports.py \
        --llm-analysis artifacts/llm-analysis.json \
        --code-diffs artifacts/code-diffs.json \
        --test-name stripe_plans \
        --output-dir artifacts/
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate analysis reports")
    parser.add_argument("--llm-analysis", required=True, help="Path to llm-analysis.json")
    parser.add_argument("--code-diffs", help="Path to code-diffs.json (optional)")
    parser.add_argument("--test-name", help="Name of the test")
    parser.add_argument("--output-dir", required=True, help="Output directory for reports")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def load_json_file(path: str) -> Dict:
    """Load JSON file."""
    if not path or not Path(path).exists():
        return {}
    with open(path, 'r') as f:
        return json.load(f)


def generate_executive_summary(llm_analysis: Dict, code_diffs: Optional[Dict], test_name: str) -> str:
    """Generate executive summary markdown."""
    lines = []
    
    # Header
    lines.append("# Test Failure Executive Summary")
    lines.append("")
    lines.append(f"**Test**: `{test_name}`")
    lines.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Executive Verdict
    executive_verdict = llm_analysis.get('executive_verdict', 'No executive verdict available')
    lines.append("## Executive Verdict")
    lines.append("")
    lines.append(executive_verdict)
    lines.append("")
    
    # Root Cause
    root_cause = llm_analysis.get('root_cause', 'No root cause identified')
    lines.append("## Root Cause")
    lines.append("")
    lines.append(root_cause)
    lines.append("")
    
    # Impact
    impact = llm_analysis.get('impact', {})
    severity = impact.get('severity', 'unknown')
    blast_radius = impact.get('blast_radius', 'unknown')
    
    lines.append("## Impact Assessment")
    lines.append("")
    lines.append(f"- **Severity**: {severity.upper()}")
    lines.append(f"- **Blast Radius**: {blast_radius}")
    lines.append("")
    
    # Code Changes (if available)
    if code_diffs:
        lines.append("## Code Changes Since Deployment")
        lines.append("")
        
        for repo, diff in code_diffs.items():
            if not diff.get('changed'):
                continue
            
            old_ver = diff.get('old_version', 'unknown')
            new_ver = diff.get('new_version', 'unknown')
            summary = diff.get('summary', {})
            
            total_func_changes = summary.get('total_functions_added', 0) + summary.get('total_functions_removed', 0)
            total_endpoint_changes = summary.get('total_endpoints_added', 0) + summary.get('total_endpoints_removed', 0)
            
            lines.append(f"### {repo}")
            lines.append(f"- Version: `{old_ver}` → `{new_ver}`")
            lines.append(f"- Function changes: {total_func_changes}")
            lines.append(f"- Endpoint changes: {total_endpoint_changes}")
            lines.append("")
    
    # Recommended Actions
    recommended_fix = llm_analysis.get('recommended_fix', [])
    if recommended_fix:
        lines.append("## Recommended Actions")
        lines.append("")
        for i, action in enumerate(recommended_fix, 1):
            lines.append(f"{i}. {action}")
        lines.append("")
    
    return "\n".join(lines)


def generate_full_report(llm_analysis: Dict, code_diffs: Optional[Dict], test_name: str) -> str:
    """Generate full analysis report markdown."""
    lines = []
    
    # Header
    lines.append("# Test Failure Analysis - Full Report")
    lines.append("")
    lines.append(f"**Test**: `{test_name}`")
    lines.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Executive Verdict
    executive_verdict = llm_analysis.get('executive_verdict', 'No executive verdict available')
    lines.append("## Executive Verdict")
    lines.append("")
    lines.append(executive_verdict)
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Root Cause
    root_cause = llm_analysis.get('root_cause', 'No root cause identified')
    lines.append("## Root Cause Analysis")
    lines.append("")
    lines.append(root_cause)
    lines.append("")
    
    # Evidence
    evidence = llm_analysis.get('evidence', [])
    if evidence:
        lines.append("## Supporting Evidence")
        lines.append("")
        for item in evidence:
            lines.append(f"- {item}")
        lines.append("")
    
    # Impact
    impact = llm_analysis.get('impact', {})
    severity = impact.get('severity', 'unknown')
    blast_radius = impact.get('blast_radius', 'unknown')
    
    lines.append("## Impact Assessment")
    lines.append("")
    lines.append(f"**Severity**: {severity.upper()}")
    lines.append("")
    lines.append(f"**Blast Radius**: {blast_radius}")
    lines.append("")
    
    # Code Changes (detailed)
    if code_diffs:
        lines.append("---")
        lines.append("")
        lines.append("## Code Changes Since Deployment")
        lines.append("")
        
        for repo, diff in code_diffs.items():
            if not diff.get('changed'):
                continue
            
            old_ver = diff.get('old_version', 'unknown')
            new_ver = diff.get('new_version', 'unknown')
            summary = diff.get('summary', {})
            
            lines.append(f"### {repo} (`{old_ver}` → `{new_ver}`)")
            lines.append("")
            
            # Summary stats
            lines.append("**Change Summary:**")
            lines.append(f"- Functions added: {summary.get('total_functions_added', 0)}")
            lines.append(f"- Functions removed: {summary.get('total_functions_removed', 0)}")
            lines.append(f"- Functions unchanged: {summary.get('total_functions_unchanged', 0)}")
            lines.append(f"- Endpoints added: {summary.get('total_endpoints_added', 0)}")
            lines.append(f"- Endpoints removed: {summary.get('total_endpoints_removed', 0)}")
            lines.append("")
            
            # Added functions
            functions = diff.get('functions', {})
            added_funcs = functions.get('added', [])
            if added_funcs:
                lines.append("**New Functions:**")
                for func in added_funcs[:20]:  # Show up to 20
                    lines.append(f"- `{func.get('file')}:{func.get('name')}` ({func.get('lines', 0)} lines)")
                if len(added_funcs) > 20:
                    lines.append(f"- ... and {len(added_funcs) - 20} more")
                lines.append("")
            
            # Removed functions
            removed_funcs = functions.get('removed', [])
            if removed_funcs:
                lines.append("**Removed Functions:**")
                for func in removed_funcs[:20]:
                    lines.append(f"- `{func.get('file')}:{func.get('name')}` ({func.get('lines', 0)} lines)")
                if len(removed_funcs) > 20:
                    lines.append(f"- ... and {len(removed_funcs) - 20} more")
                lines.append("")
            
            # Endpoint changes
            endpoints = diff.get('endpoints', {})
            added_eps = endpoints.get('added', [])
            if added_eps:
                lines.append("**New Endpoints:**")
                for ep in added_eps:
                    lines.append(f"- `{ep.get('method')} {ep.get('path')}`")
                lines.append("")
            
            removed_eps = endpoints.get('removed', [])
            if removed_eps:
                lines.append("**Removed Endpoints:**")
                for ep in removed_eps:
                    lines.append(f"- `{ep.get('method')} {ep.get('path')}`")
                lines.append("")
    
    # Recommended Fix
    recommended_fix = llm_analysis.get('recommended_fix', [])
    if recommended_fix:
        lines.append("---")
        lines.append("")
        lines.append("## Recommended Fix")
        lines.append("")
        for i, action in enumerate(recommended_fix, 1):
            lines.append(f"{i}. {action}")
        lines.append("")
    
    # Metadata
    metadata = llm_analysis.get('_metadata', {})
    if metadata:
        lines.append("---")
        lines.append("")
        lines.append("## Analysis Metadata")
        lines.append("")
        lines.append(f"- **Model**: {metadata.get('model', 'unknown')}")
        lines.append(f"- **Tokens**: {metadata.get('total_tokens', 0)} total ({metadata.get('prompt_tokens', 0)} prompt + {metadata.get('completion_tokens', 0)} completion)")
        lines.append("")
    
    return "\n".join(lines)


def main():
    args = parse_args()
    
    if args.debug:
        print("="*70)
        print("  Report Generation")
        print("="*70)
        print()
    
    # Load LLM analysis
    if args.debug:
        print(f"📖 Loading LLM analysis from {args.llm_analysis}...")
    
    llm_analysis = load_json_file(args.llm_analysis)
    if not llm_analysis:
        print(f"❌ Error: Could not load LLM analysis from {args.llm_analysis}", file=sys.stderr)
        sys.exit(1)
    
    # Load code diffs (optional)
    code_diffs = None
    if args.code_diffs:
        if args.debug:
            print(f"📖 Loading code diffs from {args.code_diffs}...")
        code_diffs = load_json_file(args.code_diffs)
    
    test_name = args.test_name or "unknown"
    
    # Generate reports
    if args.debug:
        print(f"📝 Generating reports...")
    
    executive_summary = generate_executive_summary(llm_analysis, code_diffs, test_name)
    full_report = generate_full_report(llm_analysis, code_diffs, test_name)
    
    # Save reports
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    exec_path = output_dir / "executive-summary.md"
    with open(exec_path, 'w') as f:
        f.write(executive_summary)
    
    full_path = output_dir / "full-analysis-report.md"
    with open(full_path, 'w') as f:
        f.write(full_report)
    
    # Print summary
    print(f"✅ Reports generated")
    print(f"   Executive summary: {exec_path}")
    print(f"   Full report: {full_path}")
    
    if args.debug:
        print()
        print("📋 Report Statistics:")
        print(f"   Executive summary: {len(executive_summary)} chars")
        print(f"   Full report: {len(full_report)} chars")


if __name__ == '__main__':
    main()


#!/usr/bin/env python3
"""
LLM-powered test failure analysis.

Uses OpenAI GPT-4 to analyze test failures with complete context including
code changes, test implementation, error logs, and service logs.

Usage:
    export OPENAI_API_KEY="sk-..."
    python llm_analyzer.py \
        --llm-context artifacts/llm-context.json \
        --code-diffs artifacts/code-diffs.json \
        --output artifacts/llm-analysis.json
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LLM-powered test failure analysis")
    parser.add_argument("--llm-context", required=True, help="Path to llm-context.json from Phase 7")
    parser.add_argument("--code-diffs", help="Path to code-diffs.json (optional)")
    parser.add_argument("--output", required=True, help="Output JSON file path")
    parser.add_argument("--model", default="gpt-4o", help="OpenAI model (default: gpt-4o)")
    parser.add_argument("--max-tokens", type=int, default=6000, help="Max output tokens (default: 6000)")
    parser.add_argument("--temperature", type=float, default=0.3, help="Temperature (default: 0.3)")
    parser.add_argument("--api-key", help="OpenAI API key (or use OPENAI_API_KEY env var)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def load_json_file(path: str) -> Dict:
    """Load JSON file."""
    if not path or not Path(path).exists():
        return {}
    with open(path, 'r') as f:
        return json.load(f)


def build_prompt(llm_context: Dict, code_diffs: Optional[Dict] = None) -> str:
    """
    Build LLM prompt from context and diffs.
    
    Returns:
        Formatted prompt string
    """
    metadata = llm_context.get('metadata', {})
    test_name = metadata.get('test_name', 'unknown')
    error_log = llm_context.get('error_log', '')
    
    # Build prompt sections
    prompt_parts = []
    
    # Header
    prompt_parts.append(f"""You are analyzing a system test failure. Provide a comprehensive root cause analysis.

## Test Information
- **Test Name**: {test_name}
- **Test Type**: System integration test
""")
    
    # Code changes section (if available)
    if code_diffs:
        prompt_parts.append("\n## Code Changes Since Deployment\n")
        
        for repo, diff in code_diffs.items():
            old_ver = diff.get('old_version', 'unknown')
            new_ver = diff.get('new_version', 'unknown')
            summary = diff.get('summary', {})
            
            prompt_parts.append(f"\n### {repo} ({old_ver} → {new_ver})")
            
            # Check if there are function-level changes
            has_function_changes = diff.get('changed', False)
            
            if has_function_changes:
                # Show function-level changes
                prompt_parts.append(f"- Functions added: {summary.get('total_functions_added', 0)}")
                prompt_parts.append(f"- Functions removed: {summary.get('total_functions_removed', 0)}")
                prompt_parts.append(f"- Endpoints added: {summary.get('total_endpoints_added', 0)}")
                prompt_parts.append(f"- Endpoints removed: {summary.get('total_endpoints_removed', 0)}")
                
                # Show top changed functions
                functions = diff.get('functions', {})
                added_funcs = functions.get('added', [])
                if added_funcs:
                    prompt_parts.append(f"\n**New Functions:**")
                    for func in added_funcs[:5]:
                        prompt_parts.append(f"- {func.get('file')}:{func.get('name')}")
                
                removed_funcs = functions.get('removed', [])
                if removed_funcs:
                    prompt_parts.append(f"\n**Removed Functions:**")
                    for func in removed_funcs[:5]:
                        prompt_parts.append(f"- {func.get('file')}:{func.get('name')}")
                
                # Show endpoint changes
                endpoints = diff.get('endpoints', {})
                added_eps = endpoints.get('added', [])
                if added_eps:
                    prompt_parts.append(f"\n**New Endpoints:**")
                    for ep in added_eps[:5]:
                        prompt_parts.append(f"- {ep.get('method')} {ep.get('path')}")
            else:
                # No function-level changes, but check for git-based diff info
                git_diff = diff.get('git_diff')
                if git_diff:
                    total_commits = git_diff.get('total_commits', 0)
                    files = git_diff.get('files', [])
                    
                    if files:
                        total_additions = sum(f.get('additions', 0) for f in files)
                        total_deletions = sum(f.get('deletions', 0) for f in files)
                        
                        prompt_parts.append(f"- No new functions or endpoints added")
                        prompt_parts.append(f"- Code modifications: {len(files)} files, {total_commits} commits, +{total_additions}/-{total_deletions} lines")
                        prompt_parts.append(f"\n**Modified Files (with code changes):**")
                        for i, file in enumerate(files[:10]):  # Limit to top 10 files
                            filename = file.get('filename', 'unknown')
                            additions = file.get('additions', 0)
                            deletions = file.get('deletions', 0)
                            status = file.get('status', 'modified')
                            patch = file.get('patch', '')
                            
                            prompt_parts.append(f"\n{i+1}. **{filename}** ({status}): +{additions}/-{deletions}")
                            
                            # Include actual code diff (limited to 500 chars to avoid token explosion)
                            if patch:
                                # Clean up the patch for better readability
                                patch_lines = patch.split('\\n')[:15]  # First 15 lines
                                patch_preview = '\\n'.join(patch_lines)
                                if len(patch_preview) > 500:
                                    patch_preview = patch_preview[:500] + '...'
                                prompt_parts.append(f"```diff\n{patch_preview}\n```")
                    else:
                        prompt_parts.append(f"- No code changes detected")
                else:
                    prompt_parts.append(f"- No code changes detected")
    
    # Error logs
    if error_log:
        prompt_parts.append(f"\n## Error Logs\n\n```\n{error_log[:2000]}\n```")
    
    # Code chunks
    code_chunks = llm_context.get('code_chunks', [])
    if code_chunks:
        prompt_parts.append(f"\n## Relevant Code ({len(code_chunks)} chunks)\n")
        for i, chunk in enumerate(code_chunks[:10]):  # Limit to first 10 chunks
            chunk_id = chunk.get('id', f'chunk_{i}')
            chunk_type = chunk.get('type', 'unknown')
            source = chunk.get('source', 'unknown')  # source is a string, not a dict
            file_path = chunk.get('file', 'unknown')  # file is at chunk level
            
            prompt_parts.append(f"\n### {chunk_id} ({chunk_type}, source: {source})")
            prompt_parts.append(f"File: {file_path}")
            
            code = chunk.get('code', '')
            if code:
                prompt_parts.append(f"\n```\n{code[:500]}\n```")
    
    # Service logs (Loki)
    loki_logs = llm_context.get('loki_logs', [])
    if loki_logs:
        prompt_parts.append(f"\n## Service Logs ({len(loki_logs)} entries)\n")
        for log in loki_logs[:10]:
            prompt_parts.append(f"- {log[:200]}")
    
    # Analysis request
    prompt_parts.append("""

## Analysis Required

Based on the information above, provide:

1. **Root Cause** (2-3 sentences): What is the core issue causing this test failure?

2. **Evidence** (bullet points): Specific log lines, code patterns, or changes that support your analysis.

3. **Impact Assessment**:
   - Severity: (low/medium/high/critical)
   - Blast Radius: Which other tests/features might be affected?

4. **Recommended Fix** (actionable steps): What specific changes should be made to fix this issue?

5. **Executive Verdict** (1-2 sentences): High-level summary for leadership explaining the issue and urgency.

Respond in JSON format with these exact keys:
{
  "root_cause": "...",
  "evidence": ["...", "..."],
  "impact": {
    "severity": "...",
    "blast_radius": "..."
  },
  "recommended_fix": ["...", "..."],
  "executive_verdict": "..."
}
""")
    
    return "\n".join(prompt_parts)


def call_openai_api(prompt: str, api_key: str, model: str, max_tokens: int, temperature: float, debug: bool = False) -> Dict:
    """
    Call OpenAI API to analyze the test failure.
    
    Returns:
        Parsed JSON response from LLM
    """
    try:
        import openai
    except ImportError:
        print("❌ Error: openai package not installed", file=sys.stderr)
        print("   Install with: pip install openai", file=sys.stderr)
        sys.exit(1)
    
    client = openai.OpenAI(api_key=api_key)
    
    if debug:
        print(f"🤖 Calling OpenAI API...")
        print(f"   Model: {model}")
        print(f"   Max tokens: {max_tokens}")
        print(f"   Temperature: {temperature}")
        print(f"   Prompt length: {len(prompt)} chars")
        print()
    
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert software engineer analyzing test failures. Provide concise, actionable analysis."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=temperature,
            response_format={"type": "json_object"}
        )
        
        content = response.choices[0].message.content
        
        if debug:
            print(f"✅ Got response from OpenAI")
            print(f"   Usage: {response.usage.prompt_tokens} prompt + {response.usage.completion_tokens} completion = {response.usage.total_tokens} total tokens")
            print()
        
        # Parse JSON response
        result = json.loads(content)
        
        # Add metadata
        result['_metadata'] = {
            'model': model,
            'prompt_tokens': response.usage.prompt_tokens,
            'completion_tokens': response.usage.completion_tokens,
            'total_tokens': response.usage.total_tokens
        }
        
        return result
    
    except Exception as e:
        if debug:
            print(f"❌ Error calling OpenAI API: {e}", file=sys.stderr)
        raise


def main():
    args = parse_args()
    
    # Get API key
    api_key = args.api_key or os.environ.get('OPENAI_API_KEY')
    if not api_key:
        print("❌ Error: OpenAI API key required (use --api-key or OPENAI_API_KEY env var)", file=sys.stderr)
        sys.exit(1)
    
    if args.debug:
        print("="*70)
        print("  LLM Test Failure Analysis")
        print("="*70)
        print()
    
    # Load context
    if args.debug:
        print(f"📖 Loading LLM context from {args.llm_context}...")
    
    llm_context = load_json_file(args.llm_context)
    if not llm_context:
        print(f"❌ Error: Could not load LLM context from {args.llm_context}", file=sys.stderr)
        sys.exit(1)
    
    # Load code diffs (optional)
    code_diffs = None
    if args.code_diffs:
        if args.debug:
            print(f"📖 Loading code diffs from {args.code_diffs}...")
        code_diffs = load_json_file(args.code_diffs)
    
    # Build prompt
    if args.debug:
        print(f"📝 Building prompt...")
    
    prompt = build_prompt(llm_context, code_diffs)
    
    # Call LLM
    if args.debug:
        print(f"🤖 Analyzing with {args.model}...")
        print()
    
    try:
        analysis = call_openai_api(
            prompt,
            api_key,
            args.model,
            args.max_tokens,
            args.temperature,
            args.debug
        )
    except Exception as e:
        print(f"❌ LLM analysis failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    # Print summary
    print(f"✅ LLM analysis complete")
    print(f"   Output: {args.output}")
    
    if args.debug:
        print()
        print("📋 Analysis Summary:")
        print(f"   Root Cause: {analysis.get('root_cause', 'N/A')[:100]}...")
        print(f"   Severity: {analysis.get('impact', {}).get('severity', 'N/A')}")
        print(f"   Executive Verdict: {analysis.get('executive_verdict', 'N/A')[:100]}...")


if __name__ == '__main__':
    main()


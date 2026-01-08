#!/usr/bin/env python3
"""
LLM-powered test failure analysis.

Supports Google Gemini (default) and OpenAI GPT-4 for analyzing test failures
with complete context including code changes, test implementation, error logs, and service logs.

Usage:
    # Google Gemini (default, recommended - gemini-2.5-flash)
    export GOOGLE_API_KEY="..."  # or SYSTEM_TEST_ANALYZER_GOOGLE_API_KEY in CI
    python llm_analyzer.py \
        --llm-context artifacts/llm-context.json \
        --code-diffs artifacts/code-diffs.json \
        --output artifacts/llm-analysis.json
    
    # OpenAI GPT-4
    export OPENAI_API_KEY="sk-..."  # or SYSTEM_TEST_ANALYZER_OPENAI_API_KEY in CI
    python llm_analyzer.py \
        --provider openai \
        --llm-context artifacts/llm-context.json \
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
    parser.add_argument("--provider", default="google", choices=["google", "openai"], 
                        help="LLM provider: google (default, Gemini) or openai (GPT-4)")
    parser.add_argument("--model", help="Model name (default: gemini-1.5-pro for Google, gpt-4o for OpenAI)")
    parser.add_argument("--max-tokens", type=int, default=6000, help="Max output tokens (default: 6000)")
    parser.add_argument("--temperature", type=float, default=0.3, help="Temperature (default: 0.3)")
    parser.add_argument("--api-key", help="API key (or use GOOGLE_API_KEY / OPENAI_API_KEY env var)")
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
    Cross-test interference data is read from llm_context['cross_test_interference'].
    
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

    # Explicitly instruct about test-side fixes (system-tests repo)
    st_meta = metadata.get("system_tests") if isinstance(metadata, dict) else None
    st_files = []
    try:
        if isinstance(st_meta, dict) and isinstance(st_meta.get("implementation_files"), list):
            st_files = [x for x in st_meta.get("implementation_files") if isinstance(x, str)]
    except Exception:
        st_files = []

    prompt_parts.append(f"""
## Test-Side Analysis (system-tests repo)

In addition to service-side/root-cause analysis, you MUST evaluate whether the failure is caused by the **system test flow** itself and propose **system-tests** fixes if needed.

Use the LLM context:
- Code chunks with `source=system_test_code` are test-side chunks extracted from the system-tests code index for this failing test.

If you propose a test fix, make it concrete:
- Mention the relevant file(s) and what should change (wait/poll logic, retries, assertions, parsing, IDs, cleanup, isolation).
- Prefer minimal, targeted changes.

System-test implementation files (from mapping):
{chr(10).join([f"- {p}" for p in st_files[:25]]) if st_files else "- (not available)"}
""")

    prompt_parts.append("""
## Analyzer Improvement Suggestions (future analysis quality)

After you finish the root-cause analysis and recommended fixes, also provide **2-5 concrete improvements** to the *system test failure analyzer flow* itself.

Focus on improvements that would make future analyses more accurate and less ambiguous, for example:
- Better failing-request extraction (ensure the “failing endpoint” is the one that actually failed, not the first request in logs)
- Capture/attach the exact system-tests ref/commit that ran and include it in metadata
- Include additional test-side chunks (or narrower chunk selection) when a specific helper is in the traceback
- Improve Loki queries (narrow by pod/app labels, add keywords like “failed to connect”, include relevant DB/proxy logs)
- Emit explicit “data readiness” signals (e.g., whether aggregator/ingest completed) to distinguish infra vs eventual consistency vs app bugs

Provide each suggestion as:
- **Problem** (what is missing today)
- **Change** (what to add/change in the analyzer)
- **Benefit** (why it helps)
""")
    
    # Add cross-test interference data from context (this is INPUT, not a conclusion)
    interference_data = llm_context.get('cross_test_interference')
    if interference_data and interference_data.get('interference_detected'):
        prompt_parts.append(f"""
## ⚠️ Cross-Test Interference Detected

**CRITICAL**: Cross-test interference has been detected! This suggests a **test isolation failure**, not an application bug.

- **Parallel Tests**: {', '.join(interference_data.get('parallel_tests', []))}
- **Bulk Operations Found**:""")
        
        for bulk_op in interference_data.get('bulk_operations', []):
            if bulk_op.get('risk') == 'high':
                prompt_parts.append(f"""
  - Operation: `{bulk_op.get('operation')}`
  - Filter Used: {bulk_op.get('filters')}
  - Filter Value: {bulk_op.get('filter_values')}
  - Risk Level: {bulk_op.get('risk')} ⚠️""")
        
        prompt_parts.append(f"""
- **Shared Resources**:""")
        for resource in interference_data.get('shared_resources', []):
            if isinstance(resource, dict):
                prompt_parts.append(f"""
  - Type: {resource.get('type')}
  - Values: {resource.get('values')}
  - Affected by: {resource.get('parallel_test')}""")
        
        recommendations = interference_data.get('recommendations', [])
        if recommendations:
            prompt_parts.append(f"""
- **Recommendations**:
{chr(10).join('  - ' + r for r in recommendations)}

**IMPORTANT**: Given the cross-test interference detection, focus your analysis on:
1. **Test Isolation Failure** (not application bugs)
2. Verify if parallel test resolved/affected the incident
3. Check if bulk operations with filters affected shared resources
4. Recommend fixing test isolation (use specific GUIDs instead of filters)
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


def call_google_api(prompt: str, api_key: str, model: str, max_tokens: int, temperature: float, debug: bool = False) -> Dict:
    """
    Call Google Gemini API to analyze the test failure.
    Tries multiple models with fallback if the primary model is unavailable.
    
    Returns:
        Parsed JSON response from LLM
    """
    try:
        import google.generativeai as genai
    except ImportError:
        print("❌ Error: google-generativeai package not installed", file=sys.stderr)
        print("   Install with: pip install google-generativeai", file=sys.stderr)
        sys.exit(1)
    
    genai.configure(api_key=api_key)
    
    # Model fallback chain
    models_to_try = [
        "gemini-3-pro-preview",  # Latest preview (if available)
        "gemini-2.5-flash",      # Fast and reliable fallback
        "gemini-1.5-pro-latest", # Older stable version
        "gemini-pro"             # Legacy fallback
    ]
    
    # If user specified a model, try that first
    if model and model not in models_to_try:
        models_to_try.insert(0, model)
    elif model in models_to_try:
        # Move specified model to front
        models_to_try.remove(model)
        models_to_try.insert(0, model)
    
    last_error = None
    
    for attempt_model in models_to_try:
        try:
            if debug:
                print(f"🤖 Trying Google Gemini API...")
                print(f"   Model: {attempt_model}")
                print(f"   Max tokens: {max_tokens}")
                print(f"   Temperature: {temperature}")
                print(f"   Prompt length: {len(prompt)} chars")
                print()
            
            # Create model with generation config
            generation_config = {
                "temperature": temperature,
                "max_output_tokens": max_tokens,
                "response_mime_type": "application/json"
            }
            
            gemini_model = genai.GenerativeModel(
                model_name=attempt_model,
                generation_config=generation_config,
                system_instruction="You are an expert software engineer analyzing test failures. Provide concise, actionable analysis in JSON format."
            )
            
            response = gemini_model.generate_content(prompt)
            
            content = response.text
            
            if debug:
                print(f"✅ Got response from Google Gemini")
                print(f"   Model used: {attempt_model}")
                print(f"   Candidates: {len(response.candidates)}")
                if hasattr(response, 'usage_metadata'):
                    print(f"   Usage: {response.usage_metadata.prompt_token_count} prompt + {response.usage_metadata.candidates_token_count} completion = {response.usage_metadata.total_token_count} total tokens")
                print()
            
            # Parse JSON response
            result = json.loads(content)
            
            # Add metadata (include actual model used)
            metadata = {
                'model': attempt_model,
                'provider': 'google',
                'requested_model': model
            }
            if hasattr(response, 'usage_metadata'):
                metadata.update({
                    'prompt_tokens': response.usage_metadata.prompt_token_count,
                    'completion_tokens': response.usage_metadata.candidates_token_count,
                    'total_tokens': response.usage_metadata.total_token_count
                })
            result['_metadata'] = metadata
            
            return result
        
        except Exception as e:
            last_error = e
            error_msg = str(e).lower()
            
            # Check if it's a "model not found" error
            if '404' in error_msg or 'not found' in error_msg or 'not available' in error_msg:
                if debug:
                    print(f"⚠️  Model {attempt_model} not available, trying next fallback...")
                    print(f"   Error: {e}")
                    print()
                continue
            else:
                # Other error, don't fallback
                if debug:
                    print(f"❌ Error calling Google Gemini API: {e}", file=sys.stderr)
                raise
    
    # All models failed
    if debug:
        print(f"❌ All Gemini models failed. Last error: {last_error}", file=sys.stderr)
    raise Exception(f"All Gemini models failed. Last error: {last_error}")


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
            'provider': 'openai',
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
    
    # Determine provider and get appropriate API key
    provider = args.provider.lower()
    
    if provider == "google":
        # Check multiple env var names (CI uses SYSTEM_TEST_ANALYZER_ prefix)
        api_key = args.api_key or os.environ.get('GOOGLE_API_KEY') or os.environ.get('SYSTEM_TEST_ANALYZER_GOOGLE_API_KEY')
        default_model = "gemini-3-pro-preview"  # Latest preview (with fallback to gemini-2.5-flash)
        api_name = "Google Gemini"
        env_var_name = "GOOGLE_API_KEY / SYSTEM_TEST_ANALYZER_GOOGLE_API_KEY"
    else:  # openai
        # Check multiple env var names (CI uses SYSTEM_TEST_ANALYZER_ prefix)
        api_key = args.api_key or os.environ.get('OPENAI_API_KEY') or os.environ.get('SYSTEM_TEST_ANALYZER_OPENAI_API_KEY')
        default_model = "gpt-4o"
        api_name = "OpenAI"
        env_var_name = "OPENAI_API_KEY / SYSTEM_TEST_ANALYZER_OPENAI_API_KEY"
    
    # Use default model if not specified
    model = args.model or default_model
    
    # Check API key
    if not api_key:
        print(f"❌ Error: {api_name} API key required", file=sys.stderr)
        print(f"   Use --api-key or set {env_var_name} environment variable", file=sys.stderr)
        sys.exit(1)
    
    if args.debug:
        print("="*70)
        print("  LLM Test Failure Analysis")
        print("="*70)
        print(f"Provider: {api_name}")
        print(f"Model: {model}")
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
    
    # Check for cross-test interference data in context (it's part of the input context, not conclusions)
    if args.debug and llm_context.get('cross_test_interference'):
        interference = llm_context.get('cross_test_interference')
        if interference.get('interference_detected'):
            print(f"   ✅ Cross-test interference data found in context!")
            print(f"      Parallel tests: {', '.join(interference.get('parallel_tests', []))}")
    
    # Build prompt (interference data is already in llm_context)
    if args.debug:
        print(f"📝 Building prompt...")
    
    prompt = build_prompt(llm_context, code_diffs)
    
    # Call LLM based on provider
    if args.debug:
        print(f"🤖 Analyzing with {api_name} ({model})...")
        print()
    
    try:
        if provider == "google":
            analysis = call_google_api(
                prompt,
                api_key,
                model,
                args.max_tokens,
                args.temperature,
                args.debug
            )
        else:  # openai
            analysis = call_openai_api(
                prompt,
                api_key,
                model,
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
    print(f"   Provider: {api_name}")
    print(f"   Model: {model}")
    print(f"   Output: {args.output}")
    
    if args.debug:
        print()
        print("📋 Analysis Summary:")
        print(f"   Root Cause: {analysis.get('root_cause', 'N/A')[:100]}...")
        print(f"   Severity: {analysis.get('impact', {}).get('severity', 'N/A')}")
        print(f"   Executive Verdict: {analysis.get('executive_verdict', 'N/A')[:100]}...")


if __name__ == '__main__':
    main()


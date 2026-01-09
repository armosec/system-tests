#!/usr/bin/env python3
"""
LLM Analyzer v2 - Using agent_runtime orchestrator.

This is the next-generation analyzer that uses the agent_runtime SDK
from agents-infra for provider-agnostic LLM analysis.

Usage:
    # With FakeProvider (no API key)
    python llm_analyzer_v2.py \
        --provider fake \
        --llm-context artifacts/llm-context.json \
        --output artifacts/llm-analysis.json
    
    # With Google Gemini
    export GOOGLE_API_KEY="..."
    python llm_analyzer_v2.py \
        --provider google \
        --llm-context artifacts/llm-context.json \
        --output artifacts/llm-analysis.json
    
    # With AWS Bedrock (uses IAM role or BEDROCK_API_KEY)
    python llm_analyzer_v2.py \
        --provider bedrock \
        --model anthropic.claude-3-5-sonnet-20241022-v2:0 \
        --llm-context artifacts/llm-context.json \
        --output artifacts/llm-analysis.json
"""

import argparse
import json
import sys
from pathlib import Path

# Add agents-infra/src to path so we can import agent_runtime
# This assumes both repos are in the same parent directory
agents_infra_src = Path(__file__).parents[3] / "agents-infra" / "src"
if agents_infra_src.exists():
    sys.path.insert(0, str(agents_infra_src))

try:
    from agent_runtime import (
        AnalysisRequest,
        analyze_with_llm,
        validate_provider,
        estimate_analysis_cost
    )
    from agent_runtime.providers import (
        FakeProvider,
        GoogleProvider,
        OpenAIProvider,
        BedrockProvider
    )
except ImportError as e:
    print(f"❌ Error: Could not import agent_runtime: {e}", file=sys.stderr)
    print(f"   Make sure agents-infra is at: {agents_infra_src}", file=sys.stderr)
    sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(description="LLM Test Failure Analysis (v2 - with orchestrator)")
    parser.add_argument("--llm-context", required=True, help="Path to llm-context.json")
    parser.add_argument("--code-diffs", help="Path to code-diffs.json (optional)")
    parser.add_argument("--output", required=True, help="Output JSON file")
    parser.add_argument(
        "--provider",
        required=True,
        choices=["fake", "google", "openai", "bedrock"],
        help="LLM provider"
    )
    parser.add_argument("--model", help="Model name (uses provider default if not specified)")
    parser.add_argument("--max-tokens", type=int, default=6000, help="Max output tokens")
    parser.add_argument("--temperature", type=float, default=0.3, help="Temperature")
    parser.add_argument("--region", default="us-east-1", help="AWS region (for Bedrock)")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    return parser.parse_args()


def load_json_file(path):
    """Load JSON file."""
    if not path or not Path(path).exists():
        return {}
    with open(path, 'r') as f:
        return json.load(f)


def build_analysis_context(llm_context, code_diffs=None):
    """
    Build analysis context string from llm_context and code_diffs.
    
    This is a simplified version - the full prompt building logic
    is in llm_analyzer.py build_prompt().
    """
    metadata = llm_context.get('metadata', {})
    test_name = metadata.get('test_name', 'unknown')
    error_log = llm_context.get('error_log', '')
    
    parts = []
    parts.append(f"Test Name: {test_name}")
    
    if error_log:
        parts.append(f"\nError Log:\n{error_log[:2000]}")
    
    code_chunks = llm_context.get('code_chunks', [])
    if code_chunks:
        parts.append(f"\nRelevant Code ({len(code_chunks)} chunks):")
        for chunk in code_chunks[:5]:
            chunk_id = chunk.get('id', 'unknown')
            code = chunk.get('code', '')[:300]
            parts.append(f"\n{chunk_id}:\n{code}")
    
    parts.append("\n\nProvide analysis in JSON format with: root_cause, evidence, impact, recommended_fix, executive_verdict")
    
    return "\n".join(parts)


def create_provider(provider_name, args):
    """Create LLM provider based on args."""
    if provider_name == "fake":
        return FakeProvider()
    elif provider_name == "google":
        return GoogleProvider()
    elif provider_name == "openai":
        return OpenAIProvider()
    elif provider_name == "bedrock":
        return BedrockProvider(region=args.region)
    else:
        raise ValueError(f"Unknown provider: {provider_name}")


def main():
    args = parse_args()
    
    if args.debug:
        print(f"🚀 LLM Analyzer v2 (orchestrator-based)")
        print(f"   Provider: {args.provider}")
        print(f"   Model: {args.model or '(default)'}")
        print()
    
    # Load context
    if args.debug:
        print(f"📖 Loading LLM context...")
    
    llm_context = load_json_file(args.llm_context)
    if not llm_context:
        print(f"❌ Error: Could not load LLM context from {args.llm_context}", file=sys.stderr)
        sys.exit(1)
    
    code_diffs = None
    if args.code_diffs:
        code_diffs = load_json_file(args.code_diffs)
    
    # Create provider
    if args.debug:
        print(f"🔧 Creating provider: {args.provider}")
    
    try:
        provider = create_provider(args.provider, args)
    except Exception as e:
        print(f"❌ Error creating provider: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Validate provider
    if args.debug:
        print(f"✅ Validating provider...")
    
    if not validate_provider(provider):
        print(f"❌ Provider validation failed", file=sys.stderr)
        sys.exit(1)
    
    # Build analysis context
    if args.debug:
        print(f"📝 Building analysis context...")
    
    context = build_analysis_context(llm_context, code_diffs)
    
    # Create analysis request
    request = AnalysisRequest(
        context=context,
        model_name=args.model,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        attribution={
            "analyzer_version": "v2",
            "provider": args.provider
        }
    )
    
    # Estimate cost
    if args.debug:
        try:
            estimate = estimate_analysis_cost(provider, request)
            print(f"💰 Estimated cost: ${estimate.estimated_usd:.4f} ({estimate.tokens} tokens)")
            print()
        except Exception:
            pass
    
    # Analyze with orchestrator
    if args.debug:
        print(f"🤖 Analyzing with {args.provider}...")
    
    try:
        response = analyze_with_llm(provider, request)
    except Exception as e:
        print(f"❌ Analysis failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Convert to legacy format for backward compatibility
    analysis = response.to_legacy_format()
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    # Print summary
    print(f"✅ LLM analysis complete")
    print(f"   Provider: {response.provider}")
    print(f"   Model: {response.model}")
    print(f"   Tokens: {response.usage.total_tokens} (in: {response.usage.input_tokens}, out: {response.usage.output_tokens})")
    print(f"   Cost: ${response.cost_usd:.4f}")
    print(f"   Output: {args.output}")
    
    if args.debug:
        print()
        print(f"📋 Analysis Summary:")
        print(f"   Root Cause: {analysis.get('root_cause', 'N/A')[:100]}...")
        severity = analysis.get('impact', {}).get('severity', 'N/A')
        print(f"   Severity: {severity}")


if __name__ == '__main__':
    main()


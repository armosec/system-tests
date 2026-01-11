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
import os
import re
import sys
from pathlib import Path

# Add agents-infra/src to path so we can import agent_runtime.
# Supported layouts:
# - local dev: repos/{system-tests,agents-infra}/...
# - ECS task: agents-infra cloned under WORKDIR (/work/agents-infra)
agents_infra_src = Path(__file__).parents[3] / "agents-infra" / "src"
workdir = os.environ.get("WORKDIR") or "/work"
agents_infra_src_workdir = Path(workdir) / "agents-infra" / "src"
if agents_infra_src_workdir.exists():
    agents_infra_src = agents_infra_src_workdir
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
    # Default Bedrock region should follow infra region; allow overrides via flag.
    default_region = (
        os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "eu-north-1"
    )
    parser.add_argument("--region", default=default_region, help="AWS region (for Bedrock)")
    parser.add_argument("--inference-profile", help="Bedrock inference profile for cost attribution (e.g., 'team-platform', 'agents-infra')")
    parser.add_argument("--owner-team", default="unknown", help="Owner team for cost attribution (e.g., 'platform', 'security')")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    return parser.parse_args()


def load_json_file(path):
    """Load JSON file."""
    if not path or not Path(path).exists():
        return {}
    with open(path, 'r') as f:
        return json.load(f)


def _extract_json_from_text(text: str):
    """
    Best-effort extraction of a JSON object from LLM output.
    Handles common cases:
    - Raw JSON
    - Markdown fenced JSON: ```json ... ```
    - Extra prose before/after JSON
    """
    if not isinstance(text, str):
        return None

    s = text.strip()
    if not s:
        return None

    # Try direct parse first
    try:
        v = json.loads(s)
        if isinstance(v, dict):
            return v
    except Exception:
        pass

    # Try fenced ```json ... ```
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", s, flags=re.IGNORECASE)
    if m:
        inner = m.group(1).strip()
        try:
            v = json.loads(inner)
            if isinstance(v, dict):
                return v
        except Exception:
            pass

    # Try to locate first {...} block
    m = re.search(r"(\{[\s\S]*\})", s)
    if m:
        candidate = m.group(1).strip()
        try:
            v = json.loads(candidate)
            if isinstance(v, dict):
                return v
        except Exception:
            pass

    return None


def _normalize_legacy_analysis(analysis: dict, response) -> dict:
    """
    Ensure output shape is stable even when the model returns odd types.
    Prefer JSON object embedded in the model content (very common with Claude).
    """
    parsed = _extract_json_from_text(getattr(response, "content", ""))
    if isinstance(parsed, dict) and parsed:
        analysis = {**analysis, **parsed}

    def to_str(v):
        if v is None:
            return ""
        if isinstance(v, str):
            return v
        return json.dumps(v, ensure_ascii=False)

    def to_list(v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            return [v]
        return [v]

    analysis["root_cause"] = to_str(analysis.get("root_cause"))
    analysis["executive_verdict"] = to_str(analysis.get("executive_verdict"))
    analysis["evidence"] = to_list(analysis.get("evidence"))
    analysis["recommended_fix"] = to_list(analysis.get("recommended_fix"))
    analysis["evidence_quotes"] = to_list(analysis.get("evidence_quotes"))

    # Normalize confidence/category (optional but recommended)
    conf = str(analysis.get("confidence") or "").strip().lower()
    if conf not in ("low", "medium", "high"):
        analysis["confidence"] = "low" if analysis.get("evidence_quotes") else "unknown"
    cat = str(analysis.get("most_likely_category") or "").strip().lower()
    allowed = {"aws_auth", "eventual_consistency", "backend_bug", "test_bug", "infra", "unknown"}
    if cat not in allowed:
        analysis["most_likely_category"] = "unknown"

    impact = analysis.get("impact")
    if not isinstance(impact, dict):
        analysis["impact"] = {"severity": "unknown", "blast_radius": "unknown", "raw": impact}
    else:
        impact.setdefault("severity", "unknown")
        impact.setdefault("blast_radius", "unknown")
        analysis["impact"] = impact

    return analysis


def build_analysis_context(llm_context, code_diffs=None):
    """
    Build analysis context string from llm_context and code_diffs.
    
    This is a simplified version - the full prompt building logic
    is in llm_analyzer.py build_prompt().
    """
    metadata = llm_context.get('metadata', {})
    test_name = metadata.get('test_name', 'unknown')
    env_name = metadata.get("environment") or "unknown"
    failing_req = metadata.get("failing_request") or {}
    primary_sig = (metadata.get("primary_error_signature") or "").strip()
    evidence_quotes = metadata.get("evidence_quotes") or []
    instructions = (metadata.get("analysis_instructions_rendered") or metadata.get("analysis_instructions") or "").strip()

    # Correct key is "error_logs" (produced by build_llm_context.py)
    error_logs = llm_context.get('error_logs', '') or ''
    test_code = llm_context.get("test_code") or ""
    
    parts = []
    parts.append("You are an expert SRE + backend engineer doing postmortem-quality test failure triage.")
    parts.append("You MUST ground your conclusions in the provided evidence. If evidence is insufficient, say so.")
    parts.append("")
    parts.append(f"## Test\n- name: {test_name}\n- environment: {env_name}")
    if isinstance(failing_req, dict) and failing_req.get("method") and failing_req.get("request_uri"):
        parts.append(
            "## Failing request (from logs)\n"
            f"- {failing_req.get('method')} {failing_req.get('request_uri')} (source={failing_req.get('source')})"
        )
    if primary_sig:
        parts.append(f"## Primary error signature\n{primary_sig}")

    if evidence_quotes and isinstance(evidence_quotes, list):
        parts.append("## Top Failure Evidence (verbatim)\n```")
        for ln in evidence_quotes[:12]:
            parts.append(str(ln))
        parts.append("```")

    if test_code:
        parts.append("## Test code (snippet)\n```")
        parts.append(test_code[:3000] + ("..." if len(test_code) > 3000 else ""))
        parts.append("```")

    if error_logs:
        parts.append("## Error logs (excerpt)\n```")
        parts.append(error_logs[:4000] + ("..." if len(error_logs) > 4000 else ""))
        parts.append("```")

    if instructions:
        parts.append("## Analysis instructions (rendered)\n")
        parts.append(instructions)

    # Code chunks: include fewer but higher signal
    code_chunks = llm_context.get('code_chunks', []) or []
    if code_chunks:
        def _score(ch):
            try:
                return int(ch.get("priority", 999))
            except Exception:
                return 999

        # group: api handlers + system test code first, then rest by priority
        handlers = [c for c in code_chunks if c.get("source") == "api_handler"]
        tests = [c for c in code_chunks if c.get("source") == "system_test_code"]
        rest = [c for c in code_chunks if c.get("source") not in ("api_handler", "system_test_code")]
        rest.sort(key=_score)
        selected = handlers[:20] + tests[:20] + rest[:40]
        parts.append(f"\n## Relevant code chunks (showing {len(selected)} of {len(code_chunks)})")
        for chunk in selected:
            chunk_id = chunk.get('id', chunk.get("chunk_id", 'unknown'))
            repo = chunk.get("repo", "unknown")
            file_ = chunk.get("file", "")
            name = chunk.get("name", "")
            code = (chunk.get('code', '') or '')[:800]
            parts.append(f"\n### {chunk_id} ({repo}) {file_} {name}\n```")
            parts.append(code)
            parts.append("```")

    parts.append(
        "\n## Output format (STRICT)\n"
        "Return ONLY a single JSON object (no markdown fences) with keys:\n"
        "- root_cause: string\n"
        "- evidence_quotes: array of verbatim lines copied from the 'Top Failure Evidence' / logs\n"
        "- most_likely_category: one of ['aws_auth','eventual_consistency','backend_bug','test_bug','infra','unknown']\n"
        "- confidence: one of ['low','medium','high']\n"
        "- impact: {severity, blast_radius, raw}\n"
        "- recommended_fix: array of concrete actions (code and/or ops)\n"
        "- executive_verdict: string\n"
        "\nRules:\n"
        "- If you cannot cite at least 2 evidence_quotes for your root_cause, set confidence='low' and category='unknown'.\n"
        "- Prefer explanations supported by the error logs over unrelated code details.\n"
    )
    
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
        return BedrockProvider(
            region=args.region,
            inference_profile=args.inference_profile
        )
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
            "provider": args.provider,
            "owner_team": args.owner_team,
            "inference_profile": args.inference_profile
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
    
    # Convert to legacy format for backward compatibility, then normalize.
    analysis = _normalize_legacy_analysis(response.to_legacy_format(), response)
    
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


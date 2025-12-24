#!/usr/bin/env python3
"""
Example implementations for log optimization strategies.

These can be integrated into analyzer.py to improve log information preservation
without increasing context size.
"""

import re
from typing import List, Dict, Set, Tuple

# Configuration parameters
MAX_SNIPPETS = 500
MAX_CHARS = 7000
SIMILARITY_THRESHOLD = 0.9


def deduplicate_logs(snippets: List[str], similarity_threshold: float = 0.9) -> List[str]:
    """
    Strategy 1: Remove duplicate log lines.
    
    Args:
        snippets: List of log lines
        similarity_threshold: Threshold for considering logs similar (0.0-1.0)
    
    Returns:
        Deduplicated list of logs
    """
    seen_logs: List[str] = []
    deduplicated: List[str] = []
    
    for line in snippets:
        # Normalize for comparison
        normalized = normalize_log_line(line)
        
        # Check if we've seen this pattern before
        is_duplicate = False
        for seen in seen_logs:
            if are_logs_similar(normalized, seen, similarity_threshold):
                is_duplicate = True
                break
        
        if not is_duplicate:
            seen_logs.append(normalized)
            deduplicated.append(line)
    
    return deduplicated


def normalize_log_line(line: str) -> str:
    """Normalize log line for comparison (remove timestamps, IDs, etc.)"""
    # Remove timestamps
    normalized = re.sub(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}[.\d]*[Z]?', '', line)
    # Remove bracketed IDs (e.g., [abc123], [request-id: xyz])
    normalized = re.sub(r'\[.*?\]', '', normalized)
    # Remove UUIDs
    normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '', normalized, flags=re.IGNORECASE)
    # Remove extra whitespace
    normalized = ' '.join(normalized.split())
    # Take first 200 chars for comparison
    return normalized[:200].lower()


def are_logs_similar(log1: str, log2: str, threshold: float) -> bool:
    """Check if two normalized logs are similar (simple character-based similarity)"""
    if not log1 or not log2:
        return False
    
    # Simple character overlap ratio
    set1 = set(log1)
    set2 = set(log2)
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    
    if union == 0:
        return False
    
    similarity = intersection / union
    return similarity >= threshold


def score_log_importance(line: str) -> int:
    """
    Strategy 2: Score log line by importance.
    
    Returns:
        Score (higher = more important)
    """
    score = 0
    line_lower = line.lower()
    
    # Critical patterns (highest priority)
    critical_patterns = ['error', 'exception', 'panic', 'fatal', 'critical', 'crash']
    if any(pattern in line_lower for pattern in critical_patterns):
        score += 100
    
    # Stack traces
    if 'stack trace' in line_lower or 'traceback' in line_lower or 'goroutine' in line_lower:
        score += 80
    
    # Failure patterns
    failure_patterns = ['failed', 'failure', 'timeout', 'deadline exceeded', 'connection refused']
    if any(pattern in line_lower for pattern in failure_patterns):
        score += 60
    
    # Warnings
    if 'warn' in line_lower or 'warning' in line_lower:
        score += 40
    
    # Test-related (may contain test run ID or test context)
    if 'test' in line_lower or 'test_run_id' in line_lower:
        score += 30
    
    # Stack trace line indicators
    if line.strip().startswith('at ') or line.strip().startswith('goroutine'):
        score += 50
    
    # HTTP errors
    if re.search(r'\b(4\d{2}|5\d{2})\b', line):  # 4xx or 5xx status codes
        score += 45
    
    # Database errors
    if any(pattern in line_lower for pattern in ['sql error', 'database error', 'connection pool']):
        score += 55
    
    return score


def prioritize_logs(snippets: List[Tuple[str, str]], max_count: int = 500) -> List[str]:
    """
    Strategy 2: Prioritize logs by importance score.
    
    Args:
        snippets: List of (timestamp, log_line) tuples
        max_count: Maximum number of logs to keep
    
    Returns:
        Prioritized list of log lines
    """
    # Score each log
    scored_logs = [(score_log_importance(line), ts, line) for ts, line in snippets]
    
    # Sort by score (descending), then by timestamp (most recent first)
    scored_logs.sort(reverse=True, key=lambda x: (x[0], x[1]))
    
    # Take top logs
    prioritized = [line for _, _, line in scored_logs[:max_count]]
    
    return prioritized


def extract_structured_log_info(snippets: List[str]) -> Dict:
    """
    Strategy 4: Extract structured information from logs.
    
    Returns:
        Dictionary with structured log information
    """
    errors = []
    warnings = []
    services: Set[str] = set()
    time_ranges = []
    error_types: Dict[str, int] = {}
    
    for log in snippets:
        # Extract service name (various patterns)
        service_patterns = [
            r'\[service[=:]\s*(\w+)\]',
            r'service[=:]\s*(\w+)',
            r'component[=:]\s*(\w+)',
            r'pod[=:]\s*([\w-]+)',
        ]
        for pattern in service_patterns:
            match = re.search(pattern, log, re.IGNORECASE)
            if match:
                services.add(match.group(1))
                break
        
        # Extract errors
        if re.search(r'\b(error|exception|panic|fatal|critical)\b', log, re.IGNORECASE):
            error_type = extract_error_type(log)
            error_types[error_type] = error_types.get(error_type, 0) + 1
            errors.append({
                'message': log[:200],
                'type': error_type,
                'service': list(services)[-1] if services else 'unknown'
            })
        
        # Extract warnings
        if re.search(r'\b(warn|warning)\b', log, re.IGNORECASE):
            warnings.append(log[:150])
        
        # Extract timestamp
        ts_patterns = [
            r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})',
            r'(\d{2}:\d{2}:\d{2})',
        ]
        for pattern in ts_patterns:
            match = re.search(pattern, log)
            if match:
                time_ranges.append(match.group(1))
                break
    
    return {
        'error_count': len(errors),
        'errors': errors[:50],  # Top 50 errors
        'error_types': dict(sorted(error_types.items(), key=lambda x: x[1], reverse=True)[:10]),
        'warning_count': len(warnings),
        'warnings': warnings[:30],
        'services': sorted(list(services)),
        'time_range': {
            'start': min(time_ranges) if time_ranges else None,
            'end': max(time_ranges) if time_ranges else None
        }
    }


def extract_error_type(log: str) -> str:
    """Extract error type from log line"""
    patterns = [
        r'error[:\s]+([A-Za-z]+Error)',
        r'([A-Za-z]+Exception)',
        r'panic[:\s]+(.+?)(?:\s|$)',
        r'fatal[:\s]+(.+?)(?:\s|$)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, log, re.IGNORECASE)
        if match:
            error_type = match.group(1) if len(match.groups()) > 0 else match.group(0)
            # Clean up
            error_type = error_type.strip().split()[0] if error_type else "UnknownError"
            return error_type[:50]  # Limit length
    
    return "UnknownError"


def summarize_logs_heuristic(logs: List[str], max_output_chars: int = 7000) -> str:
    """
    Strategy 3: Summarize logs using heuristics (no LLM required).
    
    Args:
        logs: List of log lines
        max_output_chars: Maximum output size
    
    Returns:
        Summarized log text
    """
    # Group by error type
    error_groups: Dict[str, List[str]] = {}
    stack_traces = []
    warnings = []
    info_logs = []
    
    for log in logs:
        log_lower = log.lower()
        if 'error' in log_lower or 'exception' in log_lower or 'panic' in log_lower:
            error_type = extract_error_type(log)
            if error_type not in error_groups:
                error_groups[error_type] = []
            error_groups[error_type].append(log[:200])  # Keep snippet
        elif 'stack trace' in log_lower or 'traceback' in log_lower or 'goroutine' in log_lower:
            stack_traces.append(log)
        elif 'warn' in log_lower:
            warnings.append(log[:150])
        else:
            info_logs.append(log[:100])
    
    # Build summary
    summary_parts = []
    
    # Error summary
    if error_groups:
        summary_parts.append(f"## Error Summary ({len(error_groups)} unique error types)")
        for error_type, examples in list(error_groups.items())[:15]:
            count = len(error_groups[error_type])
            summary_parts.append(f"\n### {error_type}: {count} occurrences")
            # Show first 3 examples
            for example in examples[:3]:
                summary_parts.append(f"  - {example}")
    
    # Stack traces (keep full, but limit count)
    if stack_traces:
        summary_parts.append(f"\n## Stack Traces ({len(stack_traces)} total)")
        for i, trace in enumerate(stack_traces[:5]):  # Keep first 5
            summary_parts.append(f"\n### Stack Trace {i+1}")
            summary_parts.append(trace[:800])  # Keep more of stack traces
    
    # Warnings summary
    if warnings:
        summary_parts.append(f"\n## Warnings ({len(warnings)} total)")
        summary_parts.extend(warnings[:30])
    
    # Info logs summary (only if we have space)
    remaining_chars = max_output_chars - sum(len(part) for part in summary_parts)
    if remaining_chars > 500 and info_logs:
        summary_parts.append(f"\n## Info Logs Sample ({len(info_logs)} total, showing sample)")
        summary_parts.extend(info_logs[:20])
    
    summary = "\n".join(summary_parts)
    
    # Truncate if needed
    if len(summary) > max_output_chars:
        summary = summary[:max_output_chars] + "\n\n... (truncated, see full logs for details)"
    
    return summary


# Example integration function
def optimize_logs_for_llm(snippets: List[str], max_snippets: int = 500, max_chars: int = 7000) -> List[str]:
    """
    Combined optimization: Apply multiple strategies.
    
    This is the main function to use - it combines deduplication, prioritization,
    and summarization.
    """
    if not snippets:
        return []
    
    # Step 1: Deduplicate
    deduplicated = deduplicate_logs(snippets)
    print(f"  Deduplication: {len(snippets)} → {len(deduplicated)} logs")
    
    # Step 2: If still too many, prioritize
    if len(deduplicated) > max_snippets:
        # Convert to (timestamp, log) tuples (use index as fake timestamp)
        timestamped = [(str(i), log) for i, log in enumerate(deduplicated)]
        prioritized = prioritize_logs(timestamped, max_snippets)
        print(f"  Prioritization: {len(deduplicated)} → {len(prioritized)} logs")
    else:
        prioritized = deduplicated
    
    # Step 3: If still too large, summarize
    total_chars = sum(len(log) for log in prioritized)
    if total_chars > max_chars:
        summarized_text = summarize_logs_heuristic(prioritized, max_chars)
        print(f"  Summarization: {len(prioritized)} logs ({total_chars} chars) → 1 summary ({len(summarized_text)} chars)")
        return [summarized_text]
    
    return prioritized


if __name__ == "__main__":
    # Example usage
    test_logs = [
        "2025-01-15 10:00:00 [ERROR] Database connection failed: timeout",
        "2025-01-15 10:00:01 [ERROR] Database connection failed: timeout",
        "2025-01-15 10:00:02 [INFO] Processing request 12345",
        "2025-01-15 10:00:03 [WARN] Slow query detected",
        "2025-01-15 10:00:04 [ERROR] Database connection failed: timeout",
    ]
    
    optimized = optimize_logs_for_llm(test_logs, max_snippets=500, max_chars=7000)
    print("\nOptimized logs:")
    for log in optimized:
        print(f"  {log}")


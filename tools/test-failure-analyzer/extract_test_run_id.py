#!/usr/bin/env python3
"""
Extract Test Run ID from workflow logs.

This script parses workflow logs to find the test run ID, which is used for
filtering Loki logs and correlating test failures with service logs.

Patterns supported:
1. Primary: "Test Run ID updated to cluster name: <cluster-name>"
2. Fallback: "Test Run ID: <id>"

Usage:
    python extract_test_run_id.py <log_file_or_stdin> [--output artifacts/test-run-id.txt]
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Optional


def extract_test_run_id(logs_text: str) -> Optional[str]:
    """
    Extract test run ID from workflow logs.
    
    Args:
        logs_text: The full text of workflow logs
        
    Returns:
        Test run ID string if found, None otherwise
        
    Patterns:
        1. "Test Run ID updated to cluster name: <name>" (primary)
        2. "Test Run ID: <id>" (fallback)
    """
    if not logs_text:
        return None
    
    # Pattern 1: "Test Run ID updated to cluster name: <name>"
    # This is the primary pattern - cluster name becomes the test run ID
    pattern1 = re.compile(
        r'Test\s+Run\s+ID\s+updated\s+to\s+cluster\s+name:\s*(\S+)',
        re.IGNORECASE | re.MULTILINE
    )
    match = pattern1.search(logs_text)
    if match:
        test_run_id = match.group(1).strip()
        if test_run_id:
            return test_run_id
    
    # Pattern 2: "Test Run ID: <id>" (fallback)
    pattern2 = re.compile(
        r'Test\s+Run\s+ID\s*:\s*(\S+)',
        re.IGNORECASE | re.MULTILINE
    )
    match = pattern2.search(logs_text)
    if match:
        test_run_id = match.group(1).strip()
        if test_run_id:
            return test_run_id
    
    return None


def main():
    parser = argparse.ArgumentParser(
        description='Extract test run ID from workflow logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Read from file
    python extract_test_run_id.py workflow-logs.txt
    
    # Read from stdin
    cat workflow-logs.txt | python extract_test_run_id.py
    
    # Save to file
    python extract_test_run_id.py workflow-logs.txt --output artifacts/test-run-id.txt
        """
    )
    parser.add_argument(
        'input',
        nargs='?',
        type=argparse.FileType('r'),
        default=sys.stdin,
        help='Input file (default: stdin)'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Output file path (default: print to stdout)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print verbose output'
    )
    
    args = parser.parse_args()
    
    # Read logs
    try:
        logs_text = args.input.read()
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Extract test run ID
    test_run_id = extract_test_run_id(logs_text)
    
    if test_run_id:
        if args.verbose:
            print(f"Found test run ID: {test_run_id}", file=sys.stderr)
        
        # Write output
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(test_run_id + '\n')
            if args.verbose:
                print(f"Saved to: {output_path}", file=sys.stderr)
        else:
            print(test_run_id)
        
        sys.exit(0)
    else:
        if args.verbose:
            print("No test run ID found in logs", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()


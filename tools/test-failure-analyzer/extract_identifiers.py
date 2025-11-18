#!/usr/bin/env python3
"""
Extract both test run ID and workflow commit from a workflow run.

This is a convenience script that combines extract_test_run_id.py and
extract_workflow_commit.py to extract both identifiers in one go.

Usage:
    python extract_identifiers.py --run-url <url> [--logs <log_file>] [--output-dir artifacts/]
"""

import argparse
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description='Extract test run ID and workflow commit from workflow run',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # From workflow run URL
    python extract_identifiers.py --run-url https://github.com/armosec/shared-workflows/actions/runs/123456789
    
    # With logs file
    python extract_identifiers.py --run-url <url> --logs workflow-logs.txt
    
    # Custom output directory
    python extract_identifiers.py --run-url <url> --output-dir artifacts/
        """
    )
    parser.add_argument(
        '--run-url',
        type=str,
        help='GitHub Actions run URL'
    )
    parser.add_argument(
        '--run-id',
        type=str,
        help='GitHub Actions run ID (numeric)'
    )
    parser.add_argument(
        '--repo',
        type=str,
        help='Repository in format owner/repo (required if using --run-id)'
    )
    parser.add_argument(
        '--logs',
        type=str,
        help='Workflow logs file path'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default='artifacts',
        help='Output directory for artifacts (default: artifacts)'
    )
    parser.add_argument(
        '--token',
        type=str,
        help='GitHub token (or use GITHUB_TOKEN env var)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print verbose output'
    )
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    test_run_id_file = output_dir / 'test-run-id.txt'
    workflow_commit_file = output_dir / 'workflow-commit.txt'
    
    success = True
    
    # Extract test run ID from logs
    if args.logs:
        if args.verbose:
            print(f"Extracting test run ID from logs: {args.logs}", file=sys.stderr)
        
        try:
            result = subprocess.run(
                [sys.executable, 'extract_test_run_id.py', args.logs, '--output', str(test_run_id_file)],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                if args.verbose:
                    test_run_id = test_run_id_file.read_text().strip()
                    print(f"✅ Test Run ID: {test_run_id}", file=sys.stderr)
            else:
                print(f"⚠️  Could not extract test run ID: {result.stderr}", file=sys.stderr)
                success = False
        except Exception as e:
            print(f"Error extracting test run ID: {e}", file=sys.stderr)
            success = False
    else:
        if args.verbose:
            print("⚠️  No logs file provided, skipping test run ID extraction", file=sys.stderr)
    
    # Extract workflow commit
    if args.run_url or (args.run_id and args.repo):
        if args.verbose:
            print("Extracting workflow commit...", file=sys.stderr)
        
        cmd = [sys.executable, 'extract_workflow_commit.py', '--output', str(workflow_commit_file)]
        
        if args.run_url:
            cmd.append(args.run_url)
        elif args.run_id:
            cmd.extend(['--run-id', args.run_id])
            if args.repo:
                cmd.extend(['--repo', args.repo])
        
        if args.logs:
            cmd.extend(['--logs', args.logs])
        
        if args.token:
            cmd.extend(['--token', args.token])
        
        if args.verbose:
            cmd.append('--verbose')
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                if args.verbose:
                    commit_sha = workflow_commit_file.read_text().strip()
                    print(f"✅ Workflow Commit: {commit_sha}", file=sys.stderr)
            else:
                print(f"⚠️  Could not extract workflow commit: {result.stderr}", file=sys.stderr)
                success = False
        except Exception as e:
            print(f"Error extracting workflow commit: {e}", file=sys.stderr)
            success = False
    else:
        if args.verbose:
            print("⚠️  No run URL or run-id/repo provided, skipping workflow commit extraction", file=sys.stderr)
    
    # Summary
    if args.verbose:
        print("\n=== Summary ===", file=sys.stderr)
        if test_run_id_file.exists():
            print(f"Test Run ID: {test_run_id_file.read_text().strip()}", file=sys.stderr)
        else:
            print("Test Run ID: Not found", file=sys.stderr)
        
        if workflow_commit_file.exists():
            print(f"Workflow Commit: {workflow_commit_file.read_text().strip()}", file=sys.stderr)
        else:
            print("Workflow Commit: Not found", file=sys.stderr)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()


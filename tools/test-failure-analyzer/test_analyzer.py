#!/usr/bin/env python3
"""Test script for analyzer.py"""
import sys
import os
sys.path.insert(0, '.')

# Force stdout/stderr to be unbuffered
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

print("=" * 60, file=sys.stderr)
print("Testing analyzer.py", file=sys.stderr)
print("=" * 60, file=sys.stderr)

# Test 1: Import check
print("Test 1: Importing modules...", file=sys.stderr)
try:
    import analyzer
    import schemas
    print("✅ All modules imported successfully", file=sys.stderr)
except Exception as e:
    print(f"❌ Import failed: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)

# Test 2: Function existence
print("\nTest 2: Checking functions...", file=sys.stderr)
required_functions = ['parse_args', 'main', 'resolve_run_info', 'load_config']
for func in required_functions:
    if hasattr(analyzer, func):
        print(f"✅ {func} exists", file=sys.stderr)
    else:
        print(f"❌ {func} missing", file=sys.stderr)
        sys.exit(1)

# Test 3: Parse args
print("\nTest 3: Testing parse_args...", file=sys.stderr)
try:
    args = analyzer.parse_args(['--run-id', '12345', '--output-dir', '/tmp/test'])
    print(f"✅ parse_args works: run_id={args.run_id}, output_dir={args.output_dir}", file=sys.stderr)
except Exception as e:
    print(f"❌ parse_args failed: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)

# Test 4: Load config
print("\nTest 4: Testing load_config...", file=sys.stderr)
try:
    cfg = analyzer.load_config('config.yaml')
    print(f"✅ Config loaded: {len(cfg)} top-level keys", file=sys.stderr)
except Exception as e:
    print(f"❌ Config load failed: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)

print("\n✅ All basic tests passed! analyzer.py is ready to use.", file=sys.stderr)


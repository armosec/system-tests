# Fix: Test Run ID Printed Twice for K8s Tests

## Problem

K8s tests were printing the Test Run ID **twice**:

```
INFO  14:16:59 base_test.py:96: Test Run ID: fcebae2d-6614-4988-bb2c-3cccca45c0b7
...
INFO  14:17:00 base_k8s.py:149: Test Run ID: kind-c7cbe6e7-ad2b-4780-8443-347d1fadce79 (from cluster)
```

This was confusing and violated the design principle that:
1. We generate a Test Run ID (UUID)
2. If there's a cluster name, it **overrides** the Test Run ID value
3. We should only print the Test Run ID **once** (with the final value)

## Root Cause

In `tests_scripts/base_test.py`, the `_print_test_run_id_if_needed()` method tried to check if it was a K8s test:

```python
is_k8s_test = hasattr(self, 'kubernetes_obj')  # ← ALWAYS False at __init__ time!
```

**Problem**: The `kubernetes_obj` attribute doesn't exist yet during `BaseTest.__init__()`. It's only created later in `BaseK8S.__init__()` which calls `super().__init__()` first.

**Result**: The check always returned `False`, so it printed for K8s tests, then printed again in `BaseK8S.setup()` with the cluster name.

## The Fix

Changed to use `isinstance()` to check the class hierarchy instead of checking for an attribute:

```python
from tests_scripts.kubernetes.base_k8s import BaseK8S
is_k8s_test = isinstance(self, BaseK8S)
```

This correctly identifies K8s tests even during `__init__()`, so they skip printing and only print once in `setup()` with the cluster name.

## Behavior After Fix

### Non-K8s Tests (no cluster)
```
INFO  base_test.py:97: Test Run ID: fcebae2d-6614-4988-bb2c-3cccca45c0b7
```
✅ Prints once with UUID

### K8s Tests (with cluster)
```
INFO  base_k8s.py:149: Test Run ID: kind-c7cbe6e7-ad2b-4780-8443-347d1fadce79 (from cluster)
```
✅ Prints once with cluster name (the value that matters)

## Analyzer Compatibility

Updated `tools/test-failure-analyzer/analyzer.py` to take the **last** match when extracting test_run_id. This ensures:
- ✅ New logs (single print): Works correctly
- ✅ Old logs (double print): Takes the last (cluster name), not the first (UUID)

```python
matches = re.findall(test_run_id_pattern, text)
if matches:
    # Take the LAST match (handles both single-print and old double-print logs)
    test_run_id = matches[-1].strip()
```

## Files Modified

1. `tests_scripts/base_test.py` - Fixed K8s test detection to use `isinstance()`
2. `tools/test-failure-analyzer/analyzer.py` - Take last match for backward compatibility

## Impact

✅ Cleaner logs - no duplicate Test Run ID prints  
✅ Correct behavior - cluster name used as test_run_id for K8s tests  
✅ Better analysis - analyzer finds correct ID for Loki queries  
✅ Backward compatible - analyzer handles old logs with double prints


# Fix: Analyzer Using Wrong Test Run ID for Loki Queries

## Problem

The failure analyzer was using the **first** Test Run ID printed in logs instead of the **last** one, resulting in 0 Loki results for Kubernetes tests.

### Example from Logs

K8s tests print the test run ID **twice**:

```
INFO  14:16:59 base_test.py:96: Test Run ID: fcebae2d-6614-4988-bb2c-3cccca45c0b7
...
INFO  14:17:00 base_k8s.py:149: Test Run ID: kind-c7cbe6e7-ad2b-4780-8443-347d1fadce79 (from cluster)
```

**Wrong behavior**: Analyzer used `fcebae2d-6614-4988-bb2c-3cccca45c0b7` (UUID)  
**Correct behavior**: Should use `kind-c7cbe6e7-ad2b-4780-8443-347d1fadce79` (cluster name)

## Why This Matters

The backend logs requests using the **cluster name**, not the UUID:
- ✅ Backend logs: `cluster=kind-c7cbe6e7-ad2b-4780-8443-347d1fadce79`
- ❌ Analyzer queries: `fcebae2d-6614-4988-bb2c-3cccca45c0b7`

**Result**: Loki query finds 0 matching logs, making root cause analysis impossible.

## Root Cause

In `tools/test-failure-analyzer/analyzer.py` line 601:

```python
m = re.search(test_run_id_pattern, text)  # Takes FIRST match
```

`re.search()` returns the **first** match it finds, which is the UUID printed by `base_test.py`.

## The Fix

Changed to use `re.findall()` and take the **last** match:

```python
matches = re.findall(test_run_id_pattern, text)
if matches:
    # Take the LAST match (K8s tests override with cluster name in base_k8s.py setup)
    test_run_id = matches[-1].strip()
```

### Why the Last Match?

For K8s tests, the execution flow is:

1. **`base_test.py.__init__`** (line 96-98):
   - Generates UUID: `fcebae2d-6614-4988-bb2c-3cccca45c0b7`
   - Prints first Test Run ID
   - Sets `backend.test_run_id = uuid`

2. **`base_k8s.py.setup()`** (line 138-152):
   - Gets cluster name: `kind-c7cbe6e7-ad2b-4780-8443-347d1fadce79`
   - **Overrides**: `backend.set_test_run_id(cluster_name)`
   - Prints second Test Run ID with "(from cluster)"

The **last** printed ID is the one actually used by the backend for all API calls.

## Impact

### Before Fix
```
Query: {namespace="event-sourcing-be-stage"} |= "fcebae2d-6614-4988-bb2c-3cccca45c0b7"
Results: 0 lines ❌
```

### After Fix
```
Query: {namespace="event-sourcing-be-stage"} |= "kind-c7cbe6e7-ad2b-4780-8443-347d1fadce79"
Results: Expected to return backend logs for this test ✅
```

## Testing

To verify the fix works:

1. Run a K8s system test that fails
2. Trigger the analyzer on that failure
3. Check the Loki query in `artifacts/report.json`
4. Verify it uses the cluster name, not the UUID
5. Confirm Loki returns log entries

## Files Modified

- `tools/test-failure-analyzer/analyzer.py` - Lines 596-607

## Related Issues

This fix addresses one of the reasons why Loki queries were returning 0 results. There may be other issues:

- Loki endpoint configuration (404 on primary endpoint)
- Namespace label matching
- Log retention/indexing delays

But this was a definite bug that would prevent **all** K8s test analysis from working.


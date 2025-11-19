# Backend Stress Test - Direct HTTP Alert Simulation

## Overview

The **Backend Stress Test** sends runtime alerts directly to the Kubescape synchronizer via HTTP, bypassing the node-agent. This tests the backend's alert processing capacity without executing commands in Kubernetes pods.

## Infrastructure Flow

```
Test Script (Python)
    │
    │ HTTP POST (via port-forward)
    ▼
Synchronizer (in-cluster)
    │
    │ Forward alerts
    ▼
Backend API (cloud)
```

### What Happens

1. **Helm Installation**: Installs Kubescape with runtime detection capabilities
2. **Workload Deployment**: Deploys test workloads to generate application profiles
3. **Port-Forward Setup**: Automatically establishes port-forward to synchronizer (if using localhost)
4. **Alert Generation**: Sends HTTP POST requests with alert payloads at configured rates
5. **Cleanup**: Stops threads and tears down port-forward

## Configuration

Configure in `configurations/system/tests_cases/runtime_tests.py`:

```python
@staticmethod
def backend_stress_test():
    from tests_scripts.runtime.stress.stress_backend_only import BackendStressTest
    return TestConfiguration(
        name=inspect.currentframe().f_code.co_name,
        test_obj=BackendStressTest,
        backend_stress_config={
            "duration_minutes": 10,
            "synchronizer_url": "http://localhost:8089/apis/v1/kubescape.io",
            "cluster_name": "stress-test-cluster",
            "namespace": "stress-test-namespace",
            "alert_profiles": [
                {
                    "name": "unexpected_syscall",
                    "rate_per_minute": 500,      # Per worker
                    "worker_count": 2,           # Parallel workers
                    "alert_name": "Unexpected system call",
                    "rule_id": "R0003",
                    "severity": 1,
                    "syscall": "sched_yield"
                }
            ]
        }
    )
```

### Key Parameters

| Parameter | Description |
|-----------|-------------|
| `duration_minutes` | Test duration in minutes |
| `synchronizer_url` | Synchronizer endpoint (auto port-forwards if localhost) |
| `rate_per_minute` | Alerts per minute **per worker** |
| `worker_count` | Number of parallel worker threads |

**Rate Calculation**: `Total alerts/min = rate_per_minute × worker_count` (summed across all profiles)

## Usage

### Prerequisites

- Kubernetes cluster with `kubectl` configured
- Python 3.x with dependencies
- Backend credentials (set via environment variables or config)
- Helm 3.x installed

### Running the Test

```bash
python systest-cli.py -t backend_stress_test -b <backend> --logger DEBUG
```

Replace `<backend>` with your target backend environment (e.g., `development`, `production`, `staging`).

### Environment Variables

Set backend credentials via environment variables:

```bash
export CUSTOMER="YourCustomerName"
export USERNAME="your-email@example.com"
export PASSWORD="your-password"
export CLIENT_ID="your-client-id"
export SECRET_KEY="your-secret-key"
```

Or configure in `launch.json` for VS Code debugging.

## Performance Guidelines

### Recommended Rates

- **Sustainable**: ~3,000 alerts/min total (~50 alerts/sec)
- **Per Profile**: 400-600 alerts/min with 2 workers
- **Maximum**: ~75 alerts/sec initial burst, ~50 alerts/sec sustained

### Example Configuration

```python
"alert_profiles": [
    {"name": "profile_1", "rate_per_minute": 500, "worker_count": 2},  # 1,000/min
    {"name": "profile_2", "rate_per_minute": 400, "worker_count": 2},  # 800/min
    {"name": "profile_3", "rate_per_minute": 600, "worker_count": 2}   # 1,200/min
]
# Total: 3,000 alerts/min = ~50 alerts/sec
```

### What Happens if Rates Are Too High?

- Timeouts (30-second timeout per request)
- Failed alerts increase
- Throughput drops below target
- Workers block waiting for timeouts

**Solution**: Reduce `rate_per_minute` and `worker_count` values.

## Output

### Progress Updates (every 30 seconds)

```
INFO Progress: 30s elapsed, 570s remaining | Alerts: 1500 sent, 0 failed | Rate: 50.0/s
```

### Final Results

```
================================================================================
BACKEND STRESS TEST RESULTS
================================================================================
Duration: 600.0 seconds
Alerts sent: 30000
Alerts failed: 0
Success rate: 100.0%
Average rate: 50.0 alerts/second
Expected alerts: 30000
Actual alerts: 30000 (100.0% of expected)
================================================================================
```

## Limitations

1. **Port-Forward Bottleneck**: Single TCP connection, no connection pooling
2. **Synchronizer Capacity**: ~50-100 alerts/second maximum sustainable throughput
3. **Sequential Processing**: Workers wait for response before next alert
4. **No Batching**: One alert per HTTP request (node-agent may batch)

## Troubleshooting

### Connection Refused

- Check synchronizer pod: `kubectl get pods -n kubescape | grep synchronizer`
- Verify port-forward: `kubectl port-forward -n kubescape svc/synchronizer 8089:8089`
- Confirm synchronizer URL in config

### Many Timeouts

- Reduce `rate_per_minute` values
- Reduce `worker_count` values
- Target total rate ≤ 3,000 alerts/min

### 400 Bad Request

- Verify URL includes `/v1/runtimealerts` endpoint
- Check payload structure matches node-agent format
- Review synchronizer logs for validation errors

## Comparison with RuntimeStressTest

| Feature | RuntimeStressTest | BackendStressTest |
|---------|-------------------|-------------------|
| **Method** | `kubectl exec` into pods | Direct HTTP POST |
| **Alert Source** | Real commands trigger node-agent | Simulated payloads |
| **Rate Control** | Limited by command execution | Full HTTP control |
| **Use Case** | Test full pipeline | Test backend processing only |

---

**Test File**: `tests_scripts/runtime/stress/stress_backend_only.py`  
**Configuration**: `configurations/system/tests_cases/runtime_tests.py`

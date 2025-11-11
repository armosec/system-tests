# Runtime Stress Test - User Guide

The Runtime Stress Test simulates real-world load on the ARMO Runtime Detection system by creating multiple namespaces and generating a configurable mix of security alerts and benign activity. It helps you verify that the backend can handle high volumes of runtime alerts without dropping data or degrading performance.

**Key Point**: This test creates **multiple namespaces within a single tenant/cluster**. All namespaces share the same Kubescape installation and customer account.

## Quick Start

### 1. Prerequisites

- Kubernetes cluster (minikube, colima, EKS, GKE, etc.)
- Backend API access configured
- Python environment with test dependencies installed

### 2. Basic Configuration

Edit `configurations/system/tests_cases/runtime_tests.py`:

```python
stress_config={
    "namespace_count": 3,        # How many namespaces to create
    "duration_minutes": 5,       # How long to run the test
    "pods_per_namespace": 1,     # Pods per namespace (3 total in this example)
    "alert_profiles": [          # What activities to generate
        {
            "name": "malware_detection",
            "rate_per_minute": 5,
            "is_trigger": True,  # Should create incidents
            "worker_count": 1,
            "command": "more /root/malware.o"
        },
        {
            "name": "benign_dns_lookup",
            "rate_per_minute": 50,
            "is_trigger": False,  # Benign activity, no incidents
            "worker_count": 1,
            "command": 'nslookup $(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1).nip.io || true',
            "use_shell": True
        }
    ]
}
```

### 3. Run the Test

```bash
python test_driver.py -t runtime_stress_test -b
```

### 4. Monitor Results

While the test runs, check the backend dashboards:
- **Telematics Dashboard**: View alert ingestion rates and processing latency
- **Backlog Dashboard**: Monitor incident creation and handling

## What Happens During the Test

```
1. Setup Phase (1-2 min)
   └─ Installs Kubescape with runtime detection enabled

2. Deploy Phase (1-2 min)
   └─ Creates 3 namespaces (systest-ns-xxx1, systest-ns-xxx2, systest-ns-xxx3)
   └─ Deploys 1 pod in each namespace (3 pods total)

3. Learning Phase (2-3 min)
   └─ Waits for application profiles to complete

4. Stress Test Phase (5 min - configured duration)
   └─ Generates 5 malware alerts per minute (15 total across 3 pods)
   └─ Generates 50 DNS lookups per minute (150 total across 3 pods)
   └─ All 3 pods generate alerts simultaneously

5. Verification Phase (1 min)
   └─ Confirms runtime detection system is still operational
```

## Configuration Parameters

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `namespace_count` | Number of namespaces to create | `5` |
| `duration_minutes` | How long to run the stress test | `10` |
| `alert_profiles` | List of activities to generate | See below |

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `ramp_up_seconds` | `60` | Time to gradually increase load |
| `pods_per_namespace` | `1` | Pods to create in each namespace |

### Alert Profiles

Each alert profile defines an activity to simulate:

```python
{
    "name": "unique_identifier",         # Give it a descriptive name
    "rate_per_minute": 10,              # How often to run it (per pod)
    "is_trigger": True,                 # True = should alert, False = benign
    "command": "cat /etc/hosts",        # Command to execute in pod
    "use_shell": False,                 # True if command has shell syntax
    "description": "What this does"     # Human-readable description
}
```

**Important**: If your command contains shell syntax like `$()`, `|`, `||`, set `use_shell: True`.

## Pre-Built Alert Profiles

### Trigger Alerts (Create Incidents)

**1. Malware Detection**
```python
{
    "name": "malware_detection",
    "rate_per_minute": 5,
    "is_trigger": True,
    "command": "more /root/malware.o",
    "description": "Trigger malware detection alert"
}
```

**2. Unexpected Process**
```python
{
    "name": "unexpected_process",
    "rate_per_minute": 10,
    "is_trigger": True,
    "command": "cat /etc/hosts",
    "description": "Trigger unexpected process alert"
}
```

### Non-Trigger Alerts (Benign Activity)

**3. Random DNS Lookups**
```python
{
    "name": "benign_dns_lookup",
    "rate_per_minute": 50,
    "is_trigger": False,
    "command": 'nslookup $(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1).nip.io || true',
    "use_shell": True,
    "description": "Non-trigger DNS lookup to random subdomain"
}
```
- Generates unique random subdomains each time
- Won't trigger malicious domain alerts
- Creates network activity for load testing

**4. Random HTTP Requests**
```python
{
    "name": "benign_network_activity",
    "rate_per_minute": 30,
    "is_trigger": False,
    "command": 'wget --timeout=2 -q -O- $(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1).nip.io || true',
    "use_shell": True,
    "description": "Non-trigger network activity"
}
```

## Example Configurations

### Light Load (Good for First Run)

```python
stress_config={
    "namespace_count": 1,
    "duration_minutes": 5,
    "pods_per_namespace": 1,
    "alert_profiles": [
        {
            "name": "malware_detection",
            "rate_per_minute": 5,
            "is_trigger": True,
            "command": "more /root/malware.o"
        },
        {
            "name": "benign_dns_lookup",
            "rate_per_minute": 20,
            "is_trigger": False,
            "command": 'nslookup $(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1).nip.io || true',
            "use_shell": True
        }
    ]
}
```
**Expected Load**: ~25 alerts/minute from 1 pod

### Medium Load (Realistic Scenario)

```python
stress_config={
    "namespace_count": 5,
    "duration_minutes": 10,
    "pods_per_namespace": 2,
    "alert_profiles": [
        {
            "name": "malware_detection",
            "rate_per_minute": 5,
            "is_trigger": True,
            "command": "more /root/malware.o"
        },
        {
            "name": "unexpected_process",
            "rate_per_minute": 10,
            "is_trigger": True,
            "command": "cat /etc/hosts"
        },
        {
            "name": "benign_dns_lookup",
            "rate_per_minute": 50,
            "is_trigger": False,
            "command": 'nslookup $(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1).nip.io || true',
            "use_shell": True
        }
    ]
}
```
**Expected Load**: ~650 alerts/minute from 10 pods (5 namespaces × 2 pods)

### Heavy Load (Stress Testing)

```python
stress_config={
    "namespace_count": 10,
    "duration_minutes": 30,
    "pods_per_namespace": 2,
    "alert_profiles": [
        {
            "name": "high_trigger_rate",
            "rate_per_minute": 20,
            "is_trigger": True,
            "command": "cat /etc/hosts"
        },
        {
            "name": "very_high_benign_rate",
            "rate_per_minute": 200,
            "is_trigger": False,
            "command": 'nslookup $(cat /proc/sys/kernel/random/uuid | cut -d"-" -f1).nip.io || true',
            "use_shell": True
        }
    ]
}
```
**Expected Load**: ~4,400 alerts/minute from 20 pods (10 namespaces × 2 pods)

## Understanding Test Output

### During Execution

```
INFO     11:17:22 stress_test.py: STRESS TEST EXECUTION - Starting load generation
INFO     11:17:22 stress_test.py: Started alert generation thread: malware_detection
INFO     11:17:22 stress_test.py: Started alert generation thread: benign_dns_lookup
INFO     11:17:52 stress_test.py: Stress test progress: 30s elapsed, 270s remaining | Commands: 33 success, 0 failed
INFO     11:18:22 stress_test.py: Stress test progress: 60s elapsed, 240s remaining | Commands: 68 success, 0 failed
```

### After Completion

```
================================================================================
RUNTIME STRESS TEST - Completed Successfully
Duration: 300s
Commands executed: 945
Success rate: 99.47%
Check backend dashboards for detailed metrics:
  - Telematics: Alert ingestion and processing
  - Backlog: Incident creation and handling
================================================================================
```

## Interpreting Results

### ✅ Healthy System

Check the **backend dashboards** after the test:

**Telematics Dashboard:**
- Alert ingestion rate matches your configuration (e.g., ~95 alerts/min)
- Processing latency stays consistent throughout the test
- No dropped alerts

**Backlog Dashboard:**
- Incidents created for trigger alerts (malware, unexpected process)
- No incidents created for benign alerts (DNS lookups, wget requests)
- Backend remains responsive

**Test Output:**
- Success rate > 95%
- All threads completed
- No crashes or errors

### ⚠️ Issues to Investigate

**Low Success Rate (< 90%)**
- Check pod health: `kubectl get pods -n systest-ns-*`
- Check cluster resources: `kubectl top nodes`
- Review pod logs for errors

**No Incidents Created**
- Verify application profiles were created
- Check runtime detection is enabled in helm config
- Wait longer for learning period to complete

**Backend Errors**
- Check Telematics for error rates
- Review backend logs
- Reduce load and retry


## Best Practices

1. **Start Small**: Begin with 1 namespace, 5 minutes
2. **Watch Resources**: Monitor cluster CPU/memory usage
3. **Increase Gradually**: Double load each run to find limits
4. **Use Backend Dashboards**: They have all the detailed metrics
5. **Clean Between Runs**: Delete test namespaces before rerunning
6. **Document Baselines**: Record results for future comparison

## Summary

The Runtime Stress Test helps you validate that your runtime detection system can handle real-world load. Configure the number of namespaces, test duration, and types of activities to simulate, then monitor the backend dashboards to see how the system performs under stress.

**Remember**: All detailed metrics (latency, throughput, incident rates) come from the backend dashboards. The test itself just generates the load and reports basic execution stats.

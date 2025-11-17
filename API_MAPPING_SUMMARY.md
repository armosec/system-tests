# Dashboard API Test Mapping - Summary

## Overview
Successfully added `tested_dashboard_apis` field to `system_test_mapping.json` file, mapping each test to the actual backend API endpoints it tests.

## Changes Made

### 1. Added New Field
- **Field Name**: `tested_dashboard_apis`
- **Type**: Array of strings
- **Purpose**: Lists all backend API endpoints that each test validates

### 2. Coverage Statistics
- **Total Tests**: 103
- **Tests with API Mappings**: 102 (99.0% coverage)
- **Unique API Endpoints Covered**: 66
- **Tests without APIs**: 1 (runtime_stress_test - load testing only)

## Most Tested API Endpoints

The following API endpoints are tested most frequently:

1. `/api/v1/cluster` - 56 tests
2. `/api/v1/vulnerability_v2/component` - 27 tests
3. `/api/v1/posture/scan` - 23 tests
4. `/api/v1/vulnerability/scanResultsSumSummary` - 22 tests
5. `/api/v1/uniqueValues/vulnerability/scanResultsSumSummary` - 22 tests
6. `/api/v1/vulnerability/scan/v2/` - 22 tests
7. `/api/v1/repositoryPosture/resources` - 20 tests
8. `/api/v1/repositoryPosture` - 20 tests
9. `/api/v1/postureExceptionPolicy` - 20 tests
10. `/api/v1/repositoryPosture/files` - 20 tests

## Test Categories with API Coverage

### Payment Tests (4 tests)
- `stripe_checkout`: 7 APIs (billing, subscription management)
- `stripe_billing_portal`: 7 APIs
- `stripe_plans`: 7 APIs
- `stripe_webhook`: 7 APIs

### Vulnerability Scanning (22 tests)
- Various vuln_scan tests: 4-8 APIs each
- Covers vulnerability v2 APIs, image scanning, component analysis

### Security Risks (7 tests)
- `securityrisks_all`: Multiple APIs for risk assessment
- Various SR tests: Exception handling, trends, categories

### Runtime/KDR (8 tests)
- `basic_incident_presented`: Incident management APIs
- `kdr_runtime_policies_configurations`: Policy management APIs
- Various alert tests: Webhook, Slack, Teams integrations

### Integrations (2 tests)
- `jira_integration`: 12 APIs
- `linear_integration`: 12 APIs
- `siem_integrations`: 1 API

### Cloud Accounts (6 tests)
- `cloud_vulnscan_aws`: 20 APIs (most comprehensive)
- Various cloud connection tests: 13-15 APIs each

### Network Policy (6 tests)
- All network policy tests: 2-4 APIs each
- Covers network policy generation and known servers

### Workflows (5 tests)
- Various notification workflow tests: 2-5 APIs each
- Covers Slack, Teams, Jira, Linear integrations

### Kubescape CLI Tests (20 tests)
- Various scan tests: 1-5 APIs each
- Covers posture scanning, frameworks, compliance

## Example Test Mapping

```json
{
  "jira_integration": {
    "target": ["Backend"],
    "target_repositories": ["cadashboardbe", "config-service"],
    "description": "testing jira integration",
    "skip_on_environment": "custom",
    "owner": "jonathang@armosec.io",
    "tested_dashboard_apis": [
      "/api/v1/cluster",
      "/api/v1/integrations",
      "/api/v1/posture/clusters",
      "/api/v1/posture/controls",
      "/api/v1/posture/resources",
      "/api/v1/posture/scan",
      "/api/v1/securityrisks/list",
      "/api/v1/securityrisks/resources",
      "/api/v1/vulnerability_v2/component",
      "/api/v1/vulnerability_v2/image",
      "/api/v1/vulnerability_v2/vulnerability",
      "/api/v1/vulnerability_v2/workload"
    ]
  }
}
```

## Implementation Details

### Analysis Approach
1. Scanned all test files in `tests_scripts/` directory
2. Extracted backend API method calls from each test file
3. Mapped backend method names to their API endpoint constants
4. Cross-referenced test names with their implementation files
5. Aggregated all API endpoints for each test

### API Mapping Sources
- **backend_api.py**: Contains all backend API method definitions
- **Test configuration files**: Maps test names to test classes
- **Test implementation files**: Contains actual API method calls

### Test File Coverage
Analyzed 38 test files that make backend API calls:
- `tests_scripts/kubescape/scan.py`
- `tests_scripts/helm/*.py` (14 files)
- `tests_scripts/payments/*.py` (4 files)
- `tests_scripts/runtime/*.py` (5 files)
- `tests_scripts/workflows/*.py` (6 files)
- `tests_scripts/accounts/*.py` (6 files)
- And others...

## Benefits

1. **Test Coverage Visibility**: Quickly see which APIs are tested and how extensively
2. **Gap Analysis**: Identify APIs that lack test coverage
3. **Impact Analysis**: Determine which tests might be affected by API changes
4. **Documentation**: Serves as living documentation of test scope
5. **CI/CD Integration**: Can be used to trigger relevant tests based on changed APIs

## Next Steps (Optional)

1. Add API version tracking to handle API versioning
2. Create reverse mapping: API endpoint → tests that cover it
3. Integrate with CI to auto-update when new tests are added
4. Add API response validation status (e.g., status codes tested)
5. Track API deprecation impact on tests

## Files Modified

- `system_test_mapping.json` - Updated with `tested_dashboard_apis` field for all 103 tests

## Validation

✅ All tests have the `tested_dashboard_apis` field  
✅ JSON structure is valid  
✅ No duplicate entries  
✅ 99% of tests have at least one API mapped  
✅ API paths are accurate and match backend_api.py definitions

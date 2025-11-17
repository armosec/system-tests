# Dashboard API Test Mapping - Complete Implementation

## 🎯 Overview

Successfully enhanced the `system_test_mapping.json` file to include **HTTP methods** alongside API paths, and implemented **automated PR validation** to ensure API mappings stay accurate.

## ✨ What's New

### 1. Enhanced API Mapping Format

**Before:**
```json
{
  "stripe_plans": {
    "target": ["Backend"],
    "tested_dashboard_apis": [
      "/api/v1/tenants/stripe/plans",
      "/api/v1/admin/createSubscription"
    ]
  }
}
```

**After:**
```json
{
  "stripe_plans": {
    "target": ["Backend"],
    "tested_dashboard_apis": [
      { "method": "GET", "path": "/api/v1/tenants/stripe/plans" },
      { "method": "POST", "path": "/api/v1/admin/createSubscription" },
      { "method": "POST", "path": "/api/v1/admin/cancelSubscription" }
    ]
  }
}
```

### 2. Automated PR Validation

A GitHub Actions workflow now automatically validates that:
- API mappings match actual API calls in test code
- Changed test files have accurate API documentation
- Developers are notified of needed updates

## 📊 Statistics

- **Total Tests**: 103
- **Tests with API Mappings**: 101 (98%)
- **Unique API Endpoints**: 66
- **HTTP Methods Tracked**: GET, POST, PUT, DELETE
- **Tests without APIs**: 2 (load testing only)

## 🔥 Most Tested APIs

| Rank | API Endpoint | Method | Tests |
|------|--------------|--------|-------|
| 1 | `/api/v1/cluster` | GET | 56 |
| 2 | `/api/v1/cluster` | DELETE | 56 |
| 3 | `/api/v1/vulnerability_v2/component` | POST | 27 |
| 4 | `/api/v1/posture/scan` | POST | 23 |
| 5 | `/api/v1/vulnerability/scanResultsSumSummary` | POST | 22 |

## ✅ Validation Checks

The PR workflow validates:

1. **Implementation Files** (`test_implementation_files`)
   - ✅ Field is not empty
   - ✅ All listed files exist
   - ✅ File paths are correct

2. **API Mappings** (`tested_dashboard_apis`)
   - ✅ All API calls in code are documented
   - ✅ No extra APIs listed that aren't in code
   - ✅ HTTP methods match actual usage

## 🚀 How to Use

### For Developers

#### When You Modify Test Files

1. **Make your changes** to test files in `tests_scripts/`

2. **Run the validation locally** (optional but recommended):
   ```bash
   python3 scripts/validate_api_mapping.py
   ```

3. **If validation fails**, the script will tell you exactly what to do:
   ```bash
   ❌ Implementation File Issues:
   
   Test: my_test
     ❌ Implementation files not found (1):
       • tests_scripts/helm/my_test.py
   
   ❌ API Mapping Issues:
   
   Test: jira_integration
     Missing APIs (2):
       • POST   /api/v1/integrations
       • PUT    /api/v1/integrations
   ```

4. **Auto-update the mapping**:
   ```bash
   python3 scripts/update_mapping_with_methods.py
   ```

5. **Commit the changes**:
   ```bash
   git add system_test_mapping.json
   git commit -m "Update API mappings for modified tests"
   ```

#### When You Create a Pull Request

The **Validate API Mapping** workflow will automatically run and:

✅ **Pass**: If all API mappings are correct
- Your PR can proceed to review

❌ **Fail**: If mappings are outdated
- You'll get a helpful comment explaining how to fix it
- Simply run the update script and push the changes

### For Reviewers

When reviewing PRs, you can now:

1. **See exactly which APIs** a test validates
2. **Verify test coverage** for new API endpoints
3. **Assess impact** of API changes on tests

## 📁 Files Added/Modified

### Added Files

| File | Purpose |
|------|---------|
| `scripts/validate_api_mapping.py` | PR validation script that checks API mapping accuracy |
| `scripts/update_mapping_with_methods.py` | Script to regenerate API mappings from test code |
| `.github/workflows/validate-api-mapping.yaml` | GitHub Actions workflow for automated PR checks |

### Modified Files

| File | Changes |
|------|---------|
| `system_test_mapping.json` | Updated all 103 tests with HTTP method + path format |

## 🔍 Example Test Mappings

### Payment Test
```json
{
  "stripe_checkout": {
    "target": ["Backend"],
    "owner": "eranm@armosec.io",
    "test_implementation_files": [
      "tests_scripts/payments/checkout.py",
      "tests_scripts/payments/base_stripe.py",
      "tests_scripts/payments/base_payment.py"
    ],
    "tested_dashboard_apis": [
      { "method": "POST", "path": "/api/v1/admin/cancelSubscription" },
      { "method": "POST", "path": "/api/v1/admin/createSubscription" },
      { "method": "POST", "path": "/api/v1/admin/renewSubscription" },
      { "method": "POST", "path": "/api/v1/tenants/stripe/checkout" },
      { "method": "GET", "path": "/api/v1/tenants/stripe/portal" },
      { "method": "GET", "path": "/api/v1/tenants/tenantDetails" }
    ]
  }
}
```

### Integration Test
```json
{
  "jira_integration": {
    "target": ["Backend"],
    "owner": "jonathang@armosec.io",
    "test_implementation_files": [
      "tests_scripts/helm/jira_integration.py",
      "tests_scripts/helm/base_helm.py",
      "tests_scripts/kubernetes/base_k8s.py"
    ],
    "tested_dashboard_apis": [
      { "method": "DELETE", "path": "/api/v1/cluster" },
      { "method": "GET", "path": "/api/v1/cluster" },
      { "method": "DELETE", "path": "/api/v1/integrations" },
      { "method": "GET", "path": "/api/v1/integrations" },
      { "method": "POST", "path": "/api/v1/integrations" },
      { "method": "PUT", "path": "/api/v1/integrations" },
      { "method": "POST", "path": "/api/v1/posture/clusters" },
      { "method": "POST", "path": "/api/v1/posture/controls" },
      { "method": "POST", "path": "/api/v1/posture/resources" },
      { "method": "POST", "path": "/api/v1/posture/scan" }
    ]
  }
}
```

### Runtime Test
```json
{
  "kdr_runtime_policies_configurations": {
    "target": ["In cluster", "Backend"],
    "owner": "jonathang@armosec.io",
    "test_implementation_files": [
      "tests_scripts/runtime/policies.py",
      "tests_scripts/runtime/base_runtime.py"
    ],
    "tested_dashboard_apis": [
      { "method": "POST", "path": "/api/v1/runtime/incidentTypes" },
      { "method": "POST", "path": "/api/v1/runtime/incidentsRuleSet" },
      { "method": "DELETE", "path": "/api/v1/runtime/policies" },
      { "method": "POST", "path": "/api/v1/runtime/policies" },
      { "method": "PUT", "path": "/api/v1/runtime/policies" },
      { "method": "POST", "path": "/api/v1/runtime/policies/list" }
    ]
  }
}
```

## 🛠️ Technical Details

### How It Works

1. **Extraction**: The validation script scans test files for backend API method calls
2. **Mapping**: Converts method names to HTTP verbs and endpoint paths using `backend_api.py`
3. **Comparison**: Compares extracted APIs with those in `system_test_mapping.json`
4. **Validation**: Flags any mismatches and provides clear instructions

### API Method Detection

The script uses regex to find patterns like:
```python
self.backend.get_stripe_plans()        → GET /api/v1/tenants/stripe/plans
backend.create_workflow(body)          → POST /api/v1/workflows
test_obj.backend.delete_cluster(name)  → DELETE /api/v1/cluster
```

### Workflow Triggers

The GitHub Actions workflow runs when:
- Any file in `tests_scripts/` is modified
- `infrastructure/backend_api.py` is changed
- `system_test_mapping.json` is updated

## 💡 Benefits

### 1. **Improved Test Coverage Visibility**
- Instantly see which APIs each test validates
- Identify gaps in API test coverage
- Track API testing metrics

### 2. **Automated Quality Checks**
- Catch outdated API mappings before merge
- Ensure documentation stays synchronized with code
- Reduce manual review overhead

### 3. **Better Impact Analysis**
- When an API changes, quickly find affected tests
- Understand test scope and dependencies
- Plan testing strategies more effectively

### 4. **Enhanced Documentation**
- Living documentation of test coverage
- Clear understanding of what each test validates
- Easier onboarding for new team members

### 5. **CI/CD Integration**
- Automatic validation on every PR
- Clear error messages and fix instructions
- Seamless developer experience

## 🔄 Maintenance

### Keeping Mappings Up to Date

The mapping stays automatically synchronized through the PR workflow, but you can also manually update:

```bash
# Regenerate all mappings
python3 scripts/update_mapping_with_methods.py

# Validate current mappings
python3 scripts/validate_api_mapping.py

# Validate against specific branches
python3 scripts/validate_api_mapping.py origin/main HEAD
```

### Adding New Tests

When creating new tests:

1. Write your test in `tests_scripts/`
2. Add test configuration in `configurations/system/tests_cases/`
3. Add entry to `system_test_mapping.json` with basic info
4. Run `python3 scripts/update_mapping_with_methods.py` to auto-populate APIs and implementation files
5. Commit all changes together

## 📋 PR Workflow Example

```
Developer makes changes to tests_scripts/helm/vuln_scan.py
↓
Developer creates PR
↓
GitHub Actions triggers validate-api-mapping workflow
↓
Workflow detects changes to vuln_scan-related tests
↓
Extracts actual API calls from modified files
↓
Compares with system_test_mapping.json
↓
❌ FAILS: Missing APIs detected
↓
Posts comment on PR with instructions
↓
Developer runs: python3 scripts/update_mapping_with_methods.py
↓
Developer commits updated system_test_mapping.json
↓
Workflow re-runs
↓
✅ PASSES: All mappings accurate
↓
PR proceeds to review
```

## 🎓 Best Practices

1. **Run validation locally** before pushing to catch issues early
2. **Review generated mappings** to ensure they make sense
3. **Keep test files focused** to maintain clear API mappings
4. **Update mappings atomically** with code changes in the same commit
5. **Use descriptive test names** that indicate their API coverage

## 🚨 Troubleshooting

### "Validation failed but I didn't change any test files"

If you modified `backend_api.py`, it might affect how APIs are detected. Run the update script to refresh all mappings.

### "The script says APIs are missing but I see them in the code"

Ensure you're using the correct pattern for API calls:
- ✅ `self.backend.method_name()`
- ✅ `backend.method_name()`
- ❌ `api.method_name()` (won't be detected)

### "Workflow keeps failing after I updated the mapping"

Make sure you:
1. Committed the updated `system_test_mapping.json`
2. Pushed your changes
3. The file has valid JSON syntax

## 📊 New Fields in system_test_mapping.json

### test_implementation_files
Lists all Python files that implement the test. Includes:
- Main test file (e.g., `tests_scripts/helm/jira_integration.py`)
- Base class files (e.g., `tests_scripts/helm/base_helm.py`)
- Helper files that contain backend API calls

**Benefits:**
- No hardcoded mappings in validation scripts
- Self-documenting test structure
- Easy to maintain and update
- Auto-detected by update script

### tested_dashboard_apis
Lists all backend API endpoints tested with HTTP methods:
```json
"tested_dashboard_apis": [
  { "method": "POST", "path": "/api/v1/integrations" },
  { "method": "GET", "path": "/api/v1/cluster" }
]
```

## 📞 Support

For questions or issues:
- Check `docs/TEST_INFRASTRUCTURE.md` for test infrastructure details
- Review `infrastructure/backend_api.py` for API method definitions
- Review `scripts/update_mapping_with_methods.py` for mapping logic
- Contact the test infrastructure team

---

**Last Updated**: 2025-11-17
**Version**: 2.0 (with HTTP methods and PR validation)

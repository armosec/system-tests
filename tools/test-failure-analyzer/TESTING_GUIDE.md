# Test Failure Analyzer - Testing Guide

## 1. Files to Push (Git Status)

### System-Tests Repository

**New files to add (core functionality):**
```bash
cd /Users/eranmadar/repos/system-tests

# Core Phase 7 script (FIXED and working)
git add tools/test-failure-analyzer/build_llm_context.py

# Supporting scripts (if not already in repo)
git add tools/test-failure-analyzer/map_apis_to_code.py
git add tools/test-failure-analyzer/map_apis_with_call_chains.py
git add tools/test-failure-analyzer/extract_call_chain.py
git add tools/test-failure-analyzer/map_tag_to_commit.py
git add tools/test-failure-analyzer/resolve_repo_commits.py
git add tools/test-failure-analyzer/filter_by_errors.py
git add tools/test-failure-analyzer/trace_http_calls.py
git add tools/test-failure-analyzer/trace_pulsar_topics.py

# Configuration
git add tools/test-failure-analyzer/config.yaml
git add tools/test-failure-analyzer/index-registry.json
```

**Modified files:**
```bash
git add tools/test-failure-analyzer/load_multi_repo_indexes.py
```

**Documentation (optional but recommended):**
```bash
git add tools/test-failure-analyzer/PHASE7_COMPLETE.md
git add tools/test-failure-analyzer/SOLUTION.md
git add tools/test-failure-analyzer/SUMMARY.md
```

**DO NOT add:**
- `artifacts/` - These are test outputs
- `CLEANUP_LOG.md`, `TEST_PHASE7_FINAL.md` - Debug documentation
- `test_output.log` - Debug logs

### Cadashboardbe Repository

**Check if code index is generated:**
```bash
cd /Users/eranmadar/repos/cadashboardbe
git status

# If docs/indexes/code-index.json is modified, add it:
git add docs/indexes/code-index.json
```

**Important:** Make sure the code indexing CI/CD workflow is set up and running.

---

## 2. What You Need to Provide

### Required Information:
1. **Workflow Run URL** - Link to a failed test workflow
   - Example: `https://github.com/armosec/system-tests/actions/runs/12345678`
   - Must be a **failed** test run
   - Must have logs available

2. **Test Name** - The specific test that failed
   - Example: `jira_integration`
   - Should match a test in `system_test_mapping.json`

3. **Environment** (if not obvious from workflow)
   - staging, production, production-us, development

---

## 3. How to Test Properly

### Prerequisites

1. **Code Indexes Must Exist**
   - ✅ cadashboardbe: `/Users/eranmadar/repos/cadashboardbe/docs/indexes/code-index.json`
   - ❓ event-ingester-service: Check if index exists
   - ❓ config-service: Check if index exists
   - ❓ users-notification-service: Check if index exists

2. **GitHub Token** (for API access)
   ```bash
   export GITHUB_TOKEN="your_github_token"
   ```

3. **Python Environment**
   ```bash
   cd /Users/eranmadar/repos/system-tests
   python3 -m venv systest_python_env
   source systest_python_env/bin/activate
   pip install -r tools/test-failure-analyzer/requirements.txt
   ```

### Testing Steps

#### Step 1: Extract Test Information

```bash
cd /Users/eranmadar/repos/system-tests/tools/test-failure-analyzer

# Extract workflow commit
python3 extract_workflow_commit.py \
  --workflow-url "https://github.com/armosec/system-tests/actions/runs/XXXXXX" \
  --output artifacts/workflow-commit.txt

# Extract test run ID (if available in logs)
python3 extract_test_run_id.py \
  --log-file path/to/workflow-log.txt \
  --output artifacts/test-run-id.txt
```

#### Step 2: Extract Image Tags

```bash
# From event-sourcing-chart values file (RECOMMENDED)
python3 extract_image_tags.py \
  --event-sourcing-values /Users/eranmadar/repos/kubernetes-deployment/event-sourcing-chart/stage-env-values.yaml \
  --output artifacts/running-images.json
```

#### Step 3: Map Tags to Commits

```bash
python3 map_tag_to_commit.py \
  --running-images artifacts/running-images.json \
  --output artifacts/resolved-repo-commits.json
```

#### Step 4: Map APIs to Code

```bash
python3 map_apis_to_code.py \
  --test-name jira_integration \
  --mapping ../../system_test_mapping.json \
  --code-index /Users/eranmadar/repos/cadashboardbe/docs/indexes/code-index.json \
  --output artifacts/api-code-map.json
```

#### Step 5: Add Call Chains

```bash
python3 map_apis_with_call_chains.py \
  --api-mapping artifacts/api-code-map.json \
  --code-index /Users/eranmadar/repos/cadashboardbe/docs/indexes/code-index.json \
  --output artifacts/api-code-map-with-chains.json \
  --max-depth 2
```

#### Step 6: Build LLM Context (Phase 7)

```bash
# Use system Python (not pyenv!)
/usr/bin/python3 build_llm_context.py \
  --test-name jira_integration \
  --api-mapping artifacts/api-code-map-with-chains.json \
  --resolved-commits artifacts/resolved-repo-commits.json \
  --code-index /Users/eranmadar/repos/cadashboardbe/docs/indexes/code-index.json \
  --output artifacts/llm-context.json \
  --format json
```

### Verification

```bash
# Check output file was created
ls -lh artifacts/llm-context.json

# Verify structure
jq '.metadata | {test_name, total_chunks, total_lines_of_code}' artifacts/llm-context.json

# Check chunks have code
jq '[.code_chunks[] | select(.code == "")] | length' artifacts/llm-context.json  # Should be 0

# View first chunk
jq '.code_chunks[0] | {id, name, type, has_code: (.code | length > 0)}' artifacts/llm-context.json
```

---

## 4. Dashboard Alignment Check

### Verify cadashboardbe is Aligned

```bash
cd /Users/eranmadar/repos/cadashboardbe

# Check current branch
git branch --show-current

# Check if code index exists and is up to date
ls -lh docs/indexes/code-index.json

# Check index metadata
jq '.metadata | {total_chunks, total_endpoints}' docs/indexes/code-index.json

# Verify specific handler exists (example)
jq '[.chunks[] | select(.name == "ClusterHandler" and .file | contains("clusterhandlers.go"))] | length' docs/indexes/code-index.json
```

### Expected Results:
- ✅ code-index.json exists
- ✅ Contains ~4000-4500 chunks
- ✅ Contains ~490-500 endpoints
- ✅ Has recent modification date

### If Index is Missing or Outdated:

```bash
cd /Users/eranmadar/repos/cadashboardbe

# Regenerate index
go run ./scripts/code-indexing/indexgen docs/indexes/code-index.json . --versioned

# Verify it worked
ls -lh docs/indexes/code-index.json
jq '.metadata' docs/indexes/code-index.json
```

---

## 5. Common Issues & Solutions

### Issue: "pyenv Python suppresses output"
**Solution:** Use `/usr/bin/python3` explicitly

### Issue: "Chunks have no code"
**Solution:** Provide `--code-index` parameter with path to index

### Issue: "Code index not found"
**Solution:** 
1. Check index exists at expected location
2. Regenerate if needed: `go run ./scripts/code-indexing/indexgen ...`
3. Verify path in command

### Issue: "API not found in index"
**Solution:**
1. Check test name in `system_test_mapping.json`
2. Verify endpoints are correct
3. Regenerate cadashboardbe index if handlers changed

---

## 6. Quick Test Command (All-in-One)

```bash
cd /Users/eranmadar/repos/system-tests/tools/test-failure-analyzer

# Set variables
TEST_NAME="jira_integration"
WORKFLOW_URL="https://github.com/armosec/system-tests/actions/runs/XXXXX"
CADASHBOARD_INDEX="/Users/eranmadar/repos/cadashboardbe/docs/indexes/code-index.json"

# Run Phase 7 (assuming you have api-code-map-with-chains.json and resolved-repo-commits.json)
/usr/bin/python3 build_llm_context.py \
  --test-name "$TEST_NAME" \
  --api-mapping artifacts/api-code-map-with-chains.json \
  --resolved-commits artifacts/resolved-repo-commits.json \
  --code-index "$CADASHBOARD_INDEX" \
  --output artifacts/llm-context.json \
  --format json

# Verify
jq '.metadata' artifacts/llm-context.json
```

---

## 7. Next Steps After Testing

Once you verify it works:

1. **Push changes** to your branch
2. **Create PR** with description of what was fixed
3. **Test in CI/CD** - Run actual workflow
4. **Document results** - Share output and any issues
5. **Iterate** - Fix any issues found in real workflow

---

## Need Help?

If you encounter issues:
1. Check logs for error messages
2. Verify all input files exist
3. Check file permissions
4. Ensure code indexes are up to date
5. Use `/usr/bin/python3` (not pyenv)


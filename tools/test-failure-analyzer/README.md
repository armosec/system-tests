# Test Failure Analyzer

Automated test failure analysis using LLM-powered insights. This tool collects comprehensive context about test failures and structures it for AI analysis.

## Quick Start

### Run a Full Analysis

```bash
# Set up environment
export GITHUB_TOKEN="your_token_here"
export GITHUB_WORKSPACE="/path/to/workspace"

# Run analysis for a failed test
./analyze_test_failure.sh \
  --workflow-url "https://github.com/armosec/system-tests/actions/runs/12345" \
  --test-name "test_user_authentication" \
  --output-dir ./analysis-results
```

### Output

The analyzer generates:
- `llm-context.json` - Complete LLM-ready context
- `report.json` - Analysis report
- `report.md` - Human-readable report
- Phase-specific outputs (api-map, call-chains, etc.)

## Code Index Version Resolution

The analyzer intelligently resolves which code index to use based on the **deployed version** being tested:

### Automatic Version Detection

The analyzer extracts the deployed version from `running-images.json`:
```json
{
  "repos": {
    "cadashboardbe": {
      "images": [{"tag": "v0.0.223"}]
    }
  }
}
```

### Resolution Strategy (4 tiers)

1. **Version tag** (preferred): `code-index-v0.0.223` ⭐
2. **Commit hash** (fallback): `code-index-d2714b50...`
3. **Latest** (backward compatibility): `code-index-latest`
4. **Local file** (development): Local checkout

### Benefits

✅ Uses **exact deployed version** code (not just latest main)  
✅ Accurate analysis matching the actual running code  
✅ Clear logging shows which strategy succeeded  
✅ Backward compatible with old releases  
✅ Future-ready for diff analysis (deployed vs latest)

### Visibility

The analyzer logs show the resolution process:
```
📦 Deployed Version:  v0.0.223
📌 Deployed Commit:   d2714b50
🔍 Strategy 2: Trying version tag: code-index-v0.0.223
✅ Strategy 2: Successfully downloaded!
```

**See**: `../../shared-workflows/CODE_INDEX_VERSION_RESOLUTION.md` for complete details.

## Pipeline Phases

Each phase can be run independently:

### Phase 1-2: Extract Test Metadata

```bash
# Extract run ID and test info
python3 extract_test_run_id.py \
  --workflow-url "https://github.com/armosec/system-tests/actions/runs/12345" \
  --output test-run-info.json

# Extract workflow commit
python3 extract_workflow_commit.py \
  --run-id "12345-1" \
  --output workflow-commit.txt
```

### Phase 3: Load Code Indexes

```bash
# Find indexes for all relevant repos
python3 find_indexes.py \
  --registry index-registry.json \
  --triggering-repo cadashboardbe \
  --triggering-commit abc123def \
  --output found-indexes.json

# Load the indexes
python3 load_multi_repo_indexes.py \
  --found-indexes found-indexes.json \
  --output loaded-indexes.json
```

### Phase 4: Extract Connected Context

```bash
# Get cross-repository dependencies
python3 extract_connected_context.py \
  --test-name test_user_authentication \
  --triggering-repo cadashboardbe \
  --repos-to-scan "authentication-service,event-ingester-service" \
  --output connected-context.json
```

### Phase 5-6: Resolve Service Versions

```bash
# Extract running image tags
python3 extract_image_tags.py \
  --values-file /path/to/kubernetes/values.yaml \
  --deployment-dir /path/to/kubernetes/deployment \
  --output running-images.json

# Map tags to commits
python3 resolve_repo_commits.py \
  --images running-images.json \
  --workflow-commit abc123def \
  --triggering-repo cadashboardbe \
  --output resolved-repo-commits.json
```

### Phase 7: Build LLM Context

```bash
# Generate final LLM context
python3 build_llm_context.py \
  --test-file tests/test_auth.py \
  --test-name test_user_authentication \
  --error-log error.log \
  --api-map api-code-map.json \
  --call-chain test-call-chain.json \
  --connected-context connected-context.json \
  --resolved-commits resolved-repo-commits.json \
  --code-index /path/to/code-index.json \
  --output llm-context.json
```

## Configuration

### index-registry.json

Defines where to find code indexes:

```json
{
  "version": "1.0",
  "registries": {
    "github-actions": {
      "type": "github-artifacts",
      "priority": 1
    }
  },
  "repositories": [
    {
      "name": "cadashboardbe",
      "repo_url": "https://github.com/armosec/cadashboardbe",
      "index_workflow": "code-index-generation.yml"
    }
  ]
}
```

### config.yaml

General configuration:

```yaml
github:
  api_url: https://api.github.com
  org: armosec
  
repositories:
  - name: cadashboardbe
    type: go
  - name: authentication-service
    type: go
```

## Helper Scripts

### Update Index Registry

```bash
# Add or update repository in registry
python3 update_index_registry.py \
  --registry index-registry.json \
  --repo-name new-service \
  --repo-url https://github.com/armosec/new-service \
  --index-workflow code-index-generation.yml
```

### Validate Analysis

```bash
# Check that analysis is complete and valid
python3 validate_analysis.py \
  --llm-context llm-context.json \
  --check-code-populated \
  --min-chunks 5
```

## Debugging

### Enable Verbose Logging

```bash
export DEBUG=1
python3 build_llm_context.py ... 2>&1 | tee debug.log
```

### Inspect Intermediate Outputs

```bash
# Pretty-print JSON
cat llm-context.json | jq '.'

# Check chunk count
cat llm-context.json | jq '.metadata.total_chunks'

# List all chunks
cat llm-context.json | jq '.code_chunks[] | {id, type, source}'

# Find empty chunks
cat llm-context.json | jq '.code_chunks[] | select(.code == "")'
```

### Common Issues

**No code indexes found**
- Check that `code-index-generation.yml` workflow ran for the deployed version
- For releases, verify version-tagged artifact exists: `code-index-v0.0.XXX`
- Check artifact retention (90 days for version/commit, 7 days for latest)
- Verify artifact was uploaded successfully
- Check analyzer logs to see which strategies were tried
- Fallback: Ensure `code-index-latest` exists for backward compatibility

**Empty code chunks**
- Verify code index was loaded: `cat loaded-indexes.json | jq`
- Check chunk IDs match: compare IDs in api-map vs code-index
- Ensure `--code-index` path is correct

**Connected context missing**
- Check that connected repos have indexes
- Verify topic/endpoint patterns in tracer scripts
- Check size limits aren't excluding chunks

## Testing

### Unit Tests

```bash
# Test individual scripts
python3 test_extract_test_run_id.py
python3 test_extract_workflow_commit.py

# Test with sample data
python3 build_llm_context.py \
  --test-file samples/test_sample.py \
  --test-name test_sample \
  --error-log samples/error.log \
  --api-map samples/api-map.json \
  --code-index samples/code-index.json \
  --output test-output.json
```

### Integration Tests

```bash
# Run full pipeline with test data
bash test_full_pipeline.sh
```

## Extending

### Add a New Context Source

1. Create new extractor script:
   ```python
   # extract_new_context.py
   def extract_new_context(test_name):
       # Your logic here
       return {"chunks": [...]}
   ```

2. Update `build_llm_context.py`:
   ```python
   # Add new argument
   parser.add_argument('--new-context', type=str)
   
   # Load and merge
   if args.new_context:
       with open(args.new_context) as f:
           new_context = json.load(f)
       all_chunks.extend(new_context['chunks'])
   ```

3. Update documentation

### Add Support for a New Language

1. Update `indexgen` to parse the language
2. Update chunk ID format in `build_llm_context.py`
3. Update API mapping patterns
4. Test with sample repos

## Best Practices

### When to Run Analysis
- ✅ Flaky tests that fail intermittently
- ✅ Regression tests that started failing after a code change
- ✅ Integration tests involving multiple services
- ❌ Known failures (e.g., missing infrastructure)
- ❌ Test code issues (not application code issues)

### Optimizing Context Size
- Set `--max-lines-per-source` to limit code volume
- Use `--priority-threshold` to exclude low-priority chunks
- Enable `--error-keywords` to focus on error-related code
- Exclude test setup/teardown code if not relevant

### Maintaining Indexes
- Indexes are auto-generated on push to main and on version tags
- **Version-tagged artifacts** (e.g., `code-index-v0.0.223`):
  - Created when pushing version tags: `git tag v0.0.223 && git push origin v0.0.223`
  - Retention: 90 days (for historical analysis)
  - Preferred for test failure analysis
- **Commit-hash artifacts** (e.g., `code-index-abc123...`):
  - Created on every commit
  - Retention: 90 days
  - Used as fallback
- **Latest artifact** (`code-index-latest`):
  - Created on every commit (overwrites previous)
  - Retention: 7 days (rolling window)
  - Used for backward compatibility
- Clean up old artifacts manually if storage is an issue
- Re-run index generation if schema changes

## Documentation

- [Main Documentation](../../../armosec-ai-shared-rules/docs/test-failure-analysis/README.md)
- [Architecture](../../../armosec-ai-shared-rules/docs/test-failure-analysis/ARCHITECTURE.md)
- [Testing Guide](./TESTING_GUIDE.md)
- [Phase 7 Details](./PHASE7_COMPLETE.md)

## Requirements

```bash
pip install -r requirements.txt
```

Dependencies:
- `requests` - GitHub API calls
- `PyYAML` - Config file parsing
- `python-dotenv` - Environment variable management
- Standard library: `json`, `argparse`, `subprocess`, `pathlib`

## Support

For issues:
1. Check [Common Issues](#common-issues)
2. Review script help: `python3 script_name.py --help`
3. Check main documentation
4. Contact team in #test-automation


# LLM Analysis Integration - Implementation Progress

## ✅ Completed Steps

### 1. Test Mapping Workflow (system-tests)
- ✅ Created `.github/workflows/generate-test-mapping.yml`
- Triggers on PR and main push
- Auto-generates test→API mappings
- Uploads artifacts: `test-mapping-{commit}` and `test-mapping-latest`

### 2. Generalized Code Index Template (armosec-ai-shared-rules)
- ✅ Created `workflow-templates/code-index-generation.yml` (reusable template)
- ✅ Created `scripts/code-indexing/install-code-index-workflow.sh` (installer)
- One-command installation for any repo
- Creates 3 artifacts: by commit, by version tag, and latest

### 3. Code Index in postgres-connector
- ✅ Verified postgres-connector already has code-index-generation workflow
- Ready to use for dependency analysis

### 4. go.mod Dependency Extraction
- ✅ Created `extract_gomod_dependencies.py`
- Extracts all armosec/* and kubescape/* dependencies from go.mod
- Checks which dependencies have code indexes available

### 5. Multi-Version Index Resolution
- ✅ Created enhanced `find_indexes.py`
- Supports PR-based RC resolution (extracts PR number from RC tags)
- Downloads deployed and RC/latest versions for all repos
- 4-tier fallback strategy: PR commit → version tag → commit hash → latest

### 6. Code Diff Generation
- ✅ Created `compare_code_indexes.py`
- Compares deployed vs RC for dashboard
- Compares deployed vs latest for dependencies
- Identifies changed functions, new/removed endpoints

### 7. LLM Analysis Integration
- ✅ Created `llm_analyzer.py` with OpenAI GPT-4o integration
- Analyzes test failures with complete context
- Generates structured analysis: root cause, evidence, impact, recommended fix, executive verdict

### 8. Report Generation
- ✅ Created `generate_reports.py`
- Generates `executive-summary.md` (for management)
- Generates `full-analysis-report.md` (for engineers)
- Includes code changes, LLM analysis, and actionable recommendations

### 9. Workflow Integration
- ✅ Added Phase 3.5 to `system-tests-analyzer.yml`: Extract go.mod dependencies
- ✅ Added Phase 4.5: Generate code diffs
- ✅ Added Phase 8: LLM analysis and report generation
- ✅ Updated `requirements.txt` to include openai package

## Configuration Required

### GitHub Secrets
Add to organization secrets:
- `OPENAI_API_KEY` - Required for LLM analysis in Phase 8

### Cost Estimate
- GPT-4o: ~$0.08 per test analysis
- Very reasonable for the value provided

## Usage

### Trigger Analyzer Manually
```bash
# Go to shared-workflows repo → Actions → System Tests - Failure Analyzer
# Provide:
# - run_ref: URL of failed test run
# - only_test: (optional) specific test to analyze
```

### Artifacts Generated
- `test-mapping-latest` - Auto-updated test→API mappings
- `code-diffs-phase4.5` - Code changes since deployment
- `llm-analysis-reports-phase8` - LLM analysis with executive summary

## Next Steps (Not in This Plan)

- Auto-trigger analyzer from CI workflow failures
- Extract service versions from kubernetes-deployment repo
- Post analysis summaries as PR comments
- Build historical failure database

## Testing

To test end-to-end:
1. Push changes to trigger test-mapping and code-index workflows
2. Manually trigger `system-tests-analyzer.yml` with a failed test run
3. Verify all phases complete successfully
4. Review generated executive summary and full report

---

**Status**: Implementation Complete ✅  
**Date**: 2024-12-02


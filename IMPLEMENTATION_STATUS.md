# Multi-Repo Code Context - Implementation Status

**Branch**: `feature/multi-repo-code-context`
**Date**: December 4, 2024

## ✅ Completed Steps

### 1. Enhanced Call Chain Extraction (extract_call_chain.py)
- ✅ Added `extract_repo_from_import()` function to parse Go import paths
- ✅ Added `parse_imports()` function to build alias → repo mapping
- ✅ Modified `extract_call_chain()` to detect cross-repo calls
- ✅ Added `cross_repo_calls` and `repositories_in_chain` to output
- ✅ Added `--dependency-indexes` parameter
- ✅ Added multi-repo chunk loading and tagging with `_repo`
- ✅ Updated to search across all repos when resolving function calls

**Files Modified**: `tools/test-failure-analyzer/extract_call_chain.py`

### 2. Dependency Version Comparison (extract_gomod_dependencies.py)
- ✅ Added `--deployed-code-index` and `--rc-code-index` parameters
- ✅ Added `compare_dependency_versions()` function
- ✅ Implemented comparison mode (deployed vs RC)
- ✅ Maintained backward compatibility with single-index mode
- ✅ Output format includes `version_changed` flag

**Files Modified**: `tools/test-failure-analyzer/extract_gomod_dependencies.py`

### 3. Dependency Index Resolution (find_indexes.py)
- ✅ Added `find_dependency_index()` function
- ✅ Updated `resolve_dependency_indexes()` to handle new format
- ✅ Support for both deployed and RC version resolution
- ✅ Added `dependencies_summary` to output
- ✅ Tracks version changes and found/missing indexes

**Files Modified**: `tools/test-failure-analyzer/find_indexes.py`

### 4. Workflow Phase 3.5 Update
- ✅ Updated to handle both deployed and RC code indexes
- ✅ Runs in comparison mode when both indexes available
- ✅ Shows version change count in output
- ✅ Backward compatible with single-index mode

**Files Modified**: `shared-workflows/.github/workflows/system-tests-analyzer.yml`

## 🚧 Remaining Work

### Phase 4: Code Index Download & Dependency Resolution
**Current State**: Phase 4 inline downloads cadashboardbe index only

**Needs**:
1. Refactor inline bash code to use `find_indexes.py`
2. Pass `--gomod-dependencies` to `find_indexes.py`
3. Download RC version in addition to deployed
4. Download dependency indexes (postgres-connector, etc.)
5. Store results in `found-indexes.json`

**Estimated Effort**: 2-3 hours

### Phase 4.5: Multi-Repo Code Diffs
**Current State**: Only compares cadashboardbe deployed vs RC

**Needs**:
1. Loop through all dependencies with `version_changed: true`
2. For each changed dependency, run `compare_code_indexes.py`
3. Merge results into `code-diffs.json`
4. Add placeholders for missing indexes

**Location**: After line 1400 in workflow

**Estimated Effort**: 1 hour

### Phase 6: Multi-Repo Call Chain Extraction
**Current State**: Only uses cadashboardbe index

**Needs**:
1. Build `DEPENDENCY_INDEXES_JSON` from `found-indexes.json`
2. Pass to `map_apis_with_call_chains.py` via `--dependency-indexes`
3. Update `map_apis_with_call_chains.py` to accept and forward parameter

**Location**: Around line 1045-1050 in workflow

**Estimated Effort**: 1-2 hours

### Phase 7: Impact Assessment (build_llm_context.py)
**Needs**:
1. Add `calculate_dependency_impact()` function
2. Read `code-diffs.json` to get changed dependencies
3. Cross-reference with call chains to find changed+called functions
4. Add `dependency_analysis` to metadata
5. Support multi-repo chunks (with `_repo` tag)

**Files to Modify**: `tools/test-failure-analyzer/build_llm_context.py`

**Estimated Effort**: 2-3 hours

### Phase 8: Enhanced Summary Output
**Needs**:
1. Add "Dependency Analysis" section after "Code Differences"
2. Show high-impact dependencies (changed + called)
3. Show all included dependencies
4. Show changed dependencies without indexes
5. Extract data from `llm-context.json` metadata

**Location**: Around line 1800 in workflow (LLM Context Summary)

**Estimated Effort**: 1 hour

### Phase 9: Verify postgres-connector
- ✅ Already verified - has code-index-generation.yml
- ⏭️ No action needed

## 📁 Files Changed

### system-tests repository
- `tools/test-failure-analyzer/extract_call_chain.py` ✅
- `tools/test-failure-analyzer/extract_gomod_dependencies.py` ✅
- `tools/test-failure-analyzer/find_indexes.py` ✅
- `tools/test-failure-analyzer/build_llm_context.py` ❌ (not started)
- `tools/test-failure-analyzer/map_apis_with_call_chains.py` ❌ (may need minor update)

### shared-workflows repository
- `.github/workflows/system-tests-analyzer.yml` 🟡 (partially complete)

## 🧪 Testing Plan

### Unit Testing
- Test `extract_call_chain.py` with dependency indexes
- Test `extract_gomod_dependencies.py` comparison mode
- Test `find_indexes.py` with multiple dependencies

### Integration Testing
1. Run analyzer on test that calls postgres-connector
2. Verify postgres-connector chunks appear in llm-context.json
3. Verify impact assessment identifies HIGH vs LOW
4. Verify GitHub compare URLs work

### Test Scenarios
1. **High Impact**: postgres-connector version changed + GetWorkloads() called
2. **Low Impact**: storage version unchanged + called
3. **Missing Index**: messaging version changed + no index
4. **No External Calls**: Only cadashboardbe code

## 🔗 Related Documentation
- Plan: `/cross.plan.md`
- Changelog: `shared-workflows/CHANGELOG_DEC_2024.md`

## 📊 Progress: ~40% Complete

**Completed**: Steps 1-3, partial Step 4
**Remaining**: Steps 4-8 (workflow integration, impact assessment, summary)

## 🎯 Next Actions

1. Complete Phase 4 (code index download refactor)
2. Add Phase 4.5 (multi-repo code diffs)
3. Update Phase 6 (multi-repo call chains)
4. Implement Phase 7 (impact assessment)
5. Add Phase 8 (enhanced summary)
6. Test end-to-end
7. Create PRs

## 💡 Notes

- All Python changes maintain backward compatibility
- Workflow changes are incremental and safe
- postgres-connector already has code index generation
- Error handling is built into all new functions
- Plan emphasizes graceful degradation when indexes missing


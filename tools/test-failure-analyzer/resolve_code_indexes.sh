#!/bin/bash
set -euo pipefail

# This script can be very verbose/heavy; GitHub Actions log I/O can significantly slow runtime.
# Enable xtrace/debug only when explicitly requested.
ANALYZER_DEBUG="${ANALYZER_DEBUG:-false}"
if [[ "${ANALYZER_DEBUG}" == "true" ]]; then
  set -x
fi

echo "🔍 Phase 4: Code Index Resolution (3-Pass) & API Mapping"
echo "================================================================"
echo ""
echo "📦 This phase will:"
echo "   1. Pass 1: Download triggering repo indexes"
echo "   2. Pass 2: Extract go.mod dependencies"
echo "   3. Pass 3: Download ALL dependency indexes"
echo "   4. Map APIs to code with cross-repo call chains"
echo ""

# Step 1: Extract version info from running-images.json
DEPLOYED_VERSION=""
RC_VERSION=""
WORKFLOW_COMMIT=""
GOMOD_DEPLOYED_VERSION=""  # Initialize to ensure it's always defined
TRIGGERING_REPO_COMMIT_FROM_JSON="" # Optional; only available when test-deployed-services.json exists
TRIGGERING_REPO="$TRIGGERING_REPO_FROM_STEP"

# Prefer new format (test-deployed-services.json), fallback to legacy (running-images.json)
TAG_FILE=""
if [[ -f artifacts/test-deployed-services.json ]]; then
  TAG_FILE="artifacts/test-deployed-services.json"
  [[ "${ANALYZER_DEBUG}" == "true" ]] && echo "🔍 DEBUG (Phase 4): Using new format (test-deployed-services.json)"
elif [[ -f artifacts/running-images.json ]]; then
  TAG_FILE="artifacts/running-images.json"
  [[ "${ANALYZER_DEBUG}" == "true" ]] && echo "🔍 DEBUG (Phase 4): Using legacy format (running-images.json)"
fi

if [[ -n "$TAG_FILE" ]]; then
  if [[ "${ANALYZER_DEBUG}" == "true" ]]; then
    echo "🔍 DEBUG (Phase 4): Keys in $TAG_FILE:"
    jq 'keys' "$TAG_FILE" || echo "Failed to parse JSON"
  fi
  
  # Extract triggering repo (handles both formats)
  if [[ "$TAG_FILE" == *"test-deployed-services.json" ]]; then
    DETECTED_REPO=$(jq -r '.triggering_repo.normalized // empty' "$TAG_FILE" 2>/dev/null || echo "")
    if [[ -n "$DETECTED_REPO" && "$DETECTED_REPO" != "null" && "$DETECTED_REPO" != "empty" ]]; then
      TRIGGERING_REPO="$DETECTED_REPO"
      echo "📦 Using triggering repo from test-deployed-services.json: $TRIGGERING_REPO"
    else
      echo "❌ ERROR: Could not extract triggering_repo.normalized from test-deployed-services.json"
      echo "   File: $TAG_FILE"
      echo "   Extracted value: '$DETECTED_REPO'"
      echo "   Full triggering_repo object:"
      jq '.triggering_repo' "$TAG_FILE" || echo "   Failed to parse triggering_repo"
      echo ""
      echo "   This is a critical error - the analyzer cannot proceed without knowing the triggering repo."
      echo "   Please check Step 11.5 logs in the original test run to see why triggering_repo was not populated."
      exit 1
    fi
    
    # Extract the tag currently running in the cluster for the triggering repo
    ACTUAL_DEPLOYED_VERSION=$(jq -r '.triggering_repo.images[0].tag // empty' "$TAG_FILE" 2>/dev/null || echo "")
    
    # Extract the commit hash from test-deployed-services.json (MOST RELIABLE)
    TRIGGERING_REPO_COMMIT_FROM_JSON=$(jq -r '.triggering_repo.commit_hash // empty' "$TAG_FILE" 2>/dev/null || echo "")
    if [[ -n "$TRIGGERING_REPO_COMMIT_FROM_JSON" && "$TRIGGERING_REPO_COMMIT_FROM_JSON" != "null" && "$TRIGGERING_REPO_COMMIT_FROM_JSON" =~ ^[0-9a-f]{7,40}$ ]]; then
      echo "✅ Found triggering repo commit from test-deployed-services.json: ${TRIGGERING_REPO_COMMIT_FROM_JSON:0:8}"
    else
      echo "⚠️  No valid commit_hash in test-deployed-services.json (value: '$TRIGGERING_REPO_COMMIT_FROM_JSON')"
      TRIGGERING_REPO_COMMIT_FROM_JSON=""
    fi
    
    # Extract global RC version
    GLOBAL_RC_VERSION="$INPUT_RC_VERSION"
    [[ "${ANALYZER_DEBUG}" == "true" ]] && echo "🔍 DEBUG: inputs.rc_version = '$INPUT_RC_VERSION'"
    [[ "${ANALYZER_DEBUG}" == "true" ]] && echo "🔍 DEBUG: GLOBAL_RC_VERSION (from input) = '$GLOBAL_RC_VERSION'"
    if [[ -z "$GLOBAL_RC_VERSION" || "$GLOBAL_RC_VERSION" == "null" || "$GLOBAL_RC_VERSION" == "unknown" ]]; then
      GLOBAL_RC_VERSION=$(jq -r '.triggering_repo.rc_version // empty' "$TAG_FILE" 2>/dev/null || echo "")
      [[ "${ANALYZER_DEBUG}" == "true" ]] && echo "🔍 DEBUG: GLOBAL_RC_VERSION (from JSON) = '$GLOBAL_RC_VERSION'"
    fi
  else
    # Legacy format
    if [[ "${ANALYZER_DEBUG}" == "true" ]]; then
      echo "🔍 DEBUG (Phase 4): Repos in running-images.json:"
      jq '.repos | keys' "$TAG_FILE" || echo "Failed to parse JSON"
    fi
    
    DETECTED_REPO=$(jq -r '.triggering_repo_normalized // empty' "$TAG_FILE" 2>/dev/null || echo "")
    if [[ -n "$DETECTED_REPO" && "$DETECTED_REPO" != "null" ]]; then
      TRIGGERING_REPO="$DETECTED_REPO"
      echo "📦 Using triggering repo from running-images.json: $TRIGGERING_REPO"
    fi
    
    # Extract the tag currently running in the cluster for the triggering repo
    ACTUAL_DEPLOYED_VERSION=$(jq -r --arg repo "$TRIGGERING_REPO" '.repos[$repo].images[0].tag // empty' "$TAG_FILE" 2>/dev/null || echo "")
    
    # Extract global RC version
    GLOBAL_RC_VERSION="$INPUT_RC_VERSION"
    [[ "${ANALYZER_DEBUG}" == "true" ]] && echo "🔍 DEBUG: inputs.rc_version = '$INPUT_RC_VERSION'"
    [[ "${ANALYZER_DEBUG}" == "true" ]] && echo "🔍 DEBUG: GLOBAL_RC_VERSION (from input) = '$GLOBAL_RC_VERSION'"
    if [[ -z "$GLOBAL_RC_VERSION" || "$GLOBAL_RC_VERSION" == "null" || "$GLOBAL_RC_VERSION" == "unknown" ]]; then
      GLOBAL_RC_VERSION=$(jq -r '.rc_version // empty' "$TAG_FILE" 2>/dev/null || echo "")
      [[ "${ANALYZER_DEBUG}" == "true" ]] && echo "🔍 DEBUG: GLOBAL_RC_VERSION (from JSON legacy) = '$GLOBAL_RC_VERSION'"
    fi
  fi
    
  [[ "${ANALYZER_DEBUG}" == "true" ]] && echo "🔍 DEBUG (Phase 4): ACTUAL_DEPLOYED_VERSION='${ACTUAL_DEPLOYED_VERSION}'"
  [[ "${ANALYZER_DEBUG}" == "true" ]] && echo "🔍 DEBUG (Phase 4): TRIGGERING_REPO='${TRIGGERING_REPO}'"

  echo "📦 Version discovery for $TRIGGERING_REPO:"
  echo "   - Cluster Tag: ${ACTUAL_DEPLOYED_VERSION:-none}"
  echo "   - Global RC:   ${GLOBAL_RC_VERSION:-none}"
  echo "   - inputs.rc_version: ${INPUT_RC_VERSION:-'(not set)'}"
  echo "   - TAG_FILE: $TAG_FILE"

  # For triggering repo: ALWAYS derive deployed version from RC version
  # Never use cluster tag - RC version is the source of truth
  # PRIORITY 1: Derive from global RC version (if available)
  # PRIORITY 2: Derive from cluster RC tag (if cluster has RC)
  # PRIORITY 3: Fall back to cluster stable tag (only if no RC available)
  
  if [[ -n "$GLOBAL_RC_VERSION" && "$GLOBAL_RC_VERSION" =~ ^rc-v([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    # ALWAYS derive deployed version from RC for triggering repo
    echo "🔍 Deriving deployed version from RC: $GLOBAL_RC_VERSION"
    echo "   (For triggering repo, deployed version is always derived from RC, ignoring cluster tag)"
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[3]}"
    
    if [[ "$PATCH" -gt 0 ]]; then
      PREV_PATCH=$((PATCH - 1))
      DEPLOYED_VERSION="v${MAJOR}.${MINOR}.${PREV_PATCH}"
    else
      DEPLOYED_VERSION="v${MAJOR}.${MINOR}.0"
    fi
    RC_VERSION="$GLOBAL_RC_VERSION"
    echo "   Derived deployed version: $DEPLOYED_VERSION"
    echo "   RC version: $RC_VERSION"
    
  elif [[ -n "$ACTUAL_DEPLOYED_VERSION" && "$ACTUAL_DEPLOYED_VERSION" =~ ^rc- ]]; then
    # Cluster has RC version, derive stable baseline
    echo "🔍 Cluster tag is RC: $ACTUAL_DEPLOYED_VERSION"
    echo "   Deriving deployed version from cluster RC tag"
    if [[ "$ACTUAL_DEPLOYED_VERSION" =~ ^rc-v([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
      MAJOR="${BASH_REMATCH[1]}"
      MINOR="${BASH_REMATCH[2]}"
      PATCH="${BASH_REMATCH[3]}"
      if [[ "$PATCH" -gt 0 ]]; then
        PREV_PATCH=$((PATCH - 1))
        DEPLOYED_VERSION="v${MAJOR}.${MINOR}.${PREV_PATCH}"
      else
        DEPLOYED_VERSION="v${MAJOR}.${MINOR}.0"
      fi
      RC_VERSION="$ACTUAL_DEPLOYED_VERSION"
      echo "   Derived baseline: $DEPLOYED_VERSION"
      echo "   RC version: $RC_VERSION"
    fi
    
  elif [[ -n "$ACTUAL_DEPLOYED_VERSION" && "$ACTUAL_DEPLOYED_VERSION" != "null" && "$ACTUAL_DEPLOYED_VERSION" != "empty" && ! "$ACTUAL_DEPLOYED_VERSION" =~ ^rc- ]]; then
    # Fallback: Use cluster stable tag only if no RC version available
    echo "⚠️  No RC version available, using cluster stable tag as fallback: $ACTUAL_DEPLOYED_VERSION"
    echo "   (This should rarely happen - RC version should always be available for triggering repo)"
    DEPLOYED_VERSION="$ACTUAL_DEPLOYED_VERSION"
    RC_VERSION="${GLOBAL_RC_VERSION:-unknown}"
    echo "   Using cluster tag: $DEPLOYED_VERSION"
    echo "   RC version: $RC_VERSION"
    
  else
    echo "⚠️  No deployed version found in cluster and no RC version available"
    echo "⚠️  Using defaults (may not be accurate)"
    DEPLOYED_VERSION="latest"
    RC_VERSION="${GLOBAL_RC_VERSION:-unknown}"
    echo "   Set DEPLOYED_VERSION: $DEPLOYED_VERSION"
    echo "   Set RC_VERSION (fallback): $RC_VERSION"
  fi
  
  # Use the same version for both code index and go.mod (no mismatch)
  GOMOD_DEPLOYED_VERSION="$DEPLOYED_VERSION"
  echo "   Final: DEPLOYED_VERSION=$DEPLOYED_VERSION (for code index and go.mod)"
else
  # TAG_FILE doesn't exist - this shouldn't happen but handle it gracefully
  echo ""
  echo "❌ ERROR: No running images file found!"
  echo "=========================================="
  echo ""
  echo "Expected files:"
  echo "  - artifacts/test-deployed-services.json (new format)"
  echo "  - artifacts/running-images.json (legacy format)"
  echo ""
  echo "These files should have been downloaded from the test run artifacts."
  echo ""
  echo "Possible causes:"
  echo "  1. Test run artifacts expired (GitHub keeps artifacts for 90 days)"
  echo "  2. Test run failed before uploading artifacts"
  echo "  3. Test run is from an old workflow that doesn't create these artifacts"
  echo "  4. Artifact download failed in Step 11 (check logs above)"
  echo ""
  echo "Without these files, the analyzer cannot:"
  echo "  - Determine deployed versions"
  echo "  - Download version-specific code indexes"
  echo "  - Extract go.mod dependencies"
  echo "  - Generate code chunks"
  echo ""
  echo "The analyzer will proceed with minimal context (test logs only)."
  echo "=========================================="
  echo ""
  
  # Set defaults to allow analyzer to continue (though with limited functionality)
  DEPLOYED_VERSION="unknown"
  RC_VERSION="${INPUT_RC_VERSION:-unknown}"
  GOMOD_DEPLOYED_VERSION="unknown"
  
  echo "Using fallback values:"
  echo "  - DEPLOYED_VERSION: $DEPLOYED_VERSION"
  echo "  - RC_VERSION: $RC_VERSION"
  echo "  - GOMOD_DEPLOYED_VERSION: $GOMOD_DEPLOYED_VERSION"
  echo ""
fi

# Get workflow commit - prefer file (updated by download-image-tags step) over step output
if [[ -f artifacts/workflow-commit.txt ]]; then
  WORKFLOW_COMMIT=$(cat artifacts/workflow-commit.txt 2>/dev/null || echo "")
fi
if [[ -z "$WORKFLOW_COMMIT" ]]; then
  WORKFLOW_COMMIT="$WORKFLOW_COMMIT_FROM_STEP"
fi

# Validate workflow commit is a valid SHA (not an error message)
if [[ -n "$WORKFLOW_COMMIT" ]] && ! [[ "$WORKFLOW_COMMIT" =~ ^[0-9a-f]{7,40}$ ]]; then
  echo "⚠️  Invalid workflow commit format: $WORKFLOW_COMMIT"
  echo "   This may be an error message, clearing it..."
  WORKFLOW_COMMIT=""
fi

# Extract triggering repo commit
# Priority order:
# 1. test-deployed-services.json commit_hash (most reliable - from test run)
# 2. RC tag (from GitHub API)
# 3. RC workflow run (extract from RC version suffix)
# 4. Resolved commits (from tag mapping)
# 5. Repo commits (from tag mapping)
# 6. Workflow commit (from shared-workflows - last resort)
TRIGGERING_REPO_COMMIT=""

# Priority 0: Use commit from test-deployed-services.json if available (MOST RELIABLE)
if [[ -n "${TRIGGERING_REPO_COMMIT_FROM_JSON:-}" ]]; then
  TRIGGERING_REPO_COMMIT="$TRIGGERING_REPO_COMMIT_FROM_JSON"
  echo "✅ Using triggering repo commit from test-deployed-services.json: ${TRIGGERING_REPO_COMMIT:0:8}"
  echo "   This is the most reliable source (extracted during test run)"
fi

# Priority 1: Extract commit from RC version (if not already found from JSON)
# RC version format: rc-v0.0.394-20549238574 or rc-v0.0.394-PR_NUMBER
# The RC is created from the merge commit, so we need to get that commit from GitHub
if [[ -z "$TRIGGERING_REPO_COMMIT" && -n "$RC_VERSION" && "$RC_VERSION" =~ ^rc-v ]]; then
  echo "🔍 Extracting triggering repo commit from RC version: $RC_VERSION"
  echo "   Querying: gh api repos/armosec/$TRIGGERING_REPO/git/refs/tags/$RC_VERSION"
  
  # Get the commit that the RC tag points to
  RC_COMMIT=$(gh api repos/armosec/$TRIGGERING_REPO/git/refs/tags/$RC_VERSION --jq '.object.sha' 2>&1)
  RC_API_EXIT=$?
  
  if [[ $RC_API_EXIT -ne 0 ]]; then
    echo "⚠️  GitHub API call failed (exit code: $RC_API_EXIT)"
    echo "   Error: $RC_COMMIT"
    echo "   This could be due to:"
    echo "   - Network issues"
    echo "   - GitHub token not set or expired"
    echo "   - RC tag doesn't exist yet (tag creation may be delayed)"
    RC_COMMIT=""
  fi
  
  if [[ -n "$RC_COMMIT" && "$RC_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    TRIGGERING_REPO_COMMIT="$RC_COMMIT"
    echo "✅ Found triggering repo commit from RC tag: ${TRIGGERING_REPO_COMMIT:0:8}"
  elif [[ -n "$RC_COMMIT" ]]; then
    echo "⚠️  RC tag API returned unexpected value: '$RC_COMMIT'"
    echo "   Expected: 40-character hex SHA"
    echo "   Trying alternative methods..."
  else
    echo "⚠️  RC tag $RC_VERSION not found or returned empty"
    echo "   Possible reasons:"
    echo "   - Tag hasn't been created yet (release workflow may still be running)"
    echo "   - Tag was deleted"
    echo "   - Network/API issues"
    echo "   Trying alternative methods..."
  fi
fi

# Priority 1.5: If RC tag failed, try to extract from the RC version number suffix
# RC format: rc-v0.0.394-20549238574 where 20549238574 is the workflow run ID
# We can get the commit from that workflow run
if [[ -z "$TRIGGERING_REPO_COMMIT" && -n "$RC_VERSION" && "$RC_VERSION" =~ rc-v[0-9]+\.[0-9]+\.[0-9]+-([0-9]+)$ ]]; then
  RUN_ID="${BASH_REMATCH[1]}"
  # Only try this if it looks like a workflow run ID (8+ digits)
  if [[ ${#RUN_ID} -ge 8 ]]; then
    echo "🔍 Attempting to extract commit from RC workflow run ID: $RUN_ID"
    
    # Try to get the head SHA from the workflow run
    # This requires checking the release workflow in the triggering repo
    RC_RUN_COMMIT=$(gh api repos/armosec/$TRIGGERING_REPO/actions/runs/$RUN_ID --jq '.head_sha' 2>/dev/null || echo "")
    
    if [[ -n "$RC_RUN_COMMIT" && "$RC_RUN_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
      TRIGGERING_REPO_COMMIT="$RC_RUN_COMMIT"
      echo "✅ Found triggering repo commit from RC workflow run: ${TRIGGERING_REPO_COMMIT:0:8}"
    else
      echo "⚠️  Could not get commit from workflow run $RUN_ID"
    fi
  fi
fi

# Priority 2: Try resolved commits (from tag mapping)
if [[ -z "$TRIGGERING_REPO_COMMIT" && -f artifacts/resolved-repo-commits.json ]]; then
  # Try normalized repo name first (most common)
  TRIGGERING_REPO_COMMIT=$(jq -r --arg repo "$TRIGGERING_REPO" '.resolved_commits[$repo] // empty' artifacts/resolved-repo-commits.json 2>/dev/null || echo "")
  # If not found, try case-insensitive search
  if [[ -z "$TRIGGERING_REPO_COMMIT" || "$TRIGGERING_REPO_COMMIT" == "null" ]]; then
    TRIGGERING_REPO_COMMIT=$(jq -r --arg repo "$TRIGGERING_REPO" '.resolved_commits | to_entries | map(select(.key | ascii_downcase == ($repo | ascii_downcase))) | .[0].value // empty' artifacts/resolved-repo-commits.json 2>/dev/null || echo "")
  fi
  if [[ -n "$TRIGGERING_REPO_COMMIT" && "$TRIGGERING_REPO_COMMIT" != "null" && "$TRIGGERING_REPO_COMMIT" =~ ^[0-9a-f]{7,40}$ ]]; then
    echo "✅ Found triggering repo commit from resolved-repo-commits.json: ${TRIGGERING_REPO_COMMIT:0:8}"
  else
    TRIGGERING_REPO_COMMIT=""
  fi
fi

# Priority 3: Try repo-commits.json (tag mapping)
if [[ -z "$TRIGGERING_REPO_COMMIT" && -f artifacts/repo-commits.json ]]; then
  # Try normalized repo name first
  TRIGGERING_REPO_COMMIT=$(jq -r --arg repo "$TRIGGERING_REPO" '.[$repo].commit // empty' artifacts/repo-commits.json 2>/dev/null || echo "")
  # If not found, try case-insensitive search
  if [[ -z "$TRIGGERING_REPO_COMMIT" || "$TRIGGERING_REPO_COMMIT" == "null" ]]; then
    TRIGGERING_REPO_COMMIT=$(jq -r --arg repo "$TRIGGERING_REPO" 'to_entries | map(select(.key | ascii_downcase == ($repo | ascii_downcase))) | .[0].value.commit // empty' artifacts/repo-commits.json 2>/dev/null || echo "")
  fi
  if [[ -n "$TRIGGERING_REPO_COMMIT" && "$TRIGGERING_REPO_COMMIT" != "null" && "$TRIGGERING_REPO_COMMIT" =~ ^[0-9a-f]{7,40}$ ]]; then
    echo "✅ Found triggering repo commit from repo-commits.json: ${TRIGGERING_REPO_COMMIT:0:8}"
  else
    TRIGGERING_REPO_COMMIT=""
  fi
fi

# Final fallback: Use workflow commit (but this is from shared-workflows, not the triggering repo)
if [[ -z "$TRIGGERING_REPO_COMMIT" && -n "$WORKFLOW_COMMIT" ]]; then
  echo "⚠️  No triggering repo commit found, using workflow commit as fallback"
  echo "   Note: Workflow commit is from shared-workflows repo, not $TRIGGERING_REPO"
  TRIGGERING_REPO_COMMIT="$WORKFLOW_COMMIT"
fi

# If RC version not set, use triggering repo commit as fallback
if [[ -z "$RC_VERSION" && -n "$TRIGGERING_REPO_COMMIT" ]]; then
  RC_VERSION="commit-${TRIGGERING_REPO_COMMIT:0:8}"
fi

echo ""
echo "📊 Version Info Summary:"
echo "   Triggering Repo:  ${TRIGGERING_REPO:-unknown}"
echo "   Deployed Version: ${DEPLOYED_VERSION:-unknown}"
echo "   RC Version:       ${RC_VERSION:-unknown}"
echo "   Triggering Repo Commit: ${TRIGGERING_REPO_COMMIT:-unknown}"
echo "   Workflow Commit (shared-workflows): ${WORKFLOW_COMMIT:-unknown}"
echo ""

# ====================================================================
# Index resolution mode (optional)
# ====================================================================
# Modes:
# - full (default): current behavior
# - targeted: limit service + go.mod dependency resolution to allowlist repos
INDEX_RESOLUTION_MODE="${INDEX_RESOLUTION_MODE:-full}"
INDEX_RESOLUTION_ALLOWLIST="${INDEX_RESOLUTION_ALLOWLIST:-}"
echo "🧭 Index Resolution Mode: ${INDEX_RESOLUTION_MODE}"
if [[ -n "${INDEX_RESOLUTION_ALLOWLIST}" ]]; then
  echo "   Allowlist: ${INDEX_RESOLUTION_ALLOWLIST}"
fi
echo ""

# Validate triggering repo is set (but allow "cadashboardbe" as valid default)
if [[ -z "$TRIGGERING_REPO" || "$TRIGGERING_REPO" == "unknown" ]]; then
  echo "❌ ERROR: Triggering repository is not properly set!"
  echo "   Current value: '$TRIGGERING_REPO'"
  echo "   This is a critical error - the analyzer cannot proceed without knowing the triggering repo."
  echo "   Please check Step 11.5 logs in the original test run to see why triggering_repo was not populated."
  exit 1
fi

echo "🔄 Calling find_indexes.py with:"
echo "   --deployed-version '${DEPLOYED_VERSION:-unknown}'"
echo "   --rc-version '${RC_VERSION:-unknown}'"
echo ""

# ====================================================================
# PASS 1: Download triggering repo indexes (deployed + RC)
# ====================================================================
echo "📥 PASS 1: Downloading $TRIGGERING_REPO indexes..."
python find_indexes.py \
  --triggering-repo "$TRIGGERING_REPO" \
  --deployed-version "${DEPLOYED_VERSION:-unknown}" \
  --rc-version "${RC_VERSION:-unknown}" \
  --triggering-commit "${TRIGGERING_REPO_COMMIT:-unknown}" \
  --images "artifacts/test-deployed-services.json" \
  --output-dir "artifacts/code-indexes" \
  --output "artifacts/found-indexes-pass1.json" \
  --github-token "$GITHUB_TOKEN" \
  --github-orgs "armosec,kubescape" \
  --debug || {
  echo "⚠️  Pass 1 failed, creating minimal found-indexes"
  cat > artifacts/found-indexes-pass1.json <<EOF
{
  "triggering_repo": "$TRIGGERING_REPO",
  "indexes": {
    "$TRIGGERING_REPO": {
      "deployed": {"version": "${DEPLOYED_VERSION:-unknown}", "found": false},
      "rc": {"version": "${RC_VERSION:-unknown}", "commit": "${TRIGGERING_REPO_COMMIT:-unknown}", "found": false}
    }
  }
}
EOF
}

# ====================================================================
# PASS 2: Extract go.mod dependencies from downloaded indexes
# ====================================================================
echo ""
echo "🔍 PASS 2: Extracting go.mod dependencies..."

DEPLOYED_INDEX=$(jq -r --arg repo "$TRIGGERING_REPO" '.indexes[$repo].deployed.index_path // empty' artifacts/found-indexes-pass1.json 2>/dev/null || echo "")
RC_INDEX=$(jq -r --arg repo "$TRIGGERING_REPO" '.indexes[$repo].rc.index_path // empty' artifacts/found-indexes-pass1.json 2>/dev/null || echo "")

GOMOD_DEPLOYED_OUT="artifacts/gomod-dependencies-deployed.json"
GOMOD_RC_OUT="artifacts/gomod-dependencies-rc.json"

# Choose an index file to use for parsing (we may download go.mod by tag anyway)
GOMOD_PARSE_INDEX=""
if [[ -n "$DEPLOYED_INDEX" && -f "$DEPLOYED_INDEX" ]]; then
  GOMOD_PARSE_INDEX="$DEPLOYED_INDEX"
elif [[ -n "$RC_INDEX" && -f "$RC_INDEX" ]]; then
  GOMOD_PARSE_INDEX="$RC_INDEX"
fi

# 1) RC go.mod snapshot (source of truth for "RC versions" column)
if [[ -n "$RC_INDEX" && -f "$RC_INDEX" ]]; then
  echo "📌 Extracting RC go.mod snapshot"
  echo "   Data source: RC code index (${RC_VERSION:-unknown})"
  python extract_gomod_dependencies.py \
    --code-index "$RC_INDEX" \
    --triggering-repo "$TRIGGERING_REPO" \
    --output "$GOMOD_RC_OUT" \
    --github-token "$GITHUB_TOKEN" \
    --debug || {
    echo "⚠️  RC go.mod extraction failed"
    echo "{}" > "$GOMOD_RC_OUT"
  }
else
  echo "⚠️  RC code index not available - cannot extract RC go.mod snapshot"
  echo "{}" > "$GOMOD_RC_OUT"
fi

# 2) Deployed go.mod snapshot (baseline for comparison)
# We fetch go.mod by deployed tag (DEPLOYED_VERSION) to avoid PR/merge commit ambiguity.
if [[ -n "$GOMOD_PARSE_INDEX" && -f "$GOMOD_PARSE_INDEX" && -n "${DEPLOYED_VERSION:-}" && "${DEPLOYED_VERSION:-}" != "unknown" && "${DEPLOYED_VERSION:-}" != "latest" ]]; then
  echo "📌 Extracting deployed go.mod snapshot"
  echo "   Data source: GitHub go.mod @ tag ${DEPLOYED_VERSION} (baseline)"
  python extract_gomod_dependencies.py \
    --code-index "$GOMOD_PARSE_INDEX" \
    --triggering-repo "$TRIGGERING_REPO" \
    --deployed-version "$DEPLOYED_VERSION" \
    --output "$GOMOD_DEPLOYED_OUT" \
    --github-token "$GITHUB_TOKEN" \
    --debug || {
    echo "⚠️  Deployed go.mod extraction failed"
    echo "{}" > "$GOMOD_DEPLOYED_OUT"
  }
else
  echo "⚠️  Deployed tag not available or no index for parsing - cannot extract deployed go.mod snapshot"
  echo "   DEPLOYED_VERSION='${DEPLOYED_VERSION:-<empty>}'"
  echo "   GOMOD_PARSE_INDEX='${GOMOD_PARSE_INDEX:-<empty>}'"
  echo "{}" > "$GOMOD_DEPLOYED_OUT"
fi

# 3) Compare mode: Create gomod-dependencies.json with version_changed detection
# This is the proper format that find_indexes.py expects (with deployed_version, rc_version, version_changed)
if [[ -n "$DEPLOYED_INDEX" && -f "$DEPLOYED_INDEX" && -n "$RC_INDEX" && -f "$RC_INDEX" ]]; then
  echo "📌 Comparing deployed vs RC go.mod to detect version changes"
  echo "   Deployed: $DEPLOYED_INDEX"
  echo "   RC: $RC_INDEX"
  python extract_gomod_dependencies.py \
    --deployed-code-index "$DEPLOYED_INDEX" \
    --rc-code-index "$RC_INDEX" \
    --triggering-repo "$TRIGGERING_REPO" \
    --deployed-version "$DEPLOYED_VERSION" \
    --rc-version "$RC_VERSION" \
    --output artifacts/gomod-dependencies.json \
    --github-token "$GITHUB_TOKEN" \
    --debug || {
    echo "⚠️  Compare mode failed, falling back to single snapshot"
    # Fallback: use deployed snapshot if compare fails
    if [[ -f "$GOMOD_DEPLOYED_OUT" && "$(jq 'length' "$GOMOD_DEPLOYED_OUT" 2>/dev/null || echo 0)" -gt 0 ]]; then
      cp "$GOMOD_DEPLOYED_OUT" artifacts/gomod-dependencies.json
    elif [[ -f "$GOMOD_RC_OUT" && "$(jq 'length' "$GOMOD_RC_OUT" 2>/dev/null || echo 0)" -gt 0 ]]; then
      cp "$GOMOD_RC_OUT" artifacts/gomod-dependencies.json
    else
      echo "{}" > artifacts/gomod-dependencies.json
    fi
  }
else
  # Fallback: Backward-compat - use single snapshot if compare mode not possible
  echo "⚠️  Compare mode not available (missing deployed or RC index), using single snapshot"
  if [[ -f "$GOMOD_DEPLOYED_OUT" && "$(jq 'length' "$GOMOD_DEPLOYED_OUT" 2>/dev/null || echo 0)" -gt 0 ]]; then
    cp "$GOMOD_DEPLOYED_OUT" artifacts/gomod-dependencies.json
  elif [[ -f "$GOMOD_RC_OUT" && "$(jq 'length' "$GOMOD_RC_OUT" 2>/dev/null || echo 0)" -gt 0 ]]; then
    cp "$GOMOD_RC_OUT" artifacts/gomod-dependencies.json
  else
    echo "{}" > artifacts/gomod-dependencies.json
  fi
fi

# Optional: Targeted mode filtering (limit go.mod deps to allowlist)
GOMOD_DEPS_FILE="artifacts/gomod-dependencies.json"
if [[ "${INDEX_RESOLUTION_MODE}" == "targeted" ]] && [[ -n "${INDEX_RESOLUTION_ALLOWLIST}" ]] && [[ -f "${GOMOD_DEPS_FILE}" ]]; then
  echo ""
  echo "🎯 Targeted mode: filtering go.mod dependencies by allowlist"
  echo "   Input:  ${GOMOD_DEPS_FILE}"
  echo "   Output: artifacts/gomod-dependencies.filtered.json"
  jq -c --arg csv "${INDEX_RESOLUTION_ALLOWLIST}" '
    ($csv | split(",") | map(ascii_downcase)) as $allow
    | with_entries(select((.key | ascii_downcase) as $k | ($allow | index($k))))
  ' "${GOMOD_DEPS_FILE}" > artifacts/gomod-dependencies.filtered.json 2>/dev/null || true
  if [[ -s artifacts/gomod-dependencies.filtered.json ]]; then
    GOMOD_DEPS_FILE="artifacts/gomod-dependencies.filtered.json"
    echo "✅ Filtered go.mod deps: $(jq 'length' "${GOMOD_DEPS_FILE}" 2>/dev/null || echo 0)"
  else
    echo "⚠️  Filter produced empty/invalid output, keeping full go.mod deps"
    rm -f artifacts/gomod-dependencies.filtered.json 2>/dev/null || true
    GOMOD_DEPS_FILE="artifacts/gomod-dependencies.json"
  fi
fi

# ====================================================================
# PASS 3: Download dependency indexes using gomod-dependencies.json
# ====================================================================
echo ""
echo "📥 PASS 3: Downloading dependency indexes (defaults + version-changed go.mod deps)..."

SERVICES_ONLY_FILE="artifacts/services-only.json"
if [[ "${INDEX_RESOLUTION_MODE}" == "targeted" ]] && [[ -n "${INDEX_RESOLUTION_ALLOWLIST}" ]] && [[ -f "${SERVICES_ONLY_FILE}" ]]; then
  echo ""
  echo "🎯 Targeted mode: filtering service repos by allowlist"
  echo "   Input:  ${SERVICES_ONLY_FILE}"
  echo "   Output: artifacts/services-only.filtered.json"
  jq -c --arg csv "${INDEX_RESOLUTION_ALLOWLIST}" '
    ($csv | split(",") | map(ascii_downcase)) as $allow
    | with_entries(select((.key | ascii_downcase) as $k | ($allow | index($k))))
  ' "${SERVICES_ONLY_FILE}" > artifacts/services-only.filtered.json 2>/dev/null || true
  if [[ -s artifacts/services-only.filtered.json ]]; then
    SERVICES_ONLY_FILE="artifacts/services-only.filtered.json"
    echo "✅ Filtered services: $(jq 'length' "${SERVICES_ONLY_FILE}" 2>/dev/null || echo 0)"
  else
    echo "⚠️  Filter produced empty/invalid output, keeping full services-only.json"
    rm -f artifacts/services-only.filtered.json 2>/dev/null || true
    SERVICES_ONLY_FILE="artifacts/services-only.json"
  fi
fi

if [[ -f "${GOMOD_DEPS_FILE}" ]] && [[ $(jq 'length' "${GOMOD_DEPS_FILE}" 2>/dev/null || echo 0) -gt 0 ]]; then
  TOTAL_DEPS="$(jq 'length' "${GOMOD_DEPS_FILE}" 2>/dev/null || echo 0)"
  CHANGED_DEPS="$(jq '[.[] | select(.version_changed==true)] | length' "${GOMOD_DEPS_FILE}" 2>/dev/null || echo 0)"
  echo "✅ Parsed go.mod dependencies: total=$TOTAL_DEPS, version_changed=$CHANGED_DEPS"
  if [[ "${INDEX_RESOLUTION_MODE}" == "targeted" ]]; then
    echo "   (Targeted mode: deps are filtered to allowlist; services are filtered to allowlist)"
  else
    echo "   (Resolution will still be limited by find_indexes.py default repos + version_changed=true)"
  fi

  DEFAULT_REPOS_ARGS=()
  if [[ "${INDEX_RESOLUTION_MODE}" == "targeted" ]] && [[ -n "${INDEX_RESOLUTION_ALLOWLIST}" ]]; then
    DEFAULT_REPOS_ARGS=( --default-repos "${INDEX_RESOLUTION_ALLOWLIST}" )
  fi

  python find_indexes.py \
    --triggering-repo "$TRIGGERING_REPO" \
    --deployed-version "${DEPLOYED_VERSION:-unknown}" \
    --rc-version "${RC_VERSION:-unknown}" \
    --triggering-commit "${TRIGGERING_REPO_COMMIT:-unknown}" \
    --images "artifacts/test-deployed-services.json" \
    --services-only "${SERVICES_ONLY_FILE}" \
    --output-dir "artifacts/code-indexes" \
    --output "artifacts/found-indexes.json" \
    --github-token "$GITHUB_TOKEN" \
    --github-orgs "armosec,kubescape" \
    --gomod-dependencies "${GOMOD_DEPS_FILE}" \
    "${DEFAULT_REPOS_ARGS[@]}" \
    --debug || {
    echo "⚠️  Pass 3 failed, using Pass 1 results"
    cp artifacts/found-indexes-pass1.json artifacts/found-indexes.json
  }
else
  echo "⚠️  No dependencies found, using Pass 1 results"
  cp artifacts/found-indexes-pass1.json artifacts/found-indexes.json
fi

echo ""
echo "✅ Code index resolution complete (3-pass approach)!"
echo "📋 Indexes available for API mapping:"
jq '.indexes | keys' artifacts/found-indexes.json || true
echo ""

# Step 3: Extract deployed index path from found-indexes.json
# NOTE: APIs are always in cadashboardbe, so always use cadashboardbe index for API mapping
# The triggering repo indexes are downloaded for code diffs (Phase 4.5), not for API mapping
DEPLOYED_INDEX_PATH=""
if [[ -f artifacts/found-indexes.json ]]; then
  # Always use cadashboardbe index for API mapping (APIs are always in dashboard)
  DEPLOYED_INDEX_PATH=$(jq -r ".indexes[\"cadashboardbe\"].deployed.index_path // empty" artifacts/found-indexes.json 2>/dev/null || echo "")
  
  # Check if local file exists (for development/testing)
  if [[ -z "$DEPLOYED_INDEX_PATH" ]] && [[ -f "../../../cadashboardbe/docs/indexes/code-index.json" ]]; then
    DEPLOYED_INDEX_PATH="../../../cadashboardbe/docs/indexes/code-index.json"
    echo "✅ Using local code index (for development)"
  fi
fi

# Check if we found an index
if [[ -z "$DEPLOYED_INDEX_PATH" ]]; then
  echo ""
  echo "❌ ERROR: Could not find any code index"
  echo "   Check found-indexes.json for details"
  echo ""
  echo "💡 To fix:"
  echo "   - Ensure code-index-generation workflow ran for ${DEPLOYED_VERSION:-the deployed version}"
  echo "   - Check artifact retention (90 days for versions, 7 for latest)"
  exit 0
fi

echo ""
echo "✅ Code Index Resolution Complete"
echo "   Using: $DEPLOYED_INDEX_PATH"
echo "   Index size: $(du -h "$DEPLOYED_INDEX_PATH" | cut -f1)"
echo "================================================================"
echo ""

INDEX_PATH="$DEPLOYED_INDEX_PATH"

# Note: Index download is complete. Even if we skip API mapping (no test name),
# the indexes are available for Phase 4.5 (code diffs) and Phase 7 (LLM context).


#!/bin/bash
set -euxo pipefail

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
TRIGGERING_REPO="$TRIGGERING_REPO_FROM_STEP"

# Prefer new format (test-deployed-services.json), fallback to legacy (running-images.json)
TAG_FILE=""
if [[ -f artifacts/test-deployed-services.json ]]; then
  TAG_FILE="artifacts/test-deployed-services.json"
  echo "🔍 DEBUG (Phase 4): Using new format (test-deployed-services.json)"
elif [[ -f artifacts/running-images.json ]]; then
  TAG_FILE="artifacts/running-images.json"
  echo "🔍 DEBUG (Phase 4): Using legacy format (running-images.json)"
fi

if [[ -n "$TAG_FILE" ]]; then
  echo "🔍 DEBUG (Phase 4): Keys in $TAG_FILE:"
  jq 'keys' "$TAG_FILE" || echo "Failed to parse JSON"
  
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
    
    # Extract global RC version
    GLOBAL_RC_VERSION="$INPUT_RC_VERSION"
    echo "🔍 DEBUG: inputs.rc_version = '$INPUT_RC_VERSION'"
    echo "🔍 DEBUG: GLOBAL_RC_VERSION (from input) = '$GLOBAL_RC_VERSION'"
    if [[ -z "$GLOBAL_RC_VERSION" || "$GLOBAL_RC_VERSION" == "null" || "$GLOBAL_RC_VERSION" == "unknown" ]]; then
      GLOBAL_RC_VERSION=$(jq -r '.triggering_repo.rc_version // empty' "$TAG_FILE" 2>/dev/null || echo "")
      echo "🔍 DEBUG: GLOBAL_RC_VERSION (from JSON) = '$GLOBAL_RC_VERSION'"
    fi
  else
    # Legacy format
    echo "🔍 DEBUG (Phase 4): Repos in running-images.json:"
    jq '.repos | keys' "$TAG_FILE" || echo "Failed to parse JSON"
    
    DETECTED_REPO=$(jq -r '.triggering_repo_normalized // empty' "$TAG_FILE" 2>/dev/null || echo "")
    if [[ -n "$DETECTED_REPO" && "$DETECTED_REPO" != "null" ]]; then
      TRIGGERING_REPO="$DETECTED_REPO"
      echo "📦 Using triggering repo from running-images.json: $TRIGGERING_REPO"
    fi
    
    # Extract the tag currently running in the cluster for the triggering repo
    ACTUAL_DEPLOYED_VERSION=$(jq -r --arg repo "$TRIGGERING_REPO" '.repos[$repo].images[0].tag // empty' "$TAG_FILE" 2>/dev/null || echo "")
    
    # Extract global RC version
    GLOBAL_RC_VERSION="$INPUT_RC_VERSION"
    echo "🔍 DEBUG: inputs.rc_version = '$INPUT_RC_VERSION'"
    echo "🔍 DEBUG: GLOBAL_RC_VERSION (from input) = '$GLOBAL_RC_VERSION'"
    if [[ -z "$GLOBAL_RC_VERSION" || "$GLOBAL_RC_VERSION" == "null" || "$GLOBAL_RC_VERSION" == "unknown" ]]; then
      GLOBAL_RC_VERSION=$(jq -r '.rc_version // empty' "$TAG_FILE" 2>/dev/null || echo "")
      echo "🔍 DEBUG: GLOBAL_RC_VERSION (from JSON legacy) = '$GLOBAL_RC_VERSION'"
    fi
  fi
    
  echo "🔍 DEBUG (Phase 4): ACTUAL_DEPLOYED_VERSION='${ACTUAL_DEPLOYED_VERSION}'"
  echo "🔍 DEBUG (Phase 4): TRIGGERING_REPO='${TRIGGERING_REPO}'"

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

# Extract triggering repo commit - PRIORITY: Use commit from RC version
# The RC version is created from the actual merge commit (before code index commit)
# This ensures we get the right commit even if code index workflow created a new commit
TRIGGERING_REPO_COMMIT=""

# Priority 1: Extract commit from RC version (if available)
# RC version format: rc-v0.0.394-20549238574 or rc-v0.0.394-PR_NUMBER
# The RC is created from the merge commit, so we need to get that commit from GitHub
if [[ -n "$RC_VERSION" && "$RC_VERSION" =~ ^rc-v ]]; then
  echo "🔍 Extracting triggering repo commit from RC version: $RC_VERSION"
  
  # Get the commit that the RC tag points to
  RC_COMMIT=$(gh api repos/armosec/$TRIGGERING_REPO/git/refs/tags/$RC_VERSION --jq '.object.sha' 2>/dev/null || echo "")
  
  if [[ -n "$RC_COMMIT" && "$RC_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    TRIGGERING_REPO_COMMIT="$RC_COMMIT"
    echo "✅ Found triggering repo commit from RC tag: ${TRIGGERING_REPO_COMMIT:0:8}"
  else
    echo "⚠️  RC tag $RC_VERSION not found or invalid, trying alternative methods..."
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

if [[ -n "$DEPLOYED_INDEX" && -f "$DEPLOYED_INDEX" && -n "$RC_INDEX" && -f "$RC_INDEX" ]]; then
  echo "📊 Comparing dependencies between deployed and RC versions"
  # Use same version for both code index and go.mod (no mismatch)
  echo "📌 Using DEPLOYED_VERSION for go.mod: ${DEPLOYED_VERSION:-unknown} (same as code index)"
  python extract_gomod_dependencies.py \
    --deployed-code-index "$DEPLOYED_INDEX" \
    --rc-code-index "$RC_INDEX" \
    --triggering-repo "$TRIGGERING_REPO" \
    --deployed-version "$GOMOD_DEPLOYED_VERSION" \
    --output artifacts/gomod-dependencies.json \
    --github-token "$GITHUB_TOKEN" \
    --debug || {
    echo "⚠️  go.mod comparison failed"
    echo "{}" > artifacts/gomod-dependencies.json
  }
elif [[ -n "$DEPLOYED_INDEX" && -f "$DEPLOYED_INDEX" ]]; then
  echo "⚠️  RC index not available, using deployed index only"
  # Use same version for both code index and go.mod (no mismatch)
  echo "📌 Using DEPLOYED_VERSION for go.mod: ${DEPLOYED_VERSION:-unknown} (same as code index)"
  python extract_gomod_dependencies.py \
    --code-index "$DEPLOYED_INDEX" \
    --triggering-repo "$TRIGGERING_REPO" \
    --deployed-version "$GOMOD_DEPLOYED_VERSION" \
    --output artifacts/gomod-dependencies.json \
    --github-token "$GITHUB_TOKEN" \
    --debug || {
    echo "⚠️  go.mod extraction failed"
    echo "{}" > artifacts/gomod-dependencies.json
  }
else
  echo "⚠️  No code indexes available for go.mod extraction"
  echo "{}" > artifacts/gomod-dependencies.json
fi

# ====================================================================
# PASS 3: Download dependency indexes using gomod-dependencies.json
# ====================================================================
echo ""
echo "📥 PASS 3: Downloading dependency indexes..."

if [[ -f artifacts/gomod-dependencies.json ]] && [[ $(jq 'length' artifacts/gomod-dependencies.json) -gt 0 ]]; then
  echo "✅ Found $(jq 'length' artifacts/gomod-dependencies.json) dependencies"
  python find_indexes.py \
    --triggering-repo "$TRIGGERING_REPO" \
    --deployed-version "${DEPLOYED_VERSION:-unknown}" \
    --rc-version "${RC_VERSION:-unknown}" \
    --triggering-commit "${TRIGGERING_REPO_COMMIT:-unknown}" \
    --images "artifacts/test-deployed-services.json" \
    --services-only "artifacts/services-only.json" \
    --output-dir "artifacts/code-indexes" \
    --output "artifacts/found-indexes.json" \
    --github-token "$GITHUB_TOKEN" \
    --github-orgs "armosec,kubescape" \
    --gomod-dependencies artifacts/gomod-dependencies.json \
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


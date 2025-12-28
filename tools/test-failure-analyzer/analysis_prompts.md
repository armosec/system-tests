# Test Failure Analysis Context

## Test Run Information
- **Test Name**: {test_name}
- **Test Run ID**: {test_run_id}
- **Environment**: {environment}
- **Workflow Run**: {workflow_run_url}

## Repository Information
- **Triggering Repository**: {triggering_repo}
- **Commit**: {triggering_commit}
- **PR Number**: {pr_number} (if applicable)
- **PR Title**: {pr_title}
- **PR Author**: {pr_author}
- **Changed Files**: {changed_files_count} files

## Backend Service Information
- **Tested Services**: {tested_services}
- **Image Tags**: {image_tags}
- **Deployment Namespace**: {namespace}

## Timing
- **Test Start Time**: {test_start_time}
- **Test Duration**: {test_duration}
- **Failure Time**: {failure_time}

---

# Analysis Instructions

⚠️ **CRITICAL: Follow this analysis order. Do NOT skip steps or make assumptions.**

## 🚨 Mandatory Analysis Flow

**You MUST follow these steps in order. Do not analyze code changes until you've completed steps 1-3.**

### Step 1: Identify the Exact API Endpoint
**DO THIS FIRST - Before looking at code changes**

1. Read the test code to understand what API is being called
2. Identify the EXACT API endpoint:
   - HTTP method (GET, POST, PUT, DELETE, etc.)
   - Full path (e.g., `/api/v1/posture/resources`)
   - All query parameters (e.g., `?relatedExceptions=true&customerGUID=...`)
   - Request body (if applicable)
3. Document the API call with all parameters

**Example:**
```
API: POST /api/v1/posture/resources
Query Params: relatedExceptions=true, customerGUID=3f4a257e-...
Body: {"pageNum": 1, "pageSize": 150, "innerFilters": [...]}
```

### Step 2: Trace the Execution Flow
**DO THIS SECOND - Map the code path**

1. Find the handler function that processes this API endpoint
2. Trace through the handler code step-by-step:
   - What does the handler do first?
   - What functions does it call?
   - What services/connectors does it use?
   - Where does it get data from?
3. Document the complete execution path

**Example:**
```
Handler: postureReportResourceHandler (httphandlerv2/posturehandler.go:437)
Flow:
  1. Reads relatedExceptions=true from query params (line 442)
  2. Calls RetrievePostureReportResourcesSummaryClientPagination (line 459)
  3. Calls GetPostureExceptionPolicies from config-service (line 616)
  4. Sets resp.Response[i].RelatedExceptions = definedExceptions (line 651)
```

### Step 3: Understand What Should Happen
**DO THIS THIRD - Define expected behavior**

1. Based on the test, what is the expected behavior?
2. What is the actual behavior (from error message)?
3. What's the difference between expected and actual?

**Example:**
```
Expected: After deleting all exceptions, relatedExceptions should be empty []
Actual: relatedExceptions contains exceptions even after deletion
Difference: Config-service is returning exceptions when it shouldn't
```

### Step 4: Check Code Changes (ONLY AFTER Steps 1-3)
**NOW you can look at code changes, but verify connections**

1. Review code changes in the execution path you traced
2. **VERIFY each connection:**
   - Search for changed function names in the handler code
   - Check if changed functions are imported/called
   - Verify the change affects the execution path
3. **DO NOT assume connections based on keyword similarity**
   - Just because two things have similar names doesn't mean they're related
   - Example: `insertRelatedFieldsIntoLabels` ≠ `relatedExceptions` (different domains!)

**Verification Checklist:**
- [ ] Is the changed function called in the execution path? (Search for it!)
- [ ] Is the changed file imported in the handler? (Check imports!)
- [ ] Does the change affect the logic that processes this API? (Read the code!)
- [ ] Can you show the exact call site? (Provide line numbers!)

### Step 5: Root Cause Analysis
**Only after verifying connections**

1. If code changes ARE related:
   - Explain how the change affects the execution path
   - Show the exact line where the issue occurs
   - Explain WHY the failure happened

2. If code changes are NOT related:
   - Look elsewhere (caching, timing, data issues, other services)
   - Check if the issue is in a different part of the codebase
   - Consider infrastructure/environmental factors

## 1. Failing API Call
- **EXACT API endpoint** (method + path) - from Step 1
- **All parameters** (query params, body) - from Step 1
- **Code path taken** - from Step 2

## 2. Root Cause
- **Complete execution flow** - from Step 2
- **Exact line of code** where issue occurs - from Step 4 (if related)
- **WHY it failed** - from Step 3 and Step 5
- **Evidence** - code references, log excerpts, error messages

## 3. Missing Data Analysis
- What data is missing from the LLM context that would help diagnose this better?
  - Database schema information?
  - Additional function implementations?
  - Configuration values?
  - Related code from other services?
- What logging would be helpful?
- What additional code chunks should be captured?

## 4. Suggested Fixes
- Provide specific code changes needed
- Include file paths and function names
- Explain the impact of the fix

## 5. Context Usage Guidelines
When analyzing this failure, make use of the context information above:
- **Test Information**: Use the test name and run ID to understand what was being tested
- **Repository/Commit**: Reference the specific commit and PR to understand recent changes
- **Changed Files**: ⚠️ **DO NOT assume changed files are related** - verify they're in the execution path first!
- **Environment**: Consider environment-specific configuration (dev vs staging vs production)
- **Services/Images**: Identify which backend services were involved and their versions
- **Timing**: Use timestamps to correlate with log entries and understand failure sequence

## 6. Common Pitfalls to Avoid

### ❌ DON'T: Pattern Match on Keywords
**Wrong:** "I see `insertRelatedFieldsIntoLabels` was removed and the test fails on `relatedExceptions` - they must be related!"

**Right:** "Let me search for `insertRelatedFieldsIntoLabels` in the handler code... Not found. They're not related."

### ❌ DON'T: Analyze Code Changes Before Tracing Flow
**Wrong:** Start with code diffs → See removed function → Assume it's the cause

**Right:** Trace execution flow → Identify handler → Check if changed function is called → Verify connection

### ❌ DON'T: Make Assumptions Without Evidence
**Wrong:** "This function was removed, so it must be causing the issue."

**Right:** "This function was removed. Let me verify: grep shows it's not called in the handler. Conclusion: Not related."

### ✅ DO: Use Code Search to Verify
Before claiming a connection, search for it:
```bash
grep -r "functionName" path/to/handler/file
# If not found → Not related!
```

### ✅ DO: Provide Evidence
Always include:
- File paths and line numbers
- Code references showing the connection
- Log excerpts supporting your analysis
- Execution flow trace

## 7. Response Format
Please structure your analysis as:
```
### Summary
[Brief 1-2 sentence summary of the root cause]

### API Endpoint Analysis (Step 1)
- **Endpoint**: [method + path]
- **Parameters**: [query params, body]
- **Test expectation**: [what the test expects]

### Execution Flow (Step 2)
- **Handler**: [file:line]
- **Flow**: [step-by-step trace]
  1. Handler does X
  2. Calls function Y
  3. Gets data from service Z
  4. Returns result

### Expected vs Actual (Step 3)
- **Expected**: [what should happen]
- **Actual**: [what actually happened]
- **Difference**: [the gap]

### Code Changes Analysis (Step 4)
- **Changed functions**: [list]
- **Verification**: [did you search for them in the handler?]
- **Connection**: [are they called in the execution path?]
- **Evidence**: [code references or "not found"]

### Root Cause (Step 5)
[The specific issue - only after verifying connections]
- **Location**: [file:line]
- **Why**: [explanation]
- **Evidence**: [code/log excerpts]

### Recommended Fix
[Specific code changes with file paths and line numbers]

### Prevention
[How to prevent this issue in the future]
```


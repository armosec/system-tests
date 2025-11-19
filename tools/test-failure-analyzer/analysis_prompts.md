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

When analyzing this test failure, please provide:

## 1. Failing API Call
- Identify the EXACT API endpoint that failed (method + path)
- List all parameters passed to the API
- Show the request body/query parameters
- Indicate which code path was taken (if multiple paths exist)

## 2. Root Cause
- Trace the complete execution flow from API call to failure point
- Identify the exact line of code where the issue occurs
- Explain WHY the failure happened (missing data, wrong logic, etc.)

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
- **Changed Files**: Focus analysis on files that were modified in this PR (if available)
- **Environment**: Consider environment-specific configuration (dev vs staging vs production)
- **Services/Images**: Identify which backend services were involved and their versions
- **Timing**: Use timestamps to correlate with log entries and understand failure sequence

## 6. Response Format
Please structure your analysis as:
```
### Summary
[Brief 1-2 sentence summary of the root cause]

### Detailed Analysis
[Step-by-step breakdown of the failure]

### Root Cause
[The specific code issue that caused the failure]

### Recommended Fix
[Specific code changes with file paths and line numbers]

### Prevention
[How to prevent this issue in the future]
```


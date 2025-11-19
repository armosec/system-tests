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


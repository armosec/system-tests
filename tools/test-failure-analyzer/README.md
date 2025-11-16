### Test Failure Analyzer (Phase 1 - MVP)

**Purpose**: Given a GitHub Actions run (shared-workflows), collect failing system tests, map them to relevant repos/services via `system_test_mapping.json`, extract identifiers (customer GUID, cluster), pull focused Grafana Loki logs, and generate a concise Markdown/JSON report.

#### Quick start
1. Create config from example:
   - `cp config.example.yaml config.yaml`
2. Install deps:
   - `python3 -m venv .venv && source .venv/bin/activate`
   - `pip install -r requirements.txt`
3. Run:
   - `python analyzer.py --run-url https://github.com/armosec/shared-workflows/actions/runs/<RUN_ID> --output-dir ./artifacts`
   - Optional verbose: add `--debug`

Flags:
- `--run-url` or `--run-id` (one required)
- `--time-padding` default `10m` (accepted: e.g., `5m`, `15m`, `1h`)
- `--mapping` path to `system_test_mapping.json` (default points to repo root)
- `--output-dir` folder to place `report.md` and `report.json`
- Optional overrides: `--customer-guid`, `--cluster`
- Optional: `--debug` to print inferred service and query counts per failure
- Optional: `--fetch-pr` to fetch PR info/files into `artifacts/context/pr.json`
- Optional: `--bundle-tests` to write per-test section logs/meta into `artifacts/context/tests`
- Optional: `--map-cadb` to generate a placeholder endpoint map json
- Optional: `--fetch-loki` to create `artifacts/context/logs/excerpts.json` placeholder (Phase 2 will fetch real excerpts)
- Optional: `--only-test "<mapping_key>"` to analyze only a specific test (use mapping key as in `system_test_mapping.json`), e.g. `--only-test basic_incident_presented`

#### What the MVP does now
- Downloads the run logs ZIP via GitHub API, parses all jobs, and focuses on Step 18 sections for system tests.
- Extracts failing tests and their full Step 18 section content.
- Infers the triggering service from `GITHUB_REPOSITORY` (repo basename). If not detected from logs, falls back to ZIP scan and run metadata. If still unknown, exits with error.
- Forces analysis to that single service (plus `cadashboardbe` always) and generates Loki queries from config templates (namespace + app).
- Extracts identifiers (customer GUID, clusterName) from logs.
- Extracts time window (first/last ISO8601 in Step 18) and adds ±5 minutes padding; shows it under Loki queries for each failure.
- Extracts error lines (e.g., `run_test: Test error`, `ERROR`, `Error:` and Tracebacks) and prints top lines under each failure.
- Emits structured `report.json` and human `report.md`.

#### Configuration
See `config.example.yaml` for GitHub/Loki endpoints and auth. Environment-variable interpolation is supported for secrets (e.g., `${GITHUB_TOKEN}`).

- Loki templates (used in Phase 1) must include both `{namespace}` and `{app}` label keys:
  - Example:
    - `event-ingester-service: '{{{namespace}="event-sourcing-be-stage", {app}="event-ingester-service", {level_selector}}} {id_filters}'`
  - The analyzer renders templates even when the service is inferred from the workflow.
  - No fallback services are used; analyzer fails if service cannot be detected.

#### Next steps (Phase 1)
- [Done] GitHub logs fetch + test parsing + time window and errors.
- [Optional] Add `--fetch-loki` to execute queries and embed top error excerpts.
- [Optional] Enrich PR context (changed files/diffs) and test-to-handler mapping.

#### Notes
- Mapping file: `system-tests/system_test_mapping.json` is the source of truth.
- Tests with `"dummy"` in the name are skipped.
- Time window for Loki is derived from Step 18 timestamps ± padding.
- Analyzer always includes `cadashboardbe` logs alongside the triggering service for API-path failures.

#### Outputs
- `artifacts/report.md`: human-readable summary per failing test:
  - Repos, Services
  - Identifiers
  - Time window and Loki queries (with time window noted)
  - Error lines
- `artifacts/report.json`: machine-readable structure with all fields (including `loki.from_time` and `loki.to_time`).
- `artifacts/context/` (for Cursor exploration):
  - `summary.json`: run summary and counts
  - `tests/*.json` and `tests/*.log`: per-failure meta and full Step 18 section text
  - `logs/queries.json`: list of Loki queries with from/to
  - `pr.json` (when `--fetch-pr`)
  - `cadashboard_endpoints.json` (when `--map-cadb`)
  - `logs/excerpts.json` (when `--fetch-loki`, placeholder in Phase 1)



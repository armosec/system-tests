#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import zipfile
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from dateutil import parser as dateparser
from datetime import datetime, timezone, timedelta as td
import subprocess
import shutil
import glob
try:
    from rich.console import Console
except ImportError:
    # Fallback if rich not available (should not happen if requirements.txt is installed)
    class Console:
        def print(self, *args, **kwargs):
            print(*args)

from schemas import Report, RunInfo, FailureEntry, Identifiers, MappingInfo, LokiData
try:
    from detect_cross_test_interference import detect_cross_test_interference
except ImportError:
    # Fallback if module not available
    def detect_cross_test_interference(*args, **kwargs):
        return []

console = Console()

# Known service names mapped from repository basenames
KNOWN_SERVICE_NAMES = {
    "cadashboardbe": "cadashboardbe",
    "event-ingester-service": "event-ingester-service",
    "config-service": "config-service",
    "users-notification-service": "users-notification-service",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="System test failure analyzer (Phase 1 MVP)")
    parser.add_argument("--run-url", help="GitHub Actions run URL")
    parser.add_argument("--run-id", help="GitHub Actions run ID")
    parser.add_argument("--time-padding", default=None, help="Padding around run time window (e.g., 10m, 1h)")
    parser.add_argument("--mapping", default=None, help="Path to system_test_mapping.json")
    parser.add_argument("--output-dir", default="./artifacts", help="Output directory for reports")
    parser.add_argument("--customer-guid", default=None, help="Override customer GUID")
    parser.add_argument("--cluster", default=None, help="Override cluster name")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--logs-zip", default=None, help="Path to a pre-downloaded GitHub Actions run logs ZIP")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    # Context bundling flags
    parser.add_argument("--fetch-pr", action="store_true", help="Fetch PR info and changed files into artifacts/context")
    parser.add_argument("--bundle-tests", action="store_true", help="Bundle test files/sections into artifacts/context/tests")
    parser.add_argument("--map-cadb", action="store_true", help="Generate lightweight cadashboard endpoint map (placeholder)")
    parser.add_argument("--fetch-loki", action="store_true", help="Fetch Loki excerpts (placeholder)")
    parser.add_argument("--only-test", default=None, help="Analyze only a specific test (use mapping key as it appears in mapping file)")
    parser.add_argument("--bundle-test-sources", action="store_true", help="Copy matching system-tests source files into context")
    parser.add_argument("--bundle-repos", action="store_true", help="Clone or link triggering repo and cadashboardbe into context")
    return parser.parse_args()


def load_config(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        example = Path(__file__).with_name("config.example.yaml")
        console.print(f"[yellow]Config not found at {path}. Using defaults from {example.name} if present.[/yellow]")
        if example.exists():
            with open(example, "r") as f:
                return yaml.safe_load(f) or {}
        return {}
    with open(path, "r") as f:
        raw = f.read()
    # environment variable interpolation like ${VAR}
    raw = os.path.expandvars(raw)
    return yaml.safe_load(raw) or {}


def parse_duration(s: Optional[str], default: str) -> timedelta:
    val = s or default
    m = re.match(r"^(\d+)([smhd])$", val)
    if not m:
        return timedelta(minutes=10)
    num = int(m.group(1))
    unit = m.group(2)
    if unit == "s":
        return timedelta(seconds=num)
    if unit == "m":
        return timedelta(minutes=num)
    if unit == "h":
        return timedelta(hours=num)
    if unit == "d":
        return timedelta(days=num)
    return timedelta(minutes=10)


def resolve_run_info(run_url: Optional[str], run_id: Optional[str], cfg: Dict[str, Any]) -> RunInfo:
    if not run_url and not run_id:
        console.print("[red]--run-url or --run-id is required[/red]")
        sys.exit(2)

    # Parse owner/repo/run_id from URL if provided
    owner = "armosec"
    repo = "shared-workflows"
    rid = run_id
    if run_url:
        # Expected: https://github.com/{owner}/{repo}/actions/runs/{id}
        m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/actions/runs/(\d+)", run_url.strip())
        if m:
            owner, repo, rid = m.group(1), m.group(2), m.group(3)
        else:
            console.print("[yellow]Unable to parse run URL; falling back to provided --run-id[/yellow]")
    if not rid:
        # If still missing, last path segment
        rid = run_url.rstrip("/").split("/")[-1] if run_url else None
    if not rid:
        console.print("[red]Unable to determine run id[/red]")
        sys.exit(2)

    import requests
    base = cfg.get("github", {}).get("api_base_url", "https://api.github.com").rstrip("/")
    token = os.environ.get("GITHUB_TOKEN") or cfg.get("github", {}).get("token")
    headers = {"Accept": "application/vnd.github+json"}
    if token and "${" not in str(token):
        headers["Authorization"] = f"Bearer {token}"

    run_api = f"{base}/repos/{owner}/{repo}/actions/runs/{rid}"
    r = requests.get(run_api, headers=headers, timeout=60)
    if r.status_code != 200:
        console.print(f"[yellow]Failed to fetch run info ({r.status_code}); continuing with minimal info[/yellow]")
        return RunInfo(id=str(rid), repo=f"{owner}/{repo}")
    data = r.json()
    return RunInfo(
        id=str(data.get("id") or rid),
        repo=f"{owner}/{repo}",
        branch=(data.get("head_branch") or None),
        commit=(data.get("head_sha") or None),
        started_at=(data.get("run_started_at") or None),
        completed_at=(data.get("updated_at") or None),
    )


def download_and_parse_logs(run: RunInfo, cfg: Dict[str, Any], logs_zip_path: Optional[str] = None) -> Tuple[List[str], str]:
    # Downloads the run logs ZIP (or uses provided ZIP) and returns lines that look like failures + full combined text
    import time
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    m = re.match(r"^([^/]+)/([^/]+)$", run.repo or "")
    owner, repo = (m.group(1), m.group(2)) if m else ("armosec", "shared-workflows")

    tmp_zip = None
    cleanup_tmp = False

    # If pre-downloaded logs ZIP is provided, use it instead of downloading
    if logs_zip_path and os.path.exists(logs_zip_path):
        console.print(f"[cyan]Using pre-downloaded logs ZIP: {logs_zip_path}[/cyan]")
        tmp_zip = Path(logs_zip_path)
        cleanup_tmp = False  # Don't delete user-provided file
    else:
        # Download from GitHub API
        base = cfg.get("github", {}).get("api_base_url", "https://api.github.com").rstrip("/")
        token = os.environ.get("GITHUB_TOKEN") or cfg.get("github", {}).get("token")

        # Two header sets: JSON for run info; ZIP for logs endpoint
        json_headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "armosec-test-failure-analyzer/1.0",
        }
        # For logs endpoint, GitHub returns a 302 to a ZIP URL. Using JSON Accept is fine.
        # Some orgs return 415 when Accept is not JSON, so prefer JSON here.
        zip_headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "armosec-test-failure-analyzer/1.0",
        }
        if token and "${" not in str(token):
            json_headers["Authorization"] = f"Bearer {token}"
            zip_headers["Authorization"] = f"Bearer {token}"

        logs_api = f"{base}/repos/{owner}/{repo}/actions/runs/{run.id}/logs"
        console.print(f"[cyan]Downloading logs ZIP from {logs_api}[/cyan]")

        # Session with retries for transient network/S3 issues
        session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        tmp_zip = Path(".") / f"_run_{run.id}_logs.zip"
        cleanup_tmp = True  # Clean up downloaded file

        # Non-streamed download with retries and redirects
        try:
            resp = session.get(logs_api, headers=zip_headers, timeout=(10, 300), allow_redirects=True)
            if resp.status_code == 415 or resp.status_code == 406:
                # Retry with no Accept header as a fallback
                console.print(f"[yellow]Got {resp.status_code}. Retrying without Accept header...[/yellow]")
                alt_headers = dict(zip_headers)
                alt_headers.pop("Accept", None)
                resp = session.get(logs_api, headers=alt_headers, timeout=(10, 300), allow_redirects=True)
            if resp.status_code != 200:
                console.print(f"[yellow]Failed to fetch logs ZIP ({resp.status_code}). URL may be expired or token lacks permissions.[/yellow]")
                return [], ""
            with open(tmp_zip, "wb") as f:
                f.write(resp.content)
        except requests.exceptions.RequestException as e:
            console.print(f"[yellow]Error downloading logs ZIP: {e}[/yellow]")
            return [], ""

    combined = []
    try:
        with zipfile.ZipFile(tmp_zip, "r") as zf:
            names = zf.namelist()
            console.print(f"[cyan]Processing {len(names)} files from logs ZIP[/cyan]")
            for name in names:
                # Only text files
                if not name.lower().endswith((".txt", ".log")):
                    continue
                try:
                    content = zf.read(name).decode("utf-8", errors="replace")
                    # Focus on system-tests content; include if:
                    # - file name indicates system-tests call job, or
                    # - content contains Step 18 markers, or
                    # - file name looks like an ST (suite) job, or
                    # - content mentions call-system-tests
                    include = False
                    if ("call-system-tests" in name.lower() or
                        re.search(r"\bST\s*\(", name) or
                        "system-tests" in name.lower() or
                        "call-system-tests" in content or
                        "Step 18" in content or
                        "Step 18 - run system tests" in content or
                        "GITHUB_REPOSITORY" in content):
                        include = True
                    if not include:
                        continue
                    combined.append(f"\n===== {name} =====\n")
                    combined.append(content)
                except Exception:
                    continue
    finally:
        # Only cleanup if we downloaded the file (not user-provided)
        if cleanup_tmp:
            try:
                tmp_zip.unlink(missing_ok=True)
            except Exception:
                pass

    full_text = "".join(combined)
    fail_lines = []
    # Broad failure indicators across Go tests, bash, and general logs
    patterns = [
        r"^--- FAIL: .+$",
        r"^FAIL\s+.+$",
        r"^\s*✗ .+$",
        r"^not ok\b.+$",
        r"\bERROR\b.+",
        r"\bTest failed\b.+",
        r"^=== FAIL\s+.+$",
        r"Error: Process completed with exit code 1\.",
    ]
    for line in full_text.splitlines():
        for pat in patterns:
            if re.search(pat, line):
                fail_lines.append(line)
                break
    console.print(f"[green]Collected {len(fail_lines)} failure-indicative lines from Step 18 logs[/green]")
    return fail_lines, full_text


def parse_failing_tests(log_text: str) -> List[Dict[str, Any]]:
    # Heuristic parser that scans per-log-section and extracts failing test names
    # from common patterns: Go ('--- FAIL: <name>') and ST(<name>) job names.
    if not log_text:
        return []

    results: List[Dict[str, Any]] = []

    # Split the combined text into sections we added: "===== <name> ====="
    section_pattern = re.compile(r"\n===== (.+?) =====\n")
    sections: List[Tuple[str, str]] = []
    last_end = 0
    last_name = "combined"
    for m in section_pattern.finditer(log_text):
        # previous chunk
        if last_end > 0:
            prev_chunk = log_text[last_end:m.start()]
            sections.append((last_name, prev_chunk))
        last_name = m.group(1)
        last_end = m.end()
    # tail
    if last_end > 0:
        sections.append((last_name, log_text[last_end:]))
    if not sections:
        sections.append(("combined", log_text))

    fail_indicator_patterns = [
        r"Error: Process completed with exit code 1\.",
        r"^--- FAIL: .+$",
        r"^FAIL\s+.+$",
        r"^=== FAIL\s+.+$",
        r"\bTest failed\b",
        r"\bERROR\b",
    ]
    
    # Pattern for ST(<name>) test names
    st_pattern = r"ST\s*\(([^)]+)\)"

    for sec_name, sec_text in sections:
        # Extract test names first (we'll filter by failure status later if needed)
        # Extract Go test failure names
        for m in re.finditer(r"^--- FAIL: ([^\s]+)(?:\s+\(.+\))?", sec_text, re.MULTILINE):
            name = m.group(1)
            start = m.start()
            snippet = sec_text[start:start + 2000]
            results.append({"name": name, "file": None, "suite": None, "raw": snippet, "section": sec_text})

        # Extract ST(<name>) style names from job logs (match anywhere, not just start of line)
        # Also try to extract from section name if it contains ST(...)
        for m in re.finditer(st_pattern, sec_text, re.MULTILINE):
            name = m.group(1).strip()
            start = m.start()
            snippet = sec_text[start:start + 2000]
            results.append({"name": name, "file": None, "suite": None, "raw": snippet, "section": sec_text})
        
        # Also try to extract ST(...) from section name itself (file names often contain this)
        sec_st_match = re.search(st_pattern, sec_name)
        if sec_st_match:
            name = sec_st_match.group(1).strip()
            # Only add if we haven't already added this name from the section text
            if not any(r.get("name") == name for r in results):
                trimmed = sec_text[:2000]
                results.append({"name": name, "file": None, "suite": None, "raw": trimmed, "section": sec_text})

        # If nothing matched, use the section name as a fallback
        if not any(r.get("raw") in sec_text for r in results[-2:]):
            # Add a minimal entry with the section name
            trimmed = sec_text[:2000]
            results.append({"name": sec_name, "file": None, "suite": None, "raw": trimmed, "section": sec_text})
    
    # Filter by failure status: only keep tests that look like failures
    # BUT: include ALL tests extracted from ST() patterns (they may have succeeded but still be relevant)
    # The caller will filter by --only-test and failure status as needed
    filtered_results = []
    for r in results:
        sec_text = r.get("section", "")
        test_name = r.get("name", "")
        looks_failed = any(re.search(p, sec_text, re.MULTILINE) for p in fail_indicator_patterns)
        
        # Find which section this result came from to check if it has ST() pattern
        original_sec_name = None
        for sec_n, sec_t in sections:
            if sec_t == sec_text or (sec_text and len(sec_text) > 0 and sec_text[:100] in sec_t[:200]):
                original_sec_name = sec_n
                break
        
        # Include if:
        # 1. It looks failed (has failure indicators), OR
        # 2. It was extracted from an ST() pattern (these are actual test names, even if they succeeded)
        #    - Test names extracted from ST() patterns are clean names like "stripe_plans"
        #    - Section names containing ST() look like "call-system-tests-staging / ST (stripe_plans)/..."
        is_st_test = False
        if original_sec_name and re.search(st_pattern, original_sec_name):
            # This test was extracted from a section name containing ST()
            is_st_test = True
        elif test_name and not "/" in test_name and not "\\" in test_name:
            # Simple test name (not a file path) - likely extracted from ST() pattern
            # Check if any section name contains this test name in ST() format
            for sec_n, _ in sections:
                if re.search(rf"ST\s*\(\s*{re.escape(test_name)}\s*\)", sec_n):
                    is_st_test = True
                    break
        
        if looks_failed or is_st_test:
            filtered_results.append(r)
    
    results = filtered_results

    # Deduplicate by name
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for r in results:
        key = (r.get("name") or r.get("raw") or "")[:256]
        if key and key not in seen:
            seen.add(key)
            deduped.append(r)

    return deduped


def parse_all_tests_with_timestamps(log_text: str) -> List[Dict[str, Any]]:
    """
    Extract ALL tests from raw_log (including successful ones) with timestamps.
    Similar to parse_failing_tests() but includes all tests, not just failures.
    
    Returns:
        List of dicts with {name, time_start, time_end, section_text}
    """
    if not log_text:
        return []
    
    results: List[Dict[str, Any]] = []
    
    # Split the combined text into sections: "===== <name> ====="
    section_pattern = re.compile(r"\n===== (.+?) =====\n")
    sections: List[Tuple[str, str]] = []
    last_end = 0
    last_name = "combined"
    for m in section_pattern.finditer(log_text):
        if last_end > 0:
            prev_chunk = log_text[last_end:m.start()]
            sections.append((last_name, prev_chunk))
        last_name = m.group(1)
        last_end = m.end()
    if last_end > 0:
        sections.append((last_name, log_text[last_end:]))
    if not sections:
        sections.append(("combined", log_text))
    
    # Pattern for ST(<name>) test names
    st_pattern = r"ST\s*\(([^)]+)\)"
    
    for sec_name, sec_text in sections:
        # Extract test names from ST() patterns (these are actual test names)
        test_name = None
        
        # Try to extract from section name first
        sec_st_match = re.search(st_pattern, sec_name)
        if sec_st_match:
            test_name = sec_st_match.group(1).strip()
        else:
            # Try to extract from section text
            for m in re.finditer(st_pattern, sec_text, re.MULTILINE):
                test_name = m.group(1).strip()
                break
        
        # If no ST() pattern found, skip this section (it's not a test)
        if not test_name:
            continue
        
        # Extract timestamps from this section
        first_ts, last_ts, _, _, _ = extract_time_window_and_errors(sec_text, padding_minutes=0)
        
        results.append({
            'name': test_name,
            'time_start': first_ts,
            'time_end': last_ts,
            'section_text': sec_text,
            'section_name': sec_name
        })
    
    # Deduplicate by name
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for r in results:
        name = r.get('name')
        if name and name not in seen:
            seen.add(name)
            deduped.append(r)
    
    return deduped


def load_mapping(path: Optional[str], cfg_defaults_path: Optional[str]) -> Dict[str, Any]:
    mapping_path = path or cfg_defaults_path
    if not mapping_path:
        # default relative to repo root:
        # prefer the richer artifact mapping (methods + tested_dashboard_apis) when available
        repo_root = Path(__file__).parents[2]
        artifact_mapping = repo_root / "system_test_mapping_artifact.json"
        if artifact_mapping.exists():
            mapping_path = str(artifact_mapping)
        else:
            mapping_path = str(repo_root / "system_test_mapping.json")
    if not os.path.exists(mapping_path):
        console.print(f"[yellow]Mapping file not found at {mapping_path}. Continuing without mapping.[/yellow]")
        return {}
    with open(mapping_path, "r") as f:
        return json.load(f)


def infer_service_from_logs(log_text: str) -> Optional[str]:
    """
    Try to infer triggering repository from logs (GITHUB_REPOSITORY=org/repo)
    and return the repo basename to be used as service/app.
    """
    if not log_text:
        return None
    m = re.search(r"(?m)^\s*GITHUB_REPOSITORY[=:]\s*([A-Za-z0-9._\-/]+)\s*$", log_text)
    if not m:
        return None
    full = m.group(1).strip()
    base = full.split("/")[-1]
    return base or None


def infer_service_from_run_meta(run: RunInfo, cfg: Dict[str, Any]) -> Optional[str]:
    """
    Try to infer service from the run's name/title, which often contains 'armosec/<repo>'.
    """
    try:
        import requests
        base = cfg.get("github", {}).get("api_base_url", "https://api.github.com").rstrip("/")
        token = os.environ.get("GITHUB_TOKEN") or cfg.get("github", {}).get("token")
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "armosec-test-failure-analyzer/1.0"}
        if token and "${" not in str(token):
            headers["Authorization"] = f"Bearer {token}"
        owner_repo = (run.repo or "armosec/shared-workflows")
        run_api = f"{base}/repos/{owner_repo}/actions/runs/{run.id}"
        r = requests.get(run_api, headers=headers, timeout=30)
        if r.status_code != 200:
            return None
        data = r.json()
        candidates = [data.get("name"), data.get("display_title"), data.get("head_repository", {}).get("full_name")]
        for s in candidates:
            if not s or not isinstance(s, str):
                continue
            m = re.search(r"armosec/([A-Za-z0-9._\-]+)", s)
            if m:
                return m.group(1)
    except Exception:
        return None
    return None

def detect_repo_from_zip(run: RunInfo, cfg: Dict[str, Any]) -> Optional[str]:
    """
    Fallback: download the run logs ZIP and scan all files for GITHUB_REPOSITORY.
    Returns repo basename if found.
    """
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    m = re.match(r"^([^/]+)/([^/]+)$", run.repo or "")
    owner, repo = (m.group(1), m.group(2)) if m else ("armosec", "shared-workflows")

    base = cfg.get("github", {}).get("api_base_url", "https://api.github.com").rstrip("/")
    token = os.environ.get("GITHUB_TOKEN") or cfg.get("github", {}).get("token")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "armosec-test-failure-analyzer/1.0",
    }
    if token and "${" not in str(token):
        headers["Authorization"] = f"Bearer {token}"

    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["GET", "HEAD"])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.mount("http://", HTTPAdapter(max_retries=retries))

    logs_api = f"{base}/repos/{owner}/{repo}/actions/runs/{run.id}/logs"
    try:
        resp = session.get(logs_api, headers=headers, timeout=(10, 120), allow_redirects=True)
        if resp.status_code != 200:
            return None
        import io, zipfile
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for n in zf.namelist():
                if not n.lower().endswith((".txt", ".log")):
                    continue
                try:
                    txt = zf.read(n).decode("utf-8", errors="replace")
                except Exception:
                    continue
                m2 = re.search(r"(?m)^\s*GITHUB_REPOSITORY[=:]\s*([A-Za-z0-9._\-/]+)\s*$", txt)
                if m2:
                    return m2.group(1).split("/")[-1]
    except Exception:
        return None
    return None


TIMESTAMP_REGEX = re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\b")

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    # Remove common ANSI color codes so regexes don't capture escape sequences into report.json
    return ANSI_ESCAPE_RE.sub("", s or "")


def _looks_like_noise_error_line(s: str) -> bool:
    """
    Heuristics to avoid treating random code fragments or package identifiers as "errors".
    These show up in logs frequently (e.g. JS bundles with error(...) calls).
    """
    t = (s or "").strip()
    if not t:
        return True
    # npm package identifiers, e.g. "error@2.1.0"
    if re.match(r"^[A-Za-z0-9_.-]+@\d", t):
        return True
    # Common code fragments that match our prior broad error regexes
    if re.search(r"\berror\(", t) or re.search(r"\bError\(", t):
        return True
    return False


def extract_time_window_and_errors(section_text: str, padding_minutes: int = 5) -> Tuple[Optional[str], Optional[str], List[str], Optional[str], Optional[str]]:
    """
    From a section (Step 18) text, find first/last ISO timestamps and 'run_test: Test error' lines.
    Returns: (first_ts_iso, last_ts_iso, errors, from_time_iso_with_padding, to_time_iso_with_padding)
    """
    section_text = _strip_ansi(section_text)

    timestamps: List[datetime] = []
    for m in TIMESTAMP_REGEX.finditer(section_text):
        try:
            dt = dateparser.isoparse(m.group(1))
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=timezone.utc)
            timestamps.append(dt)
        except Exception:
            continue
    first_ts = timestamps[0].isoformat() if timestamps else None
    last_ts = timestamps[-1].isoformat() if timestamps else None

    errors: List[str] = []
    lines = section_text.splitlines()

    # 1) Prefer capturing full blocks leading up to the "run_test: Test error" line.
    trigger_idxs: List[int] = [i for i, ln in enumerate(lines) if "run_test: Test error" in ln]
    for idx in trigger_idxs:
        start = idx
        # scan backwards up to 80 lines or until we hit a good anchor like a Traceback start
        anchor = None
        lo = max(0, idx - 80)
        for j in range(idx - 1, lo - 1, -1):
            lj = lines[j]
            if ("Traceback (most recent call last)" in lj or
                re.search(r"(?i)\bexception\b", lj) or
                re.search(r"(?i)^\s*(?:error|failed|fatal)[:\s]", lj) or
                re.search(r"^\s*Stack trace", lj)):
                anchor = j
        if anchor is not None:
            start = anchor
        else:
            # fallback: back up to the previous blank line or 30 lines
            back = 30
            j = idx - 1
            while j >= 0 and back > 0 and lines[j].strip() != "":
                j -= 1
                back -= 1
            start = max(0, j + 1)
        block = "\n".join(lines[start:idx + 1]).strip()
        # Truncate very long error blocks to keep them manageable
        MAX_ERROR_BLOCK_LENGTH = 2000  # Error blocks can be multi-line, allow more length
        if len(block) > MAX_ERROR_BLOCK_LENGTH:
            block = block[:MAX_ERROR_BLOCK_LENGTH - 3] + "..."
        # Avoid adding pure noise blocks that contain only code-fragment "error(" lines.
        if _looks_like_noise_error_line(block):
            continue
        if block and block not in errors:
            errors.append(block)

    # 2) Generic error patterns (in case there are other errors beyond the trigger)
    error_patterns = [
        # Prefer line-anchored patterns to avoid grabbing "error(" code fragments.
        r"(?im)^\s*Error:\s+.*$",
        r"(?im)^\s*ERROR\b.*$",
        r"(?im)^\s*FATAL\b.*$",
        r"Traceback \(most recent call last\):[\s\S]+?(?=^\S|\Z)",
    ]
    for pat in error_patterns:
        for m in re.finditer(pat, section_text, re.MULTILINE):
            snippet = m.group(0).strip()
            # Truncate very long error snippets to keep them manageable
            MAX_ERROR_BLOCK_LENGTH = 2000  # Error blocks can be multi-line, allow more length
            if len(snippet) > MAX_ERROR_BLOCK_LENGTH:
                snippet = snippet[:MAX_ERROR_BLOCK_LENGTH - 3] + "..."
            if _looks_like_noise_error_line(snippet):
                continue
            if snippet and snippet not in errors:
                errors.append(snippet)

    from_padded = to_padded = None
    if timestamps:
        # Asymmetric padding: less before test, more after test completion
        # This catches delayed errors, async processing, and cleanup issues
        padding_before = padding_minutes  # Keep same (typically 5-10 minutes)
        padding_after = padding_minutes + 25  # Add 25 minutes after test (total 30-35 minutes)
        start = timestamps[0] - td(minutes=padding_before)
        end = timestamps[-1] + td(minutes=padding_after)
        from_padded = start.isoformat()
        to_padded = end.isoformat()
    return first_ts, last_ts, errors, from_padded, to_padded

def extract_incluster_logs(section_text: str, debug: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract in-cluster component logs from test output.
    
    Looks for sections like:
        ---------------- start operator logs ----------------
        {"level":"info","ts":"...","msg":"..."}
        ---------------- end operator logs ----------------
    
    Returns a dict mapping component name -> list of parsed log entries.
    """
    components = [
        'operator',
        'synchronizer',
        'kubescape',
        'node-agent',
        'apiserver',
        'kubescape-scheduler',
        'grype-offline-db'
    ]
    
    extracted = {}
    total_lines = 0
    
    for component in components:
        start_marker = f"start {component} logs"
        end_marker = f"end {component} logs"
        
        # Find component logs between markers
        pattern = re.compile(
            rf"{re.escape(start_marker)}.*?\n(.*?)\n.*?{re.escape(end_marker)}",
            re.DOTALL | re.IGNORECASE
        )
        
        match = pattern.search(section_text)
        if not match:
            continue
        
        log_block = match.group(1).strip()
        if not log_block:
            continue
        
        # Parse JSON log lines
        parsed_logs = []
        for line in log_block.splitlines():
            line = line.strip()
            if not line:
                continue
            
            # Remove timestamp prefix if present (e.g., "2025-12-04T13:57:12.8545414Z ")
            # Pattern: YYYY-MM-DDTHH:MM:SS.nnnnnnnZ
            line = re.sub(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+', '', line)
            
            # Try to parse as JSON
            try:
                log_entry = json.loads(line)
                parsed_logs.append(log_entry)
                total_lines += 1
            except json.JSONDecodeError:
                # Not JSON, store as plain text
                parsed_logs.append({"msg": line, "_raw": True})
                total_lines += 1
        
        if parsed_logs:
            extracted[component] = parsed_logs
            if debug:
                console.print(f"[cyan]Extracted {len(parsed_logs)} log lines from {component}[/cyan]")
    
    if debug and extracted:
        console.print(f"[green]Total in-cluster log lines extracted: {total_lines} from {len(extracted)} components[/green]")
    
    return extracted


def map_test_to_repos_services(test: Dict[str, Any], mapping: Dict[str, Any]) -> MappingInfo:
    name = (test.get("name") or "").lower()
    if "dummy" in name:
        return MappingInfo(repos=[], services=[], skip_cluster=False)
    # Simplified mapping: exact or contains match on test name
    matched_repos: List[str] = []
    matched_services: List[str] = []
    skip_cluster = False
    for key, info in mapping.items():
        if key.lower() in name:
            repos = info.get("target_repositories") or info.get("repos") or info.get("triggeringRepos") or []
            # derive services from repo basenames if not provided
            derived_services: List[str] = []
            for r in repos:
                repo_only = (r or "").split("/")[-1]
                if repo_only in KNOWN_SERVICE_NAMES:
                    derived_services.append(KNOWN_SERVICE_NAMES[repo_only])
            services = info.get("services") or derived_services
            matched_repos.extend(repos)
            matched_services.extend(services)
            if info.get("skip_cluster") is True:
                skip_cluster = True
    return MappingInfo(repos=sorted(set(matched_repos)), services=sorted(set(matched_services)), skip_cluster=skip_cluster)


def extract_identifiers(text: str, overrides: Dict[str, Optional[str]], patterns: Dict[str, List[str]]) -> Identifiers:
    customer_guid = overrides.get("customer_guid")
    cluster = overrides.get("cluster")
    test_run_id = overrides.get("test_run_id")
    
    # Extract Test Run ID from logs if not provided as override
    if not test_run_id:
        # Pattern: "Test Run ID: <value>" (printed by all tests)
        # K8s tests print with cluster name (e.g., "kind-abc123")
        # Older logs may have printed twice (UUID then cluster name) - take last match for backward compatibility
        test_run_id_pattern = r'(?i)Test\s+Run\s+ID\s*:\s*(\S+)'
        matches = re.findall(test_run_id_pattern, text)
        if matches:
            # Take the LAST match (handles both single-print and old double-print logs)
            test_run_id = matches[-1].strip()
            # Remove trailing punctuation like "(from" if present
            test_run_id = re.sub(r'\s*\(.*$', '', test_run_id)
            # Clean up ANSI codes just in case
            test_run_id = re.sub(r'\x1b[^m]*m', '', test_run_id)
    
    if not customer_guid:
        # Prefer explicit "Customer guid" phrasing first if present
        prioritized_patterns: List[str] = [
            r"(?i)customer\s*guid[^\da-f]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            r"(?i)customer\s*guid[^\da-f]*([0-9a-f]{32})",
        ]
        for pat in prioritized_patterns + patterns.get("customer_guid_patterns", []):
            m = re.search(pat, text)
            if m:
                val = m.group(1)
                # Trim wrapping quotes or trailing punctuation if any
                val = val.strip().strip("\"'").rstrip(",.;)]}")
                customer_guid = val
                break
    if not cluster:
        # Prefer 'clusterName' key or common forms first
        prioritized_cluster_patterns: List[str] = [
            r'(?i)clusterName[=:]\s*"?(?P<c>[A-Za-z0-9._-]{3,64})"?',
            r'(?i)\bcluster\s*name[=:]\s*"?(?P<c>[A-Za-z0-9._-]{3,64})"?',
        ]
        for pat in prioritized_cluster_patterns + patterns.get("cluster_name_patterns", []):
            m = re.search(pat, text)
            if m:
                # support named group 'c' or first group
                val = m.groupdict().get("c") or m.group(1)
                val = val.strip().strip("\"'").rstrip(",.;)]}")
                cluster = val
                break
    
    # Final fallback: Use cluster name as test run ID if still not found
    if not test_run_id and cluster:
        test_run_id = cluster
    
    return Identifiers(customer_guid=customer_guid, cluster=cluster, test_run_id=test_run_id)


def build_loki_queries(services: List[str], ids: Identifiers, cfg: Dict[str, Any], use_templates: bool = True) -> List[str]:
    base = cfg.get("loki", {}).get("base_url", "<unset-loki-url>")
    level_selector = cfg.get("loki", {}).get("level_selector", 'level=~"error|warn"')
    labels = cfg.get("loki", {}).get("labels", {})
    namespace_key = labels.get("namespace", "namespace")
    app_key = labels.get("app", "app")
    templates = cfg.get("loki", {}).get("templates", {}) if use_templates else {}
    default_namespace = cfg.get("loki", {}).get("default_namespace")

    q = []
    id_filters = []
    # Use test_run_id to filter logs if available (this is typically the cluster name)
    if ids.test_run_id:
        id_filters.append(f'|= "{ids.test_run_id}"')
    # NOTE: customer_guid and cluster are no longer used as filters
    # We rely on namespace filtering instead (configured per environment)
    # if ids.customer_guid:
    #     id_filters.append(f'|= "{ids.customer_guid}"')
    # if ids.cluster:
    #     id_filters.append(f'|= "{ids.cluster}"')
    # Add error filter to prioritize error/warning logs (in-cluster components)
    id_filters.append('|~ "(?i)error|warn|fail|exception"')
    id_filter_str = " ".join(id_filters)

    target_services = services or []
    if not target_services:
        return []

    for svc in target_services or []:
        # If a template exists for this service, use it; otherwise default selector
        template = templates.get(svc)
        if template:
            # Render a simple template using available context
            rendered = template.format(
                app=app_key,
                namespace=namespace_key,
                level_selector=level_selector,
                customer_guid=(ids.customer_guid or ""),
                cluster=(ids.cluster or ""),
                id_filters=id_filter_str,
            )
            # Collapse any double spaces
            q.append(" ".join(rendered.split()))
        else:
            # Build a generic selector using app and optional namespace
            if default_namespace:
                selector = f'{{{namespace_key}="{default_namespace}", {app_key}="{svc}", {level_selector}}} {id_filter_str}'.strip()
            else:
                selector = f'{{{app_key}="{svc}", {level_selector}}} {id_filter_str}'.strip()
            q.append(selector)
    return q


def write_reports(report: Report, output_dir: str) -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    json_path = Path(output_dir) / "report.json"
    md_path = Path(output_dir) / "report.md"
    with open(json_path, "w") as f:
        f.write(report.model_dump_json(indent=2))
    with open(md_path, "w") as f:
        f.write(render_markdown(report))
    console.print(f"[green]Wrote {json_path} and {md_path}[/green]")


def iso_to_unix_ns(iso_s: str) -> Optional[int]:
    try:
        dt = dateparser.isoparse(iso_s)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1_000_000_000)
    except Exception:
        return None


def execute_loki_query(
    query: str,
    start_ns: int,
    end_ns: int,
    limit: int,
    query_range_url: Optional[str],
    fallback_url: Optional[str],
    headers: Dict[str, str],
    grafana_url: Optional[str],
    grafana_token: Optional[str],
    datasource_id: Optional[int],
    mode: str,
    debug: bool = False
) -> Optional[Any]:
    """
    Execute Loki query with fallback logic (direct URL → Grafana proxy → ms timestamp retry).
    Returns Response object or None if all attempts fail.
    """
    import requests
    
    params = {
        "query": query,
        "start": str(start_ns),
        "end": str(end_ns),
        "limit": str(limit),
        "direction": "forward",
    }
    
    session_ok = False
    url_tried = None
    r = None
    
    # Try direct if configured
    if query_range_url:
        url_tried = query_range_url
        r = requests.get(query_range_url, headers=headers, params=params, timeout=60)
        if r.status_code == 404 and fallback_url:
            if debug:
                print(f"[loki] 404 on {query_range_url}, retrying {fallback_url}")
            url_tried = fallback_url
            r = requests.get(fallback_url, headers=headers, params=params, timeout=60)
        if r.status_code == 200:
            session_ok = True
    
    # If still not ok, and grafana proxy configured or in auto mode with grafana creds, try proxy
    if not session_ok and (mode == "grafana_proxy" or (mode == "auto" and grafana_url and grafana_token)):
        import requests as rq
        gh = {"Accept": "application/json"}
        if grafana_token and "${" not in str(grafana_token):
            gh["Authorization"] = f"Bearer {grafana_token}"
        ds_id = datasource_id
        if ds_id is None:
            # discover first loki datasource id
            try:
                ds_resp = rq.get(f"{str(grafana_url).rstrip('/')}/api/datasources", headers=gh, timeout=30)
                if ds_resp.status_code == 200:
                    for ds in ds_resp.json():
                        if str(ds.get("type")) == "loki":
                            ds_id = ds.get("id")
                            break
            except Exception:
                pass
        if ds_id is not None:
            proxy_url = f"{str(grafana_url).rstrip('/')}/api/datasources/proxy/{ds_id}/loki/api/v1/query_range"
            if debug:
                print(f"[loki] trying grafana proxy: {proxy_url}")
            url_tried = proxy_url
            r = rq.get(proxy_url, headers=gh, params=params, timeout=60)
            if r.status_code == 200:
                session_ok = True
    
    if not session_ok:
        if debug:
            body = ""
            if r is not None:
                try:
                    body = r.text[:300]
                except Exception:
                    pass
                print(f"[loki] fetch failed ({r.status_code}) url={url_tried} body={body}")
            else:
                print(f"[loki] fetch failed (no response) url={url_tried}")
        # Fallback: try milliseconds timestamps if ns failed
        try_ms = False
        try:
            # if status is 400 and the backend might expect ms
            if r is not None and r.status_code == 400:
                try_ms = True
        except Exception:
            pass
        if try_ms:
            start_ms = int(int(params["start"]) / 1_000_000)
            end_ms = int(int(params["end"]) / 1_000_000)
            params_ms = dict(params)
            params_ms["start"] = str(start_ms)
            params_ms["end"] = str(end_ms)
            if debug:
                print(f"[loki] retry with ms: start={params_ms['start']} end={params_ms['end']}")
            r = requests.get(url_tried, headers=headers, params=params_ms, timeout=60)
            if r.status_code != 200 and debug:
                body = ""
                try:
                    body = r.text[:300]
                except Exception:
                    pass
                print(f"[loki] ms retry failed ({r.status_code}) url={url_tried} body={body}")
        if r is None or r.status_code != 200:
            return None
    
    # Return successful response
    if r and r.status_code == 200:
        return r
    
    return None


def fetch_loki_with_pagination(
    query: str,
    start_ns: int,
    end_ns: int,
    max_total: int,
    limit_per_query: int,
    execute_query_fn,
    debug: bool = False
) -> List[Tuple[str, str]]:
    """
    Fetch logs from Loki with timestamp-based pagination.
    Returns list of (timestamp, log_line) tuples.
    
    Pagination strategy:
    1. Execute query with start_ns to end_ns
    2. Extract last timestamp from results
    3. Use last_timestamp + 1ns as new start_ns for next query
    4. Continue until no more results or hit max_total
    """
    all_logs = []
    current_start = start_ns
    
    while len(all_logs) < max_total:
        # Execute query using extracted function
        response = execute_query_fn(query, current_start, end_ns, limit_per_query)
        
        if not response or response.status_code != 200:
            break
        
        try:
            data = response.json()
        except Exception:
            if debug:
                print(f"[loki] Failed to parse JSON response")
            break
        
        result = data.get("data", {}).get("result", [])
        
        # Extract logs and timestamps
        batch_logs = []
        last_timestamp = None
        
        for stream in result:
            values = stream.get("values") or []
            for ts, line in values:
                batch_logs.append((ts, str(line)))
                if last_timestamp is None or ts > last_timestamp:
                    last_timestamp = ts
        
        if not batch_logs:
            break  # No more results
        
        all_logs.extend(batch_logs)
        
        # Check if we got fewer than requested (last page)
        if len(batch_logs) < limit_per_query:
            break
        
        # Prepare for next page: use last timestamp + 1ns
        if last_timestamp:
            try:
                last_ts_ns = int(last_timestamp)
                current_start = last_ts_ns + 1  # Add 1ns to avoid duplicates
            except (ValueError, TypeError):
                if debug:
                    print(f"[loki] Invalid timestamp format: {last_timestamp}")
                break  # Invalid timestamp, stop pagination
        
        if debug:
            print(f"[loki] Pagination: fetched {len(batch_logs)} logs, total: {len(all_logs)}")
    
    return all_logs


def fetch_loki_excerpts_for_failures(failures: List[FailureEntry], cfg: Dict[str, Any], debug: bool = False) -> None:
    """
    For each failure and each query, fetch up to N log lines from Loki within the time window.
    Uses pagination to fetch more logs (up to max_total_fetch), then applies optimization
    to compress logs while preserving critical information.
    Appends optimized snippets into failure.loki.excerpts.
    """
    import requests
    import time
    
    # Read configuration (Step 1.5)
    loki_cfg = (cfg.get("loki", {}) or {})
    mode = loki_cfg.get("mode", "auto")
    limit_per_query = loki_cfg.get("limit_per_query", 5000)
    max_total_fetch = loki_cfg.get("max_total_fetch", 20000)
    enable_pagination = loki_cfg.get("enable_pagination", True)
    max_line_length = loki_cfg.get("max_line_length", 500)  # 0 = no truncation
    optimization_cfg = loki_cfg.get("optimization", {})
    max_snippets_final = optimization_cfg.get("max_snippets", 500)
    max_chars_final = optimization_cfg.get("max_chars", 7000)
    similarity_threshold = optimization_cfg.get("similarity_threshold", 0.9)
    preserve_patterns = optimization_cfg.get("preserve_patterns") or [
        # Keep request/response payload carriers and auth details (high-signal).
        r"\bRequest failed\b",
        r"\bRequest body\b",
        r"\bResponse body\b",
        r"\bHTTP status\b",
        r"\bAssumeRole\b",
        r"\bexternalID\b",
        r"\bcrossAccountsRoleARN\b",
        r"\bAccessDenied\b",
    ]

    # Optional: fetch a small "context window" (±N seconds) around top anchor logs,
    # still filtered by testRunId, but without the extra keyword regex. This keeps
    # run-id filtering while capturing nearby lines (debug/info) that often contain
    # request bodies, parameters, and HTTP response payloads.
    ctx_cfg = loki_cfg.get("context", {}) or {}
    ctx_enabled = ctx_cfg.get("enable", True)
    ctx_window_seconds = int(ctx_cfg.get("window_seconds", 30))
    ctx_max_anchors = int(ctx_cfg.get("max_anchors", 5))
    ctx_min_anchor_separation_seconds = int(ctx_cfg.get("min_anchor_separation_seconds", 5))
    ctx_limit_per_anchor = int(ctx_cfg.get("limit_per_anchor", 800))
    ctx_max_total = int(ctx_cfg.get("max_total_fetch", 4000))

    def _strip_regex_filters(query: str) -> str:
        # Typical query shape:
        #   {labels} |= "id" |~ "(?i)error|warn|..."
        # For context windows we want:
        #   {labels} |= "id"
        if "|~" in query:
            return query.split("|~", 1)[0].rstrip()
        return query.rstrip()

    def _rank_anchor_line(line: str) -> int:
        # Lower is better.
        l = line.lower()
        if "request body" in l or "response body" in l:
            return 0
        if "request failed" in l or "http status" in l:
            return 1
        if "assumerole" in l or "externalid" in l or "crossaccountsrolearn" in l:
            return 2
        if "accessdenied" in l:
            return 3
        if "error" in l or "exception" in l:
            return 4
        return 10

    headers = {"Accept": "application/json"}
    query_range_url = None
    fallback_url = None

    if mode in ("direct", "auto"):
        base_url = loki_cfg.get("base_url")
        if base_url:
            token = os.environ.get("LOKI_TOKEN") or loki_cfg.get("bearer_token")
            if token and "${" not in str(token):
                headers["Authorization"] = f"Bearer {token}"
            base = str(base_url).rstrip("/")
            query_range_url = f"{base}/loki/api/v1/query_range"
            fallback_url = f"{base}/api/v1/query_range"
            if debug:
                print(f"[loki] mode={mode} primary endpoint: {query_range_url} (fallback: {fallback_url})")

    grafana = loki_cfg.get("grafana", {}) or {}
    grafana_url = grafana.get("url")
    grafana_token = os.environ.get("GRAFANA_TOKEN") or grafana.get("api_token")
    datasource_id = grafana.get("datasource_id")

    # Create a partial function for execute_loki_query with fixed parameters
    def execute_query(query: str, start_ns: int, end_ns: int, limit: int):
        return execute_loki_query(
            query=query,
            start_ns=start_ns,
            end_ns=end_ns,
            limit=limit,
            query_range_url=query_range_url,
            fallback_url=fallback_url,
            headers=headers,
            grafana_url=grafana_url,
            grafana_token=grafana_token,
            datasource_id=datasource_id,
            mode=mode,
            debug=debug
        )

    for fentry in failures:
        start_ns = iso_to_unix_ns(fentry.loki.from_time) if fentry.loki.from_time else None
        end_ns = iso_to_unix_ns(fentry.loki.to_time) if fentry.loki.to_time else None
        if not start_ns or not end_ns:
            continue
        
        all_fetched_logs: List[Tuple[str, str]] = []
        
        for q in fentry.loki.queries:
            try:
                if debug:
                    short_q = q if len(q) < 180 else q[:177] + "..."
                    # Try to extract namespace/app for a human-friendly line
                    ns_match = re.search(r'{[^}]*\bnamespace\s*=\s*"(.*?)"', q)
                    app_match = re.search(r'{[^}]*\bapp\s*=\s*"(.*?)"', q)
                    ns_val = ns_match.group(1) if ns_match else "?"
                    app_val = app_match.group(1) if app_match else "?"
                    print(f"[loki] Query: {short_q}")
                    print(f"[loki] window: {fentry.loki.from_time} → {fentry.loki.to_time} | ns={ns_val} app={app_val}")
                    print(f"[loki] pagination={enable_pagination}, limit_per_query={limit_per_query}, max_total={max_total_fetch}")
                
                fetch_start_time = time.time()
                query_logs: List[Tuple[str, str]] = []
                
                # Use pagination if enabled, otherwise single query
                if enable_pagination:
                    try:
                        query_logs = fetch_loki_with_pagination(
                            query=q,
                            start_ns=start_ns,
                            end_ns=end_ns,
                            max_total=max_total_fetch,
                            limit_per_query=limit_per_query,
                            execute_query_fn=execute_query,
                            debug=debug
                        )
                        fetch_time = time.time() - fetch_start_time
                        if debug:
                            print(f"[loki] Pagination completed: {len(query_logs)} logs fetched in {fetch_time:.2f}s")
                    except Exception as e:
                        if debug:
                            print(f"[loki] Pagination failed: {e}, falling back to single query")
                        # Fallback to single query
                        response = execute_query(q, start_ns, end_ns, limit_per_query)
                        if response and response.status_code == 200:
                            try:
                                data = response.json()
                                result = data.get("data", {}).get("result", [])
                                for stream in result:
                                    values = stream.get("values") or []
                                    for ts, line in values[:limit_per_query]:
                                        query_logs.append((ts, str(line)))
                            except Exception:
                                pass
                else:
                    # Single query mode (pagination disabled)
                    response = execute_query(q, start_ns, end_ns, limit_per_query)
                    if response and response.status_code == 200:
                        try:
                            data = response.json()
                            result = data.get("data", {}).get("result", [])
                            for stream in result:
                                values = stream.get("values") or []
                                for ts, line in values[:limit_per_query]:
                                    query_logs.append((ts, str(line)))
                        except Exception:
                            pass
                
                all_fetched_logs.extend(query_logs)
                
                # Cap at max_total_fetch across all queries
                if len(all_fetched_logs) >= max_total_fetch:
                    all_fetched_logs = all_fetched_logs[:max_total_fetch]
                    break
                    
            except Exception as e:
                if debug:
                    print(f"[loki] Error processing query: {e}")
                continue
        
        # Apply optimization if we have logs
        if all_fetched_logs:
            try:
                # Fetch context windows around top anchors (optional).
                if ctx_enabled and fentry.loki.queries:
                    try:
                        ctx_query = _strip_regex_filters(fentry.loki.queries[0])
                        # Choose anchors from the already-fetched logs.
                        ranked = sorted(
                            all_fetched_logs,
                            key=lambda t: (_rank_anchor_line(t[1]), t[0]),
                        )

                        anchors: List[int] = []
                        for ts_s, line in ranked:
                            if len(anchors) >= ctx_max_anchors:
                                break
                            if _rank_anchor_line(line) >= 10:
                                # Not interesting enough to anchor a context fetch.
                                continue
                            try:
                                ts_ns = int(ts_s)
                            except Exception:
                                continue

                            # Enforce minimal separation between anchors.
                            too_close = any(
                                abs(ts_ns - a) <= (ctx_min_anchor_separation_seconds * 1_000_000_000)
                                for a in anchors
                            )
                            if too_close:
                                continue

                            anchors.append(ts_ns)

                        if debug and anchors:
                            print(f"[loki] Context anchors: {len(anchors)} (±{ctx_window_seconds}s), query={ctx_query[:140]}{'...' if len(ctx_query) > 140 else ''}")

                        # Collect context logs, capped.
                        context_logs: List[Tuple[str, str]] = []
                        for a in anchors:
                            if len(context_logs) >= ctx_max_total:
                                break
                            ctx_start = max(start_ns, a - (ctx_window_seconds * 1_000_000_000))
                            ctx_end = min(end_ns, a + (ctx_window_seconds * 1_000_000_000))
                            resp = execute_query(ctx_query, ctx_start, ctx_end, ctx_limit_per_anchor)
                            if not resp or resp.status_code != 200:
                                continue
                            try:
                                data = resp.json()
                                result = data.get("data", {}).get("result", [])
                                for stream in result:
                                    values = stream.get("values") or []
                                    for ts, ln in values[:ctx_limit_per_anchor]:
                                        context_logs.append((ts, str(ln)))
                                        if len(context_logs) >= ctx_max_total:
                                            break
                                    if len(context_logs) >= ctx_max_total:
                                        break
                            except Exception:
                                continue

                        if context_logs:
                            if debug:
                                print(f"[loki] Context fetch added {len(context_logs)} logs (pre-merge)")
                            all_fetched_logs.extend(context_logs)
                    except Exception as e:
                        if debug:
                            print(f"[loki] Context fetch failed: {e}")

                # De-duplicate exact (timestamp,line) pairs after merging.
                seen_pairs = set()
                merged_logs: List[Tuple[str, str]] = []
                for ts_s, line in all_fetched_logs:
                    k = (ts_s, line)
                    if k in seen_pairs:
                        continue
                    seen_pairs.add(k)
                    merged_logs.append((ts_s, line))
                merged_logs.sort(key=lambda t: t[0])
                all_fetched_logs = merged_logs

                # Convert to list of strings
                log_strings = [line for _, line in all_fetched_logs]
                
                # Apply line truncation if configured (before optimization)
                if max_line_length and max_line_length > 0:
                    log_strings = [
                        line[:max_line_length] + ("..." if len(line) > max_line_length else "")
                        for line in log_strings
                    ]
                
                # Apply optimization
                from log_optimization_examples import optimize_logs_for_llm
                
                opt_start_time = time.time()
                optimized_logs = optimize_logs_for_llm(
                    log_strings,
                    max_snippets=max_snippets_final,
                    max_chars=max_chars_final,
                    similarity_threshold=similarity_threshold,
                    preserve_patterns=preserve_patterns,
                )
                opt_time = time.time() - opt_start_time
                
                if debug:
                    print(f"[loki] Optimization: {len(log_strings)} → {len(optimized_logs)} logs in {opt_time:.2f}s")
                    total_chars = sum(len(log) for log in optimized_logs)
                    print(f"[loki] Final output: {len(optimized_logs)} snippets, {total_chars} chars")
                
                fentry.loki.excerpts = optimized_logs
            except Exception as e:
                if debug:
                    print(f"[loki] Optimization failed: {e}, using raw logs (limited)")
                # Fallback: use raw logs but limit to max_snippets_final
                log_strings = [line for _, line in all_fetched_logs]
                if max_line_length and max_line_length > 0:
                    log_strings = [
                        line[:max_line_length] + ("..." if len(line) > max_line_length else "")
                        for line in log_strings
                    ]
                fentry.loki.excerpts = log_strings[:max_snippets_final]

def bundle_context(run: RunInfo, failures: List[FailureEntry], raw_log: str, output_dir: str, args: argparse.Namespace, cfg: Dict[str, Any]) -> None:
    base_dir = Path(output_dir) / "context"
    (base_dir / "tests").mkdir(parents=True, exist_ok=True)
    (base_dir / "logs").mkdir(parents=True, exist_ok=True)

    # summary
    # Calculate total loki logs and sources
    total_loki_logs = 0
    loki_sources = set()
    for fentry in failures:
        if fentry.loki.excerpts:
            total_loki_logs += len(fentry.loki.excerpts)
        # Extract sources from services
        for service in fentry.mapping.services:
            loki_sources.add(service)
    
    summary = {
        "run": run.model_dump(),
        "num_failures": len(failures),
        "loki_logs_count": total_loki_logs,
        "loki_sources": sorted(list(loki_sources)),
    }
    with open(base_dir / "summary.json", "w") as f:
        f.write(json.dumps(summary, indent=2))

    # per-failure bundles
    for idx, fentry in enumerate(failures, start=1):
        name_safe = re.sub(r"[^A-Za-z0-9._-]+", "_", fentry.test.get("name") or f"failure_{idx}")
        # Truncate to 100 chars to avoid "File name too long" errors (filesystem limit is typically 255 bytes)
        name_safe = name_safe[:100]
        meta = {
            "test_name": fentry.test.get("name"),
            "identifiers": fentry.identifiers.model_dump(),
            "services": fentry.mapping.services,
            "repos": fentry.mapping.repos,
            "time_start": fentry.time_start,
            "time_end": fentry.time_end,
            "loki": fentry.loki.model_dump(),
            "errors": fentry.errors,
        }
        with open(base_dir / "tests" / f"{idx:02d}_{name_safe}.json", "w") as f:
            f.write(json.dumps(meta, indent=2))
        # include full section if present
        section_text = fentry.test.get("section") or fentry.test.get("raw") or ""
        with open(base_dir / "tests" / f"{idx:02d}_{name_safe}.log", "w") as f:
            f.write(section_text)

    # logs queries (for Cursor to open easily)
    queries = []
    for fentry in failures:
        for q in fentry.loki.queries:
            queries.append({
                "test": fentry.test.get("name"),
                "query": q,
                "from": fentry.loki.from_time,
                "to": fentry.loki.to_time,
            })
    with open(base_dir / "logs" / "queries.json", "w") as f:
        f.write(json.dumps(queries, indent=2))

    # Optionally bundle system-tests source files matching mapping keys
    wrote_src = False
    if args.bundle_test_sources:
        src_out = base_dir / "tests" / "src"
        src_out.mkdir(parents=True, exist_ok=True)
        st_root = Path(__file__).resolve().parents[2]
        for idx, fentry in enumerate(failures, start=1):
            tname = fentry.test.get("name") or ""
            # Extract test name from ST() pattern or use the test name directly
            m = re.search(r"ST\s*\(([^)]+)\)", tname)
            key = (m.group(1) if m else tname).strip()
            if not key:
                continue
            
            # Create a subdirectory for this test to avoid filename conflicts
            # Sanitize the key to create a safe directory name
            key_safe = re.sub(r"[^A-Za-z0-9._-]+", "_", key)
            test_dir = src_out / f"{idx:02d}_{key_safe}"
            test_dir.mkdir(parents=True, exist_ok=True)
            
            patterns = [f"**/*{key}*.py", f"**/*{key}*.go", f"**/*{key}*.yaml", f"**/*{key}*.yml", f"**/*{key}*.json"]
            matched = False
            for pat in patterns:
                for p in st_root.glob(pat):
                    try:
                        if p.is_file():
                            dst = test_dir / p.name
                            if p.stat().st_size <= 524288:
                                shutil.copy2(p, dst)
                            else:
                                with open((test_dir / p.name).with_suffix(".path.txt"), "w") as outf:
                                    outf.write(str(p))
                            wrote_src = True
                            matched = True
                    except Exception:
                        continue
            if not matched:
                # Ensure directory exists before writing
                info_file = test_dir / "info.txt"
                with open(info_file, "w") as outf:
                    outf.write(f"No matching source file found for key '{key}' under {st_root}.")

    # Optionally clone or link triggering repo and cadashboardbe
    repos_manifest_path = base_dir / "repos" / "repos.json"
    if args.bundle_repos:
        repos_dir = base_dir / "repos"
        repos_dir.mkdir(parents=True, exist_ok=True)
        repos_info = {}
        # infer triggering repo from first failure's non-dashboard service
        trig = None
        for fentry in failures:
            for s in fentry.loki.queries:  # fallback to mapping.services if needed
                pass
        # better: use mapping.services from failures
        trig = None
        for fentry in failures:
            for s in fentry.mapping.services:
                if s != "cadashboardbe":
                    trig = s
                    break
            if trig:
                break
        if not trig:
            trig = "event-ingester-service"
        for repo_name in [trig, "cadashboardbe"]:
            status = {"name": repo_name, "status": "missing"}
            local_root = Path(os.environ.get("REPOS_ROOT", "/Users/eranmadar/repos"))
            local_path = local_root / repo_name
            try:
                if local_path.exists():
                    status["status"] = "linked"
                    status["local_path"] = str(local_path)
                    try:
                        res = subprocess.run(["git", "-C", str(local_path), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
                        if res.returncode == 0:
                            status["commit"] = res.stdout.strip()
                    except Exception:
                        pass
                else:
                    token = os.environ.get("GITHUB_TOKEN") or (cfg.get("github", {}) or {}).get("token")
                    if token and "${" not in str(token):
                        clone_url = f"https://{token}@github.com/armosec/{repo_name}.git"
                        dest = repos_dir / repo_name
                        res = subprocess.run(["git", "clone", "--depth", "1", clone_url, str(dest)], capture_output=True, text=True, timeout=180)
                        if res.returncode == 0:
                            status["status"] = "cloned"
                            status["local_path"] = str(dest)
                            try:
                                res2 = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
                                if res2.returncode == 0:
                                    status["commit"] = res2.stdout.strip()
                            except Exception:
                                pass
                        else:
                            status["error"] = (res.stderr or res.stdout or "")[:500]
                    else:
                        status["error"] = "No local repo and no GITHUB_TOKEN to clone."
            except Exception as e:
                status["error"] = str(e)
            repos_info[repo_name] = status
        with open(repos_manifest_path, "w") as f:
            f.write(json.dumps(repos_info, indent=2))

    # fetch PR info if requested
    if args.fetch_pr:
        try:
            import requests
            m = re.match(r"^([^/]+)/([^/]+)$", run.repo or "")
            owner, repo = (m.group(1), m.group(2)) if m else ("armosec", "shared-workflows")
            base = cfg.get("github", {}).get("api_base_url", "https://api.github.com").rstrip("/")
            token = os.environ.get("GITHUB_TOKEN") or cfg.get("github", {}).get("token")
            headers = {"Accept": "application/vnd.github+json", "User-Agent": "armosec-test-failure-analyzer/1.0"}
            if token and "${" not in str(token):
                headers["Authorization"] = f"Bearer {token}"
            # runs API may include pull_requests field; fetch run again to get that
            run_api = f"{base}/repos/{owner}/{repo}/actions/runs/{run.id}"
            r = requests.get(run_api, headers=headers, timeout=30)
            pr_info = {"pull_requests": []}
            if r.status_code == 200:
                data = r.json()
                pr_info["pull_requests"] = data.get("pull_requests") or []
                # fetch files for first PR if present
                if pr_info["pull_requests"]:
                    pr = pr_info["pull_requests"][0]
                    prnum = pr.get("number")
                    if prnum:
                        pr_files = requests.get(f"{base}/repos/{owner}/{repo}/pulls/{prnum}/files", headers=headers, timeout=60)
                        if pr_files.status_code == 200:
                            pr_info["files"] = pr_files.json()
            with open(base_dir / "pr.json", "w") as f:
                f.write(json.dumps(pr_info, indent=2))
        except Exception as e:
            with open(base_dir / "pr.json", "w") as f:
                f.write(json.dumps({"error": str(e)}, indent=2))

    # placeholder cadashboard endpoint map if requested
    if args.map_cadb:
        cadb = {"note": "Endpoint map placeholder. Implement static scan to build path->handler map.", "generated": True}
        with open(base_dir / "cadashboard_endpoints.json", "w") as f:
            f.write(json.dumps(cadb, indent=2))

    # write loki excerpts if present on failures (populated earlier)
    if args.fetch_loki:
        excerpts = []
        for fentry in failures:
            if fentry.loki.excerpts:
                excerpts.append({
                    "test": fentry.test.get("name"),
                    "from": fentry.loki.from_time,
                    "to": fentry.loki.to_time,
                    "snippets": fentry.loki.excerpts[:500],  # Increased from 100 to 500
                })
        with open(base_dir / "logs" / "excerpts.json", "w") as f:
            f.write(json.dumps(excerpts, indent=2))

    # compute data source status and conclusions after all optional fetches
    # load PR info if exists
    pr_info = {}
    pr_path = base_dir / "pr.json"
    if pr_path.exists():
        try:
            pr_info = json.loads(pr_path.read_text())
        except Exception:
            pr_info = {}
    # determine if excerpts exist
    excerpts_exists = (base_dir / "logs" / "excerpts.json").exists()
    cadb_map_exists = (base_dir / "cadashboard_endpoints.json").exists()
    src_dir_exists = (base_dir / "tests" / "src").exists() and any((base_dir / "tests" / "src").iterdir())
    repos_manifest = (base_dir / "repos" / "repos.json").exists()


    data_status = []
    conclusions = []
    for fentry in failures:
        # statuses
        st = {
            "test": fentry.test.get("name"),
            "shared_workflows": "ok",  # we have run/job logs
            "pr": "ok" if (pr_info.get("pull_requests")) else "missing",
            "system_tests_code": ("ok+src" if src_dir_exists else ("ok" if (fentry.test.get("section") or fentry.test.get("raw")) else "missing")),
            "cadashboard_flows": "partial" if cadb_map_exists else "missing",
            "triggering_repo_code": ("ok" if repos_manifest else ("partial" if (pr_info.get("files")) else "missing")),
            "loki_results": "queries_only" if not excerpts_exists else "ok",
        }
        data_status.append(st)

        # conclusions
        errors_text = " ".join(fentry.errors).lower()
        hypothesis = "uncategorized"
        signals = []
        next_steps = []
        if any(w in errors_text for w in ["timeout", "timed out", "deadline", "connection reset", "econnreset", "broken pipe"]):
            hypothesis = "infra/network timeout"
            signals.append("timeout/connection reset in logs")
            next_steps.append("inspect service connectivity (Pulsar/Redis/Postgres) for time window")
        if any(w in errors_text for w in ["5xx", " 500 ", " 502 ", " 503 ", " 504 "]):
            hypothesis = "api/server error (5xx)"
            signals.append("HTTP 5xx detected")
            next_steps.append("check cadashboardbe handler and upstream dependency errors")
        if "permission" in errors_text or "forbidden" in errors_text:
            hypothesis = "permissions/authorization issue"
            signals.append("permission/forbidden in logs")
            next_steps.append("verify tokens/roles and config for the test tenant")
        
        if hypothesis == "uncategorized" and fentry.errors:
            hypothesis = "application error"
            signals.append("error lines present")
            next_steps.append("inspect last error lines and changed files in PR")
        
        conclusion = {
            "test": fentry.test.get("name"),
            "services": fentry.mapping.services,
            "customer_guid": fentry.identifiers.customer_guid,
            "cluster": fentry.identifiers.cluster,
            "time_from": fentry.loki.from_time,
            "time_to": fentry.loki.to_time,
            "hypothesis": hypothesis,
            "signals": signals,
            "next_steps": next_steps,
        }
        
        conclusions.append(conclusion)

    with open(base_dir / "data_status.json", "w") as f:
        f.write(json.dumps(data_status, indent=2))
    with open(base_dir / "conclusions.json", "w") as f:
        f.write(json.dumps(conclusions, indent=2))


def render_markdown(report: Report) -> str:
    lines: List[str] = []
    lines.append(f"# System Test Failure Report\n")
    lines.append(f"- Run: {report.run.repo} / {report.run.id}")
    if report.run.branch:
        lines.append(f"- Branch: {report.run.branch}")
    if report.run.commit:
        lines.append(f"- Commit: {report.run.commit}")
    lines.append("")
    if not report.failures:
        lines.append("_No failures parsed (skeleton output)._")
        return "\n".join(lines)
    for i, failure in enumerate(report.failures, start=1):
        test_name = failure.test.get("name") or "<unknown>"
        lines.append(f"## {i}. {test_name}")
        if failure.mapping.repos:
            lines.append(f"- Repos: {', '.join(failure.mapping.repos)}")
        if failure.mapping.services:
            lines.append(f"- Services: {', '.join(failure.mapping.services)}")
        if failure.identifiers.customer_guid or failure.identifiers.cluster:
            lines.append(f"- Identifiers: "
                         f"{'customer=' + failure.identifiers.customer_guid if failure.identifiers.customer_guid else ''} "
                         f"{'cluster=' + failure.identifiers.cluster if failure.identifiers.cluster else ''}".strip())
        if failure.time_start or failure.time_end:
            lines.append(f"- Time window: {failure.time_start or '?'} → {failure.time_end or '?'} (+5m padding)")
        if failure.loki.queries:
            lines.append(f"- Loki queries:")
            for q in failure.loki.queries:
                lines.append(f"  - `{q}`")
            if failure.loki.from_time or failure.loki.to_time:
                lines.append(f"  - time filter: from `{failure.loki.from_time or '?'}` to `{failure.loki.to_time or '?'}`")
        if failure.loki.excerpts:
            lines.append(f"- Loki excerpts (first 3):")
            for ex in failure.loki.excerpts[:3]:
                safe = ex.replace('`', "'")
                lines.append(f"  - `{safe}`")
        if failure.errors:
            lines.append(f"- Errors:")
            for e in failure.errors[:5]:
                lines.append(f"  - `{e}`")
        if failure.category:
            lines.append(f"- Category: {failure.category} ({failure.confidence or 0:.2f})")
        if failure.notes:
            lines.append(f"- Notes: {failure.notes}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)
    padding = parse_duration(args.time_padding, cfg.get("defaults", {}).get("time_padding", "10m"))

    run = resolve_run_info(args.run_url, args.run_id, cfg)

    failing_lines, raw_log = download_and_parse_logs(run, cfg, args.logs_zip)
    inferred_service = infer_service_from_logs(raw_log)
    if not inferred_service:
        # Fallback 1: scan entire ZIP for repo
        inferred_service = detect_repo_from_zip(run, cfg)
    if not inferred_service:
        # Fallback 2: read run metadata (name/display_title)
        inferred_service = infer_service_from_run_meta(run, cfg)

    # Debug logging
    if args.debug:
        console.print(f"[magenta]Inferred service:[/magenta] {inferred_service or '<none>'}")

    if not inferred_service:
        console.print("[red]Failed to detect triggering repository/service from logs and metadata. Aborting.[/red]")
        sys.exit(1)
    tests = parse_failing_tests(raw_log)
    
    # Extract all tests (including successful ones) for cross-test interference detection
    all_tests = parse_all_tests_with_timestamps(raw_log)
    if args.debug:
        console.print(f"[cyan]Extracted {len(all_tests)} total tests (including successful)[/cyan]")

    mapping = load_mapping(args.mapping, cfg.get("defaults", {}).get("mapping_path"))

    failures: List[FailureEntry] = []
    only_key = (args.only_test or "").strip().lower()
    for t in tests:
        if only_key:
            tname = (t.get("name") or "").lower()
            # mapping keys are expected to be substrings in the test name per mapping logic
            if only_key not in tname:
                if args.debug:
                    console.print(f"[yellow]Skipping test '{t.get('name')}' (does not match --only-test='{only_key}')[/yellow]")
                continue
        mapping_info = map_test_to_repos_services(t, mapping)
        # Restrict to the triggering repository's service when available (force single-service scope)
        if inferred_service:
            mapping_info.services = [inferred_service]
            # Clear repos from mapping to avoid confusion in report; keep only inferred
            mapping_info.repos = [inferred_service]
            # Always include cadashboardbe as additional target for API-path errors
            if "cadashboardbe" not in mapping_info.services:
                mapping_info.services.append("cadashboardbe")
        elif args.debug:
            console.print(f"[yellow]No inferred service found; mapping services remain: {mapping_info.services}[/yellow]")
        section_text = t.get("section") or t.get("raw", "")  # prefer full section text if available
        identifiers = extract_identifiers(
            text=section_text + "\n" + raw_log,
            overrides={"customer_guid": args.customer_guid, "cluster": args.cluster, "test_run_id": None},
            patterns=cfg.get("parser", {}),
        )
        # If mapping indicates skip_cluster, drop cluster from identifiers
        if getattr(mapping_info, "skip_cluster", False):
            identifiers.cluster = None
        # Use templates (namespace explicitly configured there); no fallbacks
        loki_q = build_loki_queries(mapping_info.services, identifiers, cfg, use_templates=True)
        if args.debug:
            console.print(f"[cyan]Failure '{t.get('name')}' services:[/cyan] {mapping_info.services}")
            console.print(f"[cyan]Generated {len(loki_q)} queries[/cyan]")
            for q in loki_q:
                console.print(f"  [yellow]Query:[/yellow] {q}")
            console.print(f"[cyan]Identifiers:[/cyan] customer={identifiers.customer_guid} cluster={identifiers.cluster} test_run_id={identifiers.test_run_id}")

        # Extract section time window and errors (Step 18 logs)
        first_ts, last_ts, errors, from_padded, to_padded = extract_time_window_and_errors(section_text, padding_minutes=5)
        if args.debug:
            console.print(f"[cyan]Time window:[/cyan] {first_ts} → {last_ts} (+5m) | errors={len(errors)}")

        # Extract in-cluster logs (only if test uses a cluster)
        incluster_logs = {}
        if not mapping_info.skip_cluster:
            incluster_logs = extract_incluster_logs(section_text, debug=args.debug)
            if args.debug and incluster_logs:
                console.print(f"[green]Extracted in-cluster logs from {len(incluster_logs)} components[/green]")
        elif args.debug:
            console.print(f"[yellow]Skipping in-cluster log extraction (skip_cluster=True)[/yellow]")

        failures.append(
            FailureEntry(
                test=t,
                mapping=mapping_info,
                identifiers=identifiers,
                loki=LokiData(queries=loki_q, excerpts=[], from_time=from_padded, to_time=to_padded),
                category=None,
                confidence=None,
                notes=None,
                time_start=first_ts,
                time_end=last_ts,
                errors=errors,
                incluster_logs=incluster_logs,
            )
        )

    # Optionally fetch Loki excerpts before writing reports
    if args.fetch_loki:
        fetch_loki_excerpts_for_failures(failures, cfg, debug=args.debug)

    # Save extracted identifiers to individual files for workflow artifacts
    if failures:
        first_identifiers = failures[0].identifiers
        output_path = Path(args.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        if first_identifiers.customer_guid:
            customer_guid_file = output_path / "customer-guid.txt"
            customer_guid_file.write_text(first_identifiers.customer_guid + "\n")
            if args.debug:
                console.print(f"[green]Saved customer_guid to {customer_guid_file}[/green]")
        
        if first_identifiers.cluster:
            cluster_file = output_path / "cluster.txt"
            cluster_file.write_text(first_identifiers.cluster + "\n")
            if args.debug:
                console.print(f"[green]Saved cluster to {cluster_file}[/green]")
        
        if first_identifiers.test_run_id:
            test_run_id_file = output_path / "test-run-id.txt"
            test_run_id_file.write_text(first_identifiers.test_run_id + "\n")
            if args.debug:
                console.print(f"[green]Saved test_run_id to {test_run_id_file}[/green]")

    report = Report(run=run, failures=failures, summary=None)
    write_reports(report, args.output_dir)

    # Bundle context for local Cursor exploration
    bundle_context(run, failures, raw_log, args.output_dir, args, cfg)
    
    # Detect cross-test interference AFTER conclusions.json is written
    interference_signals = []
    interference_map = {}
    try:
        # Build test code map if bundle_test_sources was used
        test_code_map = {}
        base_dir = Path(args.output_dir) / "context"
        src_dir_exists = (base_dir / "tests" / "src").exists() and any((base_dir / "tests" / "src").iterdir())
        if args.bundle_test_sources and src_dir_exists:
            src_dir = base_dir / "tests" / "src"
            for test_dir in src_dir.iterdir():
                if test_dir.is_dir():
                    # Find Python test files
                    for py_file in test_dir.glob("*.py"):
                        test_name = test_dir.name.split("_", 1)[-1] if "_" in test_dir.name else test_dir.name
                        try:
                            test_code_map[test_name] = py_file.read_text()
                        except Exception:
                            pass
        
        interference_signals = detect_cross_test_interference(
            failures=failures,
            all_tests=all_tests,
            raw_log=raw_log,
            mapping=mapping,
            config=cfg,
            test_code_map=test_code_map if test_code_map else None
        )
        if args.debug and interference_signals:
            console.print(f"[cyan]Cross-test interference detection: {len(interference_signals)} signals[/cyan]")
        
        # Build interference map for quick lookup
        interference_map = {sig['test']: sig for sig in interference_signals}
    except Exception as e:
        if args.debug:
            console.print(f"[yellow]Cross-test interference detection failed: {e}[/yellow]")
        interference_map = {}
    
    # Save interference data to separate file for LLM context (this is INPUT, not a conclusion)
    context_dir = Path(args.output_dir) / "context"
    context_dir.mkdir(parents=True, exist_ok=True)
    interference_file = context_dir / "cross_test_interference.json"
    if interference_signals:
        # Get interference data for the first failing test (or first test if analyzing single test)
        test_name_for_llm = failures[0].test.get('name') if failures else None
        if test_name_for_llm and test_name_for_llm in interference_map:
            interference_data_for_llm = interference_map[test_name_for_llm]
            interference_file.write_text(json.dumps(interference_data_for_llm, indent=2))
            if args.debug:
                console.print(f"[green]Saved cross-test interference data to {interference_file}[/green]")
        elif interference_signals:
            # If no specific test match, use first signal
            interference_file.write_text(json.dumps(interference_signals[0], indent=2))
            if args.debug:
                console.print(f"[green]Saved cross-test interference data to {interference_file}[/green]")
    
    # Update conclusions with interference data (now that file exists)
    conclusions_path = context_dir / "conclusions.json"
    if conclusions_path.exists():
        try:
            conclusions = json.loads(conclusions_path.read_text())
            for conclusion in conclusions:
                test_name = conclusion.get('test')
                interference_data = interference_map.get(test_name, {})
                if interference_data.get('interference_detected'):
                    conclusion['cross_test_interference'] = {
                        'type': 'bulk_operation_affecting_shared_resource',
                        'parallel_tests': interference_data.get('parallel_tests', []),
                        'bulk_operations': interference_data.get('bulk_operations', []),
                        'shared_resources': interference_data.get('shared_resources', []),
                        'recommendations': interference_data.get('recommendations', [])
                    }
                    # Update hypothesis if not already set
                    if conclusion.get('hypothesis') == 'uncategorized':
                        conclusion['hypothesis'] = 'cross-test interference (isolation issue)'
                        if not conclusion.get('signals'):
                            conclusion['signals'] = []
                        parallel_tests = interference_data.get('parallel_tests', [])
                        if parallel_tests:
                            conclusion['signals'].append(f"Parallel tests detected: {', '.join(parallel_tests[:3])}")
                        conclusion['signals'].append("Potential bulk operation affecting shared resources")
            conclusions_path.write_text(json.dumps(conclusions, indent=2))
            if args.debug:
                console.print(f"[green]Updated conclusions.json with interference data[/green]")
        except Exception as e:
            if args.debug:
                console.print(f"[yellow]Failed to update conclusions with interference data: {e}[/yellow]")


if __name__ == "__main__":
    main()



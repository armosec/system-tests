#!/usr/bin/env python3
"""
ECS-friendly entrypoint for Agent #1 (system-test-analyzer).

Inputs:
- JOB_REQUEST_JSON env var (preferred), or --job-request <path>

Outputs (under WORKDIR, default /work):
- job_result.json
- artifacts/ (including artifacts/report.json when analyzer succeeds)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _try_boto3():
    try:
        import boto3  # type: ignore

        return boto3
    except Exception:
        return None


def _ddb_table():
    boto3 = _try_boto3()
    if not boto3:
        return None
    table_name = os.environ.get("JOBS_TABLE", "").strip()
    if not table_name:
        return None
    return boto3.resource("dynamodb").Table(table_name)


def _s3_client():
    boto3 = _try_boto3()
    if not boto3:
        return None
    return boto3.client("s3")


def _update_job_fields(job_id: str, fields: Dict[str, Any]) -> None:
    """
    Best-effort: update job record in DynamoDB if JOBS_TABLE is configured.
    """
    table = _ddb_table()
    if not table:
        return
    expr_parts = []
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {}
    for k, v in fields.items():
        nk = f"#{k}"
        vk = f":{k}"
        names[nk] = k
        values[vk] = v
        expr_parts.append(f"{nk}={vk}")
    if not expr_parts:
        return
    try:
        table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET " + ", ".join(expr_parts),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except Exception:
        # never crash the agent due to telemetry/status updates
        return


def _start_heartbeat(job_id: str, interval_sec: int = 120) -> threading.Event:
    stop = threading.Event()

    def _beat():
        while not stop.is_set():
            time.sleep(interval_sec)
            _update_job_fields(job_id, {"last_heartbeat_at": _utcnow_iso()})

    threading.Thread(target=_beat, daemon=True).start()
    return stop


def _upload_dir_to_s3(bucket: str, prefix: str, local_dir: Path) -> None:
    """
    Best-effort: upload local_dir recursively to s3://bucket/prefix/...
    """
    s3 = _s3_client()
    if not s3:
        return
    if not local_dir.exists():
        return
    for p in local_dir.rglob("*"):
        if p.is_dir():
            continue
        rel = p.relative_to(local_dir).as_posix()
        key = f"{prefix.rstrip('/')}/{rel}"
        s3.upload_file(str(p), bucket, key)


def _derive_job_id(run_ref: str, default_repo: str = "armosec/shared-workflows") -> str:
    s = (run_ref or "").strip()
    if not s:
        raise ValueError("run_ref is required")
    if s.isdigit():
        safe_repo = default_repo.replace("/", "__")
        return f"{safe_repo}:{s}"
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/actions/runs/(\d+)/job/(\d+)", s)
    if m:
        owner, repo, run_id, job_id = m.group(1), m.group(2), m.group(3), m.group(4)
        return f"{owner}__{repo}:{run_id}:job:{job_id}"
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/actions/runs/(\d+)", s)
    if m:
        return f"{m.group(1)}__{m.group(2)}:{m.group(3)}"
    m = re.search(r"/runs/(\d+)", s)
    if m:
        safe_repo = default_repo.replace("/", "__")
        return f"{safe_repo}:{m.group(1)}"
    raise ValueError(f"unsupported run_ref format: {run_ref!r}")


def _parse_job_url(run_ref: str) -> Optional[Tuple[str, str, str, str]]:
    """
    Parse a GitHub Actions job URL:
      https://github.com/<owner>/<repo>/actions/runs/<runId>/job/<jobId>
    Returns (owner, repo, run_id, job_id) or None.
    """
    s = (run_ref or "").strip()
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/actions/runs/(\d+)/job/(\d+)", s)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3), m.group(4)


def _predownload_job_logs_zip(owner: str, repo: str, run_id: str, job_id: str, artifacts_dir: Path) -> Optional[Path]:
    """
    Download GitHub Actions job logs (text) and wrap into a zipfile in the format analyzer.py expects.
    Mirrors the GitHub workflow logic that writes artifacts/pre-logs.zip containing pre-logs/workflow-logs.txt.
    """
    token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if not token:
        return None
    try:
        import requests  # type: ignore
    except Exception:
        return None

    url = f"https://api.github.com/repos/{owner}/{repo}/actions/jobs/{job_id}/logs"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "agents-infra-system-test-analyzer/1.0",
        "Authorization": f"Bearer {token}",
    }
    try:
        r = requests.get(url, headers=headers, timeout=(10, 120), allow_redirects=True)
        if r.status_code != 200:
            return None

        pre_logs_dir = artifacts_dir / "pre-logs"
        pre_logs_dir.mkdir(parents=True, exist_ok=True)
        combined_txt = pre_logs_dir / "workflow-logs.txt"
        combined_txt.write_text(
            f"=== JOB ID: {job_id} (RUN ID: {run_id}) ===\n" + (r.text or ""),
            encoding="utf-8",
            errors="replace",
        )

        zip_path = artifacts_dir / "pre-logs.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(str(combined_txt), arcname="pre-logs/workflow-logs.txt")
        return zip_path
    except Exception:
        return None


def _parse_run_ref(run_ref: str) -> Tuple[str, str]:
    """
    Returns (flag, value) suitable for analyzer.py:
    - ("--run-url", url) if run_ref is URL
    - ("--run-id", id) otherwise
    """
    s = (run_ref or "").strip()
    if s.startswith("http://") or s.startswith("https://"):
        return "--run-url", s
    return "--run-id", s


def _load_job_request(job_request_path: Optional[str]) -> Dict[str, Any]:
    env_json = os.environ.get("JOB_REQUEST_JSON")
    if env_json:
        return json.loads(env_json)
    if job_request_path:
        return json.loads(Path(job_request_path).read_text())
    raise SystemExit("JOB_REQUEST_JSON env var or --job-request is required")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="system-test-analyzer agent entrypoint")
    p.add_argument("--job-request", help="Path to JobRequest JSON (if JOB_REQUEST_JSON not set)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    req = _load_job_request(args.job_request)

    agent_name = str(req.get("agent_name") or "system-test-analyzer")
    correlation_id = str(req.get("correlation_id") or "")
    run_ref = str(req.get("run_ref") or "")
    system_tests_ref = str(req.get("system_tests_ref") or "agent")
    environment = str(req.get("environment") or "auto")
    only_test = req.get("only_test")
    use_llm_analysis = bool(req.get("use_llm_analysis") or False)
    metadata = req.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    fetch_pr = bool(metadata.get("fetch_pr", True))
    bundle_tests = bool(metadata.get("bundle_tests", True))
    fetch_loki = bool(metadata.get("fetch_loki", True))

    default_repo = os.environ.get("DEFAULT_RUN_REPO", "armosec/shared-workflows")
    job_id = str(req.get("job_id") or _derive_job_id(run_ref, default_repo=default_repo))

    workdir = Path(os.environ.get("WORKDIR", "/work"))
    artifacts_dir = workdir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    started_at = _utcnow_iso()
    status = "succeeded"
    errors = []

    # Mark running + start heartbeat (best-effort)
    _update_job_fields(
        job_id,
        {
            "status": "running",
            "agent_name": agent_name,
            "correlation_id": correlation_id,
            "started_at": started_at,
            "last_heartbeat_at": started_at,
        },
    )
    hb_stop = _start_heartbeat(job_id)

    # --- Source of truth for analyzer code: clone system-tests at system_tests_ref ---
    # This ensures results are reproducible and tied to an explicit ref (e.g. branch "agent").
    system_tests_repo = os.environ.get("SYSTEM_TESTS_REPO", "armosec/system-tests").strip()
    git_token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    repo_dir = workdir / "repos" / "system-tests"
    analyzer_dir = repo_dir / "tools" / "test-failure-analyzer"

    def _run_git(cmd: list[str]) -> int:
        env = dict(os.environ)
        # Avoid leaking tokens into process args; pass auth via header.
        if git_token:
            env["GIT_TERMINAL_PROMPT"] = "0"
        return subprocess.run(cmd, cwd=str(repo_dir) if repo_dir.exists() else str(workdir), env=env, check=False).returncode

    try:
        (workdir / "repos").mkdir(parents=True, exist_ok=True)
        if not repo_dir.exists():
            # clone with auth header (works for private repos)
            clone_url = f"https://github.com/{system_tests_repo}.git"
            clone_cmd = ["git"]
            if git_token:
                clone_cmd += ["-c", f"http.extraheader=AUTHORIZATION: bearer {git_token}"]
            clone_cmd += ["clone", "--no-tags", "--depth", "1", "--branch", system_tests_ref, clone_url, str(repo_dir)]
            if _run_git(clone_cmd) != 0:
                raise RuntimeError("git clone failed")
        else:
            # Update existing clone and checkout requested ref
            fetch_cmd = ["git"]
            if git_token:
                fetch_cmd += ["-c", f"http.extraheader=AUTHORIZATION: bearer {git_token}"]
            fetch_cmd += ["fetch", "--prune", "origin", system_tests_ref]
            _run_git(fetch_cmd)
            _run_git(["git", "checkout", "-f", "FETCH_HEAD"])

        # Record provenance (what code produced this run)
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_dir),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.strip()
        provenance = {
            "system_tests_repo": system_tests_repo,
            "system_tests_ref": system_tests_ref,
            "system_tests_sha": sha,
        }
        (artifacts_dir / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    except Exception as e:
        # If we cannot guarantee code provenance, fail fast (better than silently using stale embedded code).
        status = "failed"
        errors.append(f"failed to clone system-tests at ref {system_tests_ref}: {e}")
        hb_stop.set()
        (workdir / "job_result.json").write_text(
            json.dumps(
                {
                    "schema_version": "v1",
                    "job_id": job_id,
                    "correlation_id": correlation_id,
                    "agent_name": agent_name,
                    "status": status,
                    "started_at": started_at,
                    "finished_at": _utcnow_iso(),
                    "artifact_prefix": os.environ.get("ARTIFACT_PREFIX", ""),
                    "errors": errors,
                },
                indent=2,
            )
            + "\n"
        )
        return 1

    flag, value = _parse_run_ref(run_ref)
    pre_logs_zip: Optional[Path] = None

    # If run_ref is a specific job URL, scope analysis to that job's logs (no need for --only-test).
    job_parts = _parse_job_url(run_ref)
    if job_parts:
        owner, repo, run_id, job_id2 = job_parts
        pre_logs_zip = _predownload_job_logs_zip(owner, repo, run_id, job_id2, artifacts_dir)
        if pre_logs_zip:
            # analyzer.py expects run identifier alongside --logs-zip (use run id, not job url)
            flag, value = "--run-id", run_id
    cmd = [
        sys.executable,
        str(analyzer_dir / "analyzer.py"),
        "--output-dir",
        str(artifacts_dir),
        "--debug",
        flag,
        value,
    ]
    if pre_logs_zip:
        cmd += ["--logs-zip", str(pre_logs_zip)]
    if only_test:
        cmd += ["--only-test", str(only_test)]
    if fetch_pr:
        cmd += ["--fetch-pr"]
    if bundle_tests:
        cmd += ["--bundle-tests"]
    # Match GitHub workflow defaults (parity):
    # - Always bundle test sources (helps triage)
    # - Always include cadashboard endpoint map placeholder
    cmd += ["--bundle-test-sources", "--map-cadb"]
    if fetch_loki:
        cmd += ["--fetch-loki"]
    # NOTE: analyzer.py uses config.yaml + env vars for tokens; keep this thin.
    # use_llm_analysis is handled by later phases in shared-workflows today; keep field for future.
    _ = (system_tests_ref, environment, use_llm_analysis)  # reserved

    rc = 0
    try:
        proc = subprocess.run(cmd, check=False, cwd=str(analyzer_dir))
        rc = int(proc.returncode)
        if rc != 0:
            status = "failed"
            errors.append(f"analyzer.py exited with code {rc}")
    except Exception as e:
        status = "failed"
        errors.append(f"failed to execute analyzer.py: {e}")
    finally:
        hb_stop.set()

    report_path = artifacts_dir / "report.json"

    # Generate a human-friendly summary (similar to GitHub step summary) as an artifact.
    # We run from WORKDIR so relative "artifacts/..." paths resolve.
    try:
        summary_out = artifacts_dir / "summary.md"
        subprocess.run(
            [
                sys.executable,
                str(analyzer_dir / "generate_github_summary.py"),
                "--environment",
                environment,
                "--run-ref",
                run_ref,
                "--output",
                str(summary_out),
            ],
            cwd=str(workdir),
            check=False,
        )
        # Add a tiny README that points to the main artifacts for quick viewing.
        readme = artifacts_dir / "README.md"
        readme.write_text(
            "\n".join(
                [
                    "# System Tests Analyzer - Artifacts",
                    "",
                    f"- Run ref: {run_ref}",
                    f"- Job id: {job_id}",
                    "",
                    "## Quick links",
                    "- `summary.md` (easy-to-read summary)",
                    "- `report.md` (detailed markdown report)",
                    "- `report.json` (full structured report)",
                    "- `context/` (supporting context files used by the analyzer)",
                    "",
                ]
            )
            + "\n"
        )
    except Exception:
        # Summary/README should never fail the agent.
        pass
    result = {
        "schema_version": "v1",
        "job_id": job_id,
        "correlation_id": correlation_id,
        "agent_name": agent_name,
        "status": status,
        "started_at": started_at,
        "finished_at": _utcnow_iso(),
        "artifact_prefix": os.environ.get("ARTIFACT_PREFIX", ""),
        "report_json": str(Path("artifacts/report.json")) if report_path.exists() else None,
        "summary_md": str(Path("artifacts/summary.md")) if (artifacts_dir / "summary.md").exists() else None,
        "llm_context_json": str(Path("artifacts/llm-context.json")) if (artifacts_dir / "llm-context.json").exists() else None,
        "llm_analysis_json": str(Path("artifacts/llm-analysis.json")) if (artifacts_dir / "llm-analysis.json").exists() else None,
        "errors": errors,
    }

    (workdir / "job_result.json").write_text(json.dumps(result, indent=2))

    # Best-effort: upload artifacts and job_result.json to S3
    artifact_bucket = os.environ.get("ARTIFACT_BUCKET", "").strip()
    artifact_prefix = os.environ.get("ARTIFACT_PREFIX", "").strip()
    if artifact_bucket and artifact_prefix:
        # Upload job_result.json at root of prefix
        s3 = _s3_client()
        if s3:
            s3.upload_file(str(workdir / "job_result.json"), artifact_bucket, f"{artifact_prefix.rstrip('/')}/job_result.json")
        _upload_dir_to_s3(artifact_bucket, f"{artifact_prefix.rstrip('/')}/artifacts", artifacts_dir)

        # Persist pointers in DynamoDB (best-effort)
        _update_job_fields(
            job_id,
            {
                "artifact_prefix": f"s3://{artifact_bucket}/{artifact_prefix.rstrip('/')}/",
                "report_json": "artifacts/report.json" if report_path.exists() else None,
            },
        )

    # Mark final status
    _update_job_fields(
        job_id,
        {
            "status": status,
            "finished_at": result["finished_at"],
            "errors": errors,
            "last_heartbeat_at": result["finished_at"],
        },
    )
    return 0 if status == "succeeded" else 1


if __name__ == "__main__":
    raise SystemExit(main())



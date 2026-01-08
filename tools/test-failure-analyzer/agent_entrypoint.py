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
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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


def _download_test_deployed_services_json(run_ref: str, artifacts_dir: Path) -> Optional[Path]:
    """
    Best-effort parity with shared-workflows/system-tests-analyzer.yml:
    download the `test-deployed-services-...` artifact from the original run and extract
    `test-deployed-services.json` into artifacts_dir.
    """
    token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if not token:
        return None

    # derive run id from run_ref (supports run id, run url, job url)
    s = (run_ref or "").strip()
    run_id = None
    if s.isdigit():
        run_id = s
    else:
        m = re.search(r"/runs/(\d+)", s)
        if m:
            run_id = m.group(1)
    if not run_id:
        return None

    out_path = artifacts_dir / "test-deployed-services.json"
    if out_path.exists():
        return out_path

    try:
        import io
        import requests  # type: ignore
    except Exception:
        return None

    # List artifacts for the run and find the newest test-deployed-services-* artifact
    list_url = f"https://api.github.com/repos/armosec/shared-workflows/actions/runs/{run_id}/artifacts"
    try:
        r = requests.get(
            list_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "agents-infra-system-test-analyzer/1.0",
                "Authorization": f"Bearer {token}",
            },
            timeout=(10, 60),
        )
        if r.status_code != 200:
            return None
        data = r.json()
        artifacts = data.get("artifacts") if isinstance(data, dict) else None
        if not isinstance(artifacts, list):
            return None
        match = None
        for a in artifacts:
            if not isinstance(a, dict):
                continue
            name = str(a.get("name") or "")
            if name.startswith("test-deployed-services-"):
                match = a
                break
        if not match:
            return None

        download_url = str(match.get("archive_download_url") or "")
        if not download_url:
            return None

        zr = requests.get(
            download_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "agents-infra-system-test-analyzer/1.0",
                "Authorization": f"Bearer {token}",
            },
            timeout=(10, 120),
            allow_redirects=True,
        )
        if zr.status_code != 200:
            return None

        artifacts_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zr.content)) as zf:
            for n in zf.namelist():
                if n.endswith("/"):
                    continue
                if n.split("/")[-1] == "test-deployed-services.json":
                    out_path.write_bytes(zf.read(n))
                    return out_path
        return None
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
    system_tests_ref = str(req.get("system_tests_ref") or "master")
    environment = str(req.get("environment") or "auto")
    only_test = req.get("only_test")
    use_llm_analysis = bool(req.get("use_llm_analysis") or False)
    metadata = req.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    fetch_pr = bool(metadata.get("fetch_pr", True))
    bundle_tests = bool(metadata.get("bundle_tests", True))
    fetch_loki = bool(metadata.get("fetch_loki", True))
    grafana_url_override = str(metadata.get("grafana_url") or "").strip()

    default_repo = os.environ.get("DEFAULT_RUN_REPO", "armosec/shared-workflows")
    job_id = str(req.get("job_id") or _derive_job_id(run_ref, default_repo=default_repo))

    workdir = Path(os.environ.get("WORKDIR", "/work"))
    artifacts_dir = workdir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    started_at = _utcnow_iso()
    status = "succeeded"
    errors = []

    def _best_effort_finalize(final_status: str, final_errors: list[str]) -> None:
        """
        Ensure we always:
        - stop heartbeat
        - write job_result.json
        - upload artifacts (if configured)
        - update DynamoDB to final state (best-effort)
        """
        finished_at = _utcnow_iso()
        try:
            hb_stop.set()
        except Exception:
            pass
        try:
            (workdir / "job_result.json").write_text(
                json.dumps(
                    {
                        "schema_version": "v1",
                        "job_id": job_id,
                        "correlation_id": correlation_id,
                        "agent_name": agent_name,
                        "status": final_status,
                        "started_at": started_at,
                        "finished_at": finished_at,
                        "artifact_prefix": os.environ.get("ARTIFACT_PREFIX", ""),
                        "errors": final_errors,
                    },
                    indent=2,
                )
                + "\n"
            )
        except Exception:
            pass

        artifact_bucket = os.environ.get("ARTIFACT_BUCKET", "").strip()
        artifact_prefix = os.environ.get("ARTIFACT_PREFIX", "").strip()
        if artifact_bucket and artifact_prefix:
            try:
                s3 = _s3_client()
                if s3:
                    s3.upload_file(
                        str(workdir / "job_result.json"),
                        artifact_bucket,
                        f"{artifact_prefix.rstrip('/')}/job_result.json",
                    )
            except Exception:
                pass

        _update_job_fields(
            job_id,
            {
                "status": final_status,
                "finished_at": finished_at,
                "errors": final_errors,
                "last_heartbeat_at": finished_at,
            },
        )

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

    # --- Workflow parity: environment-specific Grafana/Loki config + token selection ---
    # Mirrors shared-workflows/.github/workflows/system-tests-analyzer.yml env-config + token selection.
    def _detect_env_from_logs_or_job() -> str:
        # Prefer job URL: fetch job logs and search patterns (similar to workflow detect-env step).
        token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
        sref = (run_ref or "").strip()
        run_id = None
        job_id_local = None
        if sref.startswith("http://") or sref.startswith("https://"):
            m = re.search(r"/runs/(\d+)", sref)
            if m:
                run_id = m.group(1)
            m2 = re.search(r"/job/(\d+)", sref)
            if m2:
                job_id_local = m2.group(1)
        elif sref.isdigit():
            run_id = sref
        # Try local pre-logs first (we generate artifacts/pre-logs/workflow-logs.txt for job URLs)
        pre_logs_txt = artifacts_dir / "pre-logs" / "workflow-logs.txt"
        text = ""
        if pre_logs_txt.exists():
            try:
                text = pre_logs_txt.read_text(encoding="utf-8", errors="replace")
            except Exception:
                text = ""
        # If no local logs and we have job id, try fetching job logs quickly
        if (not text) and token and job_id_local:
            try:
                import requests  # type: ignore
                url = f"https://api.github.com/repos/armosec/shared-workflows/actions/jobs/{job_id_local}/logs"
                r = requests.get(
                    url,
                    headers={
                        "Accept": "application/vnd.github+json",
                        "User-Agent": "agents-infra-system-test-analyzer/1.0",
                        "Authorization": f"Bearer {token}",
                    },
                    timeout=(10, 60),
                    allow_redirects=True,
                )
                if r.status_code == 200:
                    text = r.text or ""
            except Exception:
                pass

        def _norm(x: str) -> str:
            return (x or "").strip().lower()

        detected = ""
        if text:
            # Pattern 1: "Environment: <env>"
            m = re.search(r"(?im)^.*Environment:\s*([a-z-]+)\b", text)
            if m:
                detected = m.group(1)
            # Pattern 2: ENVIRONMENT= or ENVIRONMENT:
            if not detected:
                m = re.search(r"(?im)ENVIRONMENT[:=]\s*([a-z-]+)\b", text)
                if m:
                    detected = m.group(1)
            # Pattern 3: systest-cli.py ... -b <env>
            if not detected:
                m = re.search(r"(?im)systest-cli\.py.*\s-b\s+([a-z-]+)\b", text)
                if m:
                    detected = m.group(1)

        detected = _norm(detected)
        if detected in ("development", "staging", "production", "production-us", "custom", "onprem"):
            return detected
        return "staging"

    env_name = (environment or "auto").strip()
    if env_name in ("", "auto", "unknown"):
        env_name = _detect_env_from_logs_or_job()
        environment = env_name  # ensure summary/analyzer get the resolved env
    # default staging/dev url
    grafana_url = "https://grafmon.eudev3.cyberarmorsoft.com"
    namespace = "event-sourcing-be-stage"
    datasource_id = "7"
    token_selector = "stage_and_dev"

    if env_name == "production":
        grafana_url = "https://grafmon.euprod1.cyberarmorsoft.com/"
        namespace = "event-sourcing-be-prod"
        datasource_id = "3"
        token_selector = "prod"
    elif env_name == "production-us":
        grafana_url = "https://grafmon.us.euprod1.cyberarmorsoft.com/"
        namespace = "armo-platform"
        datasource_id = "3"
        token_selector = "prod_us"
    elif env_name == "staging":
        grafana_url = grafana_url_override or "https://grafmon.eudev3.cyberarmorsoft.com"
        namespace = "event-sourcing-be-stage"
        datasource_id = "7"
        token_selector = "stage_and_dev"
    elif env_name in ("development", "custom"):
        grafana_url = grafana_url_override or "https://grafmon.eudev3.cyberarmorsoft.com"
        namespace = "event-sourcing-be-dev"
        datasource_id = "7"
        token_selector = "stage_and_dev"
    elif env_name == "onprem":
        grafana_url = grafana_url_override or "https://grafmon.eudev3.cyberarmorsoft.com"
        namespace = "armo-platform"
        datasource_id = "7"
        token_selector = "stage_and_dev"
    else:
        # unknown/auto -> staging defaults
        grafana_url = grafana_url_override or "https://grafmon.eudev3.cyberarmorsoft.com"
        namespace = "event-sourcing-be-stage"
        datasource_id = "7"
        token_selector = "stage_and_dev"

    os.environ["GRAFANA_URL"] = grafana_url.rstrip("/")
    os.environ["NAMESPACE"] = namespace
    os.environ["GRAFANA_DATASOURCE_ID"] = str(datasource_id)

    # Token selection: prefer injected per-env secrets; fallback to existing GRAFANA_TOKEN/LOKI_TOKEN if set.
    if token_selector == "prod":
        selected = (os.environ.get("GRAFANA_TOKEN_PROD") or "").strip()
    elif token_selector == "prod_us":
        selected = (os.environ.get("GRAFANA_TOKEN_PROD_US") or "").strip()
    else:
        selected = (os.environ.get("GRAFANA_TOKEN_STAGE_AND_DEV") or "").strip()

    if selected:
        os.environ["GRAFANA_TOKEN"] = selected
        os.environ["LOKI_TOKEN"] = selected

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

    def _git_auth_args() -> list[str]:
        """
        GitHub git-over-https requires Basic auth. Bearer tokens work for API, not for git clone/fetch.
        Use: Authorization: basic base64("x-access-token:<token>")
        """
        if not git_token:
            return []
        raw = f"x-access-token:{git_token}".encode("utf-8")
        b64 = base64.b64encode(raw).decode("ascii")
        return ["-c", f"http.extraheader=AUTHORIZATION: basic {b64}"]

    try:
        (workdir / "repos").mkdir(parents=True, exist_ok=True)
        if not repo_dir.exists():
            # clone with auth header (works for private repos)
            clone_url = f"https://github.com/{system_tests_repo}.git"
            clone_cmd = ["git"]
            clone_cmd += _git_auth_args()
            clone_cmd += ["clone", "--no-tags", "--depth", "1", "--branch", system_tests_ref, clone_url, str(repo_dir)]
            if _run_git(clone_cmd) != 0:
                raise RuntimeError("git clone failed")
        else:
            # Update existing clone and checkout requested ref
            fetch_cmd = ["git"]
            fetch_cmd += _git_auth_args()
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

        # Make workflow-style relative paths work:
        # Many helper scripts assume they run from analyzer_dir and write to ./artifacts.
        # We keep artifacts in WORKDIR (/work/artifacts) and link analyzer_dir/artifacts -> it.
        try:
            link_path = analyzer_dir / "artifacts"
            if link_path.is_symlink() or link_path.exists():
                # If someone created a real directory, don't delete it; just proceed.
                pass
            else:
                link_path.symlink_to(artifacts_dir, target_is_directory=True)
        except Exception:
            pass
    except Exception as e:
        # If we cannot guarantee code provenance, fail fast (better than silently using stale embedded code).
        status = "failed"
        errors.append(f"failed to clone system-tests at ref {system_tests_ref}: {e}")
        _best_effort_finalize(status, errors)
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
        proc = subprocess.run(
            cmd,
            check=False,
            cwd=str(analyzer_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        rc = int(proc.returncode)
        out = (proc.stdout or "")
        # Persist analyzer output for debugging (uploaded to S3 with artifacts/)
        try:
            max_bytes = 250_000  # keep bounded
            if len(out.encode("utf-8", errors="ignore")) > max_bytes:
                # rough truncation by characters; good enough for logs
                out = out[-max_bytes:]
            (artifacts_dir / "analyzer.log").write_text(out, encoding="utf-8", errors="replace")
        except Exception:
            pass
        if rc != 0:
            status = "failed"
            errors.append(f"analyzer.py exited with code {rc}")
    except Exception as e:
        status = "failed"
        errors.append(f"failed to execute analyzer.py: {e}")
    finally:
        hb_stop.set()

    report_path = artifacts_dir / "report.json"

    # --- Phase 4/4.5 parity (best-effort): resolve code indexes, dependencies, api mapping, diffs ---
    # This produces artifacts like:
    # - artifacts/gomod-dependencies*.json
    # - artifacts/found-indexes.json
    # - artifacts/api-code-map-with-chains.json
    # - artifacts/code-diffs.json
    # (same filenames the GitHub workflow expects)
    try:
        if report_path.exists():
            resolve_script = analyzer_dir / "resolve_code_indexes.sh"
            if resolve_script.exists():
                env = dict(os.environ)
                env.setdefault("ANALYZER_DEBUG", "false")
                # resolve_code_indexes.sh relies on TRIGGERING_REPO_FROM_STEP and INPUT_RC_VERSION.
                # It can also infer from artifacts/test-deployed-services.json when present.
                env.setdefault("TRIGGERING_REPO_FROM_STEP", "cadashboardbe")
                env.setdefault("INPUT_RC_VERSION", "")
                p = subprocess.run(
                    ["bash", str(resolve_script)],
                    cwd=str(analyzer_dir),
                    env=env,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                (artifacts_dir / "resolve_code_indexes.log").write_text((p.stdout or "").strip() + "\n")
    except Exception:
        pass

    # --- Phase 7 parity (best-effort): create artifacts/llm-context.json for richer summary ---
    llm_context_path = artifacts_dir / "llm-context.json"
    try:
        if report_path.exists():
            report_obj = json.loads(report_path.read_text())
            failures = report_obj.get("failures") or []

            test_name = "unknown"
            incluster_logs_obj: Dict[str, Any] = {}
            if isinstance(failures, list) and failures:
                f0 = failures[0] or {}
                if isinstance(f0, dict):
                    t = f0.get("test") or {}
                    if isinstance(t, dict):
                        test_name = str(t.get("name") or "unknown")
                    incluster_logs_obj = f0.get("incluster_logs") or {}

            error_logs_path = artifacts_dir / "error-logs.txt"
            lines: List[str] = []
            if isinstance(failures, list) and failures:
                f = failures[0] or {}
                if isinstance(f, dict):
                    for e in (f.get("errors") or []):
                        lines.append(str(e))
                    loki = f.get("loki") or {}
                    if isinstance(loki, dict):
                        for ex in (loki.get("excerpts") or []):
                            lines.append(str(ex))
            error_logs_path.write_text("\n".join([ln for ln in lines if ln.strip()]) + "\n")

            incluster_logs_path = artifacts_dir / "incluster-logs.json"
            if isinstance(incluster_logs_obj, dict):
                incluster_logs_path.write_text(json.dumps(incluster_logs_obj, indent=2) + "\n")

            build_cmd = [
                sys.executable,
                str(analyzer_dir / "build_llm_context.py"),
                "--test-name",
                test_name,
                "--output",
                str(llm_context_path),
                "--error-logs",
                str(error_logs_path),
            ]

            tr = artifacts_dir / "test-run-id.txt"
            if tr.exists():
                build_cmd += ["--test-run-id", tr.read_text().strip()]
            wc = artifacts_dir / "workflow-commit.txt"
            if wc.exists():
                build_cmd += ["--workflow-commit", wc.read_text().strip()]
            cti = artifacts_dir / "context" / "cross_test_interference.json"
            if cti.exists():
                build_cmd += ["--cross-test-interference", str(cti)]
            if incluster_logs_path.exists():
                build_cmd += ["--incluster-logs", str(incluster_logs_path)]

            p = subprocess.run(build_cmd, check=False, cwd=str(analyzer_dir), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if p.returncode != 0:
                # Persist build_llm_context diagnostics for debugging and to explain summary fallback
                (artifacts_dir / "llm-context-build.log").write_text((p.stdout or "").strip() + "\n")
    except Exception:
        pass

    # Generate a human-friendly summary (similar to GitHub step summary) as an artifact.
    # We run from WORKDIR so relative "artifacts/..." paths resolve.
    try:
        test_deployed_services_path = _download_test_deployed_services_json(run_ref, artifacts_dir)
        summary_out = artifacts_dir / "summary.md"
        summary_cmd = [
            sys.executable,
            str(analyzer_dir / "generate_github_summary.py"),
            "--environment",
            environment,
            "--run-ref",
            run_ref,
            "--output",
            str(summary_out),
        ]
        if llm_context_path.exists():
            summary_cmd += ["--llm-context", str(llm_context_path)]
        ctx_summary = artifacts_dir / "context" / "summary.json"
        if ctx_summary.exists():
            summary_cmd += ["--context-summary", str(ctx_summary)]
        if test_deployed_services_path and test_deployed_services_path.exists():
            summary_cmd += ["--test-deployed-services", str(test_deployed_services_path)]
        subprocess.run(summary_cmd, cwd=str(workdir), check=False)
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



import base64
import csv
import io
import json
import os
import subprocess
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


APP_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = APP_ROOT / "scan_results"
RESULTS_FILE = RESULTS_DIR / "performance_runs.json"
SCRIPT_PATH = APP_ROOT / "scripts" / "performance_large_scan_aws.sh"

AWS_REGION = os.getenv("AWS_REGION", "us-east-2")
AWS_ACCOUNT_ID = os.getenv("AWS_ACCOUNT_ID", "203733861310")
STAGING_BUCKET = os.getenv("AWS_STAGING_BUCKET", "")
CLEAN_BUCKET = os.getenv("AWS_CLEAN_BUCKET", "")
QUARANTINE_BUCKET = os.getenv("AWS_QUARANTINE_BUCKET", "")

SFTPGO_URL = os.getenv("SFTPGO_URL", "http://localhost:8090")
SFTPGO_ADMIN_USER = os.getenv("SFTPGO_ADMIN_USER", "admin")
SFTPGO_ADMIN_PASSWORD = os.getenv("SFTPGO_ADMIN_PASSWORD", "change-me-in-production")


def _sftpgo_token() -> str:
    auth = base64.b64encode(f"{SFTPGO_ADMIN_USER}:{SFTPGO_ADMIN_PASSWORD}".encode()).decode()
    req = urllib.request.Request(
        f"{SFTPGO_URL}/api/v2/token",
        headers={"Authorization": f"Basic {auth}"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())["access_token"]


def _sftpgo_get(path: str) -> dict:
    token = _sftpgo_token()
    req = urllib.request.Request(
        f"{SFTPGO_URL}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())

RESULTS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="OpenSecOps Analyzer - File Scan Dashboard")
app.mount("/static", StaticFiles(directory=str(APP_ROOT / "dashboard_ui" / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_ROOT / "dashboard_ui" / "templates"))

s3_client = boto3.client("s3", region_name=AWS_REGION) if AWS_REGION else None


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def load_runs() -> List[Dict[str, Any]]:
    if not RESULTS_FILE.exists():
        return []
    try:
        return json.loads(RESULTS_FILE.read_text())
    except Exception:
        return []


def save_runs(runs: List[Dict[str, Any]]) -> None:
    RESULTS_FILE.write_text(json.dumps(runs, indent=2, default=str))


def calculate_metrics(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not runs:
        return {
            "total_runs": 0,
            "total_files": 0,
            "total_size_mb": 0,
            "completed_runs": 0,
            "failed_runs": 0,
            "running_runs": 0,
            "avg_duration_seconds": 0,
            "throughput_mb_per_min": 0,
            "latest_status": "No Runs",
        }

    total_files = sum(int(r.get("file_count", 0)) * 2 for r in runs)
    total_size_mb = sum(int(r.get("file_count", 0)) * 2 * int(r.get("file_size_mb", 0)) for r in runs)
    completed = [r for r in runs if r.get("status") == "COMPLETED"]
    failed = [r for r in runs if r.get("status") in {"FAILED", "TIMEOUT"}]
    running = [r for r in runs if r.get("status") in {"RUNNING", "QUEUED"}]
    durations = [float(r.get("duration_seconds", 0)) for r in completed if float(r.get("duration_seconds", 0)) > 0]
    avg_duration = round(sum(durations) / len(durations), 2) if durations else 0
    completed_size = sum(int(r.get("file_count", 0)) * 2 * int(r.get("file_size_mb", 0)) for r in completed)
    completed_duration = sum(float(r.get("duration_seconds", 0)) for r in completed)
    throughput = round((completed_size / completed_duration) * 60, 2) if completed_duration > 0 else 0

    return {
        "total_runs": len(runs),
        "total_files": total_files,
        "total_size_mb": total_size_mb,
        "completed_runs": len(completed),
        "failed_runs": len(failed),
        "running_runs": len(running),
        "avg_duration_seconds": avg_duration,
        "throughput_mb_per_min": throughput,
        "latest_status": runs[-1].get("status", "UNKNOWN"),
    }


def run_perf_script(run_id: str, file_count: int, file_size_mb: int, wait_timeout: int, poll_seconds: int) -> None:
    runs = load_runs()
    run = next((item for item in runs if item["run_id"] == run_id), None)
    if not run:
        return

    env = os.environ.copy()
    env.update({
        "FILE_COUNT": str(file_count),
        "FILE_SIZE_MB": str(file_size_mb),
        "WAIT_TIMEOUT_SECONDS": str(wait_timeout),
        "POLL_SECONDS": str(poll_seconds),
        "AWS_REGION": AWS_REGION,
    })

    start = datetime.now(timezone.utc)
    run["status"] = "RUNNING"
    run["started_at"] = now_utc()
    save_runs(runs)

    try:
        completed = subprocess.run(
            ["bash", str(SCRIPT_PATH)],
            cwd=str(APP_ROOT),
            env=env,
            text=True,
            capture_output=True,
            timeout=wait_timeout + 180,
        )
        duration = round((datetime.now(timezone.utc) - start).total_seconds(), 2)
        run.update({
            "completed_at": now_utc(),
            "duration_seconds": duration,
            "stdout": completed.stdout[-12000:],
            "stderr": completed.stderr[-12000:],
            "return_code": completed.returncode,
            "status": "COMPLETED" if completed.returncode == 0 else "FAILED",
        })
    except subprocess.TimeoutExpired as exc:
        duration = round((datetime.now(timezone.utc) - start).total_seconds(), 2)
        run.update({
            "completed_at": now_utc(),
            "duration_seconds": duration,
            "stdout": str(exc.stdout or "")[-12000:],
            "stderr": str(exc.stderr or "")[-12000:],
            "return_code": 124,
            "status": "TIMEOUT",
        })
    except Exception as exc:
        duration = round((datetime.now(timezone.utc) - start).total_seconds(), 2)
        run.update({
            "completed_at": now_utc(),
            "duration_seconds": duration,
            "stdout": "",
            "stderr": str(exc),
            "return_code": 1,
            "status": "FAILED",
        })

    save_runs(runs)


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {"aws_region": AWS_REGION, "aws_account_id": AWS_ACCOUNT_ID},
    )


@app.get("/api/scan-runs")
def scan_runs():
    runs = load_runs()
    return JSONResponse({
        "generated_at": now_utc(),
        "aws_region": AWS_REGION,
        "aws_account_id": AWS_ACCOUNT_ID,
        "metrics": calculate_metrics(runs),
        "runs": list(reversed(runs[-25:])),
    })


@app.get("/api/aws/buckets")
def aws_buckets():
    buckets = {}
    for zone, bucket_name in [("staging", STAGING_BUCKET), ("clean", CLEAN_BUCKET), ("quarantine", QUARANTINE_BUCKET)]:
        if not bucket_name:
            buckets[zone] = {"bucket": "", "object_count": 0, "size_bytes": 0}
            continue
        try:
            total_size = 0
            count = 0
            paginator = s3_client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket_name):
                count += len(page.get("Contents", []))
                total_size += sum(obj.get("Size", 0) for obj in page.get("Contents", []))
            buckets[zone] = {"bucket": bucket_name, "object_count": count, "size_bytes": total_size}
        except Exception as exc:
            buckets[zone] = {"bucket": bucket_name, "object_count": 0, "size_bytes": 0, "error": str(exc)}
    return JSONResponse({"buckets": buckets})


@app.get("/api/aws/quarantine-files")
def quarantine_files(max_items: int = 50):
    if not QUARANTINE_BUCKET:
        return JSONResponse({"files": [], "total": 0})
    try:
        files = []
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=QUARANTINE_BUCKET, PaginationConfig={"MaxItems": max_items}):
            for obj in page.get("Contents", []):
                tags_resp = s3_client.get_object_tagging(Bucket=QUARANTINE_BUCKET, Key=obj["Key"])
                tags = {t["Key"]: t["Value"] for t in tags_resp.get("TagSet", [])}
                files.append({
                    "key": obj["Key"],
                    "size": obj["Size"],
                    "last_modified": str(obj["LastModified"]),
                    "tags": tags,
                })
        return JSONResponse({"files": files, "total": len(files)})
    except Exception as exc:
        return JSONResponse({"files": [], "total": 0, "error": str(exc)})


@app.get("/api/aws/detection-summary")
def detection_summary():
    if not QUARANTINE_BUCKET:
        return JSONResponse({"by_threat": {}, "by_company": {}, "total_quarantined": 0})
    try:
        by_threat = {}
        by_company = {}
        total = 0
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=QUARANTINE_BUCKET):
            for obj in page.get("Contents", []):
                total += 1
                tags_resp = s3_client.get_object_tagging(Bucket=QUARANTINE_BUCKET, Key=obj["Key"])
                tags = {t["Key"]: t["Value"] for t in tags_resp.get("TagSet", [])}
                threat = tags.get("scan:threat-name", "UNKNOWN")
                company = tags.get("source:company", "UNKNOWN")
                by_threat[threat] = by_threat.get(threat, 0) + 1
                by_company[company] = by_company.get(company, 0) + 1
        return JSONResponse({"by_threat": by_threat, "by_company": by_company, "total_quarantined": total})
    except Exception as exc:
        return JSONResponse({"by_threat": {}, "by_company": {}, "total_quarantined": 0, "error": str(exc)})


@app.get("/api/sftp/status")
def sftp_status():
    try:
        status = _sftpgo_get("/api/v2/status")
        version_info = _sftpgo_get("/api/v2/version")
        connections = _sftpgo_get("/api/v2/connections")
        users_data = _sftpgo_get("/api/v2/users?limit=100")
        users = users_data if isinstance(users_data, list) else users_data.get("data", [])
        return JSONResponse({
            "status": "online",
            "version": version_info.get("version", "unknown"),
            "build_date": version_info.get("build_date", ""),
            "features": version_info.get("features", []),
            "commit_hash": version_info.get("commit_hash", ""),
            "uptime": status.get("uptime", 0),
            "active_connections": len(connections) if isinstance(connections, list) else 0,
            "total_users": len(users),
            "providers": {
                "s3_bucket": os.getenv("AWS_STAGING_BUCKET", ""),
                "s3_region": os.getenv("AWS_REGION", ""),
            },
        })
    except Exception as exc:
        return JSONResponse({"status": "offline", "error": str(exc)})


@app.get("/api/sftp/users")
def sftp_users():
    try:
        users_data = _sftpgo_get("/api/v2/users?limit=100")
        users = users_data if isinstance(users_data, list) else users_data.get("data", [])
        return JSONResponse({"users": users})
    except Exception as exc:
        return JSONResponse({"users": [], "error": str(exc)})


@app.get("/api/report/csv")
def download_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["run_id", "status", "file_count", "file_size_mb", "total_size_mb",
                     "duration_seconds", "started_at", "completed_at", "return_code"])
    for run in load_runs():
        writer.writerow([
            run.get("run_id"), run.get("status"), run.get("file_count"),
            run.get("file_size_mb"), run.get("total_size_mb"),
            run.get("duration_seconds"), run.get("started_at"),
            run.get("completed_at"), run.get("return_code"),
        ])
    return JSONResponse({"csv": output.getvalue()})


@app.post("/api/start-scan")
def start_scan(background_tasks: BackgroundTasks, payload: Dict[str, Any]):
    file_count = int(payload.get("file_count", 5))
    file_size_mb = int(payload.get("file_size_mb", 100))
    wait_timeout = int(payload.get("wait_timeout_seconds", 1800))
    poll_seconds = int(payload.get("poll_seconds", 10))
    run_id = str(uuid.uuid4())[:8]

    runs = load_runs()
    runs.append({
        "run_id": run_id,
        "status": "QUEUED",
        "file_count": file_count,
        "file_size_mb": file_size_mb,
        "total_size_mb": file_count * 2 * file_size_mb,
        "wait_timeout_seconds": wait_timeout,
        "poll_seconds": poll_seconds,
        "created_at": now_utc(),
        "started_at": "-",
        "completed_at": "-",
        "duration_seconds": 0,
        "stdout": "",
        "stderr": "",
        "return_code": None,
    })
    save_runs(runs)
    background_tasks.add_task(run_perf_script, run_id, file_count, file_size_mb, wait_timeout, poll_seconds)
    return JSONResponse({
        "message": "Scan started",
        "run_id": run_id,
        "command": f"FILE_COUNT={file_count} FILE_SIZE_MB={file_size_mb} WAIT_TIMEOUT_SECONDS={wait_timeout} POLL_SECONDS={poll_seconds} ./scripts/performance_large_scan_aws.sh",
    })

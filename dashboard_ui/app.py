import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

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

RESULTS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="OpenSecOps Analyzer - File Scan Dashboard")
app.mount("/static", StaticFiles(directory=str(APP_ROOT / "dashboard_ui" / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_ROOT / "dashboard_ui" / "templates"))


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
        "index.html",
        {"request": request, "aws_region": AWS_REGION, "aws_account_id": AWS_ACCOUNT_ID},
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

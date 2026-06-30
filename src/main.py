import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, Query
from fastapi.responses import JSONResponse

from src.config import get_settings
from src.integrations.clamav import ClamAVClient
from src.integrations.defectdojo import DefectDojoClient
from src.integrations.aws_guardduty import GuardDutyClient
from src.integrations.aws_inspector import InspectorClient
from src.scanner.concurrent_scanner import ConcurrentScanner
from src.integrations.jira import JiraClient
from src.data_generation.test_data_generator import TestDataGenerator
from src.models.scan_result import ScanResult, ScanProgress
from src.scanner.hash_detector import HashDetector
from src.utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()

app = FastAPI(
    title="OpenSecOps-Analyzer Enterprise",
    description="Enterprise malware detection for S3 with ClamAV, DefectDojo, GuardDuty, and AWS Inspector integration",
    version="2.0.0",
)

# Global scanner state
scanner: Optional[ConcurrentScanner] = None
scan_in_progress = False
last_scan_results: List[ScanResult] = []


def malware_detection_callback(result: ScanResult):
    """Callback when malware is detected."""
    logger.warning(f"MALWARE DETECTED: {result.file_name} ({result.threat_level})")

    jira_client = JiraClient()
    ticket_id = jira_client.create_issue(result)
    if ticket_id:
        result.jira_ticket_id = ticket_id
        logger.info(f"Jira ticket created: {ticket_id}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "scan_in_progress": scan_in_progress,
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/scan/local-file")
async def scan_local_file(file: UploadFile = File(...)):
    """Scan an uploaded local file by streaming bytes to ClamAV."""
    try:
        file_bytes = await file.read()
        if not file_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        hash_detector = HashDetector()
        clamav_client = ClamAVClient()

        hashes = hash_detector.calculate_hashes(file_bytes)
        detections = clamav_client.scan_bytes(file_bytes)
        is_malware, threat_level = hash_detector.is_malware(hashes, detections)

        result = ScanResult(
            file_path=file.filename or "uploaded-file",
            file_name=file.filename or "uploaded-file",
            file_size=len(file_bytes),
            hashes=hashes,
            is_malware=is_malware,
            threat_level=threat_level,
            detection_source=",".join(sorted(detections.keys())) if detections else "clean",
            detections=detections,
            scan_timestamp=datetime.now(),
        )

        return {
            "status": "success",
            "file_name": result.file_name,
            "is_malware": result.is_malware,
            "threat_level": result.threat_level,
            "detection_source": result.detection_source,
            "detections": result.detections,
            "hashes": result.hashes,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Local file scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/s3-bucket")
async def scan_s3_bucket(
    bucket: str,
    prefix: str = "",
    max_files: Optional[int] = None,
    background_tasks: BackgroundTasks = None,
):
    """Start scanning an S3 bucket."""
    global scanner, scan_in_progress, last_scan_results

    if scan_in_progress:
        raise HTTPException(status_code=400, detail="Scan already in progress")

    scan_in_progress = True
    logger.info(f"Starting scan: s3://{bucket}/{prefix}")

    def run_scan():
        global scanner, scan_in_progress, last_scan_results
        try:
            scanner = ConcurrentScanner(detection_callback=malware_detection_callback)
            results = scanner.scan_s3_bucket(bucket, prefix, max_files)
            last_scan_results = results
            logger.info(f"Scan completed: {len(results)} files scanned")
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
        finally:
            scan_in_progress = False

    if background_tasks:
        background_tasks.add_task(run_scan)
    else:
        # Run synchronously if no background tasks available
        run_scan()

    return {
        "message": "Scan started",
        "bucket": bucket,
        "prefix": prefix,
        "max_files": max_files,
    }


@app.get("/status")
async def scan_status():
    """Get current scan status."""
    global scanner, scan_in_progress

    if not scan_in_progress or not scanner:
        return {
            "status": "idle",
            "scan_in_progress": False,
        }

    metrics = scanner.get_metrics()
    return {
        "status": "scanning",
        "scan_in_progress": True,
        "metrics": metrics,
    }


@app.get("/results")
async def get_scan_results(limit: int = 100, offset: int = 0):
    """Get scan results."""
    global last_scan_results

    if not last_scan_results:
        return {
            "total": 0,
            "results": [],
        }

    total = len(last_scan_results)
    results = last_scan_results[offset:offset + limit]

    malware_count = sum(1 for r in results if r.is_malware)

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "malware_detected": malware_count,
        "results": results,
    }


@app.get("/results/malware")
async def get_malware_results(limit: int = 100, offset: int = 0):
    """Get only malware detection results."""
    global last_scan_results

    malware_results = [r for r in last_scan_results if r.is_malware]

    if not malware_results:
        return {
            "total": 0,
            "results": [],
        }

    results = malware_results[offset:offset + limit]

    return {
        "total": len(malware_results),
        "offset": offset,
        "limit": limit,
        "results": results,
    }


@app.post("/generate-test-data")
async def generate_test_data(
    bucket: str,
    prefix: str = "test-data/",
    dataset_size: str = "small",
):
    """Generate synthetic test data."""
    try:
        generator = TestDataGenerator(bucket, prefix)

        if dataset_size == "small":
            malware, clean = generator.generate_synthetic_dataset(
                malware_count=10,
                clean_count=10,
                malware_size_mb=10,
                clean_size_mb=10,
            )
        elif dataset_size == "medium":
            malware, clean = generator.generate_synthetic_dataset(
                malware_count=100,
                clean_count=100,
                malware_size_mb=100,
                clean_size_mb=100,
            )
        elif dataset_size == "large":
            malware, clean = generator.generate_synthetic_dataset(
                malware_count=512,
                clean_count=512,
                malware_size_mb=1024,
                clean_size_mb=1024,
            )
        else:
            raise ValueError("Invalid dataset size: small/medium/large")

        return {
            "status": "success",
            "bucket": bucket,
            "prefix": prefix,
            "dataset_size": dataset_size,
            "malware_generated": malware,
            "clean_generated": clean,
            "total_size_gb": (malware + clean) * (10 if dataset_size == "small" else 100 if dataset_size == "medium" else 1024) / 1024,
        }

    except Exception as e:
        logger.error(f"Test data generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/metrics")
async def get_metrics():
    """Get detailed scan metrics."""
    global scanner

    if not scanner:
        return {
            "message": "No scan has been run yet",
            "metrics": {},
        }

    metrics = scanner.get_metrics()
    return {
        "metrics": metrics,
    }


@app.post("/clear-results")
async def clear_results():
    """Clear cached scan results."""
    global last_scan_results, scanner

    last_scan_results = []
    if scanner:
        scanner.clear_results()

    return {
        "message": "Results cleared",
    }


# =============================================================================
# Enterprise Endpoints — DefectDojo, GuardDuty, Inspector, S3 Polling
# =============================================================================

@app.get("/enterprise/health")
async def enterprise_health():
    """Health check for all enterprise integrations."""
    statuses = {
        "capsa_scanner": {"healthy": True, "version": "2.0.0"},
        "defectdojo": {"healthy": False, "message": "not configured"},
        "guardduty": {"healthy": False, "message": "not configured"},
        "inspector": {"healthy": False, "message": "not configured"},
    }

    if settings.defectdojo_url:
        dd = DefectDojoClient()
        statuses["defectdojo"] = {"healthy": dd.health_check(), "url": settings.defectdojo_url}

    if settings.aws_guardduty_enabled:
        gd = GuardDutyClient()
        findings = gd.check_for_malware_scan_findings(hours_back=24)
        statuses["guardduty"] = {"healthy": True, "active_malware_findings": findings}

    if settings.aws_inspector_enabled:
        ins = InspectorClient()
        statuses["inspector"] = {"healthy": ins.is_available(), "region": settings.aws_region}

    return statuses


@app.post("/enterprise/defectdojo/import-results")
async def defectdojo_import_results():
    """Import all cached scan results into DefectDojo."""
    global last_scan_results

    if not settings.defectdojo_url:
        raise HTTPException(status_code=400, detail="DefectDojo not configured (DEFECTDOJO_URL)")

    if not last_scan_results:
        raise HTTPException(status_code=400, detail="No scan results to import")

    dd = DefectDojoClient()
    imported = dd.import_scan_results_bulk(last_scan_results)

    return {
        "status": "success",
        "total_results": len(last_scan_results),
        "imported_findings": imported,
    }


@app.post("/enterprise/defectdojo/reimport-securityhub")
async def defectdojo_reimport_securityhub(payload: Dict[str, Any]):
    """Import AWS Security Hub findings JSON into DefectDojo.

    Payload should be the full JSON output from:
      aws securityhub get-findings
    """
    if not settings.defectdojo_url:
        raise HTTPException(status_code=400, detail="DefectDojo not configured")

    dd = DefectDojoClient()
    imported = dd.reimport_from_securityhub(payload)

    return {
        "status": "success",
        "imported_findings": imported,
    }


@app.get("/enterprise/guardduty/findings")
async def guardduty_findings(
    bucket: str = "",
    key: str = "",
    hours_back: int = Query(24, description="Lookback window in hours"),
):
    """Get GuardDuty findings correlated with a specific S3 object."""
    if not settings.aws_guardduty_enabled:
        raise HTTPException(status_code=400, detail="GuardDuty integration not enabled")

    gd = GuardDutyClient()

    if bucket and key:
        findings = gd.get_findings_for_object(bucket, key, hours_back)
    else:
        findings = []
        detector_id = gd._get_detector_id()
        if detector_id:
            findings = [{"detector_id": detector_id, "note": "Use bucket/key params for object-level correlation"}]

    return {
        "total_findings": len(findings),
        "guardduty_enabled": True,
        "findings": findings,
    }


@app.get("/enterprise/inspector/findings")
async def inspector_findings(
    severity: Optional[str] = Query(None, description="Filter: CRITICAL, HIGH, MEDIUM, LOW"),
    hours_back: int = Query(72, description="Lookback window in hours"),
    max_results: int = Query(100, description="Max findings to return"),
):
    """Get AWS Inspector vulnerability findings."""
    if not settings.aws_inspector_enabled:
        raise HTTPException(status_code=400, detail="Inspector integration not enabled")

    ins = InspectorClient()
    if not ins.is_available():
        raise HTTPException(status_code=503, detail="AWS Inspector2 is not active in this region")

    findings = ins.get_vulnerability_findings(
        max_results=max_results, severity=severity, hours_back=hours_back
    )

    return {
        "total": len(findings),
        "inspector_enabled": True,
        "region": settings.aws_region,
        "findings": findings,
    }


@app.post("/enterprise/scan/s3-polling")
async def start_s3_polling(
    bucket: str,
    prefix: str = "",
    interval_seconds: int = Query(300, description="Polling interval in seconds"),
):
    """Start polling an S3 bucket prefix for new objects and scanning them.

    For large datasets (1TB+), this enables incremental scanning without
    re-scanning previously processed objects.
    """
    global scanner, scan_in_progress

    if scan_in_progress:
        raise HTTPException(status_code=400, detail="Scan already in progress")

    scan_in_progress = True
    logger.info(f"Starting S3 polling: s3://{bucket}/{prefix} every {interval_seconds}s")

    def run_polling():
        global scanner, scan_in_progress, last_scan_results
        try:
            scanner = ConcurrentScanner(detection_callback=malware_detection_callback)
            processed_keys = set()

            while scan_in_progress:
                objects = list(scanner.s3_client.list_objects(bucket, prefix))
                new_objects = [o for o in objects if o["Key"] not in processed_keys]

                if new_objects:
                    logger.info(f"Found {len(new_objects)} new objects to scan")
                    for obj in new_objects:
                        result = scanner._scan_object(bucket, obj)
                        if result:
                            last_scan_results.append(result)
                            processed_keys.add(obj["Key"])

                time.sleep(interval_seconds)

        except Exception as e:
            logger.error(f"S3 polling failed: {str(e)}")
        finally:
            scan_in_progress = False

    import threading
    thread = threading.Thread(target=run_polling, daemon=True)
    thread.start()

    return {
        "message": "S3 polling started",
        "bucket": bucket,
        "prefix": prefix,
        "interval_seconds": interval_seconds,
    }


@app.post("/enterprise/stop-polling")
async def stop_s3_polling():
    """Stop active S3 polling."""
    global scan_in_progress
    scan_in_progress = False
    return {"message": "Polling stopped"}


# =============================================================================
# Queue Endpoints — SQS/Redis-based large-scale scanning
# =============================================================================

@app.post("/enterprise/queue/enqueue-test")
async def queue_enqueue_test(
    count: int = Query(5, description="Number of test messages to enqueue"),
):
    """Enqueue test messages directly for local development/testing.
    Creates fake scan messages to verify the queue flow end-to-end.
    """
    from src.queue import QueueMessage, create_queue
    q = create_queue()
    messages = [
        QueueMessage(
            bucket="test-bucket",
            key=f"test/eicar_test_{i+1}.bin",
            file_size=1024,
            max_attempts=3,
        )
        for i in range(count)
    ]
    enqueued = q.enqueue_batch(messages)
    return {
        "message": f"Enqueued {enqueued} test messages",
        "queue_size": q.size(),
        "queue_backend": settings.queue_backend,
    }


@app.post("/enterprise/queue/enqueue-prefix")
async def queue_enqueue_prefix(
    bucket: str,
    prefix: str = "",
    max_files: Optional[int] = Query(None, description="Limit objects to enqueue"),
):
    """List S3 objects under a prefix and enqueue them for scanning.

    For large datasets (millions of files), use this instead of direct
    scan to decouple ingestion from processing. Workers pull from the
    queue and scan as capacity allows.
    """
    sc = ConcurrentScanner()
    count = sc.enqueue_s3_prefix(bucket, prefix, max_files)
    return {
        "message": f"Enqueued {count} objects from s3://{bucket}/{prefix}",
        "queue_size": sc.queue.size(),
        "queue_backend": settings.queue_backend,
    }


@app.post("/enterprise/queue/process")
async def queue_process(max_messages: int = Query(10, description="Messages to process in this batch")):
    """Manually trigger queue processing. Workers pull messages and scan.

    In production, this runs continuously via background workers.
    For testing, use this endpoint to process N messages from the queue.
    """
    sc = ConcurrentScanner()
    processed = sc.scan_from_queue(max_messages=max_messages)

    return {
        "message": f"Processed {processed} messages from queue",
        "queue_remaining": sc.queue.size(),
        "backend": settings.queue_backend,
    }


@app.get("/enterprise/queue/status")
async def queue_status():
    """Get queue health and depth."""
    sc = ConcurrentScanner()
    stats = sc.get_queue_stats()
    return {
        "queue": stats,
        "backend": settings.queue_backend,
        "results_cached": len(last_scan_results),
    }


@app.post("/enterprise/queue/purge")
async def queue_purge():
    """Purge (clear) the entire queue and DLQ. Use with caution."""
    sc = ConcurrentScanner()
    sc.queue.purge()
    return {"message": "Queue purged"}


@app.get("/enterprise/queue/dlq")
async def queue_dlq(limit: int = Query(100, description="Max DLQ messages to return")):
    """List dead-letter queue messages for debugging."""
    sc = ConcurrentScanner()
    if hasattr(sc.queue, "get_dlq_messages"):
        messages = sc.queue.get_dlq_messages(limit=limit)
    else:
        messages = []
    return {
        "total": len(messages),
        "messages": [m.to_dict() for m in messages],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
    )

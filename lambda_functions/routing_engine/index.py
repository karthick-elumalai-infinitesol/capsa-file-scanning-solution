"""
Lambda Function: CAPSA File Routing Engine

Routes scan results according to the CAPSA report architecture:
- CLEAN -> clean/production bucket, then optionally remove staging copy.
- INFECTED/SUSPICIOUS -> quarantine bucket with review tags and metadata.
- SCAN_ERROR -> retain in staging, tag for manual review, and alert.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import quote_plus

import boto3

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

s3_client = boto3.client("s3")
sns_client = boto3.client("sns")

STAGING_BUCKET = os.environ.get("STAGING_BUCKET")
CLEAN_BUCKET = os.environ.get("CLEAN_BUCKET")
QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SEC")
DELETE_CLEAN_FROM_STAGING = os.environ.get("DELETE_CLEAN_FROM_STAGING", "true").lower() == "true"
DELETE_QUARANTINED_FROM_STAGING = os.environ.get("DELETE_QUARANTINED_FROM_STAGING", "false").lower() == "true"

STATUS_CLEAN = "CLEAN"
STATUS_INFECTED = "INFECTED"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_SCAN_ERROR = "SCAN_ERROR"
SUPPORTED_STATUSES = {STATUS_CLEAN, STATUS_INFECTED, STATUS_SUSPICIOUS, STATUS_SCAN_ERROR}
HIPAA_CLASSIFICATION = "PHI"


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Route one or more scanner result payloads."""
    logger.info("Received routing event: %s", json.dumps(event, default=str))
    validate_configuration()

    scan_results = event.get("results", [])
    if not isinstance(scan_results, list) or not scan_results:
        return {"statusCode": 400, "body": json.dumps({"error": "No scan results"})}

    summary = {
        "total": len(scan_results),
        "moved_to_clean": 0,
        "moved_to_quarantine": 0,
        "scan_errors": 0,
        "errors": 0,
        "error_details": [],
    }

    for scan_result in scan_results:
        try:
            status = normalize_status(scan_result)
            source_bucket, file_key = resolve_source(scan_result)

            if status == STATUS_CLEAN:
                route_to_clean(source_bucket, file_key, scan_result)
                summary["moved_to_clean"] += 1
            elif status in (STATUS_INFECTED, STATUS_SUSPICIOUS):
                route_to_quarantine(source_bucket, file_key, scan_result, status)
                summary["moved_to_quarantine"] += 1
            elif status == STATUS_SCAN_ERROR:
                handle_scan_error(source_bucket, file_key, scan_result)
                summary["scan_errors"] += 1
        except Exception as exc:
            logger.error("Error routing scan result: %s", exc, exc_info=True)
            summary["errors"] += 1
            summary["error_details"].append(str(exc))

    send_alert(
        "CAPSA routing complete\n"
        f"Total files: {summary['total']}\n"
        f"Clean files: {summary['moved_to_clean']}\n"
        f"Quarantined files: {summary['moved_to_quarantine']}\n"
        f"Scan errors held: {summary['scan_errors']}\n"
        f"Routing errors: {summary['errors']}",
        severity="INFO" if summary["errors"] == 0 else "ERROR",
    )
    return {"statusCode": 200 if summary["errors"] == 0 else 207, "body": json.dumps(summary)}


def validate_configuration() -> None:
    missing = []
    if not CLEAN_BUCKET:
        missing.append("CLEAN_BUCKET")
    if not QUARANTINE_BUCKET:
        missing.append("QUARANTINE_BUCKET")
    if missing:
        raise RuntimeError(f"Missing required routing environment variables: {', '.join(missing)}")


def resolve_source(scan_result: Dict[str, Any]) -> tuple[str, str]:
    source_bucket = scan_result.get("bucket")
    file_key = scan_result.get("key")
    file_path = scan_result.get("file_path")

    if (not source_bucket or not file_key) and file_path:
        source_bucket = source_bucket or parse_bucket(file_path)
        file_key = file_key or parse_key(file_path)

    if not source_bucket or not file_key:
        raise ValueError("Scan result must include bucket/key or file_path=s3://bucket/key")
    return source_bucket, file_key


def route_to_clean(source_bucket: str, file_key: str, scan_result: Dict[str, Any]) -> None:
    tags = encode_tags(build_hipaa_tags(source_bucket, file_key, scan_result, STATUS_CLEAN, "CLEAN"))

    s3_client.copy_object(
        CopySource={"Bucket": source_bucket, "Key": file_key},
        Bucket=CLEAN_BUCKET,
        Key=file_key,
        MetadataDirective="COPY",
        TaggingDirective="REPLACE",
        Tagging=tags,
    )
    logger.info("Promoted clean file to s3://%s/%s", CLEAN_BUCKET, file_key)

    if DELETE_CLEAN_FROM_STAGING and source_bucket == STAGING_BUCKET:
        s3_client.delete_object(Bucket=source_bucket, Key=file_key)
        logger.info("Deleted clean staging copy s3://%s/%s", source_bucket, file_key)


def route_to_quarantine(source_bucket: str, file_key: str, scan_result: Dict[str, Any], status: str) -> None:
    tags = encode_tags(build_hipaa_tags(source_bucket, file_key, scan_result, status, "PENDING"))

    s3_client.copy_object(
        CopySource={"Bucket": source_bucket, "Key": file_key},
        Bucket=QUARANTINE_BUCKET,
        Key=file_key,
        MetadataDirective="REPLACE",
        Metadata={
            "threat-level": str(scan_result.get("threat_level", "UNKNOWN")),
            "detected-by": str(scan_result.get("detection_engine", "UNKNOWN")),
            "original-path": f"s3://{source_bucket}/{file_key}",
            "source-company": scan_result.get("source_company") or extract_source_company(file_key),
        },
        TaggingDirective="REPLACE",
        Tagging=tags,
    )
    logger.warning("Quarantined file at s3://%s/%s", QUARANTINE_BUCKET, file_key)

    if DELETE_QUARANTINED_FROM_STAGING and source_bucket == STAGING_BUCKET:
        s3_client.delete_object(Bucket=source_bucket, Key=file_key)
        logger.info("Deleted quarantined staging copy s3://%s/%s", source_bucket, file_key)

    create_jira_ticket(file_key, scan_result)
    send_alert(
        "🚨 CAPSA file quarantined\n"
        f"File: s3://{QUARANTINE_BUCKET}/{file_key}\n"
        f"Status: {status}\n"
        f"Threat: {scan_result.get('threat_name') or 'UNKNOWN'}",
        severity="CRITICAL",
    )


def handle_scan_error(source_bucket: str, file_key: str, scan_result: Dict[str, Any]) -> None:
    # Intentionally do not copy to clean/quarantine. Scan-error files must remain in staging.
    tag_object(source_bucket, file_key, build_hipaa_tags(source_bucket, file_key, scan_result, STATUS_SCAN_ERROR, "MANUAL_REVIEW_REQUIRED"))
    send_alert(
        "❌ CAPSA scan error held in staging for manual review\n"
        f"File: s3://{source_bucket}/{file_key}\n"
        f"Error: {scan_result.get('error_message', 'unknown')}",
        severity="ERROR",
    )


def create_jira_ticket(file_key: str, scan_result: Dict[str, Any]) -> None:
    """Prepare Jira ticket payload for a production Jira hook/layer."""
    ticket_details = {
        "project": JIRA_PROJECT_KEY,
        "summary": f"[MALWARE] File detected: {file_key.split('/')[-1]}",
        "threat_name": scan_result.get("threat_name", "UNKNOWN"),
        "threat_level": scan_result.get("threat_level", "UNKNOWN"),
        "detection_engine": scan_result.get("detection_engine", "UNKNOWN"),
        "file_path": scan_result.get("file_path", f"s3://{STAGING_BUCKET}/{file_key}"),
        "hashes": scan_result.get("hashes", {}),
        "timestamp": scan_result.get("timestamp", ""),
        "quarantine_bucket": QUARANTINE_BUCKET,
    }
    logger.info("Jira ticket payload prepared: %s", json.dumps(ticket_details, indent=2, default=str))


def normalize_status(scan_result: Dict[str, Any]) -> str:
    status = str(scan_result.get("scan_status") or "").upper()
    if not status:
        status = STATUS_INFECTED if scan_result.get("is_malware") else STATUS_CLEAN
    if status not in SUPPORTED_STATUSES:
        raise ValueError(f"Unsupported scan status: {status}")
    return status


def parse_bucket(file_path: str) -> str:
    if not file_path.startswith("s3://"):
        raise ValueError(f"Invalid S3 path: {file_path}")
    return file_path.split("s3://", 1)[1].split("/", 1)[0]


def parse_key(file_path: str) -> str:
    if not file_path.startswith("s3://") or "/" not in file_path.split("s3://", 1)[1]:
        raise ValueError(f"Invalid S3 path: {file_path}")
    return file_path.split("s3://", 1)[1].split("/", 1)[1]


def tag_object(bucket: str, key: str, tags: List[Dict[str, str]]) -> None:
    s3_client.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": normalize_tags(tags)})


def encode_tags(tags: List[Dict[str, str]]) -> str:
    return "&".join(
        f"{quote_plus(tag['Key'])}={quote_plus(str(tag.get('Value', '')))}"
        for tag in normalize_tags(tags)
    )


def normalize_tags(tags: List[Dict[str, str]]) -> List[Dict[str, str]]:
    normalized = []
    for tag in tags:
        normalized.append({"Key": str(tag["Key"])[:128], "Value": str(tag.get("Value", ""))[:256]})
    return normalized


def build_hipaa_tags(source_bucket: str, file_key: str, scan_result: Dict[str, Any], status: str, review_status: str) -> List[Dict[str, str]]:
    return normalize_tags([
        {"Key": "scan:status", "Value": status},
        {"Key": "scan:engine", "Value": scan_result.get("detection_engine") or "UNKNOWN"},
        {"Key": "scan:timestamp", "Value": scan_result.get("timestamp") or now_iso()},
        {"Key": "scan:threat-name", "Value": scan_result.get("threat_name") or "NONE"},
        {"Key": "data:classification", "Value": HIPAA_CLASSIFICATION},
        {"Key": "compliance:hipaa", "Value": "true"},
        {"Key": "source:company", "Value": scan_result.get("source_company") or extract_source_company(file_key)},
        {"Key": "migration:batch-id", "Value": scan_result.get("migration_batch_id") or extract_batch_id(file_key)},
        {"Key": "review:status", "Value": review_status},
        {"Key": "source:original-path", "Value": f"s3://{source_bucket}/{file_key}"},
    ])


def extract_source_company(key: str) -> str:
    parts = [part for part in key.split("/") if part]
    if parts and not parts[0].lower().startswith("batch"):
        return parts[0]
    if len(parts) > 1:
        return parts[1]
    return "UNKNOWN"


def extract_batch_id(key: str) -> str:
    parts = [part for part in key.split("/") if part]
    for part in parts:
        if part.lower().startswith("batch") or part.upper().startswith("BATCH-"):
            return part
    return f"BATCH-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def send_alert(message: str, severity: str = "INFO") -> None:
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN is not configured; alert skipped: %s", message)
        return
    try:
        sns_client.publish(TopicArn=SNS_TOPIC_ARN, Subject=f"[{severity}] CAPSA Routing Alert", Message=message)
    except Exception as exc:
        logger.error("Error sending alert: %s", exc)

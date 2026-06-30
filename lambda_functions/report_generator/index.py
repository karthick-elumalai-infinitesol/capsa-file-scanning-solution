import csv
import io
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import boto3

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

s3_client = boto3.client("s3")
sns_client = boto3.client("sns")

STAGING_BUCKET = os.environ.get("STAGING_BUCKET")
CLEAN_BUCKET = os.environ.get("CLEAN_BUCKET")
QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET")
REPORTS_BUCKET = os.environ.get("REPORTS_BUCKET")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    report_type = event.get("report_type", "daily")
    generated_at = datetime.now(timezone.utc)
    rows = [
        summarize_bucket("staging", STAGING_BUCKET),
        summarize_bucket("clean", CLEAN_BUCKET),
        summarize_bucket("quarantine", QUARANTINE_BUCKET),
    ]

    csv_buffer = io.StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=["zone", "bucket", "object_count", "generated_at", "report_type"])
    writer.writeheader()
    for row in rows:
        writer.writerow({**row, "generated_at": generated_at.isoformat(), "report_type": report_type})

    key = f"reports/{report_type}/{generated_at.strftime('%Y/%m/%d')}/capsa-{report_type}-report.csv"
    s3_client.put_object(
        Bucket=REPORTS_BUCKET,
        Key=key,
        Body=csv_buffer.getvalue().encode("utf-8"),
        ContentType="text/csv",
    )

    message = f"CAPSA {report_type} report generated\nS3: s3://{REPORTS_BUCKET}/{key}"
    if SNS_TOPIC_ARN:
        sns_client.publish(TopicArn=SNS_TOPIC_ARN, Subject=f"CAPSA {report_type.title()} Report", Message=message)

    return {"statusCode": 200, "body": json.dumps({"report_key": key, "report_type": report_type})}


def summarize_bucket(zone: str, bucket: Optional[str]) -> Dict[str, Any]:
    if not bucket:
        return {"zone": zone, "bucket": "", "object_count": 0}

    count = 0
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        count += len(page.get("Contents", []))

    return {"zone": zone, "bucket": bucket, "object_count": count}

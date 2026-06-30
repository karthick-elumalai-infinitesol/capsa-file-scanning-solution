"""
Lambda Function: File Scan Trigger
Triggered by S3 ObjectCreated events from the CAPSA staging bucket.

Architecture:
  S3 → Lambda(scan_trigger) → Redis (ECS) → ClamAV (ECS) → Lambda(routing)

This Lambda is a thin enqueuer: it parses the S3 event notification,
creates a scan message, and pushes it to Redis. The ECS queue_worker
consumes from Redis, performs the ClamAV scan, and invokes the routing
engine with the result.
"""

import json
import logging
import os
from typing import Any, Dict, Optional
from urllib.parse import unquote_plus

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

_queue = None


class RedisQueue:
    def __init__(self, redis_url: str):
        import redis as rds
        self._redis = rds.from_url(
            redis_url,
            socket_connect_timeout=5,
            socket_timeout=10,
            retry_on_timeout=True,
        )
        self._redis.ping()

    def enqueue(self, message: str) -> bool:
        self._redis.rpush("capsa:queue:scan", message)
        return True


def get_queue():
    global _queue
    if _queue is None:
        _queue = RedisQueue(REDIS_URL)
    return _queue


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Parse S3 event, enqueue scan message to Redis."""
    logger.info("Received S3 event: %d record(s)", len(event.get("Records", [])))

    records = event.get("Records", [])
    if not records:
        return {"statusCode": 400, "body": json.dumps({"error": "Invalid S3 event: missing Records"})}

    queue = get_queue()
    enqueued = 0

    for record in records:
        bucket = record.get("s3", {}).get("bucket", {}).get("name")
        key = unquote_plus(record.get("s3", {}).get("object", {}).get("key", ""))
        file_size = int(record.get("s3", {}).get("object", {}).get("size", 0) or 0)
        etag = record.get("s3", {}).get("object", {}).get("eTag", "")

        if not bucket or not key:
            logger.warning("Skipping malformed S3 record: %s", json.dumps(record))
            continue

        message = json.dumps({
            "bucket": bucket,
            "key": key,
            "file_size": file_size,
            "etag": etag,
            "attempt": 0,
            "max_attempts": 3,
            "error": None,
            "metadata": {},
        })

        try:
            queue.enqueue(message)
            enqueued += 1
            logger.info("Enqueued scan for s3://%s/%s (%d bytes)", bucket, key, file_size)
        except Exception as exc:
            logger.error("Failed to enqueue s3://%s/%s: %s", bucket, key, exc, exc_info=True)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "enqueued": enqueued,
            "total_records": len(records),
        }),
    }

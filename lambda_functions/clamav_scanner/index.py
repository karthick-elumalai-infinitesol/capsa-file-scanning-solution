import json
import logging
import os
import socket
import struct
from typing import Any, Dict, Optional, Tuple

import boto3

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

s3_client = boto3.client("s3")

CLAMAV_HOST = os.environ.get("CLAMAV_HOST") or os.environ.get("CLAMAV_URL", "clamav.capsa.internal:3310").split(":")[0]
CLAMAV_PORT = int(os.environ.get("CLAMAV_PORT") or os.environ.get("CLAMAV_URL", "clamav.capsa.internal:3310").split(":")[-1])


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    bucket = event.get("bucket")
    key = event.get("key")
    if not bucket or not key:
        return {"statusCode": 400, "body": json.dumps({"error": "bucket and key are required"})}

    response = s3_client.get_object(Bucket=bucket, Key=key)
    file_bytes = response["Body"].read()
    verdict, signature = scan_bytes(file_bytes)

    payload = {
        "bucket": bucket,
        "key": key,
        "engine": "ClamAV",
        "verdict": verdict,
        "signature": signature,
        "is_malware": verdict == "FOUND",
    }
    return {"statusCode": 200, "body": json.dumps(payload)}


def scan_bytes(file_bytes: bytes) -> Tuple[str, Optional[str]]:
    with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=30) as sock:
        sock.sendall(b"zINSTREAM\0")
        chunk_size = 1024 * 256
        for offset in range(0, len(file_bytes), chunk_size):
            chunk = file_bytes[offset: offset + chunk_size]
            sock.sendall(struct.pack(">I", len(chunk)))
            sock.sendall(chunk)
        sock.sendall(struct.pack(">I", 0))

        response = b""
        while not response.endswith(b"\0"):
            data = sock.recv(4096)
            if not data:
                break
            response += data

    message = response.rstrip(b"\0").decode("utf-8", errors="replace")
    logger.info("ClamAV response: %s", message)
    if "FOUND" in message:
        return "FOUND", message.split(":", 1)[1].replace("FOUND", "").strip()
    return "OK", None

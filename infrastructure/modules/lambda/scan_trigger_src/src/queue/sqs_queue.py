import json
import logging
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError

from src.config import get_settings
from src.queue.interface import ScanQueue, QueueMessage

logger = logging.getLogger(__name__)


class SQSQueue(ScanQueue):
    """AWS SQS queue backend for production scanning at scale.

    Used when CAPSA is deployed in AWS. SQS provides:
    - Managed, infinitely scalable queue
    - Built-in redrive policy to DLQ
    - S3 event notifications directly to queue
    - Dead-letter queue for failed scans
    - 14-day message retention
    - 120s visibility timeout (configurable)

    Queue naming:
      capsa-scan-queue          — main queue
      capsa-scan-dlq            — dead-letter queue
    """

    def __init__(self):
        self.settings = get_settings()
        self.client = boto3.client(
            "sqs",
            region_name=self.settings.aws_region,
            aws_access_key_id=self.settings.aws_access_key_id or None,
            aws_secret_access_key=self.settings.aws_secret_access_key or None,
        )
        self._queue_url: Optional[str] = None
        self._dlq_url: Optional[str] = None

    def _get_queue_url(self) -> Optional[str]:
        if self._queue_url:
            return self._queue_url
        try:
            response = self.client.get_queue_url(QueueName=self.settings.sqs_queue_name)
            self._queue_url = response["QueueUrl"]
            return self._queue_url
        except ClientError as exc:
            logger.error("Cannot resolve SQS queue URL: %s", exc)
            return None

    def _get_dlq_url(self) -> Optional[str]:
        if self._dlq_url:
            return self._dlq_url
        try:
            response = self.client.get_queue_url(QueueName=f"{self.settings.sqs_queue_name}-dlq")
            self._dlq_url = response["QueueUrl"]
            return self._dlq_url
        except ClientError:
            return None

    def enqueue(self, message: QueueMessage) -> bool:
        url = self._get_queue_url()
        if not url:
            return False
        try:
            self.client.send_message(
                QueueUrl=url,
                MessageBody=json.dumps(message.to_dict()),
                MessageAttributes={
                    "Source": {"DataType": "String", "StringValue": "capsa-scanner"},
                    "Bucket": {"DataType": "String", "StringValue": message.bucket},
                    "ObjectKey": {"DataType": "String", "StringValue": message.key},
                },
            )
            return True
        except ClientError as exc:
            logger.error("SQS enqueue failed: %s", exc)
            return False

    def enqueue_batch(self, messages: List[QueueMessage]) -> int:
        url = self._get_queue_url()
        if not url:
            return 0
        count = 0
        entries = []
        for msg in messages:
            entries.append({
                "Id": f"{msg.bucket}/{msg.key}",
                "MessageBody": json.dumps(msg.to_dict()),
                "MessageAttributes": {
                    "Source": {"DataType": "String", "StringValue": "capsa-scanner"},
                },
            })
            if len(entries) == 10:
                count += self._send_batch(url, entries)
                entries = []
        if entries:
            count += self._send_batch(url, entries)
        return count

    def _send_batch(self, url: str, entries: List[dict]) -> int:
        try:
            response = self.client.send_message_batch(QueueUrl=url, Entries=entries)
            success = len(entries) - len(response.get("Failed", []))
            for fail in response.get("Failed", []):
                logger.warning("SQS batch send failed: %s", fail.get("Message", ""))
            return success
        except ClientError as exc:
            logger.error("SQS batch send error: %s", exc)
            return 0

    def dequeue(self, timeout: int = 30) -> Optional[QueueMessage]:
        url = self._get_queue_url()
        if not url:
            return None
        try:
            response = self.client.receive_message(
                QueueUrl=url,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=min(timeout, 20),
                VisibilityTimeout=max(timeout, 30),
                MessageAttributeNames=["All"],
            )
            messages = response.get("Messages", [])
            if not messages:
                return None
            m = messages[0]
            msg = QueueMessage.from_dict(json.loads(m["Body"]))
            msg.metadata["receipt_handle"] = m["ReceiptHandle"]
            msg.attempt += 1
            return msg
        except ClientError as exc:
            logger.error("SQS dequeue failed: %s", exc)
            return None

    def acknowledge(self, message: QueueMessage) -> bool:
        url = self._get_queue_url()
        if not url:
            return False
        receipt = message.metadata.get("receipt_handle")
        if not receipt:
            return True
        try:
            self.client.delete_message(QueueUrl=url, ReceiptHandle=receipt)
            return True
        except ClientError as exc:
            logger.error("SQS ack failed: %s", exc)
            return False

    def requeue(self, message: QueueMessage, delay: int = 0) -> bool:
        url = self._get_queue_url()
        if not url:
            return False
        try:
            self.acknowledge(message)
            self.client.send_message(
                QueueUrl=url,
                MessageBody=json.dumps(message.to_dict()),
                DelaySeconds=min(delay, 900),
            )
            return True
        except ClientError as exc:
            logger.error("SQS requeue failed: %s", exc)
            return False

    def dead_letter(self, message: QueueMessage) -> bool:
        dlq_url = self._get_dlq_url()
        if not dlq_url:
            logger.warning("No DLQ configured, dropping message: %s/%s", message.bucket, message.key)
            return self.acknowledge(message)
        try:
            self.acknowledge(message)
            self.client.send_message(
                QueueUrl=dlq_url,
                MessageBody=json.dumps(message.to_dict()),
            )
            return True
        except ClientError as exc:
            logger.error("SQS DLQ send failed: %s", exc)
            return False

    def size(self) -> int:
        url = self._get_queue_url()
        if not url:
            return 0
        try:
            attrs = self.client.get_queue_attributes(
                QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
            )
            return int(attrs["Attributes"].get("ApproximateNumberOfMessages", "0"))
        except ClientError:
            return 0

    def purge(self) -> bool:
        url = self._get_queue_url()
        if not url:
            return False
        try:
            self.client.purge_queue(QueueUrl=url)
            return True
        except ClientError as exc:
            logger.error("SQS purge failed: %s", exc)
            return False

    def health_check(self) -> bool:
        return self._get_queue_url() is not None

    def get_dlq_size(self) -> int:
        url = self._get_dlq_url()
        if not url:
            return 0
        try:
            attrs = self.client.get_queue_attributes(
                QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
            )
            return int(attrs["Attributes"].get("ApproximateNumberOfMessages", "0"))
        except ClientError:
            return 0

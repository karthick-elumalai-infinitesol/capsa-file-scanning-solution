import json
import time
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional, Callable
import boto3
from src.config import get_settings
from src.integrations.clamav import ClamAVClient
from src.integrations.virustotal import VirusTotalClient
from src.integrations.defectdojo import DefectDojoClient
from src.integrations.aws_guardduty import GuardDutyClient
from src.integrations.aws_inspector import InspectorClient
from src.scanner.s3_client import S3Client
from src.scanner.hash_detector import HashDetector
from src.models.scan_result import ScanResult, FileHash
from src.utils.logger import get_logger
from src.utils.metrics import ScanMetricsCollector
from src.queue import create_queue, QueueMessage

logger = get_logger(__name__)


class ConcurrentScanner:
    def __init__(self, detection_callback: Optional[Callable] = None):
        self.settings = get_settings()
        self.s3_client = S3Client()
        self.hash_detector = HashDetector()
        self.clamav_client = ClamAVClient()
        self.virustotal_client = VirusTotalClient()
        self.defectdojo_client = DefectDojoClient() if self.settings.defectdojo_url else None
        self.guardduty_client = GuardDutyClient() if self.settings.aws_guardduty_enabled else None
        self.inspector_client = InspectorClient() if self.settings.aws_inspector_enabled else None
        self.queue = create_queue()
        self.metrics = ScanMetricsCollector()
        self.detection_callback = detection_callback
        self.scan_results: List[ScanResult] = []
        self._lambda_client = boto3.client("lambda", region_name=self.settings.aws_region)

    def scan_s3_bucket(
        self,
        bucket: str,
        prefix: str = "",
        max_files: Optional[int] = None,
    ) -> List[ScanResult]:
        """
        Scan S3 bucket with concurrent workers.
        """
        logger.info(f"Starting scan of s3://{bucket}/{prefix}")
        self.metrics.start()

        try:
            objects = list(self.s3_client.list_objects(bucket, prefix, max_files))
            logger.info(f"Found {len(objects)} objects to scan")

            with ThreadPoolExecutor(max_workers=self.settings.max_workers) as executor:
                future_to_object = {
                    executor.submit(self._scan_object, bucket, obj): obj
                    for obj in objects
                }

                for future in as_completed(future_to_object):
                    obj = future_to_object[future]
                    try:
                        result = future.result()
                        if result:
                            self.scan_results.append(result)
                            if result.is_malware:
                                if self.detection_callback:
                                    self.detection_callback(result)
                                if self.defectdojo_client:
                                    self.defectdojo_client.import_scan_result(result)
                    except Exception as e:
                        logger.error(f"Error scanning {obj['Key']}: {str(e)}")
                        self.metrics.record_error()

        finally:
            self.metrics.end()

        logger.info(f"Scan complete. Results: {self._format_results_summary()}")
        return self.scan_results

    def _scan_object(self, bucket: str, obj: dict) -> Optional[ScanResult]:
        """
        Scan a single S3 object.
        """
        start_time = time.time()
        key = obj['Key']
        file_size = obj['Size']

        try:
            # Get file stream from S3
            stream = self.s3_client.get_object_stream(bucket, key)
            file_bytes = stream.read()

            # Calculate hashes
            file_hashes = self.hash_detector.calculate_hashes_from_stream(
                BytesIO(file_bytes),
                self.settings.chunk_size
            )

            detections = self._get_detections(file_hashes, file_bytes, bucket, key)
            is_malware, threat_level = self.hash_detector.is_malware(file_hashes, detections)

            # Record metrics
            scan_time_ms = (time.time() - start_time) * 1000
            self.metrics.record_scan(scan_time_ms)
            if is_malware:
                self.metrics.record_malware()

            # Create result
            result = ScanResult(
                file_path=f"s3://{bucket}/{key}",
                file_name=key.split('/')[-1],
                file_size=file_size,
                hashes=file_hashes,
                is_malware=is_malware,
                threat_level=threat_level,
                detection_source=self._get_detection_source(detections),
                detections=detections,
                scan_timestamp=datetime.now(),
            )

            return result

        except Exception as e:
            logger.error(f"Error scanning {key}: {str(e)}")
            self.metrics.record_error()
            return None

    def _get_detections(self, file_hashes: FileHash, file_bytes: bytes, bucket: str = "", key: str = "") -> dict:
        """Multi-engine detection: ClamAV + VirusTotal + GuardDuty (enterprise).

        Combines malware signatures from all available engines for a
        correlated verdict. Enterprise tiers add AWS-native threat signals.
        """
        detections = {}

        clamav_detections = self.clamav_client.scan_bytes(file_bytes)
        if clamav_detections and not any(
            detection.category == "error" for detection in clamav_detections.values()
        ):
            detections.update(clamav_detections)

        if file_hashes.sha256:
            virustotal_detections = self.virustotal_client.get_detections(file_hashes.sha256)
            detections.update(virustotal_detections)

        if self.guardduty_client and bucket and key:
            try:
                gd_findings = self.guardduty_client.get_findings_for_object(bucket, key)
                if gd_findings:
                    sev = max(f.get("severity", 0) for f in gd_findings)
                    detections["guardduty"] = DetectionResult(
                        engine="guardduty",
                        category="threat_intel",
                        result=f"GuardDuty severity {sev:.1f}: {gd_findings[0]['type']}",
                    )
            except Exception as exc:
                logger.debug("GuardDuty correlation skipped: %s", exc)

        return detections

    def _get_detection_source(self, detections: dict) -> str:
        if not detections:
            return "clean"
        return ",".join(sorted(detections.keys()))

    def _format_results_summary(self) -> str:
        metrics = self.metrics.get_metrics()
        return (
            f"Scanned: {metrics.get('total_files_scanned', 0)}, "
            f"Malware: {metrics.get('total_malware_detected', 0)}, "
            f"Throughput: {metrics.get('throughput_files_per_second', 0):.2f} files/sec"
        )

    # ── Queue-Based Scanning (for large datasets) ──────────────────────────

    def scan_from_queue(self, max_messages: int = 0) -> int:
        """Process scan messages from the queue.

        Pulls messages, scans each file, acknowledges on success,
        and moves to DLQ after max retries. Returns count processed.
        """
        processed = 0
        while True:
            msg = self.queue.dequeue(timeout=20)
            if msg is None:
                break

            obj = {"Key": msg.key, "Size": msg.file_size}
            try:
                result = self._scan_object(msg.bucket, obj)
                if result:
                    self.scan_results.append(result)
                    if result.is_malware:
                        if self.detection_callback:
                            self.detection_callback(result)
                        if self.defectdojo_client:
                            self.defectdojo_client.import_scan_result(result)
                    self._route_result(result)
                    self.queue.acknowledge(msg)
                    processed += 1
                else:
                    self._handle_queue_failure(msg)
            except Exception as exc:
                logger.error("Queue scan failed: %s/%s - %s", msg.bucket, msg.key, exc)
                self._handle_queue_failure(msg)

            if max_messages and processed >= max_messages:
                break

        logger.info("Queue scan: processed %d messages", processed)
        return processed

    def _route_result(self, result: ScanResult) -> None:
        fn = self.settings.routing_function_name
        if not fn:
            logger.warning("Routing function name not configured")
            return
        try:
            bucket, key = result.file_path.replace("s3://", "").split("/", 1)
            hashes_dict = result.hashes.model_dump() if hasattr(result.hashes, "model_dump") else result.hashes.dict()
            payload = json.dumps({
                "results": [{
                    "bucket": bucket,
                    "key": key,
                    "file_path": result.file_path,
                    "file_name": result.file_name,
                    "file_size": result.file_size,
                    "hashes": hashes_dict,
                    "is_malware": result.is_malware,
                    "threat_level": result.threat_level,
                    "detection_source": result.detection_source,
                    "detection_engine": result.detection_source,
                    "scan_status": "INFECTED" if result.is_malware else "CLEAN",
                    "timestamp": result.scan_timestamp.isoformat(),
                    "threat_name": next(iter(result.detections.keys())) if result.detections else "NONE",
                    "detections": {k: v.model_dump() if hasattr(v, "model_dump") else v.dict() for k, v in result.detections.items()},
                }]
            }, default=str)
            self._lambda_client.invoke(
                FunctionName=fn,
                InvocationType="Event",
                Payload=payload,
            )
            logger.info("Routed result to %s: %s/%s", fn, bucket, key)
        except Exception as exc:
            logger.error("Failed to invoke routing engine: %s", exc)

    def _handle_queue_failure(self, msg: QueueMessage):
        if msg.attempt >= msg.max_attempts:
            self.queue.dead_letter(msg)
            logger.error("Message sent to DLQ after %d attempts: %s/%s", msg.attempt, msg.bucket, msg.key)
        else:
            self.queue.requeue(msg, delay=msg.attempt * 10)

    def enqueue_s3_prefix(self, bucket: str, prefix: str = "", max_files: Optional[int] = None) -> int:
        """List S3 objects under a prefix and enqueue them for scanning.
        Returns the number of messages enqueued.
        """
        objects = list(self.s3_client.list_objects(bucket, prefix, max_files))
        messages = [
            QueueMessage(
                bucket=bucket,
                key=obj["Key"],
                file_size=obj["Size"],
                etag=obj.get("ETag", ""),
                max_attempts=self.settings.queue_max_retries,
            )
            for obj in objects
        ]
        count = self.queue.enqueue_batch(messages)
        logger.info("Enqueued %d/%d objects from s3://%s/%s", count, len(objects), bucket, prefix)
        return count

    def get_queue_stats(self) -> dict:
        return {
            "queue_size": self.queue.size(),
            "dlq_size": getattr(self.queue, "get_dlq_size", lambda: 0)(),
            "backend": self.settings.queue_backend,
            "healthy": self.queue.health_check(),
        }

    def get_metrics(self) -> dict:
        """Get scan metrics."""
        return self.metrics.get_metrics()

    def clear_results(self):
        """Clear cached results."""
        self.scan_results = []
        self.hash_detector.clear_cache()

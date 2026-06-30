import time
import psutil
from datetime import datetime
from typing import Dict, Optional


class ScanMetricsCollector:
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.scanned_files = 0
        self.malware_detected = 0
        self.errors = 0
        self.api_calls = {"virustotal": 0, "nsrl": 0, "jira": 0}
        self.scan_times = []
        self.peak_memory_mb = 0
        self.process = psutil.Process()

    def start(self):
        self.start_time = datetime.now()
        self.peak_memory_mb = 0

    def end(self):
        self.end_time = datetime.now()

    def record_scan(self, scan_time_ms: float):
        self.scanned_files += 1
        self.scan_times.append(scan_time_ms)
        self._update_memory()

    def record_malware(self):
        self.malware_detected += 1

    def record_error(self):
        self.errors += 1

    def record_api_call(self, service: str):
        if service in self.api_calls:
            self.api_calls[service] += 1

    def _update_memory(self):
        try:
            mem_mb = self.process.memory_info().rss / 1024 / 1024
            self.peak_memory_mb = max(self.peak_memory_mb, mem_mb)
        except:
            pass

    def get_metrics(self) -> Dict:
        if not self.start_time or not self.end_time:
            return {}

        duration = (self.end_time - self.start_time).total_seconds()
        avg_scan_time = sum(self.scan_times) / len(self.scan_times) if self.scan_times else 0
        throughput = self.scanned_files / duration if duration > 0 else 0
        detection_rate = (self.malware_detected / self.scanned_files * 100) if self.scanned_files > 0 else 0

        return {
            "total_files_scanned": self.scanned_files,
            "total_malware_detected": self.malware_detected,
            "detection_rate_percent": detection_rate,
            "total_errors": self.errors,
            "average_scan_time_ms": avg_scan_time,
            "peak_memory_mb": self.peak_memory_mb,
            "total_duration_seconds": duration,
            "throughput_files_per_second": throughput,
            "api_calls": self.api_calls,
        }

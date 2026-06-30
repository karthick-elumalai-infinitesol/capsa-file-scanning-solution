from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Dict


class FileHash(BaseModel):
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None


class DetectionResult(BaseModel):
    engine: str
    category: str
    result: str
    update_date: Optional[str] = None


class ScanResult(BaseModel):
    file_path: str
    file_name: str
    file_size: int
    hashes: FileHash
    is_malware: bool
    threat_level: str  # "low", "medium", "high", "critical", "clean"
    detection_source: str  # "virustotal", "nsrl", "unknown"
    detections: Dict[str, DetectionResult] = {}
    jira_ticket_id: Optional[str] = None
    scan_timestamp: datetime
    error: Optional[str] = None


class ScanProgress(BaseModel):
    total_files: int
    scanned_files: int
    malware_detected: int
    clean_files: int
    errors: int
    start_time: datetime
    current_time: datetime
    estimated_time_remaining: Optional[float] = None
    throughput_files_per_second: float


class ScanMetrics(BaseModel):
    total_files_scanned: int
    total_malware_detected: int
    detection_rate: float
    false_positive_rate: float
    average_scan_time_ms: float
    peak_memory_mb: float
    total_duration_seconds: float
    files_per_second: float

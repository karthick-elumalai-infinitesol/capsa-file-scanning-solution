import hashlib
from typing import Optional, Dict, Tuple
from src.config import get_settings
from src.models.scan_result import FileHash, DetectionResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class HashDetector:
    def __init__(self):
        self.settings = get_settings()
        self.cache = {} if self.settings.enable_cache else None

    def calculate_hashes(self, file_content: bytes) -> FileHash:
        hashes = FileHash()

        for algo in self.settings.file_hash_algorithms:
            if algo == "md5":
                hashes.md5 = hashlib.md5(file_content).hexdigest()
            elif algo == "sha1":
                hashes.sha1 = hashlib.sha1(file_content).hexdigest()
            elif algo == "sha256":
                hashes.sha256 = hashlib.sha256(file_content).hexdigest()

        return hashes

    def calculate_hashes_from_stream(self, file_stream, chunk_size: int = 8192) -> FileHash:
        """Calculate hashes while streaming large files."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        while True:
            chunk = file_stream.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

        return FileHash(
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
            sha256=sha256.hexdigest(),
        )

    def is_malware(self, file_hashes: FileHash, detections: Dict[str, DetectionResult]) -> Tuple[bool, str]:
        """
        Determine if file is malware based on detections.
        Returns (is_malware, threat_level)
        """
        if not detections:
            return False, "clean"

        detection_count = len(detections)
        if detection_count == 0:
            return False, "clean"

        detection_rate = detection_count
        if detection_rate >= 5:
            return True, "critical"
        elif detection_rate >= 3:
            return True, "high"
        elif detection_rate >= 1:
            return True, "medium"

        return False, "clean"

    def get_cached_detection(self, file_hash: str) -> Optional[Dict]:
        """Retrieve cached detection result if available."""
        if not self.cache:
            return None
        return self.cache.get(file_hash)

    def cache_detection(self, file_hash: str, result: Dict):
        """Cache a detection result."""
        if self.cache is not None:
            self.cache[file_hash] = result

    def clear_cache(self):
        """Clear the detection cache."""
        if self.cache is not None:
            self.cache.clear()

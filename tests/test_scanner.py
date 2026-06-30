import pytest
from src.scanner.hash_detector import HashDetector
from src.models.scan_result import FileHash, DetectionResult


def test_hash_calculation():
    """Test hash calculation."""
    detector = HashDetector()
    test_data = b"test file content"

    hashes = detector.calculate_hashes(test_data)

    assert hashes.md5 == "c785060c866796cc2a1708c997154c8e"
    assert hashes.sha1 == "9032bbc224ed8b39183cb93b9a7447727ce67f9d"
    assert hashes.sha256 == "60f5237ed4049f0382661ef009d2bc42e48c3ceb3edb6600f7024e7ab3b838f3"


def test_malware_detection():
    """Test malware detection logic."""
    detector = HashDetector()
    hashes = FileHash(md5="test", sha1="test", sha256="test")

    # Test with multiple detections
    detections = {
        "engine1": DetectionResult(engine="engine1", category="malware", result="Trojan.Generic"),
        "engine2": DetectionResult(engine="engine2", category="malware", result="Win.Malware"),
        "engine3": DetectionResult(engine="engine3", category="malware", result="Suspicious.Heur"),
    }

    is_malware, threat_level = detector.is_malware(hashes, detections)
    assert is_malware == True
    assert threat_level == "high"


def test_no_detections():
    """Test clean file detection."""
    detector = HashDetector()
    hashes = FileHash(md5="test", sha1="test", sha256="test")

    is_malware, threat_level = detector.is_malware(hashes, {})
    assert is_malware == False
    assert threat_level == "clean"


def test_hash_cache():
    """Test detection caching."""
    detector = HashDetector()

    test_hash = "abc123def456"
    test_result = {"detection": "malware"}

    detector.cache_detection(test_hash, test_result)
    cached = detector.get_cached_detection(test_hash)

    assert cached == test_result

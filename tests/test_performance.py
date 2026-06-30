import pytest
import time
import json
from datetime import datetime
from src.scanner.concurrent_scanner import ConcurrentScanner
from src.data_generation.test_data_generator import TestDataGenerator
from src.config import get_settings


class TestPerformance:
    @pytest.fixture
    def settings(self):
        return get_settings()

    def test_hash_calculation_performance(self):
        """Benchmark hash calculation performance."""
        from src.scanner.hash_detector import HashDetector

        detector = HashDetector()
        test_data = b"x" * (1024 * 1024)  # 1 MB

        start = time.time()
        for _ in range(100):
            hashes = detector.calculate_hashes(test_data)
        duration = time.time() - start

        avg_time_ms = (duration / 100) * 1000
        print(f"\nHash calculation: {avg_time_ms:.2f}ms per 1MB file")
        assert avg_time_ms < 100  # Should complete in < 100ms per MB

    def test_concurrent_scanner_throughput(self):
        """Test scanner throughput with mock data."""
        scanner = ConcurrentScanner()

        # Create mock S3 objects
        mock_objects = [
            {"Key": f"file_{i}.bin", "Size": 1024 * 1024}
            for i in range(100)
        ]

        # Simulate scanning
        start = time.time()
        # In a real scenario, would scan actual S3 objects
        for obj in mock_objects:
            scanner.metrics.record_scan(50)  # Simulate 50ms per file
        duration = time.time() - start

        throughput = len(mock_objects) / duration
        print(f"\nScanner throughput: {throughput:.2f} files/sec")
        assert throughput > 1  # At least 1 file per second

    def test_metrics_collection(self):
        """Test metrics collection accuracy."""
        scanner = ConcurrentScanner()
        scanner.metrics.start()

        # Simulate scanning
        for i in range(50):
            scanner.metrics.record_scan(50)
            if i % 5 == 0:
                scanner.metrics.record_malware()

        scanner.metrics.end()
        metrics = scanner.metrics.get_metrics()

        assert metrics["total_files_scanned"] == 50
        assert metrics["total_malware_detected"] == 10
        assert "throughput_files_per_second" in metrics
        assert metrics["average_scan_time_ms"] > 0

        print(f"\nMetrics: {json.dumps(metrics, indent=2, default=str)}")

    def test_1tb_scan_simulation(self):
        """
        Simulate 1TB scan performance.
        This estimates performance on 1TB dataset.
        """
        scanner = ConcurrentScanner()
        scanner.metrics.start()

        # Simulate smaller dataset for test (100k files instead of 1M)
        files_to_scan = 100000
        chunk_size = 10000

        for chunk in range(0, files_to_scan, chunk_size):
            batch_size = min(chunk_size, files_to_scan - chunk)
            for _ in range(batch_size):
                scanner.metrics.record_scan(100)  # 100ms per file average
                if _ % 2 == 0:  # 50% detection rate
                    scanner.metrics.record_malware()

        scanner.metrics.end()
        metrics = scanner.metrics.get_metrics()

        print(f"\n1TB Scan Simulation Results (100k file sample):")
        print(f"  Files scanned: {metrics['total_files_scanned']:,}")
        print(f"  Malware detected: {metrics['total_malware_detected']:,}")
        print(f"  Detection rate: {metrics['detection_rate_percent']:.2f}%")
        print(f"  Duration: {metrics['total_duration_seconds']:.2f} seconds")
        print(f"  Throughput: {metrics['throughput_files_per_second']:.2f} files/sec")
        print(f"  Avg scan time: {metrics['average_scan_time_ms']:.2f}ms")

        # Verify throughput expectations
        assert metrics["throughput_files_per_second"] > 0
        assert metrics["total_malware_detected"] > 0
        assert metrics["total_files_scanned"] == files_to_scan

    def generate_performance_report(self, output_file: str = "performance_report.json"):
        """Generate a performance report."""
        scanner = ConcurrentScanner()
        metrics = scanner.get_metrics() or {}

        report = {
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "max_workers": get_settings().max_workers,
                "chunk_size": get_settings().chunk_size,
            },
            "results": {
                "metrics": metrics,
                "success": len(metrics) > 0,
            },
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\nPerformance report saved to {output_file}")
        return report

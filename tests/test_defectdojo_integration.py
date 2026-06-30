"""Tests for DefectDojo integration.

Uses request mocking to avoid requiring a live DefectDojo instance.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.integrations.defectdojo import DefectDojoClient
from src.models.scan_result import ScanResult, FileHash, DetectionResult
from datetime import datetime


@pytest.fixture
def mock_settings():
    with patch("src.integrations.defectdojo.get_settings") as mock_get:
        settings = MagicMock()
        settings.defectdojo_url = "https://defectdojo.example.com"
        settings.defectdojo_api_key = "test-api-key-12345"
        settings.defectdojo_product_name = "CAPSA-Test"
        settings.defectdojo_engagement_name = "Test-Engagement"
        mock_get.return_value = settings
        yield settings


@pytest.fixture
def defectdojo_client(mock_settings):
    return DefectDojoClient()


@pytest.fixture
def sample_malware_result():
    return ScanResult(
        file_path="s3://test-bucket/malware/eicar.exe",
        file_name="eicar.exe",
        file_size=1024,
        hashes=FileHash(
            md5="69630e4574ec6798239b091cda43dca0",
            sha1="cf8bd9dfddff007f75adf4c2be48005cea317c62",
            sha256="131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
        ),
        is_malware=True,
        threat_level="medium",
        detection_source="clamav",
        detections={
            "clamav": DetectionResult(
                engine="clamav", category="malware", result="Eicar-Signature"
            )
        },
        scan_timestamp=datetime.now(),
    )


@pytest.fixture
def sample_clean_result():
    return ScanResult(
        file_path="s3://test-bucket/clean/readme.txt",
        file_name="readme.txt",
        file_size=512,
        hashes=FileHash(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        is_malware=False,
        threat_level="clean",
        detection_source="clean",
        detections={},
        scan_timestamp=datetime.now(),
    )


class TestDefectDojoClient:
    def test_init(self, defectdojo_client):
        assert defectdojo_client.base_url == "https://defectdojo.example.com"
        assert defectdojo_client.api_key == "test-api-key-12345"
        assert "Authorization" in defectdojo_client._headers
        assert "ApiKey" in defectdojo_client._headers["Authorization"]

    @patch("src.integrations.defectdojo.requests.request")
    def test_ensure_product_new(self, mock_request, defectdojo_client):
        mock_request.return_value.json.side_effect = [
            {"results": [], "count": 0},
            {"id": 42, "name": "CAPSA-Test"},
        ]

        product_id = defectdojo_client._ensure_product()
        assert product_id == 42

        calls = mock_request.call_args_list
        assert len(calls) == 2
        assert "products" in calls[0][0][1]
        assert calls[1][0][0] == "POST"

    @patch("src.integrations.defectdojo.requests.request")
    def test_ensure_product_existing(self, mock_request, defectdojo_client):
        mock_request.return_value.json.return_value = {
            "results": [{"id": 7, "name": "CAPSA-Test"}],
            "count": 1,
        }

        product_id = defectdojo_client._ensure_product()
        assert product_id == 7
        mock_request.assert_called_once()

    @patch("src.integrations.defectdojo.requests.request")
    def test_severity_mapping(self, mock_request, defectdojo_client, sample_malware_result):
        mock_request.return_value.json.side_effect = [
            {"results": [{"id": 1, "name": "CAPSA-Test"}], "count": 1},
            {"results": [{"id": 2, "name": "Test-Engagement"}], "count": 1},
            {"results": [{"id": 10, "name": "CAPSA ClamAV Scan"}], "count": 1},
            {"id": 100, "title": "test"},
        ]

        finding_id = defectdojo_client.import_scan_result(sample_malware_result)
        assert finding_id == 100

        last_call = mock_request.call_args_list[-1]
        assert last_call[0][0] == "POST"
        assert last_call[0][1] == "findings"
        assert "severity" in last_call[1]["data"]
        assert last_call[1]["data"]["severity"] == "Medium"

    @patch("src.integrations.defectdojo.requests.request")
    def test_import_scan_result_clean_skipped(
        self, mock_request, defectdojo_client, sample_clean_result
    ):
        mock_request.return_value.json.side_effect = [
            {"results": [{"id": 1, "name": "CAPSA-Test"}], "count": 1},
            {"results": [{"id": 2, "name": "Test-Engagement"}], "count": 1},
            {"results": [{"id": 10, "name": "CAPSA ClamAV Scan"}], "count": 1},
            {"id": 200},
        ]

        finding_id = defectdojo_client.import_scan_result(sample_clean_result)
        assert finding_id == 200

        last_call = mock_request.call_args_list[-1]
        assert last_call[1]["data"]["severity"] == "Info"

    @patch("src.integrations.defectdojo.requests.request")
    def test_health_check_ok(self, mock_request, defectdojo_client):
        mock_request.return_value.json.return_value = {"results": [], "count": 0}
        assert defectdojo_client.health_check() is True

    @patch("src.integrations.defectdojo.requests.request")
    def test_health_check_fail(self, mock_request, defectdojo_client):
        mock_request.side_effect = Exception("Connection refused")
        assert defectdojo_client.health_check() is False

    @patch("src.integrations.defectdojo.requests.request")
    def test_bulk_import(
        self, mock_request, defectdojo_client, sample_malware_result, sample_clean_result
    ):
        mock_request.return_value.json.side_effect = [
            {"results": [{"id": 1, "name": "CAPSA-Test"}], "count": 1},
            {"results": [{"id": 2, "name": "Test-Engagement"}], "count": 1},
            {"results": [{"id": 10, "name": "CAPSA ClamAV Scan"}], "count": 1},
            {"id": 100},
        ]

        results = [sample_malware_result, sample_clean_result]
        count = defectdojo_client.import_scan_results_bulk(results)

        assert count == 1

    def test_capsa_to_defectdojo_severity(self, defectdojo_client):
        assert defectdojo_client._capsa_to_defectdojo_severity("critical") == "Critical"
        assert defectdojo_client._capsa_to_defectdojo_severity("high") == "High"
        assert defectdojo_client._capsa_to_defectdojo_severity("medium") == "Medium"
        assert defectdojo_client._capsa_to_defectdojo_severity("low") == "Low"
        assert defectdojo_client._capsa_to_defectdojo_severity("clean") == "Info"
        assert defectdojo_client._capsa_to_defectdojo_severity("unknown") == "Info"

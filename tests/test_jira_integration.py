import pytest
from unittest.mock import Mock, patch
from src.integrations.jira import JiraClient
from src.config import get_settings
from src.models.scan_result import ScanResult, FileHash, DetectionResult
from datetime import datetime


@pytest.fixture(autouse=True)
def clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_jira_client_initialization():
    """Test Jira client initialization."""
    with patch.dict("os.environ", {
        "JIRA_URL": "https://example.atlassian.net",
        "JIRA_USERNAME": "user@example.com",
        "JIRA_API_TOKEN": "token",
    }, clear=False):
        client = JiraClient()
    assert client.base_url is not None
    assert client.project_key is not None


def test_create_issue_without_credentials():
    """Test issue creation without credentials."""
    with patch.dict("os.environ", {}, clear=True):
        client = JiraClient()
    client.base_url = ""

    result = ScanResult(
        file_path="s3://bucket/malware.bin",
        file_name="malware.bin",
        file_size=1024,
        hashes=FileHash(md5="test", sha1="test", sha256="test"),
        is_malware=True,
        threat_level="high",
        detection_source="virustotal",
        scan_timestamp=datetime.now(),
    )

    issue_id = client.create_issue(result)
    assert issue_id is None


def test_format_description():
    """Test description formatting."""
    with patch.dict("os.environ", {
        "JIRA_URL": "https://example.atlassian.net",
        "JIRA_USERNAME": "user@example.com",
        "JIRA_API_TOKEN": "token",
    }, clear=False):
        client = JiraClient()

    result = ScanResult(
        file_path="s3://bucket/malware.bin",
        file_name="malware.bin",
        file_size=1024,
        hashes=FileHash(md5="abc123", sha1="def456", sha256="ghi789"),
        is_malware=True,
        threat_level="high",
        detection_source="virustotal",
        scan_timestamp=datetime.now(),
        detections={
            "Engine1": DetectionResult(
                engine="Engine1",
                category="malware",
                result="Trojan.Generic"
            ),
        }
    )

    description = client._format_description(result)
    assert "malware.bin" in description
    assert "abc123" in description
    assert "def456" in description
    assert "ghi789" in description


@patch("src.integrations.jira.requests.post")
@patch("src.integrations.jira.requests.get")
def test_jira_uses_username_auth(mock_get, mock_post):
    with patch.dict("os.environ", {
        "JIRA_URL": "https://example.atlassian.net",
        "JIRA_USERNAME": "user@example.com",
        "JIRA_API_TOKEN": "token",
        "JIRA_PROJECT_KEY": "SEC",
    }, clear=False):
        client = JiraClient()

    mock_get.return_value = Mock(status_code=200, json=lambda: {"issues": []})
    mock_post.return_value = Mock(status_code=201, json=lambda: {"id": "10001"}, text="")

    result = ScanResult(
        file_path="s3://bucket/malware.bin",
        file_name="malware.bin",
        file_size=1024,
        hashes=FileHash(md5="abc123", sha1="def456", sha256="ghi789"),
        is_malware=True,
        threat_level="high",
        detection_source="clamav",
        scan_timestamp=datetime.now(),
        detections={},
    )

    issue_id = client.create_issue(result)

    assert issue_id == "10001"
    assert mock_get.call_args.kwargs["auth"] == ("user@example.com", "token")
    assert mock_post.call_args.kwargs["auth"] == ("user@example.com", "token")
    assert mock_post.call_args.args[0].endswith("/rest/api/3/issue")

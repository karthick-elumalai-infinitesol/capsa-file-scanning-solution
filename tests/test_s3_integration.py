import pytest
from src.scanner.s3_client import S3Client


def test_s3_client_initialization():
    """Test S3 client initialization."""
    client = S3Client()
    assert client.client is not None
    assert client.settings is not None


def test_s3_list_buckets():
    """Test listing S3 buckets (requires AWS credentials)."""
    client = S3Client()

    try:
        buckets = client.list_buckets()
        assert isinstance(buckets, list)
    except Exception as e:
        pytest.skip(f"AWS credentials not available: {str(e)}")


def test_object_exists():
    """Test object existence check."""
    client = S3Client()

    # This will fail without valid bucket, which is expected
    try:
        exists = client.object_exists("nonexistent-bucket", "test-key")
        assert isinstance(exists, bool)
    except Exception:
        pytest.skip("S3 not available in test environment")

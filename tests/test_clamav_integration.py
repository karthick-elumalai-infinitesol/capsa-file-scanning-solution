import io
from unittest.mock import patch

import pytest

from src.config import get_settings
from src.integrations.clamav import ClamAVClient


@pytest.fixture(autouse=True)
def clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@patch("src.integrations.clamav.clamd.ClamdNetworkSocket")
def test_scan_stream_clean(mock_socket):
    mock_socket.return_value.instream.return_value = {"stream": ("OK",)}
    client = ClamAVClient()

    result = client.scan_stream(io.BytesIO(b"clean file"))

    assert result == {}


@patch("src.integrations.clamav.clamd.ClamdNetworkSocket")
def test_scan_stream_infected(mock_socket):
    mock_socket.return_value.instream.return_value = {
        "stream": ("FOUND", "Win.Test.EICAR_HDB-1")
    }
    client = ClamAVClient()

    result = client.scan_stream(io.BytesIO(b"eicar bytes"))

    assert "clamav" in result
    assert result["clamav"].result == "Win.Test.EICAR_HDB-1"
    assert result["clamav"].category == "malware"


@patch("src.integrations.clamav.clamd.ClamdNetworkSocket")
def test_scan_stream_error(mock_socket):
    mock_socket.return_value.instream.side_effect = RuntimeError("clamav unavailable")
    client = ClamAVClient()

    result = client.scan_stream(io.BytesIO(b"data"))

    assert "clamav_error" in result
    assert result["clamav_error"].category == "error"
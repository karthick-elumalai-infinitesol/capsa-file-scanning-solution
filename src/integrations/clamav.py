import io
from typing import BinaryIO, Dict

import clamd

from src.config import get_settings
from src.models.scan_result import DetectionResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ClamAVClient:
    def __init__(self):
        self.settings = get_settings()
        self.host = self.settings.clamav_host
        self.port = self.settings.clamav_port
        self.timeout = self.settings.clamav_timeout

    def _socket(self):
        return clamd.ClamdNetworkSocket(
            host=self.host,
            port=self.port,
            timeout=self.timeout,
        )

    def scan_stream(self, stream: BinaryIO) -> Dict[str, DetectionResult]:
        """Scan a binary stream over ClamAV INSTREAM and normalize detections."""
        try:
            if hasattr(stream, "seek"):
                stream.seek(0)

            result = self._socket().instream(stream)
            status = result.get("stream", ())
            if not status:
                logger.warning("ClamAV returned an empty result")
                return {}

            verdict = status[0]
            if verdict == "OK":
                return {}

            if verdict == "FOUND":
                signature = status[1] if len(status) > 1 else "Unknown.Signature"
                return {
                    "clamav": DetectionResult(
                        engine="clamav",
                        category="malware",
                        result=signature,
                    )
                }

            logger.warning("Unexpected ClamAV verdict: %s", verdict)
            return {
                "clamav": DetectionResult(
                    engine="clamav",
                    category="unknown",
                    result=str(verdict),
                )
            }
        except Exception as exc:
            logger.error("ClamAV stream scan failed: %s", exc)
            return {
                "clamav_error": DetectionResult(
                    engine="clamav",
                    category="error",
                    result=str(exc),
                )
            }

    def scan_bytes(self, file_bytes: bytes) -> Dict[str, DetectionResult]:
        return self.scan_stream(io.BytesIO(file_bytes))
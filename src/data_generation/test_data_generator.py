import io
import os
import random
import string
import tempfile
from typing import Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)

EICAR_TEST_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class TestDataGenerator:
    """Generate synthetic test datasets for local/integration testing."""

    def __init__(self, bucket: str, prefix: str = "test-data/"):
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/"
        self._s3 = None

    @property
    def s3(self):
        if self._s3 is None:
            import boto3
            self._s3 = boto3.client("s3")
        return self._s3

    def _generate_file(self, size_mb: int, is_malware: bool = False) -> bytes:
        size = size_mb * 1024 * 1024
        if is_malware:
            payload = bytearray(size)
            payload[:len(EICAR_TEST_STRING)] = EICAR_TEST_STRING
            for i in range(len(EICAR_TEST_STRING), size):
                payload[i] = random.randint(0, 255)
            return bytes(payload)
        else:
            return bytes(random.randint(0, 255) for _ in range(size))

    def _upload(self, key: str, data: bytes):
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=data)
        logger.info("Uploaded s3://%s/%s (%d bytes)", self.bucket, key, len(data))

    def generate_synthetic_dataset(
        self,
        malware_count: int = 10,
        clean_count: int = 10,
        malware_size_mb: int = 10,
        clean_size_mb: int = 10,
    ) -> Tuple[int, int]:
        """Generate synthetic files in S3.

        Returns:
            Tuple of (malware_uploaded, clean_uploaded) counts.
        """
        logger.info(
            "Generating dataset: %d malware (%d MB), %d clean (%d MB) to s3://%s/%s",
            malware_count, malware_size_mb,
            clean_count, clean_size_mb,
            self.bucket, self.prefix,
        )

        for i in range(malware_count):
            key = f"{self.prefix}malware/sample_{i+1:04d}.bin"
            data = self._generate_file(malware_size_mb, is_malware=True)
            self._upload(key, data)

        for i in range(clean_count):
            key = f"{self.prefix}clean/file_{i+1:04d}.bin"
            data = self._generate_file(clean_size_mb, is_malware=False)
            self._upload(key, data)

        logger.info(
            "Dataset generation complete: %d malware, %d clean",
            malware_count, clean_count,
        )
        return malware_count, clean_count

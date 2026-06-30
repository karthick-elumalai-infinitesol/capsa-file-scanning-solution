#!/usr/bin/env python3
"""
Generate and upload test data for CAPSA Healthcare scanning.
Creates synthetic malware (EICAR) and clean samples for 1TB testing.
"""

import argparse
import os
import sys
import json
import boto3
import logging
from pathlib import Path
from datetime import datetime
from typing import Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# EICAR test file pattern (safe, recognized by all antivirus)
EICAR_PATTERN = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class TestDataGenerator:
    """Generate and upload test data to S3."""

    def __init__(self, bucket: str, region: str = "us-east-1"):
        """
        Initialize test data generator.

        Args:
            bucket: S3 bucket name
            region: AWS region
        """
        self.bucket = bucket
        self.region = region
        self.s3_client = boto3.client("s3", region_name=region)
        self.stats = {
            'files_created': 0,
            'files_uploaded': 0,
            'bytes_uploaded': 0,
            'errors': 0
        }

    def generate_eicar_file(self, filename: str) -> bytes:
        """Generate EICAR test file."""
        return EICAR_PATTERN + b"\n"

    def generate_clean_file(self, filename: str, size_bytes: int) -> bytes:
        """Generate random clean file."""
        # Create a clean text file with dummy content
        content = f"""
This is a clean test file: {filename}
Generated at: {datetime.now()}
File size target: {size_bytes} bytes

Lorem ipsum dolor sit amet, consectetur adipiscing elit.
Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.
"""

        # Pad to target size
        while len(content.encode()) < size_bytes:
            content += content

        return content[:size_bytes].encode()

    def upload_file(self, key: str, data: bytes, metadata: dict = None) -> bool:
        """
        Upload file to S3.

        Args:
            key: S3 object key
            data: File data
            metadata: Optional metadata tags

        Returns:
            True if successful
        """
        try:
            # Prepare tags
            tags = []
            if metadata:
                for k, v in metadata.items():
                    tags.append({'Key': k, 'Value': str(v)})

            # Upload
            self.s3_client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=data,
                ServerSideEncryption='aws:kms',
                Tagging=json.dumps({'TagSet': tags}) if tags else None,
                Metadata={'created': datetime.now().isoformat()}
            )

            self.stats['files_uploaded'] += 1
            self.stats['bytes_uploaded'] += len(data)
            logger.info(f"✅ Uploaded: s3://{self.bucket}/{key} ({len(data)} bytes)")
            return True

        except Exception as e:
            logger.error(f"❌ Error uploading {key}: {str(e)}")
            self.stats['errors'] += 1
            return False

    def generate_test_dataset(self, size_gb: float = 1.0, prefix: str = "test-data") -> None:
        """
        Generate complete test dataset.

        Args:
            size_gb: Total dataset size in GB
            prefix: S3 prefix for uploaded files
        """
        logger.info(f"🔄 Generating {size_gb} GB test dataset...")

        total_bytes = int(size_gb * 1024 * 1024 * 1024)
        malware_bytes = total_bytes // 2
        clean_bytes = total_bytes - malware_bytes

        # Generate malware files (EICAR)
        logger.info(f"📁 Generating {malware_bytes / 1024 / 1024 / 1024:.1f} GB malware samples...")
        malware_prefix = f"{prefix}/malware"
        malware_count = 0
        uploaded_malware_bytes = 0

        while uploaded_malware_bytes < malware_bytes:
            filename = f"eicar_sample_{malware_count:06d}.bin"
            key = f"{malware_prefix}/{filename}"

            eicar_data = self.generate_eicar_file(filename)

            if self.upload_file(key, eicar_data, {
                'type': 'malware',
                'pattern': 'eicar',
                'category': 'test-file'
            }):
                malware_count += 1
                uploaded_malware_bytes += len(eicar_data)

            # Show progress every 100 files
            if malware_count % 100 == 0:
                percent = (uploaded_malware_bytes / malware_bytes) * 100
                logger.info(f"  {percent:.1f}% - {malware_count} files - "
                           f"{uploaded_malware_bytes / 1024 / 1024:.1f} MB")

        # Generate clean files
        logger.info(f"📁 Generating {clean_bytes / 1024 / 1024 / 1024:.1f} GB clean samples...")
        clean_prefix = f"{prefix}/clean"
        clean_count = 0
        uploaded_clean_bytes = 0

        while uploaded_clean_bytes < clean_bytes:
            filename = f"clean_file_{clean_count:06d}.txt"
            key = f"{clean_prefix}/{filename}"

            # Vary file sizes for realism
            avg_file_size = 1024 * 1024  # 1MB average
            clean_data = self.generate_clean_file(filename, avg_file_size)

            if self.upload_file(key, clean_data, {
                'type': 'clean',
                'category': 'test-data'
            }):
                clean_count += 1
                uploaded_clean_bytes += len(clean_data)

            # Show progress every 100 files
            if clean_count % 100 == 0:
                percent = (uploaded_clean_bytes / clean_bytes) * 100
                logger.info(f"  {percent:.1f}% - {clean_count} files - "
                           f"{uploaded_clean_bytes / 1024 / 1024:.1f} MB")

        logger.info(f"✅ Dataset generation complete!")
        self.print_summary()

    def print_summary(self) -> None:
        """Print generation summary."""
        print("\n" + "=" * 80)
        print("TEST DATA GENERATION SUMMARY")
        print("=" * 80)
        print(f"Total files created:     {self.stats['files_created']}")
        print(f"Total files uploaded:    {self.stats['files_uploaded']}")
        print(f"Total bytes uploaded:    {self.stats['bytes_uploaded'] / 1024 / 1024 / 1024:.2f} GB")
        print(f"Upload errors:           {self.stats['errors']}")
        print("=" * 80 + "\n")

        if self.stats['errors'] == 0:
            logger.info("✅ All files generated and uploaded successfully!")
        else:
            logger.warning(f"⚠️  {self.stats['errors']} errors during upload")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate test data for CAPSA Healthcare scanning"
    )
    parser.add_argument(
        "--bucket",
        required=True,
        help="S3 bucket name (staging bucket)"
    )
    parser.add_argument(
        "--size",
        type=float,
        default=1.0,
        help="Dataset size in GB (default: 1.0)"
    )
    parser.add_argument(
        "--prefix",
        default="test-data",
        help="S3 prefix for uploaded files (default: test-data)"
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)"
    )

    args = parser.parse_args()

    # Validate bucket exists
    try:
        s3 = boto3.client("s3", region_name=args.region)
        s3.head_bucket(Bucket=args.bucket)
    except Exception as e:
        logger.error(f"❌ Cannot access S3 bucket: {args.bucket}")
        logger.error(f"   {str(e)}")
        logger.info("Configure AWS credentials with: aws configure")
        sys.exit(1)

    # Generate test data
    generator = TestDataGenerator(args.bucket, args.region)
    generator.generate_test_dataset(args.size, args.prefix)


if __name__ == "__main__":
    main()

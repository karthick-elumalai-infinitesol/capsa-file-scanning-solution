import boto3
from botocore.exceptions import ClientError
from typing import Optional, List, Generator
from src.config import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class S3Client:
    def __init__(self):
        self.settings = get_settings()
        self.client = boto3.client(
            's3',
            region_name=self.settings.aws_region,
            aws_access_key_id=self.settings.aws_access_key_id or None,
            aws_secret_access_key=self.settings.aws_secret_access_key or None,
        )

    def list_objects(self, bucket: str, prefix: str = "", max_keys: int = None) -> Generator[dict, None, None]:
        """
        List S3 objects in a bucket with optional prefix.
        Yields objects one at a time for memory efficiency.
        """
        paginator = self.client.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(
            Bucket=bucket,
            Prefix=prefix,
            PaginationConfig={'PageSize': 1000} if not max_keys else {'PageSize': min(1000, max_keys)}
        )

        count = 0
        for page in page_iterator:
            if 'Contents' not in page:
                continue

            for obj in page['Contents']:
                if obj['Size'] > 0:  # Skip empty objects
                    yield obj
                    count += 1
                    if max_keys and count >= max_keys:
                        return

    def get_object_stream(self, bucket: str, key: str):
        """
        Get an S3 object as a stream for memory-efficient reading.
        Returns a file-like object.
        """
        try:
            response = self.client.get_object(Bucket=bucket, Key=key)
            return response['Body']
        except ClientError as e:
            logger.error(f"Error reading S3 object {bucket}/{key}: {str(e)}")
            raise

    def get_object_bytes(self, bucket: str, key: str, max_size: int = None) -> Optional[bytes]:
        """
        Get an S3 object as bytes. Useful for small files.
        """
        try:
            response = self.client.get_object(Bucket=bucket, Key=key)
            body = response['Body'].read()

            if max_size and len(body) > max_size:
                logger.warning(f"File {key} exceeds max size {max_size}")
                return None

            return body
        except ClientError as e:
            logger.error(f"Error reading S3 object {bucket}/{key}: {str(e)}")
            raise

    def get_object_metadata(self, bucket: str, key: str) -> dict:
        """Get metadata for an S3 object without downloading it."""
        try:
            response = self.client.head_object(Bucket=bucket, Key=key)
            return {
                'size': response['ContentLength'],
                'last_modified': response['LastModified'],
                'etag': response['ETag'],
                'storage_class': response.get('StorageClass', 'STANDARD'),
            }
        except ClientError as e:
            logger.error(f"Error getting metadata for {bucket}/{key}: {str(e)}")
            raise

    def object_exists(self, bucket: str, key: str) -> bool:
        """Check if an S3 object exists."""
        try:
            self.client.head_object(Bucket=bucket, Key=key)
            return True
        except ClientError:
            return False

    def upload_object(self, bucket: str, key: str, data: bytes) -> bool:
        """Upload data to S3."""
        try:
            self.client.put_object(Bucket=bucket, Key=key, Body=data)
            return True
        except ClientError as e:
            logger.error(f"Error uploading to S3 {bucket}/{key}: {str(e)}")
            return False

    def list_buckets(self) -> List[str]:
        """List all S3 buckets."""
        try:
            response = self.client.list_buckets()
            return [bucket['Name'] for bucket in response['Buckets']]
        except ClientError as e:
            logger.error(f"Error listing buckets: {str(e)}")
            return []

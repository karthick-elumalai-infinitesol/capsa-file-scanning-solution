#!/usr/bin/env python3
"""
Monitor CAPSA Healthcare scanning in progress.
Tracks file scanning, malware detection, and bucket statistics.
"""

import argparse
import sys
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ScanMonitor:
    """Monitor scanning progress and statistics."""

    def __init__(self, region: str = "us-east-1"):
        """
        Initialize scan monitor.

        Args:
            region: AWS region
        """
        self.region = region
        self.s3_client = boto3.client("s3", region_name=region)
        self.cloudwatch_client = boto3.client("cloudwatch", region_name=region)
        self.lambda_client = boto3.client("lambda", region_name=region)

    def get_bucket_stats(self, bucket: str) -> Dict[str, Any]:
        """
        Get statistics for an S3 bucket.

        Args:
            bucket: Bucket name

        Returns:
            Dictionary with bucket statistics
        """
        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=bucket)

            total_files = 0
            total_bytes = 0
            infected_files = 0
            clean_files = 0

            for page in pages:
                if 'Contents' not in page:
                    continue

                for obj in page['Contents']:
                    total_files += 1
                    total_bytes += obj['Size']

                    # Check tags for status
                    try:
                        tags_response = self.s3_client.get_object_tagging(
                            Bucket=bucket,
                            Key=obj['Key']
                        )
                        tags = {t['Key']: t['Value'] for t in tags_response.get('TagSet', [])}

                        if tags.get('scan:status') == 'INFECTED':
                            infected_files += 1
                        elif tags.get('scan:status') == 'CLEAN':
                            clean_files += 1
                    except:
                        pass

            return {
                'bucket': bucket,
                'total_files': total_files,
                'total_bytes': total_bytes,
                'infected_files': infected_files,
                'clean_files': clean_files,
                'total_gb': total_bytes / 1024 / 1024 / 1024
            }

        except Exception as e:
            logger.error(f"Error getting stats for {bucket}: {str(e)}")
            return {
                'bucket': bucket,
                'error': str(e)
            }

    def get_lambda_metrics(self, function_name: str) -> Dict[str, Any]:
        """
        Get CloudWatch metrics for Lambda function.

        Args:
            function_name: Lambda function name

        Returns:
            Dictionary with metrics
        """
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)

            # Get invocation count
            response = self.cloudwatch_client.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='Invocations',
                Dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
                StartTime=start_time,
                EndTime=end_time,
                Period=300,
                Statistics=['Sum']
            )

            invocations = sum(dp['Sum'] for dp in response.get('Datapoints', []))

            # Get errors
            error_response = self.cloudwatch_client.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='Errors',
                Dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
                StartTime=start_time,
                EndTime=end_time,
                Period=300,
                Statistics=['Sum']
            )

            errors = sum(dp['Sum'] for dp in error_response.get('Datapoints', []))

            # Get duration
            duration_response = self.cloudwatch_client.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='Duration',
                Dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
                StartTime=start_time,
                EndTime=end_time,
                Period=300,
                Statistics=['Average', 'Maximum']
            )

            avg_duration = 0
            max_duration = 0
            if duration_response.get('Datapoints'):
                avg_duration = duration_response['Datapoints'][0].get('Average', 0)
                max_duration = duration_response['Datapoints'][0].get('Maximum', 0)

            return {
                'function': function_name,
                'invocations': int(invocations),
                'errors': int(errors),
                'avg_duration_ms': round(avg_duration, 2),
                'max_duration_ms': round(max_duration, 2),
                'error_rate': round((errors / invocations * 100) if invocations > 0 else 0, 2)
            }

        except Exception as e:
            logger.error(f"Error getting metrics for {function_name}: {str(e)}")
            return {'function': function_name, 'error': str(e)}

    def print_status(self, staging_bucket: str, clean_bucket: str, quarantine_bucket: str) -> None:
        """
        Print current scanning status.

        Args:
            staging_bucket: Staging bucket name
            clean_bucket: Clean bucket name
            quarantine_bucket: Quarantine bucket name
        """
        print("\n" + "=" * 80)
        print("CAPSA HEALTHCARE SCANNING STATUS")
        print("=" * 80)
        print(f"Timestamp: {datetime.now()}\n")

        # Staging bucket stats
        print("📥 STAGING BUCKET (Inbound)")
        print("-" * 80)
        staging_stats = self.get_bucket_stats(staging_bucket)
        if 'error' not in staging_stats:
            print(f"  Files:    {staging_stats['total_files']}")
            print(f"  Size:     {staging_stats['total_gb']:.2f} GB")
        else:
            print(f"  Error: {staging_stats['error']}")

        # Clean bucket stats
        print("\n✅ CLEAN BUCKET (Production)")
        print("-" * 80)
        clean_stats = self.get_bucket_stats(clean_bucket)
        if 'error' not in clean_stats:
            print(f"  Files:    {clean_stats['total_files']}")
            print(f"  Size:     {clean_stats['total_gb']:.2f} GB")
        else:
            print(f"  Error: {clean_stats['error']}")

        # Quarantine bucket stats
        print("\n🚨 QUARANTINE BUCKET (Infected)")
        print("-" * 80)
        quarantine_stats = self.get_bucket_stats(quarantine_bucket)
        if 'error' not in quarantine_stats:
            print(f"  Files:    {quarantine_stats['total_files']}")
            print(f"  Size:     {quarantine_stats['total_gb']:.2f} GB")
            if quarantine_stats['total_files'] > 0:
                print(f"  ⚠️  Infected samples in quarantine!")
        else:
            print(f"  Error: {quarantine_stats['error']}")

        # Lambda metrics
        print("\n⚙️  LAMBDA FUNCTION METRICS (Last Hour)")
        print("-" * 80)

        scan_trigger_metrics = self.get_lambda_metrics("capsa-file-scan-trigger")
        print(f"\n  File Scan Trigger:")
        if 'error' not in scan_trigger_metrics:
            print(f"    Invocations: {scan_trigger_metrics['invocations']}")
            print(f"    Errors:      {scan_trigger_metrics['errors']}")
            print(f"    Avg Duration: {scan_trigger_metrics['avg_duration_ms']} ms")
            print(f"    Error Rate:  {scan_trigger_metrics['error_rate']}%")
        else:
            print(f"    Error: {scan_trigger_metrics['error']}")

        routing_metrics = self.get_lambda_metrics("capsa-file-routing-engine")
        print(f"\n  File Routing Engine:")
        if 'error' not in routing_metrics:
            print(f"    Invocations: {routing_metrics['invocations']}")
            print(f"    Errors:      {routing_metrics['errors']}")
            print(f"    Avg Duration: {routing_metrics['avg_duration_ms']} ms")
            print(f"    Error Rate:  {routing_metrics['error_rate']}%")
        else:
            print(f"    Error: {routing_metrics['error']}")

        # Summary
        print("\n" + "=" * 80)
        if 'error' not in clean_stats:
            total_processed = clean_stats['total_files']
            if total_processed == 0:
                print("📊 STATUS: Waiting for files...")
            else:
                print(f"📊 STATUS: Processing {total_processed} files so far")
        else:
            print("📊 STATUS: Unable to retrieve statistics")

        print("=" * 80 + "\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor CAPSA Healthcare scanning"
    )
    parser.add_argument(
        "--staging-bucket",
        required=True,
        help="Staging bucket name"
    )
    parser.add_argument(
        "--clean-bucket",
        required=True,
        help="Clean bucket name"
    )
    parser.add_argument(
        "--quarantine-bucket",
        required=True,
        help="Quarantine bucket name"
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)"
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously monitor (every 30 seconds)"
    )

    args = parser.parse_args()

    monitor = ScanMonitor(args.region)

    if args.watch:
        import time
        try:
            while True:
                monitor.print_status(
                    args.staging_bucket,
                    args.clean_bucket,
                    args.quarantine_bucket
                )
                print("⏳ Updating in 30 seconds... (Press Ctrl+C to stop)\n")
                time.sleep(30)
        except KeyboardInterrupt:
            print("\n✅ Monitoring stopped")
            sys.exit(0)
    else:
        monitor.print_status(
            args.staging_bucket,
            args.clean_bucket,
            args.quarantine_bucket
        )


if __name__ == "__main__":
    main()

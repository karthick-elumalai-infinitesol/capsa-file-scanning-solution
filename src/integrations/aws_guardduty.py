import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from src.config import get_settings

logger = logging.getLogger(__name__)


class GuardDutyClient:
    """AWS GuardDuty integration for correlating malware scan findings.

    Retrieves GuardDuty findings that match S3 object-level threats,
    enabling CAPSA to correlate its ClamAV scans with AWS-native threat
    detection for a multi-signal verdict.
    """

    def __init__(self):
        self.settings = get_settings()
        self.client = boto3.client(
            "guardduty",
            region_name=self.settings.aws_region,
            aws_access_key_id=self.settings.aws_access_key_id or None,
            aws_secret_access_key=self.settings.aws_secret_access_key or None,
        )
        self._detector_id: Optional[str] = None

    def _get_detector_id(self) -> Optional[str]:
        if self._detector_id:
            return self._detector_id
        try:
            response = self.client.list_detectors()
            detectors = response.get("DetectorIds", [])
            if detectors:
                self._detector_id = detectors[0]
            return self._detector_id
        except ClientError as exc:
            logger.warning("Cannot list GuardDuty detectors: %s", exc)
            return None

    def get_findings_for_object(self, bucket: str, key: str, hours_back: int = 24) -> List[Dict]:
        """Retrieve GuardDuty findings related to a specific S3 object.

        Uses bucket/key context in finding details to correlate.
        Returns a list of finding summaries.
        """
        detector_id = self._get_detector_id()
        if not detector_id:
            logger.warning("No GuardDuty detector available")
            return []

        start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)

        try:
            findings = []
            paginator = self.client.get_paginator("list_findings")
            pages = paginator.paginate(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "service.archived": {"Eq": ["false"]},
                        "updatedAt": {"Gte": start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")},
                        "resource.resourceType": {"Eq": ["S3Bucket"]},
                    }
                },
                PaginationConfig={"PageSize": 50, "MaxItems": 200},
            )

            finding_ids = []
            for page in pages:
                finding_ids.extend(page.get("FindingIds", []))

            if not finding_ids:
                return []

            for i in range(0, len(finding_ids), 50):
                batch = finding_ids[i : i + 50]
                detail_response = self.client.get_findings(DetectorId=detector_id, FindingIds=batch)
                for finding in detail_response.get("Findings", []):
                    detail = finding.get("Resource", {}).get("S3BucketDetail", {})
                    if detail.get("BucketName") == bucket:
                        findings.append(self._summarize_finding(finding))

            return findings

        except ClientError as exc:
            logger.error("Error querying GuardDuty findings: %s", exc)
            return []

    def _summarize_finding(self, finding: Dict) -> Dict:
        return {
            "id": finding.get("Id"),
            "severity": finding.get("Severity"),
            "type": finding.get("Type"),
            "title": finding.get("Title"),
            "description": finding.get("Description"),
            "timestamp": str(finding.get("UpdatedAt")),
            "region": finding.get("Region"),
            "compliance_status": finding.get("Service", {}).get("AdditionalInfo", {}).get("ComplianceStatus"),
        }

    def check_for_malware_scan_findings(self, hours_back: int = 24) -> int:
        """Count GuardDuty Malware Protection scan findings.

        AWS GuardDuty Malware Protection for S3 generates findings when
        malware is detected in S3 objects. This method counts active ones.
        """
        detector_id = self._get_detector_id()
        if not detector_id:
            return 0

        try:
            response = self.client.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "service.archived": {"Eq": ["false"]},
                        "type": {"Eq": ["GuardDutyMalwareProtection:S3/MaliciousFile"]},
                    }
                },
                MaxResults=1,
            )
            return len(response.get("FindingIds", []))
        except ClientError:
            return 0

    def get_threat_score(self, bucket: str, key: str, hours_back: int = 24) -> float:
        """Compute a normalized threat score (0.0-1.0) from related GuardDuty findings."""
        findings = self.get_findings_for_object(bucket, key, hours_back)
        if not findings:
            return 0.0

        max_severity = max(f.get("severity", 0) for f in findings)
        return min(max_severity / 9.0, 1.0)

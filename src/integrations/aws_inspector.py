import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from src.config import get_settings

logger = logging.getLogger(__name__)


class InspectorClient:
    """AWS Inspector integration for infrastructure vulnerability context.

    Retrieves Inspector findings for EC2/ECS/container resources that
    CAPSA runs on, providing a unified view of both file-level malware
    and infrastructure-level vulnerabilities.
    """

    def __init__(self):
        self.settings = get_settings()
        self.session = boto3.Session(
            region_name=self.settings.aws_region,
            aws_access_key_id=self.settings.aws_access_key_id or None,
            aws_secret_access_key=self.settings.aws_secret_access_key or None,
        )
        self.client_v2 = self._get_inspector_client()

    def _get_inspector_client(self):
        try:
            return self.session.client("inspector2")
        except Exception as exc:
            logger.warning("Cannot create Inspector2 client: %s", exc)
            return None

    def is_available(self) -> bool:
        """Check if Inspector is enabled in the region."""
        if not self.client_v2:
            return False
        try:
            self.client_v2.batch_get_account_status()
            return True
        except ClientError:
            return False

    def get_vulnerability_findings(
        self, max_results: int = 100, severity: Optional[str] = None, hours_back: int = 72
    ) -> List[Dict]:
        """Retrieve Inspector vulnerability findings.

        Args:
            max_results: Maximum findings to return.
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW).
            hours_back: Lookback window in hours.

        Returns:
            List of summarized Inspector findings.
        """
        if not self.client_v2:
            logger.warning("Inspector2 is not available")
            return []

        start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)

        criteria = {
            "updatedAt": [{"gte": int(start_time.timestamp() * 1000)}],
        }
        if severity:
            criteria["severity"] = [{"eq": [severity]}]

        try:
            findings = []
            paginator = self.client_v2.get_paginator("list_findings")
            pages = paginator.paginate(
                filterCriteria={"severity": criteria.get("severity", [])} if severity else {},
                maxResults=min(max_results, 100),
            )

            count = 0
            for page in pages:
                for finding in page.get("findings", []):
                    if count >= max_results:
                        break
                    findings.append(self._summarize_finding(finding))
                    count += 1

                if count >= max_results:
                    break

            logger.info("Retrieved %d Inspector findings", len(findings))
            return findings

        except ClientError as exc:
            logger.error("Error querying Inspector findings: %s", exc)
            return []

    def _summarize_finding(self, finding: Dict) -> Dict:
        package = finding.get("packageVulnerabilityDetails", {})
        resources = finding.get("resources", [])

        return {
            "id": finding.get("findingArn", "").split("/")[-1],
            "severity": finding.get("severity", "UNKNOWN"),
            "title": package.get("vulnerabilityId", finding.get("title", "Unknown")),
            "description": package.get("vulnerabilityId", ""),
            "cvss_score": self._extract_cvss(package),
            "package": {
                "name": package.get("vulnerabilityId", ""),
                "version": "",
                "fix_version": package.get("fixAvailable", None),
            },
            "resource": resources[0] if resources else {},
            "status": finding.get("status", ""),
            "timestamp": str(finding.get("updatedAt")),
        }

    def _extract_cvss(self, package: Dict) -> Optional[float]:
        for cvss in package.get("cvssScores", []):
            if cvss.get("source", "").upper() == "NVD":
                return cvss.get("score")
        if package.get("cvssScores"):
            return package["cvssScores"][0].get("score")
        return None

    def get_critical_findings(self, hours_back: int = 72) -> List[Dict]:
        """Get only CRITICAL severity findings."""
        return self.get_vulnerability_findings(max_results=50, severity="CRITICAL", hours_back=hours_back)

    def get_ecr_image_scan_findings(self, repository_name: str, image_tag: str) -> List[Dict]:
        """Get Inspector findings for a specific ECR image.

        Useful for scanning the CAPSA scanner container images themselves.
        """
        if not self.client_v2:
            return []

        try:
            response = self.client_v2.list_findings(
                filterCriteria={
                    "resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}],
                    "ecrRepositoryName": [{"comparison": "EQUALS", "value": repository_name}],
                    "imageTag": [{"comparison": "EQUALS", "value": image_tag}],
                },
                maxResults=100,
            )
            return [self._summarize_finding(f) for f in response.get("findings", [])]
        except ClientError as exc:
            logger.error("Error querying ECR image findings: %s", exc)
            return []

    def generate_inspector_report(self, hours_back: int = 168) -> Dict:
        """Generate a summary report of Inspector findings for the given period."""
        findings = self.get_vulnerability_findings(max_results=500, hours_back=hours_back)

        summary = {"total": len(findings), "by_severity": {}, "critical_findings": []}

        for f in findings:
            sev = f.get("severity", "UNKNOWN")
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
            if sev == "CRITICAL":
                summary["critical_findings"].append(
                    {"id": f["id"], "title": f["title"], "cvss": f["cvss_score"]}
                )

        return summary

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from src.config import get_settings

logger = logging.getLogger(__name__)


class DefectDojoClient:
    """Enterprise vulnerability management via DefectDojo API.

    Imports CAPSA scan findings as DefectDojo findings, enabling
    aggregation with 200+ security tools (AWS Security Hub, Trivy,
    Snyk, etc.) in a single vulnerability management platform.
    """

    def __init__(self):
        self.settings = get_settings()
        self.base_url = self.settings.defectdojo_url.rstrip("/")
        self.api_key = self.settings.defectdojo_api_key
        self.product_name = self.settings.defectdojo_product_name
        self.engagement_name = self.settings.defectdojo_engagement_name
        self._headers = {
            "Authorization": f"ApiKey {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._product_id: Optional[int] = None
        self._engagement_id: Optional[int] = None

    def _api_request(
        self, method: str, path: str, data: Optional[Dict] = None, params: Optional[Dict] = None
    ) -> Dict:
        url = f"{self.base_url}/api/v2/{path.lstrip('/')}"
        resp = requests.request(method, url, headers=self._headers, json=data, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _ensure_product(self) -> int:
        if self._product_id:
            return self._product_id

        results = self._api_request("GET", "products", params={"name": self.product_name})
        for prod in results.get("results", []):
            if prod["name"] == self.product_name:
                self._product_id = prod["id"]
                return self._product_id

        created = self._api_request("POST", "products", data={"name": self.product_name, "description": "CAPSA automated malware scanner findings"})
        self._product_id = created["id"]
        logger.info("Created DefectDojo product %s (id=%d)", self.product_name, self._product_id)
        return self._product_id

    def _ensure_engagement(self) -> int:
        if self._engagement_id:
            return self._engagement_id

        product_id = self._ensure_product()
        results = self._api_request("GET", "engagements", params={"product": product_id, "name": self.engagement_name})
        for eng in results.get("results", []):
            if eng["name"] == self.engagement_name:
                self._engagement_id = eng["id"]
                return self._engagement_id

        created = self._api_request(
            "POST",
            "engagements",
            data={
                "name": self.engagement_name,
                "product": product_id,
                "target_start": datetime.now().strftime("%Y-%m-%d"),
                "target_end": datetime.now().strftime("%Y-%m-%d"),
                "status": "In Progress",
            },
        )
        self._engagement_id = created["id"]
        logger.info("Created DefectDojo engagement %s (id=%d)", self.engagement_name, self._engagement_id)
        return self._engagement_id

    def import_scan_result(self, scan_result: Any) -> Optional[int]:
        """Import a single CAPSA ScanResult as a DefectDojo finding.

        Returns the DefectDojo finding ID if successful, None on error.
        """
        try:
            engagement_id = self._ensure_engagement()
            product_id = self._ensure_product()

            severity = self._capsa_to_defectdojo_severity(scan_result.threat_level)
            description = self._build_description(scan_result)

            finding_data = {
                "title": f"CAPSA: {scan_result.detection_source} detection in {scan_result.file_name}",
                "product": product_id,
                "engagement": engagement_id,
                "severity": severity,
                "description": description,
                "mitigation": "Review file. If malicious, quarantine and investigate. If false positive, update NSRL allowlist.",
                "active": True,
                "verified": True,
                "false_p": False,
                "duplicate": False,
                "out_of_scope": False,
                "risk_accepted": False,
                "date": datetime.now().strftime("%Y-%m-%d"),
                "static_finding": False,
                "dynamic_finding": True,
                "found_by": [self._get_test_type_id("CAPSA ClamAV Scan")],
                "file_path": scan_result.file_path,
                "tags": [
                    f"engine:{scan_result.detection_source.replace(',', '_')}",
                    f"threat:{scan_result.threat_level}",
                    "source:capsa",
                    f"size:{scan_result.file_size}",
                ],
            }

            result = self._api_request("POST", "findings", data=finding_data)
            finding_id = result.get("id")
            logger.info("Imported finding %d to DefectDojo: %s", finding_id, scan_result.file_name)
            return finding_id

        except Exception as exc:
            logger.error("Failed to import finding to DefectDojo: %s", exc)
            return None

    def import_scan_results_bulk(self, scan_results: List[Any]) -> int:
        """Import multiple scan results as DefectDojo findings.

        Returns count of successfully imported findings.
        """
        count = 0
        for sr in scan_results:
            if sr.is_malware and self.import_scan_result(sr) is not None:
                count += 1
        logger.info("Bulk imported %d/%d malware findings to DefectDojo", count, len(scan_results))
        return count

    def _capsa_to_defectdojo_severity(self, capsa_level: str) -> str:
        mapping = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "clean": "Info",
        }
        return mapping.get(capsa_level, "Info")

    def _build_description(self, scan_result: Any) -> str:
        lines = [
            f"CAPSA Automated Scan Finding",
            f"",
            f"**File:** {scan_result.file_path}",
            f"**File Size:** {scan_result.file_size} bytes",
            f"**Detection Source:** {scan_result.detection_source}",
            f"**Threat Level:** {scan_result.threat_level}",
            f"**Scan Time:** {scan_result.scan_timestamp.isoformat() if hasattr(scan_result, 'scan_timestamp') else 'N/A'}",
            f"",
            f"**Detections:**",
        ]
        if scan_result.detections:
            for engine, det in scan_result.detections.items():
                lines.append(f"- {engine}: {det.result} ({det.category})")
        else:
            lines.append("- None")
        lines.append("")
        lines.append("**Hashes:**")
        if scan_result.hashes:
            for algo in ["md5", "sha1", "sha256"]:
                val = getattr(scan_result.hashes, algo, None)
                if val:
                    lines.append(f"- {algo.upper()}: `{val}`")
        return "\n".join(lines)

    def _get_test_type_id(self, name: str) -> int:
        results = self._api_request("GET", "test_types", params={"name": name})
        for tt in results.get("results", []):
            if tt["name"] == name:
                return tt["id"]
        created = self._api_request("POST", "test_types", data={"name": name})
        return created["id"]

    def reimport_from_securityhub(self, findings_json: Dict) -> int:
        """Import AWS Security Hub findings JSON (as DefectDojo supports natively).

        This bridges GuardDuty/Inspector findings from Security Hub into
        DefectDojo, reusing CAPSA's DefectDojo product/engagement context.
        """
        engagement_id = self._ensure_engagement()
        scan_data = json.dumps(findings_json)
        try:
            result = self._api_request(
                "POST",
                "reimport-scan/",
                data={
                    "engagement": engagement_id,
                    "product_type": "AWS Security Hub",
                    "scan_type": "AWS Security Hub Scan",
                    "scan_date": datetime.now().strftime("%Y-%m-%d"),
                    "file": scan_data,
                    "active": True,
                },
            )
            count = result.get("findings_imported", 0)
            logger.info("Reimported %d Security Hub findings to DefectDojo", count)
            return count
        except Exception as exc:
            logger.error("Failed to reimport Security Hub findings: %s", exc)
            return 0

    def health_check(self) -> bool:
        """Verify DefectDojo API connectivity."""
        try:
            self._api_request("GET", "products", params={"limit": 1})
            return True
        except Exception:
            return False

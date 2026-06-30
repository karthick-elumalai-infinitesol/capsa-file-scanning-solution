import requests
from typing import Optional, List
from src.config import get_settings
from src.models.scan_result import ScanResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class JiraClient:
    def __init__(self):
        self.settings = get_settings()
        self.base_url = self.settings.jira_url
        self.username = self.settings.jira_username
        self.api_token = self.settings.jira_api_token
        self.project_key = self.settings.jira_project_key

    def create_issue(self, scan_result: ScanResult) -> Optional[str]:
        """
        Create a Jira issue for a malware detection.
        Returns issue ID if successful, None otherwise.
        """
        if not self.base_url or not self.api_token or not self.username:
            logger.warning("Jira credentials not configured")
            return None

        try:
            # Check if issue already exists for this hash
            existing = self.find_issue_by_hash(scan_result.hashes.sha256)
            if existing:
                logger.info(f"Issue already exists for {scan_result.file_name}: {existing}")
                return existing

            # Create new issue
            issue_data = {
                "fields": {
                    "project": {"key": self.project_key},
                    "summary": f"[MALWARE] File detected: {scan_result.file_name}",
                    "description": self._format_description(scan_result),
                    "issuetype": {"name": self.settings.jira_issue_type},
                    "priority": {"name": self.settings.jira_priority},
                    "labels": ["malware", "security", "opensecops"],
                }
            }

            response = requests.post(
                f"{self.base_url}/rest/api/3/issue",
                json=issue_data,
                auth=(self.username, self.api_token),
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if response.status_code == 201:
                issue_id = response.json()['id']
                logger.info(f"Created Jira issue {issue_id} for {scan_result.file_name}")
                return issue_id
            else:
                logger.error(f"Jira API error: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"Error creating Jira issue: {str(e)}")
            return None

    def find_issue_by_hash(self, file_hash: str) -> Optional[str]:
        """Find an existing Jira issue by file hash."""
        if not self.base_url or not self.api_token or not self.username:
            return None

        try:
            jql = f'project = {self.project_key} AND text ~ "{file_hash}"'
            response = requests.get(
                f"{self.base_url}/rest/api/3/search",
                params={"jql": jql},
                auth=(self.username, self.api_token),
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if response.status_code == 200:
                issues = response.json().get('issues', [])
                if issues:
                    return issues[0]['id']

            return None

        except Exception as e:
            logger.error(f"Error searching for issue: {str(e)}")
            return None

    def _format_description(self, result: ScanResult) -> str:
        """Format scan result for Jira issue description."""
        return f"""
*Malware Detection Report*

*File Details:*
- Path: {result.file_path}
- Name: {result.file_name}
- Size: {result.file_size} bytes
- Threat Level: {result.threat_level}

*Hashes:*
- MD5: {result.hashes.md5}
- SHA1: {result.hashes.sha1}
- SHA256: {result.hashes.sha256}

*Detection:*
- Source: {result.detection_source}
- Detected At: {result.scan_timestamp}
- Detections: {len(result.detections)}

*Detected By:*
{self._format_detections(result.detections)}
""".strip()

    def _format_detections(self, detections: dict) -> str:
        """Format detection results for display."""
        if not detections:
            return "No detections"

        formatted = []
        for engine, result in detections.items():
            # Handle both dict and DetectionResult object
            if hasattr(result, 'result'):
                result_str = result.result
            else:
                result_str = result.get('result', 'Unknown')
            formatted.append(f"- {engine}: {result_str}")

        return "\n".join(formatted)

    def add_comment(self, issue_id: str, comment: str) -> bool:
        """Add a comment to a Jira issue."""
        if not self.base_url or not self.api_token or not self.username:
            return False

        try:
            response = requests.post(
                f"{self.base_url}/rest/api/3/issue/{issue_id}/comment",
                json={"body": comment},
                auth=(self.username, self.api_token),
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            return response.status_code == 201

        except Exception as e:
            logger.error(f"Error adding comment: {str(e)}")
            return False

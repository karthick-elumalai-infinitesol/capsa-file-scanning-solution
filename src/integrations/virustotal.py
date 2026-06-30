import requests
import time
from typing import Optional, Dict
from src.config import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class VirusTotalClient:
    def __init__(self):
        self.settings = get_settings()
        self.api_key = self.settings.virustotal_api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limiter = RateLimiter(self.settings.virustotal_rate_limit)
        self.max_retries = 3

    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Look up a file hash on VirusTotal.
        Returns detection results if found.
        """
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None

        try:
            headers = {"x-apikey": self.api_key}
            url = f"{self.base_url}/files/{file_hash}"

            for attempt in range(1, self.max_retries + 1):
                self.rate_limiter.wait()
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.settings.virustotal_timeout
                )

                if response.status_code != 429:
                    break

                retry_after = int(response.headers.get("Retry-After", attempt * 15))
                logger.warning(
                    "VirusTotal rate limited request for %s, retrying in %ss (attempt %s/%s)",
                    file_hash,
                    retry_after,
                    attempt,
                    self.max_retries,
                )
                time.sleep(retry_after)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.debug(f"Hash not found on VirusTotal: {file_hash}")
                return None
            elif response.status_code == 429:
                logger.error("VirusTotal API rate limit exceeded after retries for %s", file_hash)
                return None
            else:
                logger.error(f"VirusTotal API error: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"Error querying VirusTotal: {str(e)}")
            return None

    def get_detections(self, file_hash: str) -> Dict[str, Dict]:
        """
        Get detections from VirusTotal response.
        Returns dict of engine -> detection result.
        """
        result = self.lookup_hash(file_hash)
        if not result or 'data' not in result:
            return {}

        detections = {}
        analysis = result.get('data', {}).get('attributes', {}).get('last_analysis_results', {})

        for engine, detection in analysis.items():
            if detection.get('category') != 'undetected':
                detections[engine] = {
                    "category": detection.get('category'),
                    "result": detection.get('result'),
                    "update_date": detection.get('update_date'),
                }

        return detections


class RateLimiter:
    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = requests_per_minute
        self.min_interval = 60.0 / requests_per_minute
        self.last_request_time = 0

    def wait(self):
        """Wait if necessary to respect rate limits."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.min_interval:
            time.sleep(self.min_interval - time_since_last)
        self.last_request_time = time.time()

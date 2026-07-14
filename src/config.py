import os
from typing import List
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # AWS Configuration
    aws_region: str = os.getenv("AWS_REGION", "us-east-1")
    aws_access_key_id: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    aws_secret_access_key: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    aws_session_token: str = os.getenv("AWS_SESSION_TOKEN", "")
    s3_bucket: str = os.getenv("S3_BUCKET", "opensecops-analyzer")

    # AWS Enterprise Integrations
    aws_guardduty_enabled: bool = os.getenv("AWS_GUARDDUTY_ENABLED", "false").lower() == "true"
    aws_inspector_enabled: bool = os.getenv("AWS_INSPECTOR_ENABLED", "false").lower() == "true"
    aws_securityhub_enabled: bool = os.getenv("AWS_SECURITYHUB_ENABLED", "false").lower() == "true"
    aws_staging_bucket: str = os.getenv("AWS_STAGING_BUCKET", "")
    aws_clean_bucket: str = os.getenv("AWS_CLEAN_BUCKET", "")
    aws_quarantine_bucket: str = os.getenv("AWS_QUARANTINE_BUCKET", "")

    # VirusTotal Configuration
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    virustotal_timeout: int = 10
    virustotal_rate_limit: int = 4

    # NSRL Configuration
    nsrl_database_path: str = os.getenv("NSRL_DATABASE_PATH", "./data/nsrl.db")
    nsrl_update_frequency_days: int = 30

    # Jira Configuration
    jira_url: str = os.getenv("JIRA_URL", "")
    jira_username: str = os.getenv("JIRA_USERNAME", "")
    jira_api_token: str = os.getenv("JIRA_API_TOKEN", "")
    jira_project_key: str = os.getenv("JIRA_PROJECT_KEY", "SEC")
    jira_issue_type: str = "Security Issue"
    jira_priority: str = "High"

    # ClamAV Configuration
    clamav_host: str = os.getenv("CLAMAV_HOST", "localhost")
    clamav_port: int = int(os.getenv("CLAMAV_PORT", "3310"))
    clamav_timeout: int = int(os.getenv("CLAMAV_TIMEOUT", "30"))

    # DefectDojo Configuration
    defectdojo_url: str = os.getenv("DEFECTDOJO_URL", "")
    defectdojo_api_key: str = os.getenv("DEFECTDOJO_API_KEY", "")
    defectdojo_product_name: str = os.getenv("DEFECTDOJO_PRODUCT_NAME", "CAPSA-Scanner")
    defectdojo_engagement_name: str = os.getenv("DEFECTDOJO_ENGAGEMENT_NAME", "Auto-Scan")
    defectdojo_auto_import: bool = os.getenv("DEFECTDOJO_AUTO_IMPORT", "true").lower() == "true"

    # Queue Configuration (for large-scale scanning)
    queue_backend: str = os.getenv("QUEUE_BACKEND", "redis")  # "redis" or "sqs"
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    sqs_queue_name: str = os.getenv("SQS_QUEUE_NAME", "capsa-scan-queue")
    sqs_dlq_name: str = os.getenv("SQS_DLQ_NAME", "capsa-scan-dlq")
    queue_worker_concurrency: int = int(os.getenv("QUEUE_WORKER_CONCURRENCY", "4"))
    queue_visibility_timeout: int = int(os.getenv("QUEUE_VISIBILITY_TIMEOUT", "120"))
    queue_max_retries: int = int(os.getenv("QUEUE_MAX_RETRIES", "3"))

    # Scanner Configuration
    max_workers: int = int(os.getenv("MAX_WORKERS", "20"))
    chunk_size: int = 8192
    file_hash_algorithms: List[str] = ["md5", "sha1", "sha256"]
    max_file_size_mb: int = int(os.getenv("MAX_FILE_SIZE_MB", "100"))
    batch_size: int = int(os.getenv("BATCH_SIZE", "500"))
    enable_s3_polling: bool = os.getenv("ENABLE_S3_POLLING", "false").lower() == "true"
    s3_polling_interval_seconds: int = int(os.getenv("S3_POLLING_INTERVAL_SECONDS", "300"))

    # API Configuration
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    api_debug: bool = os.getenv("API_DEBUG", "false").lower() == "true"

    # Cache Configuration
    enable_cache: bool = os.getenv("ENABLE_CACHE", "true").lower() == "true"
    cache_ttl_seconds: int = 86400

    # Routing Configuration
    routing_function_name: str = os.getenv("ROUTING_FUNCTION_NAME", "")

    # Logging Configuration
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()

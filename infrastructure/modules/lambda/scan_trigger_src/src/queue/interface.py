from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class QueueBackend(str, Enum):
    REDIS = "redis"
    SQS = "sqs"


@dataclass
class QueueMessage:
    """A single message in the scan queue.

    Represents one file to scan. The queue system handles
    delivery, retry, and dead-letter routing automatically.
    """
    bucket: str
    key: str
    file_size: int = 0
    etag: str = ""
    attempt: int = 0
    max_attempts: int = 3
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bucket": self.bucket,
            "key": self.key,
            "file_size": self.file_size,
            "etag": self.etag,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "error": self.error,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QueueMessage":
        return cls(**data)


class ScanQueue(ABC):
    """Abstract queue for distributing scan work across workers.

    Decouples S3 event ingestion from scanning, enabling:
    - Horizontal scaling of scanner workers
    - Automatic retry with backoff
    - Dead-letter queues for failed scans
    - Backpressure handling during large dataset ingestion
    """

    @abstractmethod
    def enqueue(self, message: QueueMessage) -> bool:
        ...

    @abstractmethod
    def enqueue_batch(self, messages: List[QueueMessage]) -> int:
        ...

    @abstractmethod
    def dequeue(self, timeout: int = 30) -> Optional[QueueMessage]:
        ...

    @abstractmethod
    def acknowledge(self, message: QueueMessage) -> bool:
        ...

    @abstractmethod
    def requeue(self, message: QueueMessage, delay: int = 0) -> bool:
        ...

    @abstractmethod
    def dead_letter(self, message: QueueMessage) -> bool:
        ...

    @abstractmethod
    def size(self) -> int:
        ...

    @abstractmethod
    def purge(self) -> bool:
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...

import json
import logging
import time
from typing import List, Optional

from src.config import get_settings
from src.queue.interface import ScanQueue, QueueMessage

logger = logging.getLogger(__name__)


class RedisQueue(ScanQueue):
    """Local queue backend using Redis + RQ (Python RQ).

    For local development and testing. Messages are stored in Redis
    and processed by RQ workers running in the same container or
    a separate worker container.

    Queue key structure:
      capsa:queue:scan          — main scan queue
      capsa:queue:scan:dlq      — dead-letter queue (failed after max attempts)
      capsa:queue:scan:processing — in-flight messages (for crash recovery)
    """

    def __init__(self):
        self.settings = get_settings()
        self._redis = None
        self._connect()

    def _connect(self):
        try:
            import redis as rds
            self._redis = rds.from_url(
                self.settings.redis_url,
                socket_connect_timeout=5,
                socket_timeout=10,
                retry_on_timeout=True,
            )
            self._redis.ping()
            logger.info("Connected to Redis at %s", self.settings.redis_url)
        except Exception as exc:
            logger.warning("Redis not available, queue disabled: %s", exc)
            self._redis = None

    @property
    def _enabled(self) -> bool:
        return self._redis is not None

    def _qkey(self, suffix: str = "") -> str:
        base = "capsa:queue:scan"
        return f"{base}:{suffix}" if suffix else base

    def enqueue(self, message: QueueMessage) -> bool:
        if not self._enabled:
            return False
        try:
            self._redis.rpush(self._qkey(), json.dumps(message.to_dict()))
            return True
        except Exception as exc:
            logger.error("Redis enqueue failed: %s", exc)
            return False

    def enqueue_batch(self, messages: List[QueueMessage]) -> int:
        if not self._enabled:
            return 0
        count = 0
        for msg in messages:
            if self.enqueue(msg):
                count += 1
        return count

    def dequeue(self, timeout: int = 30) -> Optional[QueueMessage]:
        if not self._enabled:
            return None
        try:
            result = self._redis.blpop(self._qkey(), timeout=timeout)
            if result is None:
                return None
            data = json.loads(result[1])
            msg = QueueMessage.from_dict(data)
            msg.attempt += 1
            self._redis.lpush(self._qkey("processing"), json.dumps(msg.to_dict()))
            return msg
        except Exception as exc:
            logger.error("Redis dequeue failed: %s", exc)
            return None

    def acknowledge(self, message: QueueMessage) -> bool:
        if not self._enabled:
            return False
        try:
            self._redis.lrem(self._qkey("processing"), 0, json.dumps(message.to_dict()))
            return True
        except Exception as exc:
            logger.error("Redis ack failed: %s", exc)
            return False

    def requeue(self, message: QueueMessage, delay: int = 0) -> bool:
        if not self._enabled:
            return False
        try:
            self.acknowledge(message)
            if delay > 0:
                time.sleep(delay)
            return self.enqueue(message)
        except Exception as exc:
            logger.error("Redis requeue failed: %s", exc)
            return False

    def dead_letter(self, message: QueueMessage) -> bool:
        if not self._enabled:
            return False
        try:
            self.acknowledge(message)
            self._redis.lpush(self._qkey("dlq"), json.dumps(message.to_dict()))
            logger.warning("Message moved to DLQ: %s/%s", message.bucket, message.key)
            return True
        except Exception as exc:
            logger.error("Redis DLQ failed: %s", exc)
            return False

    def size(self) -> int:
        if not self._enabled:
            return 0
        try:
            return self._redis.llen(self._qkey())
        except Exception:
            return 0

    def purge(self) -> bool:
        if not self._enabled:
            return False
        try:
            self._redis.delete(self._qkey())
            self._redis.delete(self._qkey("processing"))
            self._redis.delete(self._qkey("dlq"))
            return True
        except Exception as exc:
            logger.error("Redis purge failed: %s", exc)
            return False

    def health_check(self) -> bool:
        try:
            return self._redis is not None and self._redis.ping()
        except Exception:
            return False

    def get_dlq_messages(self, limit: int = 100) -> List[QueueMessage]:
        if not self._enabled:
            return []
        try:
            items = self._redis.lrange(self._qkey("dlq"), 0, limit - 1)
            return [QueueMessage.from_dict(json.loads(item)) for item in items]
        except Exception as exc:
            logger.error("Redis DLQ read failed: %s", exc)
            return []

    def get_processing_messages(self) -> List[QueueMessage]:
        if not self._enabled:
            return []
        try:
            items = self._redis.lrange(self._qkey("processing"), 0, -1)
            return [QueueMessage.from_dict(json.loads(item)) for item in items]
        except Exception:
            return []

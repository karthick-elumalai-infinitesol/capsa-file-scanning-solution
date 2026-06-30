from src.queue.interface import ScanQueue, QueueMessage, QueueBackend
from src.queue.sqs_queue import SQSQueue
from src.queue.redis_queue import RedisQueue


def create_queue() -> ScanQueue:
    """Factory: creates the appropriate queue backend based on settings."""
    from src.config import get_settings
    settings = get_settings()

    if settings.queue_backend == "sqs":
        return SQSQueue()
    return RedisQueue()

#!/usr/bin/env python3
"""CAPSA Queue Worker — background process for large-scale scanning.

Pulls scan messages from the queue (Redis/SQS), scans each file via ClamAV,
acknowledges on success, and routes failures to the dead-letter queue.

Usage:
    python scripts/queue_worker.py                    # runs forever
    python scripts/queue_worker.py --max-messages 100 # process N then exit
"""

import argparse
import logging
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("queue-worker")

RUNNING = True


def handle_signal(signum, frame):
    global RUNNING
    logger.info("Received signal %d, shutting down gracefully...", signum)
    RUNNING = False


def main():
    parser = argparse.ArgumentParser(description="CAPSA Queue Worker")
    parser.add_argument("--max-messages", type=int, default=0, help="Process N messages then exit (0 = forever)")
    parser.add_argument("--batch-size", type=int, default=50, help="Messages per poll")
    parser.add_argument("--poll-interval", type=int, default=5, help="Seconds to wait when queue is empty")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    from src.scanner.concurrent_scanner import ConcurrentScanner
    scanner = ConcurrentScanner()

    logger.info(
        "Queue worker started (backend=%s, batch=%d, poll=%ds, forever=%s)",
        scanner.settings.queue_backend,
        args.batch_size,
        args.poll_interval,
        args.max_messages == 0,
    )

    total_processed = 0
    while RUNNING:
        try:
            processed = scanner.scan_from_queue(max_messages=args.batch_size)
            total_processed += processed

            if args.max_messages > 0 and total_processed >= args.max_messages:
                logger.info("Reached max messages (%d), exiting", args.max_messages)
                break

            if processed == 0:
                time.sleep(args.poll_interval)

        except KeyboardInterrupt:
            break
        except Exception as exc:
            logger.error("Worker error: %s", exc)
            time.sleep(args.poll_interval)

    logger.info("Queue worker stopped. Total processed: %d", total_processed)


if __name__ == "__main__":
    main()

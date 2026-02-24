"""Worker main loop."""

import logging
import signal
import sys
import time

from services.worker.config import settings
from services.worker.processor import process_job
from services.worker.queue import get_redis_client

logger = logging.getLogger(__name__)

# Global flag for graceful shutdown
shutdown_requested = False


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    global shutdown_requested
    shutdown_requested = True
    logger.info(f"Received signal {signum}, shutting down...")


def run_worker() -> None:
    """
    Run worker main loop.

    Continuously consumes jobs from the dispatch queue and processes them.
    """
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("Worker starting...")
    logger.info(f"Dispatch queue: {settings.WORKER_DISPATCH_QUEUE}")

    redis_client = get_redis_client()
    jobs_processed = 0

    try:
        while not shutdown_requested:
            # Wait for job
            job_id = redis_client.dequeue_job(timeout=5)

            if job_id:
                logger.info(f"Received job: {job_id}")

                # Process job
                success = process_job(job_id)

                if success:
                    jobs_processed += 1
                    logger.info(f"Jobs processed: {jobs_processed}")
            else:
                # No job available, continue waiting
                pass

    except Exception as e:
        logger.exception(f"Worker error: {e}")
        sys.exit(1)

    finally:
        redis_client.close()
        logger.info(f"Worker shutting down. Total jobs processed: {jobs_processed}")

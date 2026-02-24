"""Redis client for orchestrator job queues."""

from functools import lru_cache

import redis.asyncio as aioredis
import redis.sync as redis

from services.orchestrator.config import settings


class RedisClient:
    """Redis client for orchestrator operations."""

    def __init__(
        self,
        redis_url: str | None = None,
        password: str | None = None,
        job_queue_name: str | None = None,
        worker_dispatch_queue: str | None = None,
    ):
        """
        Initialize Redis client.

        Args:
            redis_url: Redis connection URL
            password: Redis password
            job_queue_name: Ingest job queue name
            worker_dispatch_queue: Worker dispatch queue name
        """
        self.redis_url = redis_url or settings.REDIS_URL
        self.password = password or settings.REDIS_PASSWORD
        self.job_queue_name = job_queue_name or settings.JOB_QUEUE_NAME
        self.worker_dispatch_queue = (
            worker_dispatch_queue or settings.WORKER_DISPATCH_QUEUE
        )

        self._sync_client: redis.Redis | None = None
        self._async_client: aioredis.Redis | None = None

    def _get_sync_client(self) -> redis.Redis:
        """Get synchronous Redis client."""
        if self._sync_client is None:
            self._sync_client = redis.Redis(
                url=self.redis_url,
                password=self.password,
                decode_responses=True,
            )
        return self._sync_client

    async def _get_async_client(self) -> aioredis.Redis:
        """Get asynchronous Redis client."""
        if self._async_client is None:
            self._async_client = aioredis.Redis.from_url(
                self.redis_url,
                password=self.password,
                decode_responses=True,
            )
        return self._async_client

    def enqueue_job(self, job_id: str, queue_name: str | None = None) -> int:
        """
        Add job ID to queue.

        Args:
            job_id: Job UUID to enqueue
            queue_name: Queue name (uses default if not provided)

        Returns:
            Queue length after push
        """
        queue = queue_name or self.job_queue_name
        client = self._get_sync_client()
        return client.lpush(queue, job_id)

    def dequeue_job(
        self,
        queue_name: str | None = None,
        timeout: int = 0,
    ) -> str | None:
        """
        Remove and return job ID from queue.

        Args:
            queue_name: Queue name (uses default if not provided)
            timeout: Block timeout in seconds (0 = no block)

        Returns:
            Job ID or None if queue is empty
        """
        queue = queue_name or self.job_queue_name
        client = self._get_sync_client()

        if timeout > 0:
            result = client.brpop(queue, timeout=timeout)
            return result[1] if result else None
        return client.rpop(queue)

    def get_queue_length(self, queue_name: str | None = None) -> int:
        """
        Get current queue length.

        Args:
            queue_name: Queue name (uses default if not provided)

        Returns:
            Number of items in queue
        """
        queue = queue_name or self.job_queue_name
        client = self._get_sync_client()
        return client.llen(queue)

    def get_dispatch_queue_length(self) -> int:
        """Get worker dispatch queue length."""
        client = self._get_sync_client()
        return client.llen(self.worker_dispatch_queue)

    def close(self) -> None:
        """Close Redis connections."""
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None


@lru_cache
def get_redis_client() -> RedisClient:
    """Get cached Redis client."""
    return RedisClient()

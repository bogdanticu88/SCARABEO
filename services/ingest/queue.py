"""Redis client for job queue management."""

from functools import lru_cache
from typing import Any

import redis.asyncio as aioredis
import redis

from services.ingest.config import settings


class RedisClient:
    """Redis client for job queue operations."""

    def __init__(
        self,
        redis_url: str | None = None,
        password: str | None = None,
        queue_name: str | None = None,
    ):
        """
        Initialize Redis client.

        Args:
            redis_url: Redis connection URL
            password: Redis password
            queue_name: Default queue name
        """
        self.redis_url = redis_url or settings.REDIS_URL
        self.password = password or settings.REDIS_PASSWORD
        self.queue_name = queue_name or settings.JOB_QUEUE_NAME

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
        queue = queue_name or self.queue_name
        client = self._get_sync_client()
        return client.lpush(queue, job_id)

    async def enqueue_job_async(self, job_id: str, queue_name: str | None = None) -> int:
        """
        Add job ID to queue (async).

        Args:
            job_id: Job UUID to enqueue
            queue_name: Queue name (uses default if not provided)

        Returns:
            Queue length after push
        """
        queue = queue_name or self.queue_name
        client = await self._get_async_client()
        return await client.lpush(queue, job_id)

    def dequeue_job(self, queue_name: str | None = None, timeout: int = 0) -> str | None:
        """
        Remove and return job ID from queue.

        Args:
            queue_name: Queue name (uses default if not provided)
            timeout: Block timeout in seconds (0 = no block)

        Returns:
            Job ID or None if queue is empty
        """
        queue = queue_name or self.queue_name
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
        queue = queue_name or self.queue_name
        client = self._get_sync_client()
        return client.llen(queue)

    def store_job_data(self, job_id: str, data: dict[str, Any]) -> bool:
        """
        Store job data as hash.

        Args:
            job_id: Job UUID
            data: Job data dictionary

        Returns:
            True if successful
        """
        client = self._get_sync_client()
        return client.hset(f"job:{job_id}", mapping=data) > 0

    def get_job_data(self, job_id: str) -> dict[str, Any] | None:
        """
        Retrieve job data from hash.

        Args:
            job_id: Job UUID

        Returns:
            Job data dictionary or None if not found
        """
        client = self._get_sync_client()
        return client.hgetall(f"job:{job_id}")

    def close(self) -> None:
        """Close Redis connections."""
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None


@lru_cache
def get_redis_client() -> RedisClient:
    """Get cached Redis client."""
    return RedisClient()

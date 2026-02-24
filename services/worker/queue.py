"""Redis client for worker."""

from functools import lru_cache

import redis.sync as redis

from services.worker.config import settings


class RedisClient:
    """Redis client for worker operations."""

    def __init__(
        self,
        redis_url: str | None = None,
        password: str | None = None,
        dispatch_queue: str | None = None,
    ):
        self.redis_url = redis_url or settings.REDIS_URL
        self.password = password or settings.REDIS_PASSWORD
        self.dispatch_queue = dispatch_queue or settings.WORKER_DISPATCH_QUEUE

        self._client: redis.Redis | None = None

    def _get_client(self) -> redis.Redis:
        """Get Redis client."""
        if self._client is None:
            self._client = redis.Redis(
                url=self.redis_url,
                password=self.password,
                decode_responses=True,
            )
        return self._client

    def dequeue_job(self, timeout: int = 5) -> str | None:
        """
        Dequeue job from dispatch queue.

        Args:
            timeout: Block timeout in seconds

        Returns:
            Job ID or None
        """
        client = self._get_client()
        result = client.brpop(self.dispatch_queue, timeout=timeout)
        return result[1] if result else None

    def close(self) -> None:
        """Close Redis connection."""
        if self._client:
            self._client.close()
            self._client = None


@lru_cache
def get_redis_client() -> RedisClient:
    """Get cached Redis client."""
    return RedisClient()

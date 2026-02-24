"""Rate limiting and quotas using Redis."""

import logging
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import redis

logger = logging.getLogger(__name__)


class RateLimitError(Exception):
    """Rate limit exceeded error."""

    def __init__(self, message: str, retry_after: int = 60):
        self.message = message
        self.retry_after = retry_after
        super().__init__(message)


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""

    max_uploads_per_minute: int = 60
    max_concurrent_jobs: int = 10
    window_seconds: int = 60


@lru_cache
def get_rate_limit_config() -> RateLimitConfig:
    """Get cached rate limit configuration."""
    import os
    return RateLimitConfig(
        max_uploads_per_minute=int(os.environ.get("RATE_LIMIT_UPLOADS_PER_MINUTE", "60")),
        max_concurrent_jobs=int(os.environ.get("RATE_LIMIT_CONCURRENT_JOBS", "10")),
        window_seconds=int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60")),
    )


@lru_cache
def get_redis_client() -> redis.Redis:
    """Get cached Redis client for rate limiting."""
    import os
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    redis_password = os.environ.get("REDIS_PASSWORD")
    return redis.Redis(
        url=redis_url,
        password=redis_password,
        decode_responses=True,
    )


class RateLimiter:
    """Rate limiter using Redis."""

    def __init__(
        self,
        redis_client: redis.Redis | None = None,
        config: RateLimitConfig | None = None,
    ):
        self.redis = redis_client or get_redis_client()
        self.config = config or get_rate_limit_config()

    def check_upload_limit(self, tenant_id: str) -> tuple[bool, dict[str, Any]]:
        """
        Check if tenant has exceeded upload rate limit.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Tuple of (allowed, info_dict)
        """
        key = f"ratelimit:uploads:{tenant_id}"
        now = int(time.time())
        window_start = now - self.config.window_seconds

        # Remove old entries outside window and count current entries
        self.redis.zremrangebyscore(key, 0, window_start)
        current_count = self.redis.zcard(key)

        if current_count >= self.config.max_uploads_per_minute:
            # Get retry-after from oldest entry
            oldest = self.redis.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = int(oldest[0][1]) + self.config.window_seconds - now
            else:
                retry_after = self.config.window_seconds

            return False, {
                "limit": self.config.max_uploads_per_minute,
                "remaining": 0,
                "retry_after": max(1, retry_after),
                "reset": now + self.config.window_seconds,
            }

        # Record this upload
        pipe = self.redis.pipeline()
        pipe.zadd(key, {f"{now}": now})
        pipe.expire(key, self.config.window_seconds * 2)
        pipe.execute()

        return True, {
            "limit": self.config.max_uploads_per_minute,
            "remaining": self.config.max_uploads_per_minute - current_count - 1,
            "reset": now + self.config.window_seconds,
        }

    def check_concurrent_jobs(self, tenant_id: str) -> tuple[bool, dict[str, Any]]:
        """
        Check if tenant has exceeded concurrent job limit.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Tuple of (allowed, info_dict)
        """
        key = f"ratelimit:concurrent:{tenant_id}"
        current = self.redis.get(key)
        current_count = int(current) if current else 0

        if current_count >= self.config.max_concurrent_jobs:
            return False, {
                "limit": self.config.max_concurrent_jobs,
                "remaining": 0,
                "current": current_count,
            }

        return True, {
            "limit": self.config.max_concurrent_jobs,
            "remaining": self.config.max_concurrent_jobs - current_count - 1,
            "current": current_count + 1,
        }

    def increment_concurrent_jobs(self, tenant_id: str) -> int:
        """Increment concurrent job counter."""
        key = f"ratelimit:concurrent:{tenant_id}"
        return self.redis.incr(key)

    def decrement_concurrent_jobs(self, tenant_id: str) -> int:
        """Decrement concurrent job counter."""
        key = f"ratelimit:concurrent:{tenant_id}"
        result = self.redis.decr(key)
        # Ensure non-negative
        if result < 0:
            self.redis.set(key, 0)
            return 0
        return result


class QuotaEnforcer:
    """Quota enforcement for tenants."""

    def __init__(self, redis_client: redis.Redis | None = None):
        self.redis = redis_client or get_redis_client()

    def get_tenant_quota(self, tenant_id: str) -> dict[str, Any]:
        """Get quota configuration for tenant."""
        key = f"quota:config:{tenant_id}"
        config = self.redis.hgetall(key)

        if not config:
            # Default quota
            return {
                "max_storage_bytes": 10737418240,  # 10GB
                "max_analyses_per_day": 1000,
                "max_file_size_bytes": 52428800,  # 50MB
                "retention_days": 90,
            }

        return {
            "max_storage_bytes": int(config.get("max_storage_bytes", 10737418240)),
            "max_analyses_per_day": int(config.get("max_analyses_per_day", 1000)),
            "max_file_size_bytes": int(config.get("max_file_size_bytes", 52428800)),
            "retention_days": int(config.get("retention_days", 90)),
        }

    def set_tenant_quota(self, tenant_id: str, quota: dict[str, Any]) -> None:
        """Set quota configuration for tenant."""
        key = f"quota:config:{tenant_id}"
        self.redis.hset(key, mapping={k: str(v) for k, v in quota.items()})

    def check_storage_quota(self, tenant_id: str, additional_bytes: int) -> tuple[bool, dict]:
        """Check if upload would exceed storage quota."""
        usage_key = f"quota:usage:storage:{tenant_id}"
        current_usage = int(self.redis.get(usage_key) or 0)

        quota = self.get_tenant_quota(tenant_id)
        max_storage = quota["max_storage_bytes"]

        if current_usage + additional_bytes > max_storage:
            return False, {
                "current": current_usage,
                "max": max_storage,
                "additional": additional_bytes,
                "exceeded_by": current_usage + additional_bytes - max_storage,
            }

        return True, {
            "current": current_usage,
            "max": max_storage,
            "remaining": max_storage - current_usage,
        }

    def update_storage_usage(self, tenant_id: str, delta_bytes: int) -> int:
        """Update storage usage for tenant."""
        key = f"quota:usage:storage:{tenant_id}"
        return self.redis.incrby(key, delta_bytes)


def get_rate_limiter() -> RateLimiter:
    """Get rate limiter instance."""
    return RateLimiter()


def get_quota_enforcer() -> QuotaEnforcer:
    """Get quota enforcer instance."""
    return QuotaEnforcer()

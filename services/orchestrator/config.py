"""Orchestrator service configuration."""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Orchestrator service configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Service
    HOST: str = "0.0.0.0"
    PORT: int = 8001
    DEBUG: bool = False

    # Admin authentication
    ADMIN_TOKEN: str = "orchestrator_admin_secret_token"

    # Database
    DATABASE_URL: str = "postgresql://scarabeo:scarabeo_dev_password@localhost:5432/scarabeo"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: str = "scarabeo_dev_password"

    # Job queues
    JOB_QUEUE_NAME: str = "scarabeo:jobs:triage"
    WORKER_DISPATCH_QUEUE: str = "scarabeo:workers:dispatch"

    # Worker limits
    MAX_CONCURRENT_JOBS: int = 10
    JOB_TIMEOUT_SECONDS: int = 600

    # S3/MinIO (for report storage verification)
    S3_ENDPOINT_URL: str = "http://localhost:9000"
    S3_ACCESS_KEY: str = "scarabeo"
    S3_SECRET_KEY: str = "scarabeo_dev_password"
    S3_BUCKET: str = "scarabeo-samples"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()

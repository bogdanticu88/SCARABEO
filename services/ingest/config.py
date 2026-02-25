"""Ingest Service configuration."""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Ingest service configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Service
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "postgresql://scarabeo:scarabeo_dev_password@localhost:5432/scarabeo"

    # S3/MinIO
    S3_ENDPOINT_URL: str = "http://localhost:9000"
    S3_ACCESS_KEY: str = "scarabeo"
    S3_SECRET_KEY: str = "scarabeo_dev_password"
    S3_BUCKET: str = "scarabeo-samples"
    S3_REGION: str = "us-east-1"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: str = "scarabeo_dev_password"

    # Upload limits
    MAX_UPLOAD_SIZE_MB: int = 50

    # Job queue
    JOB_QUEUE_NAME: str = "scarabeo:jobs:triage"

    # Ollama AI enrichment
    OLLAMA_ENABLED: bool = False
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "mistral:7b"
    OLLAMA_TIMEOUT: int = 120

    @property
    def max_upload_size_bytes(self) -> int:
        """Maximum upload size in bytes."""
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()

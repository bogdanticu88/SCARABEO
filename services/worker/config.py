"""Worker service configuration."""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Worker service configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Service
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "postgresql://scarabeo:scarabeo_dev_password@localhost:5432/scarabeo"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: str = "scarabeo_dev_password"
    WORKER_DISPATCH_QUEUE: str = "scarabeo:workers:dispatch"

    # S3/MinIO
    S3_ENDPOINT_URL: str = "http://localhost:9000"
    S3_ACCESS_KEY: str = "scarabeo"
    S3_SECRET_KEY: str = "scarabeo_dev_password"
    S3_BUCKET: str = "scarabeo-samples"
    S3_REGION: str = "us-east-1"

    # Docker
    DOCKER_IMAGE_TRIAGE: str = "scarabeo/triage-universal:latest"
    DOCKER_NETWORK_DISABLED: bool = True
    DOCKER_READONLY_ROOTFS: bool = True

    # Resource limits
    DOCKER_CPU_LIMIT: float = 2.0
    DOCKER_MEMORY_LIMIT: str = "2g"

    # Analyzer settings
    ANALYZER_CHUNK_SIZE: int = 4096
    ANALYZER_MAX_STRINGS: int = 10000
    ANALYZER_HIGH_ENTROPY_THRESHOLD: float = 7.5

    # Ollama AI enrichment (narrative/remediation — free text)
    OLLAMA_ENABLED: bool = False
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "mistral:7b"
    OLLAMA_TIMEOUT: int = 120

    # Structured finding explanation layer
    EXPLAINER_ENABLED: bool = False
    EXPLAINER_ENDPOINT: str = "http://localhost:11434"
    EXPLAINER_MODEL: str = "mistral:7b"
    EXPLAINER_TIMEOUT: int = 60


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()

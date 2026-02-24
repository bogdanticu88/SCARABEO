"""Search service configuration."""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class SearchConfig(BaseSettings):
    """Search service configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Service
    HOST: str = "0.0.0.0"
    PORT: int = 8002
    DEBUG: bool = False

    # Search backend: opensearch or postgres
    SEARCH_BACKEND: str = "postgres"

    # OpenSearch config
    OPENSEARCH_URL: str = "http://localhost:9200"
    OPENSEARCH_INDEX: str = "scarabeo-samples"

    # Database
    DATABASE_URL: str = "postgresql://scarabeo:scarabeo_dev_password@localhost:5432/scarabeo"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: str = "scarabeo_dev_password"

    # Pagination
    MAX_PAGE_SIZE: int = 100
    DEFAULT_PAGE_SIZE: int = 20


@lru_cache
def get_config() -> SearchConfig:
    """Get cached configuration."""
    return SearchConfig()


config = get_config()

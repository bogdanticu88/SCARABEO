"""Web Console configuration."""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class WebConfig(BaseSettings):
    """Web console configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Service
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    DEBUG: bool = False

    # API URLs
    INGEST_API_URL: str = "http://localhost:8000"
    SEARCH_API_URL: str = "http://localhost:8002"

    # Auth
    AUTH_MODE: str = "header"


@lru_cache
def get_config() -> WebConfig:
    """Get cached configuration."""
    return WebConfig()


config = get_config()

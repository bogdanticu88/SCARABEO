"""Database session management for orchestrator."""

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from services.orchestrator.config import settings


@lru_cache
def get_engine():
    """Get cached database engine."""
    return create_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )


@lru_cache
def get_session_factory():
    """Get cached session factory."""
    return sessionmaker(
        bind=get_engine(),
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )


def get_db() -> Generator[Session, None, None]:
    """Dependency for FastAPI to get database session."""
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()


def get_session() -> Session:
    """Get a new database session (for non-request contexts)."""
    return get_session_factory()()

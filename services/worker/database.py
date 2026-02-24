"""Database session management for worker."""

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from services.worker.config import settings


@lru_cache
def get_engine():
    """Get cached database engine."""
    return create_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
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


def get_session() -> Session:
    """Get a new database session."""
    return get_session_factory()()


def get_db_generator() -> Generator[Session, None, None]:
    """Get database session generator."""
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()

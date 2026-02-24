"""Search service database module."""

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from services.search.config import config


@lru_cache
def get_engine():
    """Get cached database engine."""
    return create_engine(
        config.DATABASE_URL,
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


def get_session() -> Session:
    """Get a new database session."""
    return get_session_factory()()


def get_db() -> Generator[Session, None, None]:
    """Get database session generator."""
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()

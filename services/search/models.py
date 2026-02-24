"""Search service database models."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class Case(Base):
    """Case model for grouping related samples."""

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    samples: Mapped[list["CaseSample"]] = relationship(
        back_populates="case",
        lazy="select",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_cases_tenant_created", "tenant_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Case name={self.name} tenant={self.tenant_id}>"


class CaseSample(Base):
    """Association table for cases and samples."""

    __tablename__ = "case_samples"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    case_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sample_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    case: Mapped[Case] = relationship(back_populates="samples")

    __table_args__ = (
        UniqueConstraint("case_id", "sample_sha256", name="uq_case_samples_case_sha256"),
        Index("ix_case_samples_sha256", "sample_sha256"),
    )

    def __repr__(self) -> str:
        return f"<CaseSample case={self.case_id} sample={self.sample_sha256[:16]}...>"


class IOCSighting(Base):
    """IOC sighting tracking for intelligence correlation."""

    __tablename__ = "ioc_sightings"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    ioc_value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column(String(64), nullable=False)
    sample_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    sighting_count: Mapped[int] = mapped_column(
        BigInteger,
        default=1,
        server_default="1",
    )
    ioc_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "ioc_value", "sample_sha256", "tenant_id",
            name="uq_ioc_sightings_value_sample_tenant",
        ),
        Index("ix_ioc_sightings_type_value", "ioc_type", "ioc_value"),
        Index("ix_ioc_sightings_tenant_first", "tenant_id", "first_seen"),
    )

    def __repr__(self) -> str:
        return f"<IOCSighting ioc={self.ioc_value[:32]}... count={self.sighting_count}>"


class SearchIndex(Base):
    """Search index for samples (Postgres fallback)."""

    __tablename__ = "search_index"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    sample_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    file_type: Mapped[str] = mapped_column(String(64), nullable=False)
    findings: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    iocs: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    analyzer_names: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_search_index_tenant_created", "tenant_id", "created_at"),
        Index("ix_search_index_verdict", "tenant_id", "verdict"),
    )

    def __repr__(self) -> str:
        return f"<SearchIndex sha256={self.sample_sha256[:16]}... tenant={self.tenant_id}>"

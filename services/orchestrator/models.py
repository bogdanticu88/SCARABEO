"""Orchestrator service models (shared with ingest)."""

import enum
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class JobStatus(str, enum.Enum):
    """Job status enumeration."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class AuditAction(str, enum.Enum):
    """Audit log action enumeration."""

    SAMPLE_UPLOAD = "SAMPLE_UPLOAD"
    SAMPLE_DOWNLOAD = "SAMPLE_DOWNLOAD"
    JOB_CREATED = "JOB_CREATED"
    JOB_UPDATED = "JOB_UPDATED"
    JOB_STARTED = "JOB_STARTED"
    JOB_COMPLETED = "JOB_COMPLETED"
    JOB_FAILED = "JOB_FAILED"
    JOB_RETRY = "JOB_RETRY"


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class Sample(Base):
    """Sample model representing an uploaded file."""

    __tablename__ = "samples"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sha1: Mapped[str] = mapped_column(String(40), nullable=False)
    md5: Mapped[str] = mapped_column(String(32), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(1024), nullable=False)
    file_type: Mapped[str] = mapped_column(String(64), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(255), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    # Relationships
    jobs: Mapped[list["Job"]] = relationship(back_populates="sample", lazy="select")

    # Unique constraint for idempotency
    __table_args__ = (
        UniqueConstraint("tenant_id", "sha256", name="uq_samples_tenant_sha256"),
        Index("ix_samples_tenant_created", "tenant_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Sample sha256={self.sha256[:16]}... tenant={self.tenant_id}>"


class Job(Base):
    """Job model representing an analysis task."""

    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    sample_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("samples.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    pipeline_name: Mapped[str] = mapped_column(String(255), nullable=False)
    pipeline_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus),
        default=JobStatus.QUEUED,
        nullable=False,
        index=True,
    )
    priority: Mapped[str] = mapped_column(
        String(16),
        default="normal",
        nullable=False,
    )
    timeout_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    # Relationships
    sample: Mapped[Sample] = relationship(back_populates="jobs", lazy="joined")

    # Indexes
    __table_args__ = (
        Index("ix_jobs_status_created", "status", "created_at"),
        Index("ix_jobs_sample_status", "sample_id", "status"),
        Index("ix_jobs_pipeline_dispatch", "pipeline_name", "pipeline_hash", "status"),
    )

    def __repr__(self) -> str:
        return f"<Job id={self.id[:8]}... status={self.status.value}>"


class AuditLog(Base):
    """Audit log model for tracking all actions."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    action: Mapped[AuditAction] = mapped_column(
        Enum(AuditAction),
        nullable=False,
        index=True,
    )
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict | None] = mapped_column(
        String,  # JSON stored as text
        nullable=True,
    )
    user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    __table_args__ = (
        Index("ix_audit_tenant_action_created", "tenant_id", "action", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog action={self.action.value} resource={self.resource_type}>"

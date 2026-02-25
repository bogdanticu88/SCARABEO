"""Ingest Service database models."""

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
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

import enum


class JobStatus(str, enum.Enum):
    """Job status enumeration."""

    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AuditAction(str, enum.Enum):
    """Audit log action enumeration."""

    SAMPLE_UPLOAD = "SAMPLE_UPLOAD"
    SAMPLE_DOWNLOAD = "SAMPLE_DOWNLOAD"
    JOB_CREATED = "JOB_CREATED"
    JOB_UPDATED = "JOB_UPDATED"
    JOB_COMPLETED = "JOB_COMPLETED"
    JOB_FAILED = "JOB_FAILED"


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
    # Verdict fields
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verdict_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    verdict_set_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verdict_set_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(255)),
        nullable=True,
        server_default="{}",
    )
    notes_count: Mapped[int | None] = mapped_column(Integer, nullable=True, server_default="0")

    # Relationships
    jobs: Mapped[list["Job"]] = relationship(back_populates="sample", lazy="select")

    # Unique constraint for idempotency
    __table_args__ = (
        UniqueConstraint("tenant_id", "sha256", name="uq_samples_tenant_sha256"),
        Index("ix_samples_tenant_created", "tenant_id", "created_at"),
        Index("ix_samples_verdict", "tenant_id", "verdict"),
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
    user_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[AuditAction] = mapped_column(
        Enum(AuditAction),
        nullable=False,
        index=True,
    )
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    details_json: Mapped[dict | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    __table_args__ = (
        Index("ix_audit_tenant_action_created", "tenant_id", "action", "created_at"),
        Index("ix_audit_user_created", "user_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog action={self.action.value} tenant={self.tenant_id}>"


class SampleNote(Base):
    """Sample note/comment model for collaboration."""

    __tablename__ = "sample_notes"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    sample_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    author_id: Mapped[str] = mapped_column(String(255), nullable=False)
    author_role: Mapped[str] = mapped_column(String(32), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    __table_args__ = (
        Index("ix_sample_notes_tenant_sha256", "tenant_id", "sample_sha256"),
        Index("ix_sample_notes_created", "tenant_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<SampleNote sample={self.sample_sha256[:16]}... author={self.author_id}>"


class FindingStatus(str, enum.Enum):
    """Finding status enumeration."""

    OPEN = "open"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class FindingStatusRecord(Base):
    """Finding status tracking model."""

    __tablename__ = "finding_statuses"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    sample_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus),
        default=FindingStatus.OPEN,
        nullable=False,
        index=True,
    )
    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    __table_args__ = (
        UniqueConstraint("sample_sha256", "finding_id", name="uq_finding_statuses_sample_finding"),
        Index("ix_finding_statuses_tenant_sample", "tenant_id", "sample_sha256"),
    )

    def __repr__(self) -> str:
        return f"<FindingStatus finding={self.finding_id} status={self.status.value}>"


class Cluster(Base):
    """Similarity cluster model."""

    __tablename__ = "clusters"

    cluster_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    primary_sample_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    # Relationships
    members: Mapped[list["ClusterMember"]] = relationship(
        back_populates="cluster",
        lazy="select",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_clusters_tenant_id", "tenant_id"),
        Index("ix_clusters_algorithm", "tenant_id", "algorithm"),
        Index("ix_clusters_primary", "tenant_id", "primary_sample_sha256"),
    )

    def __repr__(self) -> str:
        return f"<Cluster id={self.cluster_id} algorithm={self.algorithm}>"


class ClusterMember(Base):
    """Cluster member association model."""

    __tablename__ = "cluster_members"

    cluster_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("clusters.cluster_id", ondelete="CASCADE"),
        primary_key=True,
    )
    sample_sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    # Relationships
    cluster: Mapped[Cluster] = relationship(back_populates="members")

    __table_args__ = (
        Index("ix_cluster_members_sha256", "sample_sha256"),
        Index("ix_cluster_members_added", "added_at"),
    )

    def __repr__(self) -> str:
        return f"<ClusterMember cluster={self.cluster_id} sample={self.sample_sha256[:16]}...>"


class SampleFingerprint(Base):
    """
    Per-sample fingerprint record for similarity matching.

    Composite primary key (tenant_id, sha256) enforces one row per sample per
    tenant and is the conflict target for idempotent upserts.  All hash columns
    are nullable — not every file type yields every hash (e.g. imphash is
    PE-only).
    """

    __tablename__ = "sample_fingerprints"

    tenant_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Locality-sensitive hash (TLSH format, 72 chars with T1 prefix)
    tlsh: Mapped[str | None] = mapped_column(String(72), nullable=True)
    # Fuzzy hash (ssdeep format: "chunksize:hash:hash")
    ssdeep: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # PE import hash (MD5 of normalised import table, 32 hex chars)
    imphash: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # SHA256 of sorted printable strings extracted from the binary (64 hex chars)
    strings_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Extensible metadata (file_type, size_bytes, analyzer versions, …)
    extra: Mapped[dict | None] = mapped_column(
        JSONB(astext_type=Text()),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_sample_fingerprints_imphash", "tenant_id", "imphash"),
        Index("ix_sample_fingerprints_tlsh", "tenant_id", "tlsh"),
        Index("ix_sample_fingerprints_created", "tenant_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<SampleFingerprint sha256={self.sha256[:16]}... tenant={self.tenant_id}>"

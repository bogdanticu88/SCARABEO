"""Initial database schema.

Revision ID: 001_initial
Revises: 
Create Date: 2024-01-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create initial schema."""
    
    # Create enum types
    job_status = postgresql.ENUM(
        "QUEUED", "PROCESSING", "COMPLETED", "FAILED", "CANCELLED",
        name="jobstatus",
        create_type=True,
    )
    job_status.create(op.get_bind(), checkfirst=True)
    
    audit_action = postgresql.ENUM(
        "SAMPLE_UPLOAD", "SAMPLE_DOWNLOAD", "JOB_CREATED", "JOB_UPDATED",
        "JOB_COMPLETED", "JOB_FAILED",
        name="auditaaction",
        create_type=True,
    )
    audit_action.create(op.get_bind(), checkfirst=True)
    
    # Samples table
    op.create_table(
        "samples",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("sha1", sa.String(40), nullable=False),
        sa.Column("md5", sa.String(32), nullable=False),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("filename", sa.String(1024), nullable=False),
        sa.Column("file_type", sa.String(64), nullable=False),
        sa.Column("mime_type", sa.String(255), nullable=True),
        sa.Column("size_bytes", sa.BigInteger, nullable=False),
        sa.Column("storage_path", sa.String(2048), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "sha256", name="uq_samples_tenant_sha256"),
    )
    op.create_index("ix_samples_sha256", "samples", ["sha256"])
    op.create_index("ix_samples_tenant_id", "samples", ["tenant_id"])
    op.create_index(
        "ix_samples_tenant_created",
        "samples",
        ["tenant_id", "created_at"],
    )
    
    # Jobs table
    op.create_table(
        "jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sample_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pipeline_name", sa.String(255), nullable=False),
        sa.Column("pipeline_hash", sa.String(64), nullable=False),
        sa.Column(
            "status",
            sa.Enum("QUEUED", "PROCESSING", "COMPLETED", "FAILED", "CANCELLED", name="jobstatus"),
            nullable=False,
        ),
        sa.Column("priority", sa.String(16), nullable=False, server_default="normal"),
        sa.Column("timeout_seconds", sa.Integer, nullable=True),
        sa.Column("result", sa.Text, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["sample_id"],
            ["samples.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_jobs_sample_id", "jobs", ["sample_id"])
    op.create_index("ix_jobs_status", "jobs", ["status"])
    op.create_index(
        "ix_jobs_status_created",
        "jobs",
        ["status", "created_at"],
    )
    op.create_index(
        "ix_jobs_sample_status",
        "jobs",
        ["sample_id", "status"],
    )
    
    # Audit log table
    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column(
            "action",
            sa.Enum(
                "SAMPLE_UPLOAD", "SAMPLE_DOWNLOAD", "JOB_CREATED", "JOB_UPDATED",
                "JOB_COMPLETED", "JOB_FAILED",
                name="auditaaction",
            ),
            nullable=False,
        ),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("details", sa.String, nullable=True),
        sa.Column("user_id", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_tenant_id", "audit_log", ["tenant_id"])
    op.create_index("ix_audit_action", "audit_log", ["action"])
    op.create_index(
        "ix_audit_tenant_action_created",
        "audit_log",
        ["tenant_id", "action", "created_at"],
    )


def downgrade() -> None:
    """Drop initial schema."""
    op.drop_table("audit_log")
    op.drop_table("jobs")
    op.drop_table("samples")
    
    # Drop enum types
    op.execute("DROP TYPE IF EXISTS jobstatus")
    op.execute("DROP TYPE IF EXISTS auditaaction")

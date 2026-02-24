"""Add search, cases, and IOC intelligence tables.

Revision ID: 004_add_search_cases_intel
Revises: 003_audit_completeness
Create Date: 2024-01-18 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "004_add_search_cases_intel"
down_revision: Union[str, None] = "003_audit_completeness"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add search, cases, and IOC intelligence tables."""
    
    # Cases table
    op.create_table(
        "cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cases_tenant_id", "cases", ["tenant_id"])
    op.create_index("ix_cases_tenant_created", "cases", ["tenant_id", "created_at"])
    
    # Case samples association table
    op.create_table(
        "case_samples",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("case_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sample_sha256", sa.String(64), nullable=False),
        sa.Column(
            "added_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("notes", sa.Text, nullable=True),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "sample_sha256", name="uq_case_samples_case_sha256"),
    )
    op.create_index("ix_case_samples_case_id", "case_samples", ["case_id"])
    op.create_index("ix_case_samples_sha256", "case_samples", ["sample_sha256"])
    
    # IOC sightings table
    op.create_table(
        "ioc_sightings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ioc_value", sa.String(1024), nullable=False),
        sa.Column("ioc_type", sa.String(64), nullable=False),
        sa.Column("sample_sha256", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("sighting_count", sa.BigInteger, server_default="1", nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "ioc_value", "sample_sha256", "tenant_id",
            name="uq_ioc_sightings_value_sample_tenant",
        ),
    )
    op.create_index("ix_ioc_sightings_ioc_value", "ioc_sightings", ["ioc_value"])
    op.create_index("ix_ioc_sightings_sample_sha256", "ioc_sightings", ["sample_sha256"])
    op.create_index("ix_ioc_sightings_tenant_id", "ioc_sightings", ["tenant_id"])
    op.create_index("ix_ioc_sightings_type_value", "ioc_sightings", ["ioc_type", "ioc_value"])
    op.create_index("ix_ioc_sightings_tenant_first", "ioc_sightings", ["tenant_id", "first_seen"])
    
    # Search index table
    op.create_table(
        "search_index",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sample_sha256", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("file_type", sa.String(64), nullable=False),
        sa.Column("findings", postgresql.JSONB(astext_type=sa.Text), nullable=True),
        sa.Column("iocs", postgresql.JSONB(astext_type=sa.Text), nullable=True),
        sa.Column("analyzer_names", postgresql.JSONB(astext_type=sa.Text), nullable=True),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text), nullable=True),
        sa.Column("verdict", sa.String(32), nullable=True),
        sa.Column("score", sa.Integer, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sample_sha256"),
    )
    op.create_index("ix_search_index_tenant_id", "search_index", ["tenant_id"])
    op.create_index("ix_search_index_tenant_created", "search_index", ["tenant_id", "created_at"])
    op.create_index("ix_search_index_verdict", "search_index", ["tenant_id", "verdict"])


def downgrade() -> None:
    """Remove search, cases, and IOC intelligence tables."""
    op.drop_table("search_index")
    op.drop_table("ioc_sightings")
    op.drop_table("case_samples")
    op.drop_table("cases")

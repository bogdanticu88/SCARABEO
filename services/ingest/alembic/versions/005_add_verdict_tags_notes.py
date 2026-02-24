"""Add verdict, tags, notes, and findings status fields.

Revision ID: 005_add_verdict_tags_notes
Revises: 004_add_search_cases_intel
Create Date: 2024-01-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "005_add_verdict_tags_notes"
down_revision: Union[str, None] = "004_add_search_cases_intel"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add verdict, tags, notes, and findings status fields."""
    
    # Add verdict fields to samples table
    op.add_column("samples", sa.Column("verdict", sa.String(32), nullable=True))
    op.add_column("samples", sa.Column("verdict_reason", sa.Text, nullable=True))
    op.add_column("samples", sa.Column("verdict_set_by", sa.String(255), nullable=True))
    op.add_column("samples", sa.Column("verdict_set_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("samples", sa.Column("tags", postgresql.ARRAY(sa.String(255)), nullable=True, server_default="{}"))
    op.add_column("samples", sa.Column("notes_count", sa.Integer, nullable=True, server_default="0"))
    
    # Create sample_notes table
    op.create_table(
        "sample_notes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("sample_sha256", sa.String(64), nullable=False),
        sa.Column("author_id", sa.String(255), nullable=False),
        sa.Column("author_role", sa.String(32), nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sample_notes_tenant_sha256", "sample_notes", ["tenant_id", "sample_sha256"])
    op.create_index("ix_sample_notes_created", "sample_notes", ["tenant_id", "created_at"])
    
    # Add findings status fields - stored in JSONB within search_index and reports
    # We'll track finding statuses in a separate table for proper querying
    op.create_table(
        "finding_statuses",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("sample_sha256", sa.String(64), nullable=False),
        sa.Column("finding_id", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("analyst_note", sa.Text, nullable=True),
        sa.Column("last_updated_by", sa.String(255), nullable=True),
        sa.Column(
            "last_updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sample_sha256", "finding_id", name="uq_finding_statuses_sample_finding"),
    )
    op.create_index("ix_finding_statuses_tenant_sample", "finding_statuses", ["tenant_id", "sample_sha256"])
    op.create_index("ix_finding_statuses_status", "finding_statuses", ["status"])
    
    # Update search_index to include verdict and tags
    op.add_column("search_index", sa.Column("verdict", sa.String(32), nullable=True))
    op.add_column("search_index", sa.Column("tags", postgresql.ARRAY(sa.String(255)), nullable=True, server_default="{}"))


def downgrade() -> None:
    """Remove verdict, tags, notes, and findings status fields."""
    op.drop_column("search_index", "tags")
    op.drop_column("search_index", "verdict")
    
    op.drop_table("finding_statuses")
    op.drop_table("sample_notes")
    
    op.drop_column("samples", "notes_count")
    op.drop_column("samples", "tags")
    op.drop_column("samples", "verdict_set_at")
    op.drop_column("samples", "verdict_set_by")
    op.drop_column("samples", "verdict_reason")
    op.drop_column("samples", "verdict")

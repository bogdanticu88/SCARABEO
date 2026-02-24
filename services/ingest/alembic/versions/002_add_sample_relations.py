"""Add sample_relations table.

Revision ID: 002_add_sample_relations
Revises: 001_initial
Create Date: 2024-01-16 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "002_add_sample_relations"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add sample_relations table."""
    
    # Create enum type for relationship types
    relation_type = postgresql.ENUM(
        "extracted_from_archive", "dropped_by_pe", "child_job",
        name="samplerelationtype",
        create_type=True,
    )
    relation_type.create(op.get_bind(), checkfirst=True)
    
    # Create sample_relations table
    op.create_table(
        "sample_relations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("parent_sha256", sa.String(64), nullable=False),
        sa.Column("child_sha256", sa.String(64), nullable=False),
        sa.Column(
            "relationship",
            sa.Enum("extracted_from_archive", "dropped_by_pe", "child_job", name="samplerelationtype"),
            nullable=False,
        ),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    
    op.create_index("ix_sample_relations_parent", "sample_relations", ["parent_sha256"])
    op.create_index("ix_sample_relations_child", "sample_relations", ["child_sha256"])
    op.create_index(
        "ix_sample_relations_parent_child",
        "sample_relations",
        ["parent_sha256", "child_sha256"],
    )


def downgrade() -> None:
    """Drop sample_relations table."""
    op.drop_table("sample_relations")
    op.execute("DROP TYPE IF EXISTS samplerelationtype")

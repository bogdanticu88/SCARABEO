"""Add similarity clustering tables.

Revision ID: 006_add_similarity_clustering
Revises: 005_add_verdict_tags_notes
Create Date: 2024-01-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "006_add_similarity_clustering"
down_revision: Union[str, None] = "005_add_verdict_tags_notes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add similarity clustering tables."""
    
    # Clusters table
    op.create_table(
        "clusters",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("algorithm", sa.String(32), nullable=False),
        sa.Column("threshold", sa.Integer, nullable=False),
        sa.Column("primary_sample_sha256", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_clusters_tenant_id", "clusters", ["tenant_id"])
    op.create_index("ix_clusters_algorithm", "clusters", ["tenant_id", "algorithm"])
    op.create_index("ix_clusters_primary", "clusters", ["tenant_id", "primary_sample_sha256"])
    
    # Cluster members table
    op.create_table(
        "cluster_members",
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sample_sha256", sa.String(64), nullable=False),
        sa.Column("score", sa.Float, nullable=False),
        sa.Column(
            "added_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["cluster_id"],
            ["clusters.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("cluster_id", "sample_sha256"),
    )
    op.create_index("ix_cluster_members_sha256", "cluster_members", ["sample_sha256"])
    op.create_index("ix_cluster_members_added", "cluster_members", ["added_at"])
    
    # Add cluster_ids array to search_index for querying
    op.add_column("search_index", sa.Column("cluster_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=True, server_default="{}"))


def downgrade() -> None:
    """Remove similarity clustering tables."""
    op.drop_column("search_index", "cluster_ids")
    op.drop_table("cluster_members")
    op.drop_table("clusters")

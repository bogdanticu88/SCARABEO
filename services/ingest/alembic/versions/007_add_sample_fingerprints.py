"""Add sample fingerprints table.

Revision ID: 007_add_sample_fingerprints
Revises: 006_add_similarity_clustering
Create Date: 2024-01-21 00:00:00.000000

Each sample gets at most one fingerprint row per tenant.  The composite primary
key (tenant_id, sha256) enforces uniqueness and enables idempotent upserts via
ON CONFLICT DO UPDATE.

Indexing rationale
------------------
ix_sample_fingerprints_imphash  (tenant_id, imphash)
    Supports exact-match lookups.  Two PE files with the same imphash were
    compiled from identical import tables — a strong similarity signal.
    B-tree on a short MD5 string is O(log n) per lookup.

ix_sample_fingerprints_tlsh  (tenant_id, tlsh)
    Supports prefix-range scans for pre-filtering TLSH candidates before
    computing full distances in Python.  TLSH distance cannot be expressed
    as a SQL predicate, so this index narrows the candidate set cheaply.

ix_sample_fingerprints_created  (tenant_id, created_at)
    Used by find_similar() to load the most recent N fingerprints for
    bulk comparison (ssdeep / tlsh distance computation in Python).
    Without this index, every call would need a full table scan.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "007_add_sample_fingerprints"
down_revision: Union[str, None] = "006_add_similarity_clustering"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create sample_fingerprints table with supporting indexes."""
    op.create_table(
        "sample_fingerprints",
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        # Similarity hashes — all nullable; not every file type yields every hash
        sa.Column("tlsh", sa.String(72), nullable=True),
        sa.Column("ssdeep", sa.String(255), nullable=True),
        sa.Column("imphash", sa.String(32), nullable=True),
        sa.Column("strings_hash", sa.String(64), nullable=True),
        # Extensible JSON metadata (file_type, size, analyzer versions, …)
        sa.Column(
            "extra",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
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
        sa.PrimaryKeyConstraint("tenant_id", "sha256"),
    )

    # Exact-match imphash lookup
    op.create_index(
        "ix_sample_fingerprints_imphash",
        "sample_fingerprints",
        ["tenant_id", "imphash"],
    )
    # TLSH prefix scan / range filter
    op.create_index(
        "ix_sample_fingerprints_tlsh",
        "sample_fingerprints",
        ["tenant_id", "tlsh"],
    )
    # Chronological scan for bulk comparison (ssdeep, tlsh)
    op.create_index(
        "ix_sample_fingerprints_created",
        "sample_fingerprints",
        ["tenant_id", "created_at"],
    )


def downgrade() -> None:
    """Drop sample_fingerprints table."""
    op.drop_index("ix_sample_fingerprints_created", table_name="sample_fingerprints")
    op.drop_index("ix_sample_fingerprints_tlsh", table_name="sample_fingerprints")
    op.drop_index("ix_sample_fingerprints_imphash", table_name="sample_fingerprints")
    op.drop_table("sample_fingerprints")

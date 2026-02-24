"""Add audit log completeness fields.

Revision ID: 003_audit_completeness
Revises: 002_add_sample_relations
Create Date: 2024-01-17 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "003_audit_completeness"
down_revision: Union[str, None] = "002_add_sample_relations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add audit log completeness fields."""
    
    # Add new columns
    op.add_column("audit_log", sa.Column("user_id", sa.String(255), nullable=True))
    op.add_column("audit_log", sa.Column("role", sa.String(32), nullable=True))
    op.add_column("audit_log", sa.Column("target_type", sa.String(64), nullable=True))
    op.add_column("audit_log", sa.Column("target_id", sa.String(255), nullable=True))
    op.add_column("audit_log", sa.Column("status", sa.String(32), nullable=True))
    op.add_column("audit_log", sa.Column("user_agent", sa.String(512), nullable=True))
    op.add_column("audit_log", sa.Column("details_json", sa.Text, nullable=True))
    
    # Rename resource_type to target_type concept (keep resource_id for backward compat)
    # Add index on user_id
    op.create_index("ix_audit_user_id", "audit_log", ["user_id"])
    op.create_index("ix_audit_user_created", "audit_log", ["user_id", "created_at"])


def downgrade() -> None:
    """Remove audit log completeness fields."""
    op.drop_index("ix_audit_user_created")
    op.drop_index("ix_audit_user_id")
    
    op.drop_column("audit_log", "details_json")
    op.drop_column("audit_log", "user_agent")
    op.drop_column("audit_log", "status")
    op.drop_column("audit_log", "target_id")
    op.drop_column("audit_log", "target_type")
    op.drop_column("audit_log", "role")
    op.drop_column("audit_log", "user_id")

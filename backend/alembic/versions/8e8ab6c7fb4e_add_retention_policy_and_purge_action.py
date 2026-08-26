"""add retention_policies table and new audit actions

Revision ID: 8e8ab6c7fb4e
Revises: d9f3e335a985
Create Date: 2026-08-24 12:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '8e8ab6c7fb4e'
down_revision: Union[str, Sequence[str], None] = 'd9f3e335a985'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'document_purged'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'retention_policy_updated'")

    op.create_table(
        'retention_policies',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('retention_days', sa.Integer(), nullable=False),
        sa.Column('updated_by_id', sa.UUID(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['updated_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.execute(
        "INSERT INTO retention_policies (id, retention_days, created_at, updated_at) "
        "VALUES (gen_random_uuid(), 365, now(), now())"
    )


def downgrade() -> None:
    op.drop_table('retention_policies')
    # Postgres does not support removing enum values directly; not implemented.

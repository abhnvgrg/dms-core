"""add encryption_keys table for envelope key hierarchy

Revision ID: 604632b42c11
Revises: 06b61c2c977a
Create Date: 2026-08-24 15:30:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '604632b42c11'
down_revision: Union[str, Sequence[str], None] = '06b61c2c977a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'encryption_keys',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('purpose', sa.Enum('pii_data', 'object_storage', name='encryption_key_purpose'), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('wrapped_key', sa.Text(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('rotated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('purpose', 'version', name='uq_encryption_key_purpose_version'),
    )
    op.create_index('ix_encryption_keys_purpose', 'encryption_keys', ['purpose'])


def downgrade() -> None:
    op.drop_table('encryption_keys')
    sa.Enum(name='encryption_key_purpose').drop(op.get_bind())

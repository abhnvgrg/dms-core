"""known devices, so an unfamiliar login can be made to enrol MFA

Revision ID: c31f8a5d4e02
Revises: b7c4e1a92f30
Create Date: 2026-08-24 20:10:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'c31f8a5d4e02'
down_revision: Union[str, Sequence[str], None] = 'b7c4e1a92f30'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'known_devices',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('user_agent', sa.String(length=512), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'fingerprint', name='uq_known_device'),
    )
    op.create_index('ix_known_devices_user_id', 'known_devices', ['user_id'])
    op.create_index('ix_known_devices_fingerprint', 'known_devices', ['fingerprint'])


def downgrade() -> None:
    op.drop_table('known_devices')

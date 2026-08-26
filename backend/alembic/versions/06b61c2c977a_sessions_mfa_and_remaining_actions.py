"""add sessions table, mfa columns, remaining audit actions

Revision ID: 06b61c2c977a
Revises: 33409500914b
Create Date: 2026-08-24 15:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '06b61c2c977a'
down_revision: Union[str, Sequence[str], None] = '33409500914b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'session_reuse_detected'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'mfa_enabled'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'key_rotated'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'malware_detected'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'document_downloaded'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'asset_transfer_conflict'")

    op.add_column('users', sa.Column('totp_secret_encrypted', sa.Text(), nullable=True))
    op.add_column('users', sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default=sa.false()))

    op.create_table(
        'sessions',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('access_token_hash', sa.String(length=64), nullable=False),
        sa.Column('refresh_token_hash', sa.String(length=64), nullable=False),
        sa.Column('previous_refresh_token_hash', sa.String(length=64), nullable=True),
        sa.Column('access_expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('refresh_expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('user_agent', sa.String(length=512), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('access_token_hash'),
        sa.UniqueConstraint('refresh_token_hash'),
    )
    op.create_index('ix_sessions_user_id', 'sessions', ['user_id'])
    op.create_index('ix_sessions_access_token_hash', 'sessions', ['access_token_hash'])
    op.create_index('ix_sessions_refresh_token_hash', 'sessions', ['refresh_token_hash'])


def downgrade() -> None:
    op.drop_table('sessions')
    op.drop_column('users', 'mfa_enabled')
    op.drop_column('users', 'totp_secret_encrypted')

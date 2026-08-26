"""officer signing keys, audit checkpoints, signed asset transfers

Revision ID: b7c4e1a92f30
Revises: 604632b42c11
Create Date: 2026-08-24 18:30:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = 'b7c4e1a92f30'
down_revision: Union[str, Sequence[str], None] = '604632b42c11'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


NEW_AUDIT_ACTIONS = (
    'access_grant_expired',
    'key_revoked',
    'signing_key_registered',
    'signing_key_revoked',
    'audit_checkpoint_created',
    'user_created',
    'user_role_changed',
    'user_deactivated',
    'file_rejected',
)


def upgrade() -> None:
    for action in NEW_AUDIT_ACTIONS:
        op.execute(f"ALTER TYPE audit_action ADD VALUE IF NOT EXISTS '{action}'")

    op.execute("ALTER TYPE encryption_key_purpose ADD VALUE IF NOT EXISTS 'checkpoint_signing'")

    signing_key_status = postgresql.ENUM(
        'active', 'retired', 'revoked', name='signing_key_status', create_type=False
    )
    signing_key_status.create(op.get_bind(), checkfirst=True)

    custody_status = postgresql.ENUM(
        'police_custody', 'forensics_custody', 'court_custody', 'released',
        name='custody_status', create_type=False,
    )

    op.add_column(
        'sessions',
        sa.Column('mfa_pending', sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    op.create_table(
        'officer_signing_keys',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('public_key_pem', sa.Text(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('status', signing_key_status, nullable=False, server_default='active'),
        sa.Column('retired_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_by_id', sa.UUID(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['revoked_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('fingerprint'),
    )
    op.create_index('ix_officer_signing_keys_user_id', 'officer_signing_keys', ['user_id'])
    op.create_index('ix_officer_signing_keys_fingerprint', 'officer_signing_keys', ['fingerprint'])
    op.create_index('ix_officer_signing_keys_status', 'officer_signing_keys', ['status'])

    op.add_column('documents', sa.Column('signing_key_id', sa.UUID(), nullable=True))
    op.create_foreign_key(
        'fk_documents_signing_key_id',
        'documents',
        'officer_signing_keys',
        ['signing_key_id'],
        ['id'],
        ondelete='RESTRICT',
    )

    op.create_table(
        'asset_transfers',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('asset_id', sa.UUID(), nullable=False),
        sa.Column('performed_by_id', sa.UUID(), nullable=False),
        sa.Column('receiving_officer_id', sa.UUID(), nullable=False),
        sa.Column('from_status', custody_status, nullable=False),
        sa.Column('to_status', custody_status, nullable=False),
        sa.Column('signed_payload', sa.Text(), nullable=False),
        sa.Column('client_signature', sa.Text(), nullable=False),
        sa.Column('signing_key_id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['physical_assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['performed_by_id'], ['users.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['receiving_officer_id'], ['users.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['signing_key_id'], ['officer_signing_keys.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_asset_transfers_asset_id', 'asset_transfers', ['asset_id'])
    op.create_index('ix_asset_transfers_created_at', 'asset_transfers', ['created_at'])

    op.create_table(
        'audit_checkpoints',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('from_entry_id', sa.Integer(), nullable=False),
        sa.Column('to_entry_id', sa.Integer(), nullable=False),
        sa.Column('entry_count', sa.Integer(), nullable=False),
        sa.Column('checkpoint_hash', sa.String(length=64), nullable=False),
        sa.Column('signature', sa.Text(), nullable=False),
        sa.Column('signing_key_version', sa.Integer(), nullable=False),
        sa.Column('object_key', sa.String(length=1024), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('checkpoint_hash'),
    )
    op.create_index('ix_audit_checkpoints_to_entry_id', 'audit_checkpoints', ['to_entry_id'])
    op.create_index('ix_audit_checkpoints_created_at', 'audit_checkpoints', ['created_at'])


def downgrade() -> None:
    op.drop_table('audit_checkpoints')
    op.drop_table('asset_transfers')
    op.drop_constraint('fk_documents_signing_key_id', 'documents', type_='foreignkey')
    op.drop_column('documents', 'signing_key_id')
    op.drop_table('officer_signing_keys')
    op.drop_column('sessions', 'mfa_pending')
    sa.Enum(name='signing_key_status').drop(op.get_bind(), checkfirst=True)

"""add blockchain anchor columns to audit_ledger

Revision ID: 0de243a1fb2c
Revises: 8e8ab6c7fb4e
Create Date: 2026-08-24 12:05:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '0de243a1fb2c'
down_revision: Union[str, Sequence[str], None] = '8e8ab6c7fb4e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('audit_ledger', sa.Column('chain_tx_hash', sa.String(length=66), nullable=True))
    op.add_column('audit_ledger', sa.Column('chain_block_number', sa.Integer(), nullable=True))
    op.add_column(
        'audit_ledger', sa.Column('chain_anchored_at', sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('audit_ledger', 'chain_anchored_at')
    op.drop_column('audit_ledger', 'chain_block_number')
    op.drop_column('audit_ledger', 'chain_tx_hash')

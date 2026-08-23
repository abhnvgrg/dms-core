"""add case audit actions

Revision ID: d9f3e335a985
Revises: 97d1ce9f29e7
Create Date: 2026-08-24 00:39:47.429860

"""
from typing import Sequence, Union

from alembic import op


revision: str = 'd9f3e335a985'
down_revision: Union[str, Sequence[str], None] = '97d1ce9f29e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'case_created'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'case_assigned'")


def downgrade() -> None:
    # Postgres does not support removing enum values directly.
    # A downgrade would require recreating the enum type without these
    # values and migrating all dependent columns — not implemented here
    # since it's destructive and not needed for this project's timeline.
    pass
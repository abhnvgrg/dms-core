"""change retention_policies.retention_days to retention_minutes

Revision ID: a10cdffd6cb5
Revises: 0de243a1fb2c
Create Date: 2026-08-24 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

revision: str = 'a10cdffd6cb5'
down_revision: Union[str, Sequence[str], None] = '0de243a1fb2c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column('retention_policies', 'retention_days', new_column_name='retention_minutes')
    # Existing values were day-counts; convert to the equivalent minute-count.
    op.execute("UPDATE retention_policies SET retention_minutes = retention_minutes * 1440")


def downgrade() -> None:
    op.execute("UPDATE retention_policies SET retention_minutes = retention_minutes / 1440")
    op.alter_column('retention_policies', 'retention_minutes', new_column_name='retention_days')

"""add document classification and remaining audit actions

Revision ID: 33409500914b
Revises: a10cdffd6cb5
Create Date: 2026-08-24 14:30:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '33409500914b'
down_revision: Union[str, Sequence[str], None] = 'a10cdffd6cb5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'login_locked'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'document_reclassified'")

    document_classification = sa.Enum(
        'public_redacted', 'case_restricted', 'court_elevated', 'admin_only',
        name='document_classification',
    )
    document_classification.create(op.get_bind())

    op.add_column(
        'documents',
        sa.Column(
            'classification',
            document_classification,
            nullable=False,
            server_default='case_restricted',
        ),
    )


def downgrade() -> None:
    op.drop_column('documents', 'classification')
    sa.Enum(name='document_classification').drop(op.get_bind())

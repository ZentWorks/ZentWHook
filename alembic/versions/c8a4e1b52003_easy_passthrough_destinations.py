"""easy passthrough destinations

Revision ID: c8a4e1b52003
Revises: b7c2d8f41901
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'c8a4e1b52003'
down_revision: Union[str, Sequence[str], None] = 'b7c2d8f41901'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('destinations') as batch:
        batch.add_column(sa.Column('request_mode', sa.String(length=20), nullable=False, server_default='passthrough'))
    # Preserve the behavior of destinations created by older releases. New
    # destinations use passthrough by default, while existing ones keep their
    # explicitly configured method/headers/query/body-mapping semantics.
    op.execute("UPDATE destinations SET request_mode='custom'")


def downgrade() -> None:
    with op.batch_alter_table('destinations') as batch:
        batch.drop_column('request_mode')

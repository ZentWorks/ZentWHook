"""hmac custom payload template and timestamp validation

Revision ID: d9f7a2c63104
Revises: c8a4e1b52003
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'd9f7a2c63104'
down_revision: Union[str, Sequence[str], None] = 'c8a4e1b52003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('endpoint_auth') as batch:
        batch.add_column(sa.Column('hmac_payload_template', sa.Text(), nullable=False, server_default='{{raw_body}}'))
        batch.add_column(sa.Column('hmac_signature_prefix', sa.String(length=80), nullable=False, server_default=''))
        batch.add_column(sa.Column('hmac_verify_timestamp', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column('hmac_timestamp_header', sa.String(length=120), nullable=False, server_default=''))
        batch.add_column(sa.Column('hmac_timestamp_tolerance_seconds', sa.Integer(), nullable=False, server_default='300'))


def downgrade() -> None:
    with op.batch_alter_table('endpoint_auth') as batch:
        batch.drop_column('hmac_timestamp_tolerance_seconds')
        batch.drop_column('hmac_timestamp_header')
        batch.drop_column('hmac_verify_timestamp')
        batch.drop_column('hmac_signature_prefix')
        batch.drop_column('hmac_payload_template')

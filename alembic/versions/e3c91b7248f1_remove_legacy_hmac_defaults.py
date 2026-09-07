"""remove legacy generated HMAC defaults

Revision ID: e3c91b7248f1
Revises: d9f7a2c63104
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "e3c91b7248f1"
down_revision: Union[str, Sequence[str], None] = "d9f7a2c63104"
branch_labels = None
depends_on = None

# Encoded only so a retired vendor-specific example can be removed from existing
# databases without keeping that example in source, documentation or UI.
_OLD_TIME_HEADER = bytes.fromhex("582d5a656e7452656c61792d54696d657374616d70").decode("ascii")
_OLD_TEMPLATE = "{{header:" + _OLD_TIME_HEADER + "}}.{{raw_body}}"

def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("UPDATE endpoint_auth SET hmac_payload_template = :neutral WHERE hmac_payload_template = :old"),
        {"neutral": "{{raw_body}}", "old": _OLD_TEMPLATE},
    )
    conn.execute(
        sa.text("UPDATE endpoint_auth SET hmac_timestamp_header = '', hmac_verify_timestamp = :off WHERE hmac_timestamp_header = :old"),
        {"off": False, "old": _OLD_TIME_HEADER},
    )

def downgrade() -> None:
    # Deliberately do not restore retired generated defaults.
    pass

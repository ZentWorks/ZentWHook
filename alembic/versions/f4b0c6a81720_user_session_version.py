"""add per-user session version

Revision ID: f4b0c6a81720
Revises: e3c91b7248f1
Create Date: 2026-09-07
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "f4b0c6a81720"
down_revision: Union[str, Sequence[str], None] = "e3c91b7248f1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.add_column("users", sa.Column("session_version", sa.Integer(), nullable=False, server_default="1"))

def downgrade() -> None:
    op.drop_column("users", "session_version")

"""Outbox messages remember the request that caused them.

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-25

``correlation_id`` carries the API request ID (or the ID of the job or
operator command) into the worker that runs the message, so one identifier
links a request to every job it caused and to their log lines. Additive and
online: a nullable column.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "outbox_messages", sa.Column("correlation_id", sa.String(length=64), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("outbox_messages", "correlation_id")

"""Insight claims: when an analysis started and how often it was attempted.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-24

The maintenance reaper re-queues an analysis whose worker died (RUNNING for
longer than any analysis takes) and fails it after a bounded number of
attempts. ``started_at`` doubles as a fencing token: a worker whose claim was
reaped cannot overwrite the result of the newer run. Additive and online:
a nullable column, a column with a constant default, and a small partial index
over running analyses only.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("insights", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "insights",
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.create_index(
        "ix_insights_running",
        "insights",
        ["org_id", "started_at"],
        unique=False,
        postgresql_where=sa.text("status = 'running'"),
    )


def downgrade() -> None:
    op.drop_index("ix_insights_running", table_name="insights")
    op.drop_column("insights", "attempts")
    op.drop_column("insights", "started_at")

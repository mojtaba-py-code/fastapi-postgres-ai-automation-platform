"""Indexes for the identity retention.

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-26

Sign-in sessions (with their device and address), refresh tokens and
password-reset tokens were never deleted: personal data kept for ever, and
tables that only grow. The daily retention now deletes them after they
expire (sessions after ``retention.sessions_days``), in batches found by
these indexes. Built CONCURRENTLY, so an existing database keeps serving
sign-ins while they are built; a build that fails leaves an INVALID index:
drop it and run the migration again.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INDEXES = (
    ("ix_user_sessions_expires_at", "user_sessions"),
    ("ix_refresh_tokens_expires_at", "refresh_tokens"),
    ("ix_password_reset_tokens_expires_at", "password_reset_tokens"),
)


def upgrade() -> None:
    with op.get_context().autocommit_block():
        for name, table in INDEXES:
            op.create_index(
                name,
                table,
                ["expires_at"],
                unique=False,
                postgresql_concurrently=True,
                if_not_exists=True,
            )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        for name, table in reversed(INDEXES):
            op.drop_index(name, table_name=table, postgresql_concurrently=True, if_exists=True)

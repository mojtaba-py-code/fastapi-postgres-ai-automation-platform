"""Self-service sign-up proves the e-mail address first.

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-26

A sign-up used to create the account at once and answered ``409
email_taken`` for an address that already had one - anyone could learn who
has an account, and could open one in someone else's name. Now a sign-up
stores only the address and mails it a link; the account is created by
whoever opens that link. ``signup_requests`` holds those pending requests
and, like the password reset tokens, is reachable only in the
authentication context.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from nexusflow.infrastructure.database.rls import app_role, enable_rls, grant

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "signup_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS, nullable=True),
        sa.Column("requested_ip", sa.String(length=45), nullable=True),
        sa.Column("operator_issued", sa.Boolean(), nullable=False),
        sa.CheckConstraint("email = lower(email)", name=op.f("ck_signup_requests_email_lowercase")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_signup_requests")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_signup_requests_token_hash")),
    )
    op.create_index("ix_signup_requests_email", "signup_requests", ["email"])
    op.create_index("ix_signup_requests_expires_at", "signup_requests", ["expires_at"])
    for statement in (
        *enable_rls("signup_requests"),
        (
            "CREATE POLICY signup_requests_auth ON signup_requests "
            "USING (nf_auth_context()) WITH CHECK (nf_auth_context())"
        ),
        grant("signup_requests", "SELECT, INSERT, UPDATE, DELETE", app_role()),
    ):
        op.execute(statement)


def downgrade() -> None:
    op.drop_table("signup_requests")

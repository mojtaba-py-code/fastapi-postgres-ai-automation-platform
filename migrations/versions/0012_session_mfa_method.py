"""The second factor a session passed, so that organizations can require passkeys.

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-26

``user_sessions.mfa_method`` names the platform's second factor a session
passed - ``totp``, ``recovery_code`` or ``webauthn`` (a passkey) - at sign-in,
or TOTP when it was confirmed in the session. An organization that requires
passkeys (``require_passkey`` in ``organizations.settings``) accepts only
``webauthn``. NULL means none: no second factor, an identity provider's MFA,
and every session opened before this migration - so no existing session
satisfies the new policy. Check constraints allow those three values only,
and a method only on an MFA-verified session.

The runtime role writes the column through its table-level grants on
``user_sessions`` (SELECT, INSERT, UPDATE, DELETE since 0001), which cover
columns added later - as for ``sso_org_id`` in 0011. Row-level security is
unchanged.

Downgrading drops the column and takes ``require_passkey`` out of every
organization's settings, which 0011's code would refuse as an unknown key. It
refuses while an organization requires passkeys - the downgrade would lift the
policy silently: turn it off for those organizations first (the error says
how).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "user_sessions"
_METHODS = "'totp', 'recovery_code', 'webauthn'"
_REQUIRING = "settings @> '{\"require_passkey\": true}'"
_LIFT = (  # for the operator to run, quoted in the error below
    "UPDATE organizations SET settings = jsonb_set(settings, '{require_passkey}', 'false') "
    "WHERE settings @> '{\"require_passkey\": true}';"
)


def upgrade() -> None:
    op.add_column(TABLE, sa.Column("mfa_method", sa.String(length=20), nullable=True))
    op.create_check_constraint(
        op.f("ck_user_sessions_mfa_method"),
        TABLE,
        f"mfa_method IS NULL OR mfa_method IN ({_METHODS})",
    )
    op.create_check_constraint(
        op.f("ck_user_sessions_mfa_method_verified"), TABLE, "mfa_method IS NULL OR mfa_verified"
    )


def downgrade() -> None:
    bind = op.get_bind()
    requiring = bind.execute(
        sa.text(f"SELECT count(*) FROM organizations WHERE {_REQUIRING}")  # noqa: S608 - a constant
    ).scalar_one()
    if requiring:
        raise RuntimeError(
            f"{requiring} organization(s) require passkeys: downgrading would lift the policy "
            "silently (0011 does not know it). Turn it off for them first, then downgrade "
            "again: " + _LIFT
        )
    op.execute(
        "UPDATE organizations SET settings = settings - 'require_passkey' "
        "WHERE settings -> 'require_passkey' IS NOT NULL"
    )
    op.drop_constraint(op.f("ck_user_sessions_mfa_method_verified"), TABLE, type_="check")
    op.drop_constraint(op.f("ck_user_sessions_mfa_method"), TABLE, type_="check")
    op.drop_column(TABLE, "mfa_method")

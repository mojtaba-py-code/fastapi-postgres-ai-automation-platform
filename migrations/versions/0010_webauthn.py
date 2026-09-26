"""Passkeys (WebAuthn) as a second factor.

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-26

``webauthn_credentials`` holds each passkey's public key (SubjectPublicKeyInfo),
its COSE algorithm, signature counter, transports, backup flags, a name the
user chose and the random WebAuthn user handle - public data only, nothing
that signs. Like the MFA recovery codes it is user-scoped: row-level
security enabled and forced, rows visible to their owner (or during
authentication) only. A credential ID is unique across all accounts. The
runtime role may update only what a sign-in or a rename changes - the name,
the counter, the backup state and the last use - never a passkey's key,
algorithm, credential ID, user handle or owner.

``users.mfa_enabled`` now means "a second factor is set up": an
authenticator app (TOTP), passkeys, or both. The check constraint that
required a TOTP secret whenever MFA was on becomes its converse: a TOTP
secret means MFA is on.

Downgrading drops every passkey. It refuses while an account relies on
passkeys alone, whose MFA would otherwise end in an invalid state: turn it
off for those accounts first (the error says how).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from nexusflow.infrastructure.database.rls import app_role, enable_rls, grant

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)
TABLE = "webauthn_credentials"
# Column-level UPDATE: what a sign-in or a rename changes, and nothing else.
UPDATABLE_COLUMNS = "name, sign_count, backed_up, last_used_at"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("user_handle", sa.LargeBinary(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("algorithm", sa.Integer(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False),
        sa.Column("transports", sa.ARRAY(sa.String(length=16)), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("backup_eligible", sa.Boolean(), nullable=False),
        sa.Column("backed_up", sa.Boolean(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_used_at", TS, nullable=True),
        sa.CheckConstraint(
            "algorithm IN (-7, -8, -257)", name=op.f("ck_webauthn_credentials_algorithm")
        ),
        sa.CheckConstraint(
            "octet_length(credential_id) BETWEEN 16 AND 1023",
            name=op.f("ck_webauthn_credentials_credential_id_length"),
        ),
        sa.CheckConstraint(
            "octet_length(user_handle) BETWEEN 1 AND 64",
            name=op.f("ck_webauthn_credentials_user_handle_length"),
        ),
        sa.CheckConstraint(
            "octet_length(public_key) BETWEEN 32 AND 1024",
            name=op.f("ck_webauthn_credentials_public_key_length"),
        ),
        sa.CheckConstraint(
            "sign_count BETWEEN 0 AND 4294967295",
            name=op.f("ck_webauthn_credentials_sign_count_range"),
        ),
        sa.CheckConstraint(
            "backup_eligible OR NOT backed_up", name=op.f("ck_webauthn_credentials_backup_state")
        ),
        sa.CheckConstraint(
            "cardinality(transports) <= 6", name=op.f("ck_webauthn_credentials_transports_count")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_webauthn_credentials_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_webauthn_credentials")),
        sa.UniqueConstraint("credential_id", name=op.f("uq_webauthn_credentials_credential_id")),
    )
    op.create_index(op.f("ix_webauthn_credentials_user_id"), TABLE, ["user_id"])
    for statement in (
        *enable_rls(TABLE),
        (
            f"CREATE POLICY {TABLE}_owner ON {TABLE} "
            "USING (user_id = nf_current_user() OR nf_auth_context()) "
            "WITH CHECK (user_id = nf_current_user() OR nf_auth_context())"
        ),
        grant(TABLE, "SELECT, INSERT, DELETE", app_role()),
        f"GRANT UPDATE ({UPDATABLE_COLUMNS}) ON {TABLE} TO {app_role()}",
        # A TOTP secret without MFA is a leftover no code path writes; clear
        # any before the converse constraint below validates every row.
        (
            "UPDATE users SET mfa_secret_encrypted = NULL "
            "WHERE NOT mfa_enabled AND mfa_secret_encrypted IS NOT NULL"
        ),
        "ALTER TABLE users DROP CONSTRAINT ck_users_mfa_secret",
        (
            "ALTER TABLE users ADD CONSTRAINT ck_users_mfa_secret "
            "CHECK (mfa_enabled OR mfa_secret_encrypted IS NULL)"
        ),
    ):
        op.execute(statement)


_PASSKEYS_ONLY = "mfa_enabled AND mfa_secret_encrypted IS NULL"
_TURN_MFA_OFF = (  # for the operator to run, quoted in the error below
    "DELETE FROM mfa_recovery_codes WHERE user_id IN (SELECT id FROM users WHERE "
    "mfa_enabled AND mfa_secret_encrypted IS NULL); UPDATE users SET mfa_enabled = false "
    "WHERE mfa_enabled AND mfa_secret_encrypted IS NULL;"
)


def downgrade() -> None:
    bind = op.get_bind()
    passkeys_only = bind.execute(
        sa.text(f"SELECT count(*) FROM users WHERE {_PASSKEYS_ONLY}")  # noqa: S608 - a constant
    ).scalar_one()
    if passkeys_only:
        raise RuntimeError(
            f"{passkeys_only} account(s) use passkeys as their only second factor: downgrading "
            "would drop the passkeys and leave MFA on without any factor. Turn MFA off for "
            "those accounts first, then downgrade again: " + _TURN_MFA_OFF
        )
    op.execute("ALTER TABLE users DROP CONSTRAINT ck_users_mfa_secret")
    op.execute(
        "ALTER TABLE users ADD CONSTRAINT ck_users_mfa_secret "
        "CHECK (NOT mfa_enabled OR mfa_secret_encrypted IS NOT NULL)"
    )
    op.drop_table(TABLE)

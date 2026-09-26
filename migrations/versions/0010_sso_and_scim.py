"""Single sign-on (OpenID Connect) and SCIM provisioning, per organization.

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-26

* ``sso_connections`` - an organization's identity provider; the client
  secret is sealed (AES-256-GCM envelope, bound to the organization and row).
* ``sso_login_states`` - started sign-ins: keyed hashes of state, client
  binding and nonce, the sealed PKCE verifier; single use, minutes long.
* ``sso_identities`` - a person's (issuer, subject) at an organization's
  provider, linked to the account.
* ``scim_tokens`` - SCIM bearer tokens (keyed hashes only).
* ``scim_users`` - an organization's directory entries (SCIM User resources).
* ``user_sessions.sso_org_id`` - a session an identity provider opened is
  valid for that organization only.
* ``audit_logs.actor_type`` also allows ``scim`` (SCIM tokens are actors).

Row-level security: every new table is ENABLEd and FORCEd with the tenant
policy. Where the tenant is not known yet, a narrow authentication-context
policy (``nf_auth_context()``) allows exactly the lookup that needs it: a
state by its hash (and the retention's purge of expired ones), a SCIM token
by its prefix. A person's own identity links and directory entries are
readable and deletable under their user context, for the personal-data
export and erasure.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from nexusflow.infrastructure.database.rls import app_role, tenant_table_security

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)
_ACTOR_TYPES_BEFORE = "'user', 'api_key', 'service', 'system', 'anonymous'"


def _org_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["org_id"],
        ["organizations.id"],
        name=op.f(f"fk_{table}_org_id_organizations"),
        ondelete="CASCADE",
    )


def upgrade() -> None:
    _sessions()
    _sso_tables()
    _scim_tables()
    _security()
    op.execute("ALTER TABLE audit_logs DROP CONSTRAINT ck_audit_logs_actor_type")
    op.execute(
        "ALTER TABLE audit_logs ADD CONSTRAINT ck_audit_logs_actor_type "
        f"CHECK (actor_type IN ({_ACTOR_TYPES_BEFORE}, 'scim'))"
    )


def _sessions() -> None:
    op.add_column("user_sessions", sa.Column("sso_org_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        op.f("fk_user_sessions_sso_org_id_organizations"),
        "user_sessions",
        "organizations",
        ["sso_org_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_user_sessions_sso_org",
        "user_sessions",
        ["sso_org_id"],
        postgresql_where=sa.text("sso_org_id IS NOT NULL"),
    )


def _sso_tables() -> None:
    op.create_table(
        "sso_connections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("client_secret_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("secret_key_id", sa.String(length=32), nullable=False),
        sa.Column("allowed_domains", sa.ARRAY(sa.String(length=253)), nullable=False),
        sa.Column("verified_domains", sa.ARRAY(sa.String(length=253)), nullable=False),
        sa.Column("default_role", sa.String(length=20), nullable=False),
        sa.Column("trust_idp_mfa", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint(
            "default_role IN ('viewer', 'analyst')", name=op.f("ck_sso_connections_default_role")
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_sso_connections_created_by_users"),
            ondelete="SET NULL",
        ),
        _org_fk("sso_connections"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_connections")),
        sa.UniqueConstraint("org_id", name=op.f("uq_sso_connections_org_id")),
    )
    op.create_table(
        "sso_login_states",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("binding_hash", sa.String(length=64), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("code_verifier_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS, nullable=True),
        sa.ForeignKeyConstraint(
            ["connection_id"],
            ["sso_connections.id"],
            name=op.f("fk_sso_login_states_connection_id_sso_connections"),
            ondelete="CASCADE",
        ),
        _org_fk("sso_login_states"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_login_states")),
        sa.UniqueConstraint("state_hash", name=op.f("uq_sso_login_states_state_hash")),
    )
    op.create_index("ix_sso_login_states_org", "sso_login_states", ["org_id"])
    op.create_index("ix_sso_login_states_connection", "sso_login_states", ["connection_id"])
    op.create_index("ix_sso_login_states_expires_at", "sso_login_states", ["expires_at"])
    op.create_table(
        "sso_identities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_login_at", TS, nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_sso_identities_user_id_users"),
            ondelete="CASCADE",
        ),
        _org_fk("sso_identities"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_identities")),
        sa.UniqueConstraint("org_id", "issuer", "subject", name=op.f("uq_sso_identities_subject")),
        sa.UniqueConstraint("org_id", "issuer", "user_id", name=op.f("uq_sso_identities_user")),
    )
    op.create_index("ix_sso_identities_user_id", "sso_identities", ["user_id"])


def _scim_tables() -> None:
    op.create_table(
        "scim_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("token_prefix", sa.String(length=12), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("last_used_at", TS, nullable=True),
        sa.Column("revoked_at", TS, nullable=True),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_scim_tokens_created_by_users"),
            ondelete="SET NULL",
        ),
        _org_fk("scim_tokens"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scim_tokens")),
        sa.UniqueConstraint("token_prefix", name=op.f("uq_scim_tokens_token_prefix")),
    )
    op.create_index(op.f("ix_scim_tokens_org_id"), "scim_tokens", ["org_id"])
    op.create_table(
        "scim_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("user_name", sa.String(length=254), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("display_name", sa.String(length=120), nullable=True),
        sa.Column("given_name", sa.String(length=120), nullable=True),
        sa.Column("family_name", sa.String(length=120), nullable=True),
        sa.Column("formatted_name", sa.String(length=200), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint(
            "user_name = lower(user_name)", name=op.f("ck_scim_users_user_name_lowercase")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_scim_users_user_id_users"),
            ondelete="CASCADE",
        ),
        _org_fk("scim_users"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scim_users")),
        sa.UniqueConstraint("org_id", "user_id", name=op.f("uq_scim_users_user")),
    )
    op.create_index("ix_scim_users_user_name", "scim_users", ["org_id", "user_name"])
    op.create_index("ix_scim_users_user_id", "scim_users", ["user_id"])
    op.create_index(
        "uq_scim_users_external_id",
        "scim_users",
        ["org_id", "external_id"],
        unique=True,
        postgresql_where=sa.text("external_id IS NOT NULL"),
    )


def _security() -> None:
    role = app_role()
    statements: list[str] = [
        *tenant_table_security("sso_connections", role),
        *tenant_table_security("sso_login_states", role),
        # The callback finds a state by its hash before it knows the tenant; the
        # identity retention deletes expired ones across tenants.
        (
            "CREATE POLICY sso_login_states_auth_read ON sso_login_states FOR SELECT "
            "USING (nf_auth_context())"
        ),
        (
            "CREATE POLICY sso_login_states_auth_purge ON sso_login_states FOR DELETE "
            "USING (nf_auth_context())"
        ),
        *tenant_table_security("sso_identities", role),
        (
            "CREATE POLICY sso_identities_owner_read ON sso_identities FOR SELECT "
            "USING (user_id = nf_current_user())"
        ),
        (
            "CREATE POLICY sso_identities_owner_delete ON sso_identities FOR DELETE "
            "USING (user_id = nf_current_user())"
        ),
        *tenant_table_security("scim_tokens", role, "SELECT, INSERT, UPDATE"),
        # A SCIM request's token is found by its prefix before the tenant is known.
        "CREATE POLICY scim_tokens_auth_read ON scim_tokens FOR SELECT USING (nf_auth_context())",
        *tenant_table_security("scim_users", role),
        (
            "CREATE POLICY scim_users_owner_read ON scim_users FOR SELECT "
            "USING (user_id = nf_current_user())"
        ),
        (
            "CREATE POLICY scim_users_owner_delete ON scim_users FOR DELETE "
            "USING (user_id = nf_current_user())"
        ),
    ]
    for statement in statements:
        op.execute(statement)


def downgrade() -> None:
    op.execute("ALTER TABLE audit_logs DROP CONSTRAINT ck_audit_logs_actor_type")
    # NOT VALID: entries written by SCIM tokens stay (the audit trail is append-only).
    op.execute(
        "ALTER TABLE audit_logs ADD CONSTRAINT ck_audit_logs_actor_type "
        f"CHECK (actor_type IN ({_ACTOR_TYPES_BEFORE})) NOT VALID"
    )
    for table in ("scim_users", "scim_tokens", "sso_identities", "sso_login_states"):
        op.drop_table(table)
    op.drop_table("sso_connections")
    op.drop_index("ix_user_sessions_sso_org", table_name="user_sessions")
    op.drop_constraint(
        op.f("fk_user_sessions_sso_org_id_organizations"), "user_sessions", type_="foreignkey"
    )
    op.drop_column("user_sessions", "sso_org_id")

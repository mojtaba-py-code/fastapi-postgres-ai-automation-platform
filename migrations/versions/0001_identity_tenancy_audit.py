"""Identity, tenancy, audit trail and outbox - with row-level security.

Revision ID: 0001
Revises:
Create Date: 2026-09-24

Security layer created here:

* ``nf_current_org()`` / ``nf_current_user()`` / ``nf_auth_context()`` read the
  transaction-local tenant context set by the application's unit of work.
* Every tenant table has ``ENABLE`` + ``FORCE ROW LEVEL SECURITY`` and a policy
  pinning rows to ``nf_current_org()``. With no context set, no rows match.
* ``audit_logs`` is append-only: the application role may only ``SELECT``; the
  ``nf_append_audit`` SECURITY DEFINER function is the sole write path and
  maintains a per-tenant SHA-256 hash chain. UPDATE/DELETE/TRUNCATE are blocked
  by triggers (except the explicit retention-purge function).
* The application role receives the minimum privileges; e.g. it cannot change
  ``users.is_platform_admin`` (column-level UPDATE grant).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from nexusflow.infrastructure.database.rls import (
    app_role,
    enable_rls,
    grant,
    split_sql,
    tenant_policy,
)

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)
ROLE_CHECK = "role IN ('owner', 'admin', 'analyst', 'operator', 'viewer')"


def upgrade() -> None:
    _create_tables()
    _create_security()


def _create_tables() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("slug", sa.String(length=63), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("settings", postgresql.JSONB(), nullable=False),
        sa.Column("deletion_requested_at", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint("slug ~ '^[a-z0-9-]{1,63}$'", name=op.f("ck_organizations_slug_format")),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'pending_deletion')",
            name=op.f("ck_organizations_status"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organizations")),
        sa.UniqueConstraint("slug", name=op.f("uq_organizations_slug")),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("is_platform_admin", sa.Boolean(), nullable=False),
        sa.Column("email_verified_at", TS, nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False),
        sa.Column("mfa_secret_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("mfa_pending_secret_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("mfa_last_used_step", sa.BigInteger(), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False),
        sa.Column("lockout_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", TS, nullable=True),
        sa.Column("last_login_at", TS, nullable=True),
        sa.Column("password_changed_at", TS, nullable=False),
        sa.Column("token_version", sa.Integer(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'disabled', 'deleted')", name=op.f("ck_users_status")
        ),
        sa.CheckConstraint(
            "NOT mfa_enabled OR mfa_secret_encrypted IS NOT NULL", name=op.f("ck_users_mfa_secret")
        ),
        sa.CheckConstraint("email = lower(email)", name=op.f("ck_users_email_lowercase")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_table(
        "service_accounts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("workflow_key", sa.String(length=64), nullable=False),
        sa.Column("key_prefix", sa.String(length=12), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("scopes", sa.ARRAY(sa.String(length=64)), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("disabled_reason", sa.String(length=200), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_used_at", TS, nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_service_accounts")),
        sa.UniqueConstraint("key_prefix", name=op.f("uq_service_accounts_key_prefix")),
        sa.UniqueConstraint("name", name=op.f("uq_service_accounts_name")),
        sa.UniqueConstraint("workflow_key", name=op.f("uq_service_accounts_workflow_key")),
    )
    op.create_table(
        "audit_chain_heads",
        sa.Column("chain_key", sa.Uuid(), nullable=False),
        sa.Column("last_seq", sa.BigInteger(), nullable=False),
        sa.Column("last_hash", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("chain_key", name=op.f("pk_audit_chain_heads")),
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("chain_key", sa.Uuid(), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=True),
        sa.Column("occurred_at", TS, nullable=False),
        sa.Column("actor_type", sa.String(length=20), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=40), nullable=True),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("result", sa.String(length=10), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=False),
        sa.Column("canonical", sa.Text(), nullable=False),
        sa.Column("prev_hash", sa.LargeBinary(), nullable=False),
        sa.Column("hash", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint(
            "actor_type IN ('user', 'api_key', 'service', 'system', 'anonymous')",
            name=op.f("ck_audit_logs_actor_type"),
        ),
        sa.CheckConstraint(
            "result IN ('success', 'failure', 'denied')", name=op.f("ck_audit_logs_result")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_logs")),
        sa.UniqueConstraint("chain_key", "seq", name=op.f("uq_audit_logs_chain_key")),
    )
    op.create_index("ix_audit_logs_org_action", "audit_logs", ["org_id", "action"])
    op.create_index("ix_audit_logs_org_actor", "audit_logs", ["org_id", "actor_id"])
    op.create_index("ix_audit_logs_org_occurred", "audit_logs", ["org_id", "occurred_at"])
    op.create_table(
        "outbox_messages",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("task", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("available_at", TS, nullable=False),
        sa.Column("dispatched_at", TS, nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_outbox_messages")),
    )
    op.create_index(
        "ix_outbox_messages_pending",
        "outbox_messages",
        ["available_at"],
        postgresql_where=sa.text("dispatched_at IS NULL"),
    )
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("key_prefix", sa.String(length=12), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("scopes", sa.ARRAY(sa.String(length=64)), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=True),
        sa.Column("last_used_at", TS, nullable=True),
        sa.Column("revoked_at", TS, nullable=True),
        sa.CheckConstraint(ROLE_CHECK, name=op.f("ck_api_keys_role")),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_api_keys_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_api_keys_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_keys")),
        sa.UniqueConstraint("key_prefix", name=op.f("uq_api_keys_key_prefix")),
    )
    op.create_index(op.f("ix_api_keys_org_id"), "api_keys", ["org_id"])
    op.create_table(
        "invitations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=True),
        sa.Column("invited_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("accepted_at", TS, nullable=True),
        sa.Column("revoked_at", TS, nullable=True),
        sa.CheckConstraint(ROLE_CHECK, name=op.f("ck_invitations_role")),
        sa.ForeignKeyConstraint(
            ["invited_by"],
            ["users.id"],
            name=op.f("fk_invitations_invited_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_invitations_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_invitations")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_invitations_token_hash")),
    )
    op.create_index(
        "uq_invitations_pending_email",
        "invitations",
        ["org_id", "email"],
        unique=True,
        postgresql_where=sa.text("accepted_at IS NULL AND revoked_at IS NULL"),
    )
    op.create_table(
        "memberships",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("invited_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint(ROLE_CHECK, name=op.f("ck_memberships_role")),
        sa.ForeignKeyConstraint(
            ["invited_by"],
            ["users.id"],
            name=op.f("fk_memberships_invited_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_memberships_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_memberships_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_memberships")),
        sa.UniqueConstraint("org_id", "user_id", name=op.f("uq_memberships_org_id")),
    )
    op.create_index(op.f("ix_memberships_user_id"), "memberships", ["user_id"])
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("used_at", TS, nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mfa_recovery_codes_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mfa_recovery_codes")),
        sa.UniqueConstraint("user_id", "code_hash", name=op.f("uq_mfa_recovery_codes_user_id")),
    )
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS, nullable=True),
        sa.Column("requested_ip", sa.String(length=45), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_password_reset_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_password_reset_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_password_reset_tokens_token_hash")),
    )
    op.create_index(op.f("ix_password_reset_tokens_user_id"), "password_reset_tokens", ["user_id"])
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_used_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("revoked_at", TS, nullable=True),
        sa.Column("revoke_reason", sa.String(length=64), nullable=True),
        sa.Column("ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.Column("mfa_verified", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_user_sessions_org_id_organizations"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_sessions")),
    )
    op.create_index(op.f("ix_user_sessions_user_id"), "user_sessions", ["user_id"])
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("issued_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS, nullable=True),
        sa.Column("replaced_by_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["user_sessions.id"],
            name=op.f("fk_refresh_tokens_session_id_user_sessions"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_refresh_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_refresh_tokens_token_hash")),
    )
    op.create_index(op.f("ix_refresh_tokens_session_id"), "refresh_tokens", ["session_id"])


_CONTEXT_FUNCTIONS = """
CREATE OR REPLACE FUNCTION nf_current_org() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT NULLIF(current_setting('app.current_org_id', true), '')::uuid $$;

CREATE OR REPLACE FUNCTION nf_current_user() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT NULLIF(current_setting('app.current_user_id', true), '')::uuid $$;

CREATE OR REPLACE FUNCTION nf_auth_context() RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT COALESCE(current_setting('app.auth_context', true), '') = 'on' $$;
"""

_AUDIT_FUNCTIONS = """
CREATE OR REPLACE FUNCTION nf_append_audit(
    p_id uuid, p_org_id uuid, p_occurred_at timestamptz, p_actor_type text, p_actor_id uuid,
    p_action text, p_resource_type text, p_resource_id text, p_result text, p_ip text,
    p_user_agent text, p_request_id text, p_metadata jsonb, p_canonical text
) RETURNS bigint
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
DECLARE
    v_chain uuid := COALESCE(p_org_id, '00000000-0000-0000-0000-000000000000'::uuid);
    v_seq bigint;
    v_prev bytea;
    v_hash bytea;
BEGIN
    IF p_org_id IS NOT NULL AND p_org_id IS DISTINCT FROM public.nf_current_org() THEN
        RAISE EXCEPTION 'audit event tenant does not match the tenant context'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF position(p_id::text IN p_canonical) = 0 THEN
        RAISE EXCEPTION 'canonical form does not describe this audit event';
    END IF;
    INSERT INTO public.audit_chain_heads (chain_key, last_seq, last_hash)
        VALUES (v_chain, 0, decode(repeat('00', 32), 'hex'))
        ON CONFLICT (chain_key) DO NOTHING;
    SELECT last_seq, last_hash INTO v_seq, v_prev
        FROM public.audit_chain_heads WHERE chain_key = v_chain FOR UPDATE;
    v_seq := v_seq + 1;
    v_hash := sha256(v_prev || convert_to(p_canonical, 'UTF8'));
    INSERT INTO public.audit_logs (
        id, chain_key, seq, org_id, occurred_at, actor_type, actor_id, action, resource_type,
        resource_id, result, ip, user_agent, request_id, metadata, canonical, prev_hash, hash
    ) VALUES (
        p_id, v_chain, v_seq, p_org_id, p_occurred_at, p_actor_type, p_actor_id, p_action,
        p_resource_type, p_resource_id, p_result, p_ip, p_user_agent, p_request_id,
        p_metadata, p_canonical, v_prev, v_hash
    );
    UPDATE public.audit_chain_heads SET last_seq = v_seq, last_hash = v_hash
        WHERE chain_key = v_chain;
    RETURN v_seq;
END;
$$;

CREATE OR REPLACE FUNCTION nf_audit_guard() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('nexusflow.audit_purge', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_logs is append-only (% denied)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION nf_audit_guard();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION nf_audit_guard();

CREATE OR REPLACE FUNCTION nf_purge_audit_logs(p_before timestamptz) RETURNS bigint
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
DECLARE
    v_count bigint;
BEGIN
    PERFORM set_config('nexusflow.audit_purge', 'on', true);
    DELETE FROM public.audit_logs WHERE occurred_at < p_before;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    PERFORM set_config('nexusflow.audit_purge', 'off', true);
    RETURN v_count;
END;
$$;
"""

_APPEND_SIGNATURE = (
    "nf_append_audit(uuid, uuid, timestamptz, text, uuid, text, text, text, text, text, "
    "text, text, jsonb, text)"
)
_USER_SCOPED_TABLES = (
    "user_sessions",
    "refresh_tokens",
    "password_reset_tokens",
    "mfa_recovery_codes",
)
_USERS_UPDATABLE_COLUMNS = (
    "email, password_hash, full_name, status, email_verified_at, mfa_enabled, "
    "mfa_secret_encrypted, mfa_pending_secret_encrypted, mfa_last_used_step, "
    "failed_login_attempts, lockout_count, locked_until, last_login_at, password_changed_at, "
    "token_version, updated_at"
)


def _create_security() -> None:
    role = app_role()
    statements: list[str] = [
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
        f"GRANT USAGE ON SCHEMA public TO {role}",
        *split_sql(_CONTEXT_FUNCTIONS),
        *split_sql(_AUDIT_FUNCTIONS),
        f"REVOKE ALL ON FUNCTION {_APPEND_SIGNATURE} FROM PUBLIC",
        f"GRANT EXECUTE ON FUNCTION {_APPEND_SIGNATURE} TO {role}",
        "REVOKE ALL ON FUNCTION nf_purge_audit_logs(timestamptz) FROM PUBLIC",
        # organizations: tenant-scoped, readable by members (org switcher) and auth flows
        *enable_rls("organizations"),
        (
            "CREATE POLICY organizations_tenant_isolation ON organizations "
            "USING (id = nf_current_org()) WITH CHECK (id = nf_current_org())"
        ),
        (
            "CREATE POLICY organizations_member_read ON organizations FOR SELECT USING ("
            "nf_auth_context() OR id IN (SELECT org_id FROM memberships "
            "WHERE user_id = nf_current_user()))"
        ),
        grant("organizations", "SELECT, INSERT, UPDATE, DELETE", role),
        # users: a user sees themself; org members see each other; auth flows look up by email
        *enable_rls("users"),
        (
            "CREATE POLICY users_self ON users "
            "USING (id = nf_current_user() OR nf_auth_context()) "
            "WITH CHECK (id = nf_current_user() OR nf_auth_context())"
        ),
        (
            "CREATE POLICY users_org_members_read ON users FOR SELECT USING ("
            "id IN (SELECT user_id FROM memberships WHERE org_id = nf_current_org()))"
        ),
        grant("users", "SELECT, INSERT", role),
        f"GRANT UPDATE ({_USERS_UPDATABLE_COLUMNS}) ON users TO {role}",
        # memberships / invitations / api keys: tenant isolation + narrow auth-time reads
        *enable_rls("memberships"),
        tenant_policy("memberships"),
        (
            "CREATE POLICY memberships_self_read ON memberships FOR SELECT "
            "USING (user_id = nf_current_user() OR nf_auth_context())"
        ),
        grant("memberships", "SELECT, INSERT, UPDATE, DELETE", role),
        *enable_rls("invitations"),
        tenant_policy("invitations"),
        "CREATE POLICY invitations_auth_read ON invitations FOR SELECT USING (nf_auth_context())",
        grant("invitations", "SELECT, INSERT, UPDATE", role),
        *enable_rls("api_keys"),
        tenant_policy("api_keys"),
        "CREATE POLICY api_keys_auth_read ON api_keys FOR SELECT USING (nf_auth_context())",
        grant("api_keys", "SELECT, INSERT, UPDATE", role),
        # platform service accounts: only reachable in authentication context
        *enable_rls("service_accounts"),
        (
            "CREATE POLICY service_accounts_auth ON service_accounts "
            "USING (nf_auth_context()) WITH CHECK (nf_auth_context())"
        ),
        grant("service_accounts", "SELECT, INSERT, UPDATE", role),
        # audit: tenants read their own chain; writes only through nf_append_audit
        "ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY",
        (
            "CREATE POLICY audit_logs_tenant_read ON audit_logs FOR SELECT "
            "USING (org_id = nf_current_org())"
        ),
        grant("audit_logs", "SELECT", role),
        "ALTER TABLE audit_chain_heads ENABLE ROW LEVEL SECURITY",
        # outbox holds identifiers only (no tenant content) and is drained by the relay
        grant("outbox_messages", "SELECT, INSERT, UPDATE, DELETE", role),
    ]
    for table in _USER_SCOPED_TABLES:
        statements.extend(enable_rls(table))
        statements.append(
            f"CREATE POLICY {table}_owner ON {table} "
            "USING (user_id = nf_current_user() OR nf_auth_context()) "
            "WITH CHECK (user_id = nf_current_user() OR nf_auth_context())"
        )
        statements.append(grant(table, "SELECT, INSERT, UPDATE, DELETE", role))
    for statement in statements:
        op.execute(statement)


def downgrade() -> None:
    for table in (
        "refresh_tokens",
        "user_sessions",
        "password_reset_tokens",
        "mfa_recovery_codes",
        "memberships",
        "invitations",
        "api_keys",
        "outbox_messages",
        "audit_logs",
        "audit_chain_heads",
        "service_accounts",
        "users",
        "organizations",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    op.execute(f"DROP FUNCTION IF EXISTS {_APPEND_SIGNATURE}")
    op.execute("DROP FUNCTION IF EXISTS nf_purge_audit_logs(timestamptz)")
    op.execute("DROP FUNCTION IF EXISTS nf_audit_guard()")
    op.execute("DROP FUNCTION IF EXISTS nf_auth_context()")
    op.execute("DROP FUNCTION IF EXISTS nf_current_user()")
    op.execute("DROP FUNCTION IF EXISTS nf_current_org()")

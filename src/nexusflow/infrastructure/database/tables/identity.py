"""Tables for identity, tenancy, audit and the transactional outbox."""

from __future__ import annotations

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB

from nexusflow.domain.audit.model import ActorType, AuditResult
from nexusflow.domain.authorization.roles import Role
from nexusflow.domain.identity.model import UserStatus
from nexusflow.domain.organizations.model import OrganizationStatus
from nexusflow.domain.shared.outbox import TaskName
from nexusflow.infrastructure.database.metadata import enum_check, metadata
from nexusflow.infrastructure.database.types import StrEnumType

TS = DateTime(timezone=True)

organizations = Table(
    "organizations",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("name", String(120), nullable=False),
    Column("slug", String(63), nullable=False),
    Column("status", StrEnumType(OrganizationStatus, 20), nullable=False),
    Column("settings", JSONB, nullable=False),
    Column("deletion_requested_at", TS),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    UniqueConstraint("slug"),
    enum_check("status", OrganizationStatus),
    CheckConstraint("slug ~ '^[a-z0-9-]{1,63}$'", name="slug_format"),
)

users = Table(
    "users",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("email", String(254), nullable=False),
    Column("password_hash", String(255), nullable=False),
    Column("full_name", String(120), nullable=False),
    Column("status", StrEnumType(UserStatus, 20), nullable=False),
    Column("is_platform_admin", Boolean, nullable=False),
    Column("email_verified_at", TS),
    Column("mfa_enabled", Boolean, nullable=False),
    Column("mfa_secret_encrypted", LargeBinary),
    Column("mfa_pending_secret_encrypted", LargeBinary),
    Column("mfa_last_used_step", BigInteger),
    Column("failed_login_attempts", Integer, nullable=False),
    Column("lockout_count", Integer, nullable=False),
    Column("locked_until", TS),
    Column("last_login_at", TS),
    Column("password_changed_at", TS, nullable=False),
    Column("token_version", Integer, nullable=False),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    UniqueConstraint("email"),
    enum_check("status", UserStatus),
    CheckConstraint("email = lower(email)", name="email_lowercase"),
    CheckConstraint("NOT mfa_enabled OR mfa_secret_encrypted IS NOT NULL", name="mfa_secret"),
)

user_sessions = Table(
    "user_sessions",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("user_id", Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("org_id", Uuid, ForeignKey("organizations.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("last_used_at", TS, nullable=False),
    Column("expires_at", TS, nullable=False),
    Column("revoked_at", TS),
    Column("revoke_reason", String(64)),
    Column("ip", String(45)),
    Column("user_agent", String(256)),
    Column("mfa_verified", Boolean, nullable=False),
)

refresh_tokens = Table(
    "refresh_tokens",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column(
        "session_id",
        Uuid,
        ForeignKey("user_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    ),
    Column("user_id", Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("token_hash", String(64), nullable=False),
    Column("issued_at", TS, nullable=False),
    Column("expires_at", TS, nullable=False),
    Column("used_at", TS),
    Column("replaced_by_id", Uuid),
    UniqueConstraint("token_hash"),
)

password_reset_tokens = Table(
    "password_reset_tokens",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("user_id", Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("token_hash", String(64)),
    Column("created_at", TS, nullable=False),
    Column("expires_at", TS, nullable=False),
    Column("used_at", TS),
    Column("requested_ip", String(45)),
    UniqueConstraint("token_hash"),
)

# Pending self-service sign-ups: the address only, until its owner opens the
# link (auth context only; purged by the identity retention).
signup_requests = Table(
    "signup_requests",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("email", String(254), nullable=False),
    Column("token_hash", String(64)),
    Column("created_at", TS, nullable=False),
    Column("expires_at", TS, nullable=False),
    Column("used_at", TS),
    Column("requested_ip", String(45)),
    Column("operator_issued", Boolean, nullable=False),
    UniqueConstraint("token_hash"),
    CheckConstraint("email = lower(email)", name="email_lowercase"),
    Index("ix_signup_requests_email", "email"),
    Index("ix_signup_requests_expires_at", "expires_at"),
)

mfa_recovery_codes = Table(
    "mfa_recovery_codes",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("user_id", Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("code_hash", String(64), nullable=False),
    Column("created_at", TS, nullable=False),
    Column("used_at", TS),
    UniqueConstraint("user_id", "code_hash"),
)

memberships = Table(
    "memberships",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("org_id", Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
    Column("user_id", Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("role", StrEnumType(Role, 20), nullable=False),
    Column("invited_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    UniqueConstraint("org_id", "user_id"),
    enum_check("role", Role),
)

invitations = Table(
    "invitations",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("org_id", Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
    Column("email", String(254), nullable=False),
    Column("role", StrEnumType(Role, 20), nullable=False),
    Column("token_hash", String(64)),
    Column("invited_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("expires_at", TS, nullable=False),
    Column("accepted_at", TS),
    Column("revoked_at", TS),
    UniqueConstraint("token_hash"),
    enum_check("role", Role),
    Index(
        "uq_invitations_pending_email",
        "org_id",
        "email",
        unique=True,
        postgresql_where=text("accepted_at IS NULL AND revoked_at IS NULL"),
    ),
)

api_keys = Table(
    "api_keys",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column(
        "org_id",
        Uuid,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    ),
    Column("name", String(100), nullable=False),
    Column("key_prefix", String(12), nullable=False),
    Column("key_hash", String(64), nullable=False),
    Column("role", StrEnumType(Role, 20), nullable=False),
    Column("scopes", ARRAY(String(64)), nullable=False),
    Column("created_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("expires_at", TS),
    Column("last_used_at", TS),
    Column("revoked_at", TS),
    UniqueConstraint("key_prefix"),
    enum_check("role", Role),
)

service_accounts = Table(
    "service_accounts",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("name", String(100), nullable=False),
    Column("workflow_key", String(64), nullable=False),
    Column("key_prefix", String(12), nullable=False),
    Column("key_hash", String(64), nullable=False),
    Column("scopes", ARRAY(String(64)), nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("disabled_reason", String(200)),
    Column("created_at", TS, nullable=False),
    Column("last_used_at", TS),
    UniqueConstraint("name"),
    UniqueConstraint("workflow_key"),
    UniqueConstraint("key_prefix"),
)

audit_logs = Table(
    "audit_logs",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("chain_key", Uuid, nullable=False),
    Column("seq", BigInteger, nullable=False),
    Column("org_id", Uuid),
    Column("occurred_at", TS, nullable=False),
    Column("actor_type", String(20), nullable=False),
    Column("actor_id", Uuid),
    Column("action", String(64), nullable=False),
    Column("resource_type", String(40)),
    Column("resource_id", String(64)),
    Column("result", String(10), nullable=False),
    Column("ip", String(45)),
    Column("user_agent", String(256)),
    Column("request_id", String(64)),
    Column("metadata", JSONB, nullable=False),
    Column("canonical", Text, nullable=False),
    Column("prev_hash", LargeBinary, nullable=False),
    Column("hash", LargeBinary, nullable=False),
    UniqueConstraint("chain_key", "seq"),
    enum_check("actor_type", ActorType),
    enum_check("result", AuditResult),
    Index("ix_audit_logs_org_occurred", "org_id", "occurred_at"),
    Index("ix_audit_logs_org_action", "org_id", "action"),
    Index("ix_audit_logs_org_actor", "org_id", "actor_id"),
)

audit_chain_heads = Table(
    "audit_chain_heads",
    metadata,
    Column("chain_key", Uuid, primary_key=True),
    Column("last_seq", BigInteger, nullable=False),
    Column("last_hash", LargeBinary, nullable=False),
)

outbox_messages = Table(
    "outbox_messages",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("task", StrEnumType(TaskName, 64), nullable=False),
    Column("payload", JSONB, nullable=False),
    Column("org_id", Uuid),
    Column("created_at", TS, nullable=False),
    Column("available_at", TS, nullable=False),
    Column("dispatched_at", TS),
    Column("attempts", Integer, nullable=False),
    Column("last_error", String(500)),
    Column("correlation_id", String(64)),
    Index(
        "ix_outbox_messages_pending",
        "available_at",
        postgresql_where=text("dispatched_at IS NULL"),
    ),
)


# Migration 0007 (review E-1): the organization purge sets org_id to NULL here.
Index(
    "ix_user_sessions_org",
    user_sessions.c.org_id,
    postgresql_where=text("org_id IS NOT NULL"),
)

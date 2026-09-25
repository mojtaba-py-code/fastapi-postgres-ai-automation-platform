"""Identity aggregates: users, sessions, credentials.

Entities are plain dataclasses (persistence is mapped imperatively in the
infrastructure layer). State transitions live in methods so invariants are
enforced in one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID

from nexusflow.domain.authorization.principal import ServiceScope
from nexusflow.domain.authorization.roles import Permission, Role


class UserStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    DELETED = "deleted"


@dataclass(eq=False, kw_only=True)
class User:
    id: UUID
    email: str
    password_hash: str
    full_name: str
    status: UserStatus = UserStatus.ACTIVE
    is_platform_admin: bool = False
    email_verified_at: datetime | None = None
    mfa_enabled: bool = False
    mfa_secret_encrypted: bytes | None = None
    mfa_pending_secret_encrypted: bytes | None = None
    mfa_last_used_step: int | None = None
    failed_login_attempts: int = 0
    lockout_count: int = 0
    locked_until: datetime | None = None
    last_login_at: datetime | None = None
    password_changed_at: datetime
    token_version: int = 0
    created_at: datetime
    updated_at: datetime

    @property
    def is_active(self) -> bool:
        return self.status is UserStatus.ACTIVE

    def is_locked(self, now: datetime) -> bool:
        return self.locked_until is not None and self.locked_until > now

    def register_failed_login(
        self, now: datetime, *, threshold: int, base_seconds: int, max_seconds: int
    ) -> bool:
        """Record a failure; returns True when this failure triggers a lockout.

        Lockout duration doubles with each consecutive lockout (exponential
        back-off) up to ``max_seconds``.
        """
        self.failed_login_attempts += 1
        self.updated_at = now
        if self.failed_login_attempts < threshold:
            return False
        duration = min(base_seconds * (2**self.lockout_count), max_seconds)
        self.locked_until = now + timedelta(seconds=duration)
        self.lockout_count += 1
        self.failed_login_attempts = 0
        return True

    def register_successful_login(self, now: datetime) -> None:
        self.failed_login_attempts = 0
        self.lockout_count = 0
        self.locked_until = None
        self.last_login_at = now
        self.updated_at = now

    def change_password_hash(self, password_hash: str, now: datetime) -> None:
        """New password: bump ``token_version`` so every issued token dies."""
        self.password_hash = password_hash
        self.password_changed_at = now
        self.token_version += 1
        self.failed_login_attempts = 0
        self.locked_until = None
        self.updated_at = now

    def revoke_all_tokens(self, now: datetime) -> None:
        self.token_version += 1
        self.updated_at = now

    def anonymize(self, now: datetime) -> None:
        """GDPR-style erasure: keep the row for referential integrity only."""
        self.email = f"deleted-{self.id}@invalid"
        self.full_name = "Deleted user"
        self.password_hash = "!"  # noqa: S105 - an unusable hash: can never verify  # nosec B105
        self.mfa_enabled = False
        self.mfa_secret_encrypted = None
        self.mfa_pending_secret_encrypted = None
        self.status = UserStatus.DELETED
        self.token_version += 1
        self.updated_at = now


@dataclass(eq=False, kw_only=True)
class UserSession:
    """A login session; also the refresh-token family used for reuse detection."""

    id: UUID
    user_id: UUID
    org_id: UUID | None
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    revoke_reason: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    mfa_verified: bool = False

    def is_valid(self, now: datetime) -> bool:
        return self.revoked_at is None and self.expires_at > now

    def revoke(self, now: datetime, reason: str) -> None:
        if self.revoked_at is None:
            self.revoked_at = now
            self.revoke_reason = reason


@dataclass(eq=False, kw_only=True)
class RefreshToken:
    id: UUID
    session_id: UUID
    user_id: UUID
    token_hash: str
    issued_at: datetime
    expires_at: datetime
    used_at: datetime | None = None
    replaced_by_id: UUID | None = None


@dataclass(eq=False, kw_only=True)
class PasswordResetToken:
    id: UUID
    user_id: UUID
    token_hash: str | None
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None
    requested_ip: str | None = None

    def is_usable(self, now: datetime) -> bool:
        return self.used_at is None and self.token_hash is not None and self.expires_at > now


@dataclass(eq=False, kw_only=True)
class MfaRecoveryCode:
    id: UUID
    user_id: UUID
    code_hash: str
    created_at: datetime
    used_at: datetime | None = None


@dataclass(eq=False, kw_only=True)
class ApiKey:
    """Tenant-scoped machine credential; acts with an explicit permission subset."""

    id: UUID
    org_id: UUID
    name: str
    key_prefix: str
    key_hash: str
    role: Role
    scopes: list[str] = field(default_factory=list)
    created_by: UUID | None
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None

    def is_usable(self, now: datetime) -> bool:
        if self.revoked_at is not None:
            return False
        return self.expires_at is None or self.expires_at > now

    def effective_permissions(
        self, role_permissions: frozenset[Permission]
    ) -> frozenset[Permission]:
        requested = {Permission(scope) for scope in self.scopes if scope in Permission}
        return frozenset(requested) & role_permissions


@dataclass(eq=False, kw_only=True)
class ServiceAccount:
    """Platform-level credential for one n8n workflow (per-workflow kill switch)."""

    id: UUID
    name: str
    workflow_key: str
    key_prefix: str
    key_hash: str
    scopes: list[str] = field(default_factory=list)
    enabled: bool = True
    disabled_reason: str | None = None
    created_at: datetime
    last_used_at: datetime | None = None

    def service_scopes(self) -> frozenset[ServiceScope]:
        return frozenset(ServiceScope(s) for s in self.scopes if s in ServiceScope)

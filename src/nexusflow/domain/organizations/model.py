"""Organizations (tenants), memberships and invitations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from nexusflow.domain.authorization.roles import Role


class OrganizationStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING_DELETION = "pending_deletion"


class OrganizationSettings(BaseModel):
    """Tenant-level policy switches (validated; unknown keys rejected)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    require_mfa: bool = False
    allowed_source_domains: list[str] | None = Field(default=None, max_length=200)
    ai_external_processing: bool = False
    automation_frozen: bool = False
    default_retention_days: int = Field(default=180, ge=7, le=3650)

    @field_validator("allowed_source_domains")
    @classmethod
    def _normalize_domains(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        cleaned = sorted({d.strip().lower().rstrip(".") for d in value if d.strip()})
        for domain in cleaned:
            if len(domain) > 253 or "/" in domain or ":" in domain or " " in domain:
                raise ValueError(f"invalid domain: {domain!r}")
        return cleaned


@dataclass(eq=False, kw_only=True)
class Organization:
    id: UUID
    name: str
    slug: str
    status: OrganizationStatus = OrganizationStatus.ACTIVE
    settings: dict[str, Any] = field(default_factory=dict)
    deletion_requested_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    @property
    def policy(self) -> OrganizationSettings:
        return OrganizationSettings.model_validate(self.settings)

    @property
    def is_active(self) -> bool:
        return self.status is OrganizationStatus.ACTIVE

    def update_policy(self, policy: OrganizationSettings, now: datetime) -> None:
        self.settings = policy.model_dump(mode="json")
        self.updated_at = now


@dataclass(eq=False, kw_only=True)
class Membership:
    id: UUID
    org_id: UUID
    user_id: UUID
    role: Role
    invited_by: UUID | None = None
    created_at: datetime
    updated_at: datetime


@dataclass(eq=False, kw_only=True)
class Invitation:
    id: UUID
    org_id: UUID
    email: str
    role: Role
    token_hash: str | None
    invited_by: UUID | None
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None = None
    revoked_at: datetime | None = None

    def is_pending(self, now: datetime) -> bool:
        return self.accepted_at is None and self.revoked_at is None and self.expires_at > now


@dataclass(frozen=True, slots=True)
class MembershipView:
    """Read model joining a membership with user profile data."""

    membership_id: UUID
    user_id: UUID
    email: str
    full_name: str
    role: Role
    mfa_enabled: bool
    joined_at: datetime


@dataclass(frozen=True, slots=True)
class OrganizationView:
    org_id: UUID
    name: str
    slug: str
    role: Role
    status: OrganizationStatus

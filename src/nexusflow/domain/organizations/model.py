"""Organizations (tenants), memberships and invitations."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from nexusflow.core.errors import PermissionDeniedError
from nexusflow.domain.authorization.roles import Role


def network_not_allowed(internal_detail: str | None = None) -> PermissionDeniedError:
    """The refusal of the organization's network allowlist (the same everywhere)."""
    return PermissionDeniedError(
        "The organization does not allow access from this network.",
        code="ip_not_allowed",
        internal_detail=internal_detail,
    )


def passkey_required() -> PermissionDeniedError:
    """The refusal of an organization that requires passkeys (the same everywhere)."""
    return PermissionDeniedError(
        "This organization requires signing in with a passkey. Register one "
        "(POST /api/v1/auth/webauthn/register/begin) if you have none, then sign in with it.",
        code="passkey_required",
    )


class OrganizationStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING_DELETION = "pending_deletion"


class OrganizationSettings(BaseModel):
    """Tenant-level policy switches (validated; unknown keys rejected)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    require_mfa: bool = False
    # Members' sessions reach the organization only if they signed in with a
    # passkey (the phishing-resistant second factor) - MFA too, so this covers
    # require_mfa. API keys are not sessions: it does not apply to them.
    require_passkey: bool = False
    # Members reach the organization only through its identity provider (a
    # single sign-on session for it); owners keep a password + MFA way in.
    # Set only through the SSO configuration, never through a settings update.
    sso_required: bool = False
    # Networks (CIDR) the organization's data may be reached from - by its
    # users' sessions and its API keys. Empty or unset: from anywhere.
    allowed_ip_ranges: list[str] | None = Field(default=None, max_length=100)
    allowed_source_domains: list[str] | None = Field(default=None, max_length=200)
    ai_external_processing: bool = False
    automation_frozen: bool = False
    default_retention_days: int = Field(default=180, ge=7, le=3650)

    @field_validator("allowed_ip_ranges")
    @classmethod
    def _normalize_networks(cls, value: list[str] | None) -> list[str] | None:
        if not value:
            return None
        networks = set()
        for raw in value:
            try:
                if "%" in raw:  # an IPv6 zone names a local interface, never a remote client
                    raise ValueError(raw)
                network = ipaddress.ip_network(raw.strip(), strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid network: {raw[:60]!r}") from exc
            mapped = getattr(network.network_address, "ipv4_mapped", None)
            if mapped is not None and network.prefixlen >= 96:
                # Clients are matched as IPv4 (see allows_ip): so are such networks.
                network = ipaddress.ip_network(f"{mapped}/{network.prefixlen - 96}")
            if network.prefixlen == 0:
                raise ValueError("0.0.0.0/0 and ::/0 would allow everyone; leave the list empty")
            networks.add(network)
        return [str(n) for n in sorted(networks, key=lambda n: (n.version, n))]

    def allows_ip(self, ip: str | None) -> bool:
        """Whether ``ip`` may reach the organization's data (fails closed)."""
        if not self.allowed_ip_ranges:
            return True
        if not ip:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return any(address in ipaddress.ip_network(net) for net in self.allowed_ip_ranges)

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

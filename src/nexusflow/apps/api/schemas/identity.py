"""Schemas for authentication, users, organizations, API keys and audit."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import EmailStr, Field

from nexusflow.apps.api.schemas.common import RequestModel, ResponseModel
from nexusflow.domain.authorization.roles import Permission, Role
from nexusflow.domain.organizations.model import OrganizationSettings, OrganizationStatus

# Passwords are bounded to keep Argon2 work per request bounded (DoS guard) and
# excluded from repr so they can never end up in logs via model printing.
Password = Field(min_length=1, max_length=1024, repr=False)
OpaqueToken = Field(min_length=1, max_length=4096, repr=False)


# ------------------------------------------------------------------ auth


class RegisterRequest(RequestModel):
    email: EmailStr = Field(max_length=254)
    password: str = Password
    full_name: str = Field(min_length=1, max_length=120)
    organization_name: str | None = Field(default=None, max_length=120)
    invitation_token: str | None = Field(default=None, max_length=256, repr=False)


class LoginRequest(RequestModel):
    email: EmailStr = Field(max_length=254)
    password: str = Password
    organization_id: UUID | None = None


class TokenResponse(ResponseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    expires_in: int
    refresh_token: str
    organization_id: UUID | None


class MfaChallengeResponse(ResponseModel):
    mfa_required: Literal[True] = True
    mfa_token: str
    expires_in: int


class MfaVerifyRequest(RequestModel):
    mfa_token: str = OpaqueToken
    code: str = Field(min_length=6, max_length=32, repr=False)


class RefreshRequest(RequestModel):
    refresh_token: str = Field(min_length=1, max_length=256, repr=False)


class PasswordChangeRequest(RequestModel):
    current_password: str = Password
    new_password: str = Password


class PasswordResetRequest(RequestModel):
    email: EmailStr = Field(max_length=254)


class PasswordResetConfirmRequest(RequestModel):
    token: str = Field(min_length=1, max_length=256, repr=False)
    new_password: str = Password


class PasswordConfirmation(RequestModel):
    password: str = Password


class MfaEnrollResponse(ResponseModel):
    secret: str
    provisioning_uri: str


class MfaCodeRequest(RequestModel):
    code: str = Field(min_length=6, max_length=32, repr=False)


class MfaRecoveryCodesResponse(ResponseModel):
    recovery_codes: list[str]


class MfaDisableRequest(RequestModel):
    password: str = Password
    code: str = Field(min_length=6, max_length=32, repr=False)


class SwitchOrganizationRequest(RequestModel):
    organization_id: UUID


class AcceptInvitationRequest(RequestModel):
    token: str = Field(min_length=1, max_length=256, repr=False)


# ----------------------------------------------------------------- users


class SessionResponse(ResponseModel):
    id: UUID
    current: bool = Field(description="The session this request was made with.")
    device: str = Field(description='A coarse client description, e.g. "Firefox on Windows".')
    ip: str | None
    mfa_verified: bool
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime


class UserResponse(ResponseModel):
    id: UUID
    email: str
    full_name: str
    mfa_enabled: bool
    created_at: datetime
    last_login_at: datetime | None


class UpdateProfileRequest(RequestModel):
    full_name: str = Field(min_length=1, max_length=120)


# --------------------------------------------------------- organizations


class OrganizationSummary(ResponseModel):
    id: UUID = Field(validation_alias="org_id")
    name: str
    slug: str
    role: Role
    status: OrganizationStatus


class OrganizationResponse(ResponseModel):
    id: UUID
    name: str
    slug: str
    status: OrganizationStatus
    settings: OrganizationSettings = Field(validation_alias="policy")
    created_at: datetime


class OrganizationSettingsPatch(RequestModel):
    """Partial settings update: only the fields sent are changed.

    ``automation_frozen`` is deliberately absent - use the audited
    automation-freeze endpoint, which requires a reason.
    """

    require_mfa: bool | None = None
    # Networks (CIDR, IPv4 or IPv6) the organization may be reached from, by
    # members and API keys alike; null or [] allows every network. A change
    # that would exclude the caller's own address is refused.
    allowed_ip_ranges: list[str] | None = Field(default=None, max_length=100)
    allowed_source_domains: list[str] | None = Field(default=None, max_length=200)
    ai_external_processing: bool | None = None
    default_retention_days: int | None = Field(default=None, ge=7, le=3650)


class UpdateOrganizationRequest(RequestModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    settings: OrganizationSettingsPatch | None = None


class OrganizationDeletionRequest(RequestModel):
    confirm_slug: str = Field(min_length=1, max_length=63)


class AutomationFreezeRequest(RequestModel):
    frozen: bool
    reason: str = Field(min_length=3, max_length=200)


class MemberResponse(ResponseModel):
    membership_id: UUID
    user_id: UUID
    email: str
    full_name: str
    role: Role
    mfa_enabled: bool
    joined_at: datetime


class ChangeRoleRequest(RequestModel):
    role: Role


class InviteRequest(RequestModel):
    email: EmailStr = Field(max_length=254)
    role: Role


class InvitationResponse(ResponseModel):
    id: UUID
    email: str
    role: Role
    created_at: datetime
    expires_at: datetime


# -------------------------------------------------------------- api keys


class CreateApiKeyRequest(RequestModel):
    name: str = Field(min_length=1, max_length=100)
    role: Role
    scopes: list[Permission] = Field(min_length=1, max_length=50)
    expires_in_days: int = Field(default=90, ge=1, le=365)


class ApiKeyResponse(ResponseModel):
    id: UUID
    name: str
    prefix: str = Field(validation_alias="key_prefix")
    role: Role
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None


class ApiKeyCreatedResponse(ApiKeyResponse):
    token: str = Field(description="Shown exactly once. Store it in a secrets manager.")


# ----------------------------------------------------------------- audit


class AuditEntryResponse(ResponseModel):
    id: UUID
    seq: int
    occurred_at: datetime
    actor_type: str
    actor_id: UUID | None
    action: str
    resource_type: str | None
    resource_id: str | None
    result: str
    ip: str | None
    user_agent: str | None
    request_id: str | None
    metadata: dict[str, Any]


class AuditVerificationResponse(ResponseModel):
    ok: bool
    checked: int
    first_invalid_seq: int | None
    reason: str | None
    # False: the check stopped at its bound before the chain's head, and "ok"
    # covers only the entries checked. The daily verification checks it all.
    complete: bool

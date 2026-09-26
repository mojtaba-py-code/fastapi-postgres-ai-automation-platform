"""Schemas for authentication, users, organizations, API keys and audit."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import (
    BeforeValidator,
    EmailStr,
    Field,
    StringConstraints,
    WithJsonSchema,
    model_validator,
)

from nexusflow.apps.api.schemas.common import RequestModel, ResponseModel
from nexusflow.domain.authorization.roles import Permission, Role
from nexusflow.domain.identity.model import MfaMethod
from nexusflow.domain.identity.webauthn import b64url, b64url_decode
from nexusflow.domain.organizations.model import OrganizationSettings, OrganizationStatus

# Passwords are bounded to keep Argon2 work per request bounded (DoS guard) and
# excluded from repr so they can never end up in logs via model printing.
Password = Field(min_length=1, max_length=1024, repr=False)
OpaqueToken = Field(min_length=1, max_length=4096, repr=False)


# ------------------------------------------------------------------ auth


class RegisterRequest(RequestModel):
    email: EmailStr = Field(max_length=254)


class RegistrationStartedResponse(ResponseModel):
    status: Literal["check_email"] = "check_email"
    detail: str = Field(
        default=("If this address can be used, a link to finish the sign-up is on its way to it."),
        description="The same answer for every address: it reveals no account.",
    )


class CompleteRegistrationRequest(RequestModel):
    token: str = Field(min_length=1, max_length=256, repr=False)
    password: str = Password
    full_name: str = Field(min_length=1, max_length=120)
    organization_name: str = Field(min_length=1, max_length=120)


class InvitedRegistrationRequest(RequestModel):
    token: str = Field(min_length=1, max_length=256, repr=False)
    password: str = Password
    full_name: str = Field(min_length=1, max_length=120)


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
    methods: list[Literal["totp", "webauthn", "recovery_code"]] = Field(
        default_factory=list,
        description="How the second factor can be proved: an authenticator app code "
        "(POST /auth/mfa/verify), a passkey (POST /auth/mfa/webauthn/begin, then /verify) "
        "or a recovery code (POST /auth/mfa/verify).",
    )


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


# --------------------------------------------------------------- passkeys
#
# Binary WebAuthn values travel as unpadded base64url, as in the JSON forms of
# WebAuthn Level 3 (PublicKeyCredential.toJSON, parseCreationOptionsFromJSON).
# Each is bounded before it is decoded and decoded strictly.


def _base64url(max_bytes: int) -> Callable[[object], bytes]:
    max_length = -(-max_bytes * 4 // 3)  # characters of unpadded base64url

    def decode(value: object) -> bytes:
        if not isinstance(value, str):
            raise ValueError("must be a base64url string")
        if not value or len(value) > max_length:
            raise ValueError(f"must encode 1 to {max_bytes} bytes")
        data = b64url_decode(value)
        if not data:
            raise ValueError(f"must encode 1 to {max_bytes} bytes")
        return data

    return decode


def _base64url_schema(max_bytes: int) -> WithJsonSchema:
    return WithJsonSchema(
        {
            "type": "string",
            "contentEncoding": "base64url",
            "maxLength": -(-max_bytes * 4 // 3),
        }
    )


ClientDataJson = Annotated[bytes, BeforeValidator(_base64url(4096)), _base64url_schema(4096)]
AttestationObject = Annotated[
    bytes, BeforeValidator(_base64url(64 * 1024)), _base64url_schema(64 * 1024)
]
AuthenticatorData = Annotated[bytes, BeforeValidator(_base64url(4096)), _base64url_schema(4096)]
Signature = Annotated[bytes, BeforeValidator(_base64url(512)), _base64url_schema(512)]
UserHandle = Annotated[bytes, BeforeValidator(_base64url(64)), _base64url_schema(64)]
CredentialId = Annotated[bytes, BeforeValidator(_base64url(1023)), _base64url_schema(1023)]
PublicKeyInfo = Annotated[bytes, BeforeValidator(_base64url(2048)), _base64url_schema(2048)]
Transport = Annotated[str, StringConstraints(pattern=r"^[a-z-]{1,32}$")]


class PasskeyAttestation(RequestModel):
    """``AuthenticatorAttestationResponse`` in its JSON form. Only the client
    data and the attestation object are used; the copies some browsers add
    (``authenticatorData``, ``publicKey``, ``publicKeyAlgorithm``) are accepted,
    bounded, and ignored - everything is read from the attestation object."""

    client_data_json: ClientDataJson = Field(alias="clientDataJSON")
    attestation_object: AttestationObject = Field(alias="attestationObject")
    transports: list[Transport] = Field(default_factory=list, max_length=8)
    authenticator_data: AuthenticatorData | None = Field(default=None, alias="authenticatorData")
    public_key: PublicKeyInfo | None = Field(default=None, alias="publicKey")
    public_key_algorithm: int | None = Field(
        default=None, alias="publicKeyAlgorithm", ge=-65536, le=65535
    )


class PasskeyAssertion(RequestModel):
    """``AuthenticatorAssertionResponse`` in its JSON form."""

    client_data_json: ClientDataJson = Field(alias="clientDataJSON")
    authenticator_data: AuthenticatorData = Field(alias="authenticatorData")
    signature: Signature
    user_handle: UserHandle | None = Field(default=None, alias="userHandle")


class _PasskeyCredential(RequestModel):
    id: str = Field(min_length=1, max_length=1364)
    raw_id: CredentialId = Field(alias="rawId")
    type: Literal["public-key"]
    authenticator_attachment: Literal["platform", "cross-platform"] | None = Field(
        default=None, alias="authenticatorAttachment"
    )
    # No extensions are requested: whatever a client reports is ignored.
    client_extension_results: dict[str, Any] = Field(
        default_factory=dict, alias="clientExtensionResults", max_length=16
    )

    @model_validator(mode="after")
    def _id_is_raw_id(self) -> Self:
        if self.id != b64url(self.raw_id):
            raise ValueError("id must be the base64url form of rawId")
        return self


class PasskeyRegistrationCredential(_PasskeyCredential):
    response: PasskeyAttestation


class PasskeyAssertionCredential(_PasskeyCredential):
    response: PasskeyAssertion


class PasskeyRegistrationRequest(RequestModel):
    name: str | None = Field(
        default=None, max_length=64, description='What to call it, e.g. "Work laptop".'
    )
    credential: PasskeyRegistrationCredential


class PasskeyRenameRequest(RequestModel):
    name: str = Field(min_length=1, max_length=64)


class MfaTokenRequest(RequestModel):
    mfa_token: str = OpaqueToken


class PasskeySignInRequest(RequestModel):
    mfa_token: str = OpaqueToken
    credential: PasskeyAssertionCredential


class _WebAuthnJson(ResponseModel):
    """WebAuthn's own JSON members are camelCase (serialized by alias)."""


class RelyingPartyEntity(_WebAuthnJson):
    id: str
    name: str


class PasskeyUserEntity(_WebAuthnJson):
    id: str = Field(description="A random handle, never the account's ID or e-mail address.")
    name: str
    display_name: str = Field(alias="displayName")


class CredentialParameters(_WebAuthnJson):
    type: Literal["public-key"] = "public-key"
    alg: int


class CredentialDescriptorJson(_WebAuthnJson):
    type: Literal["public-key"] = "public-key"
    id: str
    transports: list[str]


class AuthenticatorSelection(_WebAuthnJson):
    resident_key: Literal["preferred"] = Field(default="preferred", alias="residentKey")
    require_resident_key: Literal[False] = Field(default=False, alias="requireResidentKey")
    user_verification: Literal["required"] = Field(default="required", alias="userVerification")


class PasskeyCreationOptions(_WebAuthnJson):
    """``PublicKeyCredentialCreationOptionsJSON``."""

    rp: RelyingPartyEntity
    user: PasskeyUserEntity
    challenge: str
    pub_key_cred_params: list[CredentialParameters] = Field(alias="pubKeyCredParams")
    timeout: int
    exclude_credentials: list[CredentialDescriptorJson] = Field(alias="excludeCredentials")
    authenticator_selection: AuthenticatorSelection = Field(alias="authenticatorSelection")
    attestation: Literal["none"] = "none"


class PasskeyRequestOptions(_WebAuthnJson):
    """``PublicKeyCredentialRequestOptionsJSON``."""

    challenge: str
    timeout: int
    rp_id: str = Field(alias="rpId")
    allow_credentials: list[CredentialDescriptorJson] = Field(alias="allowCredentials")
    user_verification: Literal["required"] = Field(default="required", alias="userVerification")


class PasskeyCreationOptionsResponse(ResponseModel):
    options: PasskeyCreationOptions = Field(
        description="For navigator.credentials.create({publicKey: "
        "PublicKeyCredential.parseCreationOptionsFromJSON(options)})."
    )
    expires_in: int


class PasskeyRequestOptionsResponse(ResponseModel):
    options: PasskeyRequestOptions = Field(
        description="For navigator.credentials.get({publicKey: "
        "PublicKeyCredential.parseRequestOptionsFromJSON(options)})."
    )
    expires_in: int


class PasskeyResponse(ResponseModel):
    id: UUID
    name: str
    algorithm: str
    transports: list[str]
    backup_eligible: bool = Field(description="The passkey can be synced to other devices.")
    backed_up: bool = Field(description="The passkey is synced (as last reported).")
    created_at: datetime
    last_used_at: datetime | None


class PasskeyRegisteredResponse(ResponseModel):
    passkey: PasskeyResponse
    recovery_codes: list[str] | None = Field(
        description="Only when this passkey turned two-factor authentication on: "
        "single-use recovery codes, shown exactly once."
    )


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
    mfa_method: MfaMethod | None = Field(
        description="The platform's second factor the session passed (webauthn: a passkey); "
        "null for none - or an identity provider's MFA, or a session from before it was recorded."
    )
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
    # Only sessions that signed in with a passkey reach the organization (API
    # keys are not affected). Turning it on needs such a session - otherwise
    # 422 would_lock_you_out.
    require_passkey: bool | None = None
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

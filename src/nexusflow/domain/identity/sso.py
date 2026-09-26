"""Single sign-on with OpenID Connect: one identity provider per organization.

Trust model (docs/SSO.md explains it for administrators)
--------------------------------------------------------
* **The API is a confidential client.** Authorization code flow with PKCE
  (S256), a random ``state`` and ``nonce`` (256 bits each) and a fixed
  ``redirect_uri``. A pending sign-in is stored server-side, single-use, for a
  few minutes; the code verifier is sealed at rest.
* **The flow is bound to the client that started it.** ``start`` returns a
  ``binding`` secret that never travels through a URL; ``callback`` requires
  it. Whoever sees the redirect (``code`` and ``state`` in a URL, a log, a
  Referer) cannot finish the sign-in, and a victim's browser cannot be made
  to finish an attacker's sign-in (login CSRF).
* **An identity provider speaks only for domains its organization owns.** The
  organization proves each allowed e-mail domain with a DNS TXT record (or an
  operator confirms it). Without that, any administrator could run an
  identity provider that asserts someone else's address - and sign in to that
  person's account, or learn whether it exists. With it, the provider holds
  no power the domain owner does not already have (they receive its mail).
* **An identity provider's session is valid for its organization only.** It
  cannot switch organizations, and account-wide actions from it are confined
  to that organization - one tenant's provider never opens another tenant's
  data, whatever it asserts.
* ID tokens are verified strictly: signature against the provider's JWKS with
  an algorithm allowlist (never ``none`` or HMAC), ``iss``, ``aud``/``azp``,
  time claims with a small skew, the ``nonce`` and ``email_verified``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from nexusflow.core.errors import (
    AuthenticationError,
    InvalidInputError,
    NexusFlowError,
    PermanentError,
    PermissionDeniedError,
    PolicyViolationError,
)
from nexusflow.domain.audit.model import AuditAction, AuditResult
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Role
from nexusflow.domain.identity.model import UserSession
from nexusflow.domain.organizations.model import Membership, Organization, network_not_allowed
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.unit_of_work import UnitOfWork
from nexusflow.domain.shared.url_policy import UrlPolicy

# Roles an identity provider may grant on its own (just-in-time or SCIM): never
# owner or admin - administrators are appointed in the application.
JIT_ROLES = frozenset({Role.VIEWER, Role.ANALYST})
# Algorithms accepted for ID token signatures. Never "none", never HMAC: an HMAC
# key would be the client secret or - in the classic confusion attack - a
# public key the attacker also knows.
ID_TOKEN_ALGORITHMS = ("RS256", "PS256", "ES256", "EdDSA")
# RFC 8176 authentication method references that show a second factor or a
# possession-based factor: "mfa" (multiple factors), "mca" (multiple channels),
# "hwk"/"swk" (proof of possession of a hardware / software key), "otp"
# (one-time password) and "sc" (smart card). "pwd", "kba", "pin" and the
# biometric values alone do not count.
STRONG_AMR_VALUES = frozenset({"mfa", "mca", "hwk", "swk", "otp", "sc"})
MAX_ALLOWED_DOMAINS = 20
SCOPES = "openid email profile"
VERIFICATION_RECORD_PREFIX = "_nexusflow-verification"
VERIFICATION_VALUE_PREFIX = "nexusflow-verification="
# Identity providers are reached over HTTPS on the standard port only.
ISSUER_POLICY = UrlPolicy(allow_http=False, allowed_ports=frozenset({443}))

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_PRINTABLE = re.compile(r"^[\x21-\x7e]+$")
_MAX_ISSUER_LENGTH = 512


class SsoProtocolError(PermanentError):
    """The identity provider's answer cannot be accepted (a bad discovery
    document, a refused code exchange, an invalid ID token).

    ``reason`` is a short, fixed code for the audit trail; the caller shows the
    client a generic message only.
    """

    default_code = "sso_failed"
    default_message = "Single sign-on failed."

    def __init__(self, reason: str, *, internal_detail: str | None = None) -> None:
        super().__init__(internal_detail=internal_detail or reason)
        self.reason = reason


@dataclass(eq=False, kw_only=True)
class SsoConnection:
    """An organization's OpenID Connect identity provider.

    ``allowed_domains`` are the e-mail domains its users may have;
    ``verified_domains`` the subset the organization has proved it owns - only
    those are ever accepted. The client secret is sealed (bound to this row)
    and never leaves the service.
    """

    id: UUID
    org_id: UUID
    issuer: str
    client_id: str
    client_secret_ciphertext: bytes
    secret_key_id: str
    allowed_domains: list[str] = field(default_factory=list)
    verified_domains: list[str] = field(default_factory=list)
    default_role: Role = Role.VIEWER
    trust_idp_mfa: bool = False
    created_by: UUID | None = None
    created_at: datetime
    updated_at: datetime

    @property
    def secret_context(self) -> str:
        return client_secret_context(self.org_id, self.id)

    def accepts_domain(self, domain: str) -> bool:
        return domain in self.verified_domains and domain in self.allowed_domains


@dataclass(eq=False, kw_only=True)
class SsoLoginState:
    """A started sign-in, waiting for the identity provider's redirect.

    Only keyed hashes of ``state``, the client ``binding`` and the ``nonce``
    are stored; the PKCE code verifier is sealed. Single use: ``used_at`` is set
    by the callback that consumes it.
    """

    id: UUID
    org_id: UUID
    connection_id: UUID
    state_hash: str
    binding_hash: str
    nonce_hash: str
    code_verifier_ciphertext: bytes
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None

    @property
    def verifier_context(self) -> str:
        return f"org:{self.org_id}|sso-state:{self.id}|pkce"


@dataclass(eq=False, kw_only=True)
class SsoIdentity:
    """A person's identity at an organization's provider (``iss`` + ``sub``),
    linked to their account. Later sign-ins match by it first, so a changed
    e-mail address at the provider keeps the same account."""

    id: UUID
    org_id: UUID
    user_id: UUID
    issuer: str
    subject: str
    email: str
    created_at: datetime
    last_login_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """The parts of an OpenID Provider's discovery document that are used."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    token_endpoint_auth_methods: tuple[str, ...] = ("client_secret_basic",)


@dataclass(frozen=True, slots=True)
class IdTokenClaims:
    """A verified ID token (signature, issuer, audience and times checked)."""

    issuer: str
    subject: str
    nonce: str | None
    email: str | None
    email_verified: bool
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    amr: tuple[str, ...] = ()


class OidcProvider(Protocol):
    """Talks to identity providers (implemented over the SSRF-safe HTTP client)."""

    async def metadata(self, issuer: str) -> ProviderMetadata:
        """The discovery document; its ``issuer`` equals ``issuer`` exactly."""
        ...

    async def exchange_code(
        self,
        metadata: ProviderMetadata,
        *,
        client_id: str,
        client_secret: str,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> str:
        """Redeem an authorization code; returns the raw ID token."""
        ...

    async def verify_id_token(
        self, id_token: str, metadata: ProviderMetadata, *, client_id: str, now: datetime
    ) -> IdTokenClaims: ...


class TxtResolver(Protocol):
    """DNS TXT lookups (domain-ownership proofs)."""

    async def txt_records(self, name: str) -> list[str]: ...


# ------------------------------------------------------------------ policy


def client_secret_context(org_id: UUID, connection_id: UUID) -> str:
    return f"org:{org_id}|sso:{connection_id}|client-secret"


def idp_reported_mfa(amr: tuple[str, ...]) -> bool:
    """Whether the provider says the person used a second factor (RFC 8176)."""
    return any(value in STRONG_AMR_VALUES for value in amr)


def normalize_issuer(raw: str) -> str:
    """An issuer URL as the discovery document must repeat it: ``https``, the
    standard port, a public host name, no credentials, query or fragment.
    Kept as typed (trailing slash included): OpenID Connect compares issuers
    as exact strings."""
    issuer = raw.strip()
    if not issuer or len(issuer) > _MAX_ISSUER_LENGTH:
        raise InvalidInputError("The issuer URL is empty or too long.", code="invalid_issuer")
    if "?" in issuer or "#" in issuer:
        raise InvalidInputError(
            "The issuer URL must not have a query or fragment.", code="invalid_issuer"
        )
    try:
        ISSUER_POLICY.validate(issuer)
    except PolicyViolationError as exc:
        raise InvalidInputError(
            "The issuer must be a public https URL on the standard port.", code="invalid_issuer"
        ) from exc
    return issuer


def discovery_url(issuer: str) -> str:
    return issuer.rstrip("/") + "/.well-known/openid-configuration"


def normalize_client_value(raw: str, *, what: str, max_length: int) -> str:
    value = raw.strip()
    if not value or len(value) > max_length or not _PRINTABLE.fullmatch(value):
        raise InvalidInputError(
            f"The {what} must be 1 to {max_length} printable characters.",
            code=f"invalid_{what.replace(' ', '_')}",
        )
    return value


def normalize_domain(raw: str) -> str:
    """An e-mail domain as it is compared: lower case, IDNA, a registrable
    looking name (two labels at least), no wildcard, no IP address."""
    candidate = raw.strip().rstrip(".").lower()
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidInputError(f"Invalid domain: {raw[:60]!r}", code="invalid_domain") from exc
    labels = ascii_domain.split(".")
    if (
        len(ascii_domain) > 253
        or len(labels) < 2
        or not all(_LABEL.fullmatch(label) for label in labels)
        or labels[-1].isdigit()
        or _is_ip(ascii_domain)
    ):
        raise InvalidInputError(f"Invalid domain: {raw[:60]!r}", code="invalid_domain")
    return ascii_domain


def normalize_domains(raw: list[str]) -> list[str]:
    domains = sorted({normalize_domain(value) for value in raw})
    if not domains:
        raise InvalidInputError("At least one e-mail domain is required.", code="domains_required")
    if len(domains) > MAX_ALLOWED_DOMAINS:
        raise InvalidInputError(
            f"At most {MAX_ALLOWED_DOMAINS} domains are allowed.", code="too_many_domains"
        )
    return domains


def email_domain(email: str) -> str | None:
    """The domain of a well-formed address (exactly one ``@``), else ``None``."""
    if email.count("@") != 1 or any(ch.isspace() for ch in email):
        return None
    local, _, domain = email.partition("@")
    if not local or not domain:
        return None
    try:
        return normalize_domain(domain)
    except InvalidInputError:
        return None


def verification_record_name(domain: str) -> str:
    return f"{VERIFICATION_RECORD_PREFIX}.{domain}"


def ensure_jit_role(role: Role) -> Role:
    if role not in JIT_ROLES:
        raise InvalidInputError(
            "An identity provider may grant the viewer or analyst role only.",
            code="invalid_default_role",
        )
    return role


def satisfies_sso(session: UserSession, org_id: UUID, role: Role) -> bool:
    """Whether a session may reach an organization that requires single sign-on:
    one its identity provider opened - or, break-glass, an owner's session that
    passed the platform's own MFA (the password, then TOTP, a passkey or a
    recovery code)."""
    return session.sso_org_id == org_id or (role is Role.OWNER and session.mfa_verified)


def sso_required_error() -> PermissionDeniedError:
    return PermissionDeniedError(
        "This organization requires single sign-on: sign in through its identity provider "
        "(POST /api/v1/auth/sso/start).",
        code="sso_required",
    )


def sso_session_restricted(action: str) -> PermissionDeniedError:
    """An account-wide action asked of a session an identity provider opened.

    Such a session speaks for its organization only - the provider's sign-in,
    its MFA, even the platform's second factor after it - while the account
    (its password, its second factors, its data, the account itself) belongs
    to every organization of the person."""
    return PermissionDeniedError(
        f"Sign in with your password to {action}: a single sign-on session reaches its "
        "organization only.",
        code="sso_session_restricted",
    )


def refuse_sso_session(principal: Principal, action: str) -> None:
    """Refuse ``action`` to a session an organization's identity provider opened."""
    if principal.sso_org_id is not None:
        raise sso_session_restricted(action)


def sso_failed() -> AuthenticationError:
    """The one answer for everything that must not be told apart (unknown or
    reused state, a wrong binding, an ID token that does not verify)."""
    return AuthenticationError("Single sign-on failed. Start again.", code="sso_failed")


class SsoRefusal(Exception):  # noqa: N818 - a control-flow signal, not an error type
    """A sign-in that is refused after the identity provider answered: the
    audit reason, the client's error, and who it was about (if known)."""

    def __init__(
        self,
        reason: str,
        error: NexusFlowError,
        *,
        user_id: UUID | None = None,
        membership: Membership | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.error = error
        self.user_id = user_id
        self.membership = membership


@dataclass(frozen=True, slots=True)
class SsoAccess:
    organization: Organization
    connection: SsoConnection
    membership: Membership


async def resolve_sso_access(
    uow: UnitOfWork, *, org_id: UUID, user_id: UUID, client_ip: str | None
) -> SsoAccess:
    """What a single sign-on may open, checked when the session is issued: an
    active organization that still has this provider, a member who was not
    deactivated by the organization's directory (SCIM), from an allowed network.
    Raises :class:`SsoRefusal`. ``uow`` is scoped to ``org_id``."""
    organization = await uow.organizations.get(org_id)
    if organization is None or not organization.is_active:
        raise SsoRefusal(
            "organization_inactive",
            PermissionDeniedError("The organization is not active.", code="org_inactive"),
            user_id=user_id,
        )
    connection = await uow.sso_connections.get_for_org(org_id)
    if connection is None:
        raise SsoRefusal("sso_not_configured", sso_failed(), user_id=user_id)
    directory_entry = await uow.scim_users.get_by_user(org_id, user_id)
    if directory_entry is not None and not directory_entry.active:
        raise SsoRefusal(
            "deactivated_by_directory",
            PermissionDeniedError(
                "Your access to this organization was removed by its directory.",
                code="sso_access_revoked",
            ),
            user_id=user_id,
        )
    membership = await uow.memberships.get(org_id, user_id)
    if membership is None:
        raise SsoRefusal("not_a_member", sso_failed(), user_id=user_id)
    if not organization.policy.allows_ip(client_ip):
        raise SsoRefusal(
            "network_not_allowed",
            network_not_allowed(f"org={org_id} credential=sso:{user_id} ip={client_ip}"),
            user_id=user_id,
            membership=membership,
        )
    return SsoAccess(organization=organization, connection=connection, membership=membership)


async def record_sso_failure(
    audit: AuditRecorder,
    uow: UnitOfWork,
    *,
    org_id: UUID | None,
    reason: str,
    meta: RequestMeta,
    user_id: UUID | None = None,
    membership: Membership | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """``auth.sso.failed`` in the organization's trail (the platform's when the
    organization is unknown); a refusal by the network allowlist is also shown
    as ``auth.network_denied``, as for a password sign-in. The caller commits."""
    await audit.record(
        uow.audit,
        action=AuditAction.SSO_LOGIN_FAILED,
        principal=None,
        meta=meta,
        result=AuditResult.FAILURE,
        org_id=org_id,
        actor_id=user_id,
        resource_type="organization" if org_id is not None else None,
        resource_id=org_id,
        metadata={"reason": reason, **(metadata or {})},
    )
    if membership is not None and reason == "network_not_allowed":
        await audit.record(
            uow.audit,
            action=AuditAction.NETWORK_ACCESS_DENIED,
            principal=Principal.for_user(
                user_id=membership.user_id,
                org_id=membership.org_id,
                role=membership.role,
                session_id=None,
            ),
            meta=meta,
            result=AuditResult.DENIED,
            resource_type="organization",
            resource_id=membership.org_id,
            metadata={"via": "sso"},
        )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True

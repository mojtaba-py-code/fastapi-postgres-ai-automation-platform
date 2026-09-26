"""Single sign-on use cases: an organization's identity provider (configure,
verify domains, remove) and signing in through it (start, callback).

The security model is in ``domain.identity.sso`` and docs/SSO.md. In short:
authorization code flow with PKCE, ``state``, ``nonce`` and a client binding;
strictly verified ID tokens; e-mail addresses accepted only in the domains the
organization proved it owns; sessions bound to the organization.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import (
    ConflictError,
    InvalidInputError,
    NotFoundError,
    PermissionDeniedError,
    PolicyViolationError,
    ServiceUnavailableError,
    TransientError,
)
from nexusflow.core.ids import uuid7
from nexusflow.core.text import clean_text
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal, PrincipalType
from nexusflow.domain.authorization.roles import Permission, Role
from nexusflow.domain.identity.auth_service import AuthService, LoginResult, normalize_email
from nexusflow.domain.identity.directory import new_directory_account
from nexusflow.domain.identity.model import User
from nexusflow.domain.identity.sso import (
    SCOPES,
    VERIFICATION_VALUE_PREFIX,
    IdTokenClaims,
    OidcProvider,
    ProviderMetadata,
    SsoConnection,
    SsoIdentity,
    SsoLoginState,
    SsoProtocolError,
    SsoRefusal,
    TxtResolver,
    email_domain,
    ensure_jit_role,
    idp_reported_mfa,
    managed_by_organization,
    normalize_client_value,
    normalize_domain,
    normalize_domains,
    normalize_issuer,
    record_sso_failure,
    resolve_sso_access,
    satisfies_sso,
    sso_failed,
    verification_record_name,
)
from nexusflow.domain.organizations.model import Membership, Organization, network_not_allowed
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.security import SecretCipher, TokenGenerator, TokenHasher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory

_SLUG = re.compile(r"^[a-z0-9-]{1,63}$")
_MAX_CODE_LENGTH = 2048
_MAX_STATE_LENGTH = 256


@dataclass(frozen=True, slots=True)
class SsoPolicy:
    public_base_url: str
    state_ttl_seconds: int

    @property
    def redirect_uri(self) -> str:
        """Fixed server-side: the front end's page that receives the redirect."""
        return self.public_base_url.rstrip("/") + "/sso/callback"


@dataclass(frozen=True, slots=True)
class DomainStatus:
    domain: str
    verified: bool
    record_name: str  # the TXT record that proves the domain
    record_value: str


@dataclass(frozen=True, slots=True)
class SsoConfiguration:
    connection: SsoConnection
    sso_required: bool
    domains: list[DomainStatus]
    redirect_uri: str


type CheckResult = Literal["verified", "already_verified", "record_not_found", "lookup_failed"]


@dataclass(frozen=True, slots=True)
class DomainCheck:
    domain: str
    result: CheckResult


@dataclass(frozen=True, slots=True)
class SsoStart:
    authorization_url: str
    state: str
    # Returned to the client only, never put in a URL: the callback requires it.
    binding: str
    expires_in: int


def _require_admin_session(principal: Principal) -> UUID:
    """Owners and administrators, from a signed-in session: an API key never
    changes who can sign in to the organization."""
    if principal.type is not PrincipalType.USER or principal.session_id is None:
        raise PermissionDeniedError(
            "This action requires a signed-in user session.", code="session_required"
        )
    principal.require(Permission.ORG_UPDATE)
    return principal.require_org()


def _not_available() -> NotFoundError:
    return NotFoundError(
        "Single sign-on is not available for this organization.", code="sso_not_available"
    )


def _unavailable() -> ServiceUnavailableError:
    return ServiceUnavailableError(
        "The identity provider is not available. Try again later.", code="sso_unavailable"
    )


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _authorization_url(endpoint: str, params: dict[str, str]) -> str:
    parts = urlsplit(endpoint)
    query = [*parse_qsl(parts.query, keep_blank_values=True), *params.items()]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _jit_name(claims: IdTokenClaims, email: str) -> str:
    parts = " ".join(p for p in (claims.given_name, claims.family_name) if p)
    for candidate in (claims.name, parts):
        cleaned = clean_text(candidate or "", max_length=120)
        if cleaned:
            return cleaned
    return clean_text(email.split("@", 1)[0], max_length=120) or "Member"


class SsoService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        cipher: SecretCipher,
        token_hasher: TokenHasher,
        token_generator: TokenGenerator,
        oidc: OidcProvider,
        dns: TxtResolver,
        auth: AuthService,
        policy: SsoPolicy,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._cipher = cipher
        self._hasher = token_hasher
        self._tokens = token_generator
        self._oidc = oidc
        self._dns = dns
        self._auth = auth
        self._policy = policy

    # ================================================================ configuration

    async def get_configuration(self, principal: Principal) -> SsoConfiguration:
        org_id = _require_admin_session(principal)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            connection = await uow.sso_connections.get_for_org(org_id)
            organization = await uow.organizations.get(org_id)
        if connection is None or organization is None:
            raise NotFoundError("Single sign-on is not configured.", code="sso_not_configured")
        return self._view(connection, organization)

    async def configure(
        self,
        principal: Principal,
        *,
        issuer: str,
        client_id: str,
        client_secret: str | None,
        allowed_domains: list[str],
        default_role: Role,
        sso_required: bool,
        trust_idp_mfa: bool,
        meta: RequestMeta,
    ) -> SsoConfiguration:
        """Create or replace the organization's identity provider.

        The discovery document is fetched first (through the SSRF-safe client):
        a provider that does not publish one for exactly this issuer is refused.
        Changing the issuer or client ends every session the old provider
        opened and forgets its identity links. ``sso_required`` needs a
        verified domain, and is refused when it would lock the caller out."""
        org_id = _require_admin_session(principal)
        issuer = normalize_issuer(issuer)
        client_id = normalize_client_value(client_id, what="client id", max_length=255)
        secret = (
            normalize_client_value(client_secret, what="client secret", max_length=1024)
            if client_secret is not None
            else None
        )
        domains = normalize_domains(allowed_domains)
        role = ensure_jit_role(default_role)
        await self._validate_provider(issuer)
        now = self._clock.now()
        # Revoking the sessions of every member the provider signed in crosses
        # users: the authentication context, with explicit organization filters.
        scope = TenantScope(org_id=org_id, user_id=principal.user_id, auth_context=True)
        async with self._uow_factory(scope) as uow:
            organization = await uow.organizations.get_for_update(org_id)
            if organization is None:
                raise NotFoundError()
            existing = await uow.sso_connections.get_for_org(org_id, for_update=True)
            provider_changed = existing is not None and (
                existing.issuer != issuer or existing.client_id != client_id
            )
            if existing is None:
                if secret is None:
                    raise InvalidInputError(
                        "client_secret is required.", code="client_secret_required"
                    )
                connection = SsoConnection(
                    id=uuid7(),
                    org_id=org_id,
                    issuer=issuer,
                    client_id=client_id,
                    client_secret_ciphertext=b"",  # sealed just below
                    secret_key_id="",  # a key id, set when sealed  # nosec B106
                    allowed_domains=domains,
                    verified_domains=[],
                    default_role=role,
                    trust_idp_mfa=trust_idp_mfa,
                    created_by=principal.user_id,
                    created_at=now,
                    updated_at=now,
                )
                self._seal_secret(connection, secret)
                await uow.sso_connections.add(connection)
            else:
                connection = existing
                connection.issuer = issuer
                connection.client_id = client_id
                if secret is not None:
                    self._seal_secret(connection, secret)
                connection.allowed_domains = domains
                connection.verified_domains = [d for d in existing.verified_domains if d in domains]
                connection.default_role = role
                connection.trust_idp_mfa = trust_idp_mfa
                connection.updated_at = now
            if sso_required:
                await self._ensure_sso_can_be_required(uow, principal, connection)
            organization.update_policy(
                organization.policy.model_copy(update={"sso_required": sso_required}), now
            )
            revoked = 0
            if provider_changed:
                revoked = await uow.sessions.revoke_sso_sessions(
                    org_id, now=now, reason="sso_provider_changed"
                )
                await uow.sso_states.delete_for_org(org_id)
                # Subjects can be pairwise per client - Microsoft Entra ID's are
                # per application - so links to the old client's subjects would
                # refuse every member as an identity conflict (review R14-3).
                await uow.sso_identities.delete_for_org(org_id)
            await self._audit.record(
                uow.audit,
                action=AuditAction.SSO_UPDATED
                if existing is not None
                else AuditAction.SSO_CONFIGURED,
                principal=principal,
                meta=meta,
                resource_type="sso_connection",
                resource_id=connection.id,
                metadata={
                    "issuer": issuer,
                    "client_id": client_id,
                    "allowed_domains": domains,
                    "default_role": role,
                    "sso_required": sso_required,
                    "trust_idp_mfa": trust_idp_mfa,
                    "secret_rotated": secret is not None,
                    "sessions_revoked": revoked,
                },
            )
            await uow.commit()
        return self._view(connection, organization)

    async def remove(self, principal: Principal, meta: RequestMeta) -> None:
        """Remove the identity provider: single sign-on is no longer required,
        every session it opened ends, and its identity links are forgotten.
        Accounts it created remain (they can set a password by reset link)."""
        org_id = _require_admin_session(principal)
        now = self._clock.now()
        scope = TenantScope(org_id=org_id, user_id=principal.user_id, auth_context=True)
        async with self._uow_factory(scope) as uow:
            connection = await uow.sso_connections.get_for_org(org_id, for_update=True)
            organization = await uow.organizations.get_for_update(org_id)
            if connection is None or organization is None:
                raise NotFoundError("Single sign-on is not configured.", code="sso_not_configured")
            organization.update_policy(
                organization.policy.model_copy(update={"sso_required": False}), now
            )
            revoked = await uow.sessions.revoke_sso_sessions(org_id, now=now, reason="sso_removed")
            links = await uow.sso_identities.delete_for_org(org_id)
            await uow.sso_connections.delete(connection)  # pending sign-ins go with it
            await self._audit.record(
                uow.audit,
                action=AuditAction.SSO_REMOVED,
                principal=principal,
                meta=meta,
                resource_type="sso_connection",
                resource_id=connection.id,
                metadata={
                    "issuer": connection.issuer,
                    "sessions_revoked": revoked,
                    "identities_unlinked": links,
                },
            )
            await uow.commit()

    async def verify_domains(
        self, principal: Principal, meta: RequestMeta
    ) -> tuple[SsoConfiguration, list[DomainCheck]]:
        """Look up each unverified domain's TXT record; a match verifies it."""
        org_id = _require_admin_session(principal)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            connection = await uow.sso_connections.get_for_org(org_id)
        if connection is None:
            raise NotFoundError("Single sign-on is not configured.", code="sso_not_configured")
        checks: list[DomainCheck] = []
        found: list[str] = []
        for domain in connection.allowed_domains:
            if domain in connection.verified_domains:
                checks.append(DomainCheck(domain, "already_verified"))
                continue
            try:
                records = await self._dns.txt_records(verification_record_name(domain))
            except TransientError:
                checks.append(DomainCheck(domain, "lookup_failed"))
                continue
            expected = self.verification_value(org_id, domain)
            if any(hmac.compare_digest(record.strip(), expected) for record in records):
                found.append(domain)
                checks.append(DomainCheck(domain, "verified"))
            else:
                checks.append(DomainCheck(domain, "record_not_found"))
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            current = await uow.sso_connections.get_for_org(org_id, for_update=True)
            organization = await uow.organizations.get(org_id)
            if current is None or organization is None:
                raise NotFoundError("Single sign-on is not configured.", code="sso_not_configured")
            newly = [
                d
                for d in found
                if d in current.allowed_domains and d not in current.verified_domains
            ]
            if newly:
                current.verified_domains = sorted({*current.verified_domains, *newly})
                current.updated_at = self._clock.now()
                for domain in newly:
                    await self._audit.record(
                        uow.audit,
                        action=AuditAction.SSO_DOMAIN_VERIFIED,
                        principal=principal,
                        meta=meta,
                        resource_type="sso_connection",
                        resource_id=current.id,
                        metadata={"domain": domain, "method": "dns"},
                    )
                await uow.commit()
        return self._view(current, organization), checks

    async def confirm_domain(
        self, org_id: UUID, domain: str, *, reason: str, meta: RequestMeta
    ) -> SsoConfiguration:
        """Operator path (``nexusflow sso verify-domain``): mark a domain
        verified after checking its ownership outside the platform - for a
        deployment without DNS-over-HTTPS egress, or a demonstration."""
        cleaned = clean_text(reason, max_length=200)
        if len(cleaned) < 3:
            raise InvalidInputError("A reason is required.", code="reason_required")
        name = normalize_domain(domain)
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            connection = await uow.sso_connections.get_for_org(org_id, for_update=True)
            organization = await uow.organizations.get(org_id)
            if connection is None or organization is None:
                raise NotFoundError("Single sign-on is not configured.", code="sso_not_configured")
            if name not in connection.allowed_domains:
                raise InvalidInputError(
                    "The domain is not one of the organization's allowed domains.",
                    code="domain_not_allowed",
                )
            if name not in connection.verified_domains:
                connection.verified_domains = sorted({*connection.verified_domains, name})
                connection.updated_at = self._clock.now()
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.SSO_DOMAIN_VERIFIED,
                    principal=Principal.system(org_id),
                    meta=meta,
                    resource_type="sso_connection",
                    resource_id=connection.id,
                    metadata={"domain": name, "method": "operator", "reason": cleaned},
                )
                await uow.commit()
        return self._view(connection, organization)

    def verification_value(self, org_id: UUID, domain: str) -> str:
        """The TXT value that proves ``domain`` for this organization - derived
        with the platform's pepper, so it is stable and nothing is stored."""
        digest = self._hasher.hash(f"sso-domain-verification:v1:{org_id}:{domain}")
        return VERIFICATION_VALUE_PREFIX + digest[:32]

    async def rewrap(self, org_id: UUID, *, active_key_id: str) -> int:
        """Key rotation: re-seal the client secret under the active key."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            stale = await uow.sso_connections.needing_rewrap(org_id, active_key_id, 10)
            for connection in stale:
                connection.client_secret_ciphertext = self._cipher.rewrap(
                    connection.client_secret_ciphertext, context=connection.secret_context
                )
                connection.secret_key_id = self._cipher.key_id_of(
                    connection.client_secret_ciphertext
                )
            await uow.commit()
        return len(stale)

    # ================================================================ sign-in

    async def start(self, *, organization: str, meta: RequestMeta) -> SsoStart:
        """Begin a sign-in at the organization's identity provider.

        Unknown organizations and those without (usable) single sign-on get
        the same answer."""
        slug = organization.strip().lower()
        if not _SLUG.fullmatch(slug):
            raise _not_available()
        async with self._uow_factory(TenantScope.auth()) as uow:
            org = await uow.organizations.get_by_slug(slug)
            connection = None
            if org is not None and org.is_active:
                await uow.switch_tenant(org.id)
                connection = await uow.sso_connections.get_for_org(org.id)
        if org is None or connection is None or not connection.verified_domains:
            raise _not_available()
        metadata = await self._metadata(connection.issuer)
        state = self._tokens.generate(32)
        binding = self._tokens.generate(32)
        nonce = self._tokens.generate(32)
        verifier = self._tokens.generate(48)  # 64 characters (RFC 7636: 43 to 128)
        now = self._clock.now()
        pending = SsoLoginState(
            id=uuid7(),
            org_id=org.id,
            connection_id=connection.id,
            state_hash=self._hash("state", state),
            binding_hash=self._hash("binding", binding),
            nonce_hash=self._hash("nonce", nonce),
            code_verifier_ciphertext=b"",
            created_at=now,
            expires_at=now + timedelta(seconds=self._policy.state_ttl_seconds),
        )
        pending.code_verifier_ciphertext = self._cipher.encrypt(
            verifier, context=pending.verifier_context
        )
        async with self._uow_factory(TenantScope.system(org.id)) as uow:
            await uow.sso_states.add(pending)
            await uow.commit()
        url = _authorization_url(
            metadata.authorization_endpoint,
            {
                "response_type": "code",
                "client_id": connection.client_id,
                "redirect_uri": self._policy.redirect_uri,
                "scope": SCOPES,
                "state": state,
                "nonce": nonce,
                "code_challenge": _challenge(verifier),
                "code_challenge_method": "S256",
            },
        )
        return SsoStart(
            authorization_url=url,
            state=state,
            binding=binding,
            expires_in=self._policy.state_ttl_seconds,
        )

    async def complete(
        self, *, code: str, state: str, binding: str, meta: RequestMeta
    ) -> LoginResult:
        """Finish a sign-in: consume the state, redeem the code, verify the ID
        token, then find, link or create the account and open a session bound
        to the organization (or ask for the platform's second factor)."""
        if not (
            0 < len(code) <= _MAX_CODE_LENGTH
            and 0 < len(state) <= _MAX_STATE_LENGTH
            and 0 < len(binding) <= _MAX_STATE_LENGTH
        ):
            raise sso_failed()
        pending, connection, verifier, secret = await self._consume(state, binding, meta)
        org_id = pending.org_id
        try:
            metadata = await self._oidc.metadata(connection.issuer)
            id_token = await self._oidc.exchange_code(
                metadata,
                client_id=connection.client_id,
                client_secret=secret,
                code=code,
                redirect_uri=self._policy.redirect_uri,
                code_verifier=verifier,
            )
            claims = await self._oidc.verify_id_token(
                id_token, metadata, client_id=connection.client_id, now=self._clock.now()
            )
        except SsoProtocolError as exc:
            await self._fail(org_id, exc.reason, meta)
            raise sso_failed() from None
        except PolicyViolationError as exc:
            await self._fail(org_id, "provider_address_not_allowed", meta, detail=exc.code)
            raise sso_failed() from None
        except TransientError:
            await self._fail(org_id, "provider_unavailable", meta)
            raise _unavailable() from None
        if claims.nonce is None or not hmac.compare_digest(
            self._hash("nonce", claims.nonce), pending.nonce_hash
        ):
            await self._fail(org_id, "nonce_mismatch", meta)
            raise sso_failed()
        email = normalize_email(claims.email or "")
        domain = email_domain(email) if claims.email else None
        if domain is None:
            await self._fail(org_id, "email_missing", meta)
            raise sso_failed()
        if not claims.email_verified:
            await self._fail(org_id, "email_not_verified", meta, detail=domain)
            raise PermissionDeniedError(
                "The identity provider did not confirm your e-mail address.",
                code="sso_email_not_verified",
            )
        if not connection.accepts_domain(domain):
            await self._fail(org_id, "domain_not_allowed", meta, detail=domain)
            raise PermissionDeniedError(
                "Your e-mail domain is not allowed to sign in to this organization.",
                code="sso_domain_not_allowed",
            )
        if not managed_by_organization(connection, claims):
            # Google: a personal account with an address in the domain (review R14-1).
            await self._fail(org_id, "account_not_managed", meta, detail=domain)
            raise PermissionDeniedError(
                "Sign in with the account your organization manages at its identity provider.",
                code="sso_account_not_managed",
            )
        return await self._sign_in(connection, claims, email, meta)

    # ---------------------------------------------------------------- steps

    async def _consume(
        self, state: str, binding: str, meta: RequestMeta
    ) -> tuple[SsoLoginState, SsoConnection, str, str]:
        """Find and consume the pending sign-in (committed before the identity
        provider is called: the state is spent whatever happens next)."""
        now = self._clock.now()
        async with self._uow_factory(TenantScope.auth()) as uow:
            pending = await uow.sso_states.find_by_hash(self._hash("state", state))
            if pending is None:
                await record_sso_failure(
                    self._audit, uow, org_id=None, reason="unknown_state", meta=meta
                )
                await uow.commit()
                raise sso_failed()
            await uow.switch_tenant(pending.org_id)
            # The binding is checked before the state is spent: a stolen state
            # (seen in a URL) cannot be used to cancel its owner's sign-in.
            if not hmac.compare_digest(self._hash("binding", binding), pending.binding_hash):
                reason = "binding_mismatch"
            elif not await uow.sso_states.consume(pending.org_id, pending.id, now=now):
                reason = "state_reused" if pending.used_at is not None else "state_expired"
            else:
                reason = ""
            connection = await uow.sso_connections.get_for_org(pending.org_id)
            if not reason and (connection is None or connection.id != pending.connection_id):
                reason = "provider_changed"
            if reason or connection is None:
                await record_sso_failure(
                    self._audit, uow, org_id=pending.org_id, reason=reason, meta=meta
                )
                await uow.commit()
                raise sso_failed()
            verifier = self._cipher.decrypt(
                pending.code_verifier_ciphertext, context=pending.verifier_context
            )
            secret = self._cipher.decrypt(
                connection.client_secret_ciphertext, context=connection.secret_context
            )
            await uow.commit()
        return pending, connection, verifier, secret

    async def _sign_in(
        self, connection: SsoConnection, claims: IdTokenClaims, email: str, meta: RequestMeta
    ) -> LoginResult:
        org_id = connection.org_id
        now = self._clock.now()
        idp_mfa = connection.trust_idp_mfa and idp_reported_mfa(claims.amr)
        try:
            # The account is found by address or IdP identity before it is known
            # to belong to the organization: the authentication context, with
            # explicit organization filters.
            async with self._uow_factory(TenantScope(org_id=org_id, auth_context=True)) as uow:
                current = await uow.sso_connections.get_for_org(org_id)
                if (
                    current is None
                    or current.id != connection.id
                    or current.issuer != connection.issuer
                    or current.client_id != connection.client_id
                ):
                    raise SsoRefusal("provider_changed", sso_failed())
                organization = await uow.organizations.get(org_id)
                if organization is not None and not organization.policy.allows_ip(meta.ip):
                    # Before any account or membership is created for the person.
                    raise SsoRefusal(
                        "network_not_allowed",
                        network_not_allowed(f"org={org_id} credential=sso ip={meta.ip}"),
                    )
                user, new_account = await self._account(uow, current, claims, email, now, meta)
                await self._ensure_membership(uow, current, user, now, meta)
                access = await resolve_sso_access(
                    uow, org_id=org_id, user_id=user.id, client_ip=meta.ip
                )
                if access.organization.policy.require_passkey:
                    # Only a passkey opens it: the provider's MFA, trusted or
                    # not, never stands in for one. The platform's passkey
                    # step, then a bound session (refused without a passkey).
                    challenge = await self._auth.sso_mfa_challenge(
                        uow, user, org_id, now, passkey_only=True
                    )
                    await uow.commit()
                    return challenge
                if access.organization.policy.require_mfa and not idp_mfa:
                    if not user.mfa_enabled:
                        raise SsoRefusal(
                            "mfa_required",
                            PermissionDeniedError(
                                "This organization requires multi-factor authentication, and "
                                "your identity provider did not report it.",
                                code="mfa_required",
                            ),
                            user_id=user.id,
                        )
                    # The platform's own second factor (TOTP, a passkey or a
                    # recovery code), then a bound session.
                    challenge = await self._auth.sso_mfa_challenge(uow, user, org_id, now)
                    await uow.commit()
                    return challenge
                tokens = await self._auth.complete_sso_sign_in(
                    uow,
                    user=user,
                    org_id=org_id,
                    role=access.membership.role,
                    meta=meta,
                    now=now,
                    mfa_verified=idp_mfa,
                    idp_mfa=idp_mfa,
                    new_account=new_account,
                )
                await uow.commit()
            return LoginResult(tokens=tokens)
        except SsoRefusal as refusal:
            await self._fail(
                org_id,
                refusal.reason,
                meta,
                user_id=refusal.user_id,
                membership=refusal.membership,
            )
            raise refusal.error from None
        except ConflictError:  # two first sign-ins of one person at once
            await self._fail(org_id, "concurrent_sign_in", meta)
            raise sso_failed() from None

    async def _account(
        self,
        uow: UnitOfWork,
        connection: SsoConnection,
        claims: IdTokenClaims,
        email: str,
        now: datetime,
        meta: RequestMeta,
    ) -> tuple[User, bool]:
        """The account behind the provider's identity: the linked one first;
        else the one with the (verified-domain) address - linked now, unless
        it is linked to another identity at this provider; else a new one."""
        org_id = connection.org_id
        link = await uow.sso_identities.find_by_subject(org_id, connection.issuer, claims.subject)
        if link is not None:
            user = await uow.users.get_for_update(link.user_id)
            if user is None or not user.is_active:
                raise SsoRefusal("account_inactive", sso_failed(), user_id=link.user_id)
            link.email = email
            link.last_login_at = now
            return user, False
        user = await uow.users.get_by_email(email, for_update=True)
        new_account = user is None
        if user is None:
            user = new_directory_account(email, _jit_name(claims, email), now)
            await uow.users.add(user)
        elif not user.is_active:
            raise SsoRefusal("account_inactive", sso_failed(), user_id=user.id)
        elif await uow.sso_identities.find_for_user(org_id, connection.issuer, user.id):
            # The address is linked to another identity at this provider: a
            # provider must not take over an account by asserting its address.
            raise SsoRefusal("identity_conflict", sso_failed(), user_id=user.id)
        actor = Principal.for_user(user_id=user.id, org_id=org_id, role=None, session_id=None)
        if new_account:
            await self._audit.record(
                uow.audit,
                action=AuditAction.SSO_JIT_USER_CREATED,
                principal=actor,
                meta=meta,
                resource_type="user",
                resource_id=user.id,
                metadata={"email_domain": email.rsplit("@", 1)[-1]},
            )
        identity = SsoIdentity(
            id=uuid7(),
            org_id=org_id,
            user_id=user.id,
            issuer=connection.issuer,
            subject=claims.subject,
            email=email,
            created_at=now,
            last_login_at=now,
        )
        await uow.sso_identities.add(identity)
        await self._audit.record(
            uow.audit,
            action=AuditAction.SSO_IDENTITY_LINKED,
            principal=actor,
            meta=meta,
            resource_type="user",
            resource_id=user.id,
            metadata={"new_account": new_account},
        )
        return user, new_account

    async def _ensure_membership(
        self,
        uow: UnitOfWork,
        connection: SsoConnection,
        user: User,
        now: datetime,
        meta: RequestMeta,
    ) -> Membership:
        org_id = connection.org_id
        membership = await uow.memberships.get(org_id, user.id)
        if membership is not None:
            return membership
        entry = await uow.scim_users.get_by_user(org_id, user.id)
        if entry is not None and not entry.active:
            # Deactivated by the organization's directory: signing in must not
            # quietly undo it.
            raise SsoRefusal(
                "deactivated_by_directory",
                PermissionDeniedError(
                    "Your access to this organization was removed by its directory.",
                    code="sso_access_revoked",
                ),
                user_id=user.id,
            )
        membership = Membership(
            id=uuid7(),
            org_id=org_id,
            user_id=user.id,
            role=connection.default_role,
            created_at=now,
            updated_at=now,
        )
        await uow.memberships.add(membership)
        await self._audit.record(
            uow.audit,
            action=AuditAction.SSO_JIT_MEMBERSHIP_CREATED,
            principal=Principal.for_user(
                user_id=user.id, org_id=org_id, role=None, session_id=None
            ),
            meta=meta,
            resource_type="membership",
            resource_id=membership.id,
            metadata={"user_id": str(user.id), "role": membership.role},
        )
        return membership

    # ---------------------------------------------------------------- helpers

    async def _validate_provider(self, issuer: str) -> ProviderMetadata:
        try:
            return await self._oidc.metadata(issuer)
        except PolicyViolationError as exc:
            raise InvalidInputError(
                "The identity provider's address is not allowed.", code="sso_issuer_not_allowed"
            ) from exc
        except SsoProtocolError as exc:
            raise InvalidInputError(
                f"The identity provider's discovery document could not be used ({exc.reason}).",
                code="sso_discovery_failed",
            ) from exc
        except TransientError as exc:
            raise InvalidInputError(
                "The identity provider's discovery document could not be fetched.",
                code="sso_discovery_failed",
            ) from exc

    async def _metadata(self, issuer: str) -> ProviderMetadata:
        try:
            return await self._oidc.metadata(issuer)
        except (SsoProtocolError, PolicyViolationError, TransientError) as exc:
            raise _unavailable() from exc

    async def _ensure_sso_can_be_required(
        self, uow: UnitOfWork, principal: Principal, connection: SsoConnection
    ) -> None:
        if not connection.verified_domains:
            raise InvalidInputError(
                "Verify at least one domain before requiring single sign-on.",
                code="sso_domain_not_verified",
            )
        session = await uow.sessions.get(principal.session_id) if principal.session_id else None
        if (
            session is None
            or principal.role is None
            or not satisfies_sso(session, connection.org_id, principal.role)
        ):
            # Sign in through the provider first (or, as an owner, with MFA):
            # otherwise this request would end the caller's own access.
            raise InvalidInputError(
                "Requiring single sign-on would lock you out: sign in through the identity "
                "provider first (owners: or with MFA).",
                code="would_lock_you_out",
            )

    def _seal_secret(self, connection: SsoConnection, secret: str) -> None:
        connection.client_secret_ciphertext = self._cipher.encrypt(
            secret, context=connection.secret_context
        )
        connection.secret_key_id = self._cipher.key_id_of(connection.client_secret_ciphertext)

    def _hash(self, purpose: str, value: str) -> str:
        return self._hasher.hash(f"sso-{purpose}:{value}")

    def _view(self, connection: SsoConnection, organization: Organization) -> SsoConfiguration:
        return SsoConfiguration(
            connection=connection,
            sso_required=organization.policy.sso_required,
            domains=[
                DomainStatus(
                    domain=domain,
                    verified=domain in connection.verified_domains,
                    record_name=verification_record_name(domain),
                    record_value=self.verification_value(connection.org_id, domain),
                )
                for domain in connection.allowed_domains
            ],
            redirect_uri=self._policy.redirect_uri,
        )

    async def _fail(
        self,
        org_id: UUID,
        reason: str,
        meta: RequestMeta,
        *,
        user_id: UUID | None = None,
        membership: Membership | None = None,
        detail: str | None = None,
    ) -> None:
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            await record_sso_failure(
                self._audit,
                uow,
                org_id=org_id,
                reason=reason,
                meta=meta,
                user_id=user_id,
                membership=membership,
                metadata={"detail": detail} if detail else None,
            )
            await uow.commit()

"""Resolves a bearer credential into a :class:`Principal` on every request.

Access tokens are *not* trusted on signature alone: the session, the user's
``token_version``, the membership (current role!) and the organization status
are loaded from the database for each request. Revocations, role changes and
organization suspensions therefore take effect immediately rather than when a
short-lived token happens to expire.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import AuthenticationError, PermissionDeniedError
from nexusflow.domain.authorization.principal import Principal, PrincipalType
from nexusflow.domain.authorization.roles import permissions_for, role_covers
from nexusflow.domain.identity.api_keys import (
    CREDENTIAL_PREFIXES,
    CredentialKind,
    parse_credential,
)
from nexusflow.domain.identity.sso import satisfies_sso, sso_required_error
from nexusflow.domain.identity.tokens import TokenCodec
from nexusflow.domain.organizations.model import OrganizationSettings, network_not_allowed
from nexusflow.domain.shared.security import TokenHasher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWorkFactory

__all__ = ["Authenticator", "network_not_allowed"]

_LAST_USED_RESOLUTION = timedelta(minutes=5)


def _require_allowed_network(
    policy: OrganizationSettings, client_ip: str | None, *, org_id: UUID, credential: str
) -> None:
    if not policy.allows_ip(client_ip):
        # Logged (with the credential, never its secret) and counted by the API.
        raise network_not_allowed(f"org={org_id} credential={credential} ip={client_ip}")


def _unauthenticated() -> AuthenticationError:
    return AuthenticationError("Invalid or expired credentials.", code="invalid_token")


class Authenticator:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        token_codec: TokenCodec,
        token_hasher: TokenHasher,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._codec = token_codec
        self._hasher = token_hasher

    async def authenticate(
        self, credential: str, *, client_ip: str | None = None, mfa_setup: bool = False
    ) -> Principal:
        """The principal behind ``credential``, used from ``client_ip``.

        An organization with a network allowlist is reached only from those
        networks - through its members' sessions and its API keys alike.

        ``mfa_setup`` is for the MFA enrolment endpoints only: where the
        session's organization requires MFA the session has not passed (or
        single sign-on it did not use), it yields the *account* (no
        organization, no permissions) instead of refusing - otherwise a member
        without MFA could never set it up.

        SCIM tokens are never accepted here: they work on ``/scim/v2`` only
        (:meth:`authenticate_scim`).
        """
        parsed = parse_credential(credential)
        if parsed is not None:
            if parsed.kind is CredentialKind.API_KEY:
                return await self._authenticate_api_key(parsed.prefix, parsed.full_token, client_ip)
            if parsed.kind is CredentialKind.SERVICE_TOKEN:
                return await self._authenticate_service(parsed.prefix, parsed.full_token)
            raise _unauthenticated()  # a SCIM token: provisioning only, never this API
        if credential.startswith(CREDENTIAL_PREFIXES):
            raise _unauthenticated()  # malformed/garbled key: fail before any DB access
        return await self._authenticate_access_token(credential, client_ip, mfa_setup)

    async def _authenticate_access_token(
        self, token: str, client_ip: str | None, mfa_setup: bool
    ) -> Principal:
        now = self._clock.now()
        claims = self._codec.decode_access_token(token, now=now)
        scope = TenantScope(org_id=claims.org_id, user_id=claims.user_id)
        async with self._uow_factory(scope) as uow:
            session = await uow.sessions.get(claims.session_id)
            if session is None or session.user_id != claims.user_id or not session.is_valid(now):
                raise _unauthenticated()
            # A session an identity provider opened is its organization's only.
            if session.sso_org_id is not None and claims.org_id != session.sso_org_id:
                raise _unauthenticated()
            user = await uow.users.get(claims.user_id)
            if user is None or not user.is_active or user.token_version != claims.token_version:
                raise _unauthenticated()
            account = Principal.for_user(
                user_id=user.id,
                org_id=None,
                role=None,
                session_id=session.id,
                label=user.email,
                sso_org_id=session.sso_org_id,
            )
            if claims.org_id is None:
                return account
            membership = await uow.memberships.get(claims.org_id, user.id)
            organization = await uow.organizations.get(claims.org_id)
            if membership is None or organization is None:
                raise _unauthenticated()
            if not organization.is_active:
                raise PermissionDeniedError("The organization is not active.", code="org_inactive")
            policy = organization.policy
            if policy.sso_required and not satisfies_sso(session, organization.id, membership.role):
                if mfa_setup:
                    return account  # an owner may still set up MFA for the way back in
                raise sso_required_error()
            if policy.require_mfa and not session.mfa_verified:
                if mfa_setup:
                    return account
                raise PermissionDeniedError(
                    "This organization requires multi-factor authentication: set it up "
                    "(POST /api/v1/auth/mfa/enroll, then /mfa/confirm) or sign in with it.",
                    code="mfa_required",
                )
            _require_allowed_network(
                policy, client_ip, org_id=organization.id, credential=f"user:{user.id}"
            )
            return Principal.for_user(
                user_id=user.id,
                org_id=claims.org_id,
                role=membership.role,
                session_id=session.id,
                label=user.email,
                sso_org_id=session.sso_org_id,
            )

    async def authenticate_scim(self, credential: str, *, client_ip: str | None) -> Principal:
        """A SCIM token: its organization's provisioning API, nothing else.

        The organization's network allowlist applies as for API keys: add the
        identity provider's provisioning addresses to it (docs/SSO.md)."""
        parsed = parse_credential(credential)
        if parsed is None or parsed.kind is not CredentialKind.SCIM_TOKEN:
            raise _unauthenticated()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.auth()) as uow:
            token = await uow.scim_tokens.find_by_prefix(parsed.prefix)
            if (
                token is None
                or not self._hasher.verify(parsed.full_token, token.token_hash)
                or not token.is_usable(now)
            ):
                raise _unauthenticated()
            await uow.switch_tenant(token.org_id)
            organization = await uow.organizations.get(token.org_id)
            if organization is None or not organization.is_active:
                raise _unauthenticated()
            _require_allowed_network(
                organization.policy,
                client_ip,
                org_id=organization.id,
                credential=f"scim:{parsed.prefix}",
            )
            if token.last_used_at is None or now - token.last_used_at > _LAST_USED_RESOLUTION:
                token.last_used_at = now  # throttled write: at most every few minutes
                await uow.commit()
            return Principal(
                type=PrincipalType.SCIM,
                id=token.id,
                org_id=token.org_id,
                role=None,
                label=f"scim:{token.name}",
            )

    async def _authenticate_api_key(
        self, prefix: str, token: str, client_ip: str | None
    ) -> Principal:
        now = self._clock.now()
        async with self._uow_factory(TenantScope.auth()) as uow:
            key = await uow.api_keys.find_by_prefix(prefix)
            if (
                key is None
                or not self._hasher.verify(token, key.key_hash)
                or not key.is_usable(now)
            ):
                raise _unauthenticated()
            await uow.switch_tenant(key.org_id)
            organization = await uow.organizations.get(key.org_id)
            if organization is None or not organization.is_active:
                raise _unauthenticated()
            _require_allowed_network(
                organization.policy,
                client_ip,
                org_id=organization.id,
                credential=f"api_key:{prefix}",
            )
            # A key never outlives or outranks the member who created it: it
            # stops working when they leave, and acts with at most their
            # *current* role (a demoted admin's keys are demoted with them).
            creator = (
                await uow.memberships.get(key.org_id, key.created_by)
                if key.created_by is not None
                else None
            )
            if creator is None:
                raise _unauthenticated()
            role = key.role if role_covers(creator.role, key.role) else creator.role
            allowed = permissions_for(key.role) & permissions_for(creator.role)
            if key.last_used_at is None or now - key.last_used_at > _LAST_USED_RESOLUTION:
                key.last_used_at = now  # throttled write: at most every few minutes
                await uow.commit()
            return Principal(
                type=PrincipalType.API_KEY,
                id=key.id,
                org_id=key.org_id,
                role=role,
                permissions=key.effective_permissions(allowed),
                user_id=key.created_by,
                label=f"api_key:{key.name}",
            )

    async def _authenticate_service(self, prefix: str, token: str) -> Principal:
        now = self._clock.now()
        async with self._uow_factory(TenantScope.auth()) as uow:
            account = await uow.service_accounts.find_by_prefix(prefix)
            if account is None or not self._hasher.verify(token, account.key_hash):
                raise _unauthenticated()
            if not account.enabled:
                raise PermissionDeniedError(
                    "This automation credential is disabled.", code="service_disabled"
                )
            if account.last_used_at is None or now - account.last_used_at > _LAST_USED_RESOLUTION:
                account.last_used_at = now
                await uow.commit()
            return Principal(
                type=PrincipalType.SERVICE,
                id=account.id,
                org_id=None,
                role=None,
                service_scopes=account.service_scopes(),
                label=f"service:{account.workflow_key}",
            )

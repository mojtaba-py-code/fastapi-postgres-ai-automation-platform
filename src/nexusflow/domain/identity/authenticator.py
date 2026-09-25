"""Resolves a bearer credential into a :class:`Principal` on every request.

Access tokens are *not* trusted on signature alone: the session, the user's
``token_version``, the membership (current role!) and the organization status
are loaded from the database for each request. Revocations, role changes and
organization suspensions therefore take effect immediately rather than when a
short-lived token happens to expire.
"""

from __future__ import annotations

from datetime import timedelta

from nexusflow.core.clock import Clock
from nexusflow.core.errors import AuthenticationError, PermissionDeniedError
from nexusflow.domain.authorization.principal import Principal, PrincipalType
from nexusflow.domain.authorization.roles import permissions_for, role_covers
from nexusflow.domain.identity.api_keys import CredentialKind, parse_credential
from nexusflow.domain.identity.tokens import TokenCodec
from nexusflow.domain.shared.security import TokenHasher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWorkFactory

_LAST_USED_RESOLUTION = timedelta(minutes=5)


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

    async def authenticate(self, credential: str) -> Principal:
        parsed = parse_credential(credential)
        if parsed is not None:
            if parsed.kind is CredentialKind.API_KEY:
                return await self._authenticate_api_key(parsed.prefix, parsed.full_token)
            return await self._authenticate_service(parsed.prefix, parsed.full_token)
        if credential.startswith(("nxf_", "nxs_")):
            raise _unauthenticated()  # malformed/garbled key: fail before any DB access
        return await self._authenticate_access_token(credential)

    async def _authenticate_access_token(self, token: str) -> Principal:
        now = self._clock.now()
        claims = self._codec.decode_access_token(token, now=now)
        scope = TenantScope(org_id=claims.org_id, user_id=claims.user_id)
        async with self._uow_factory(scope) as uow:
            session = await uow.sessions.get(claims.session_id)
            if session is None or session.user_id != claims.user_id or not session.is_valid(now):
                raise _unauthenticated()
            user = await uow.users.get(claims.user_id)
            if user is None or not user.is_active or user.token_version != claims.token_version:
                raise _unauthenticated()
            if claims.org_id is None:
                return Principal.for_user(
                    user_id=user.id,
                    org_id=None,
                    role=None,
                    session_id=session.id,
                    label=user.email,
                )
            membership = await uow.memberships.get(claims.org_id, user.id)
            organization = await uow.organizations.get(claims.org_id)
            if membership is None or organization is None:
                raise _unauthenticated()
            if not organization.is_active:
                raise PermissionDeniedError("The organization is not active.", code="org_inactive")
            if organization.policy.require_mfa and not session.mfa_verified:
                raise PermissionDeniedError(
                    "This organization requires multi-factor authentication.", code="mfa_required"
                )
            return Principal.for_user(
                user_id=user.id,
                org_id=claims.org_id,
                role=membership.role,
                session_id=session.id,
                label=user.email,
            )

    async def _authenticate_api_key(self, prefix: str, token: str) -> Principal:
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

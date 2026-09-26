"""Account self-service and machine credentials (API keys)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import (
    ConflictError,
    InvalidInputError,
    NotFoundError,
    PermissionDeniedError,
)
from nexusflow.core.ids import uuid7
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.core.text import clean_text
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.policies import validate_api_key_grant
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission, Role
from nexusflow.domain.identity.api_keys import CredentialKind, generate_credential
from nexusflow.domain.identity.model import ApiKey, User
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.security import TokenHasher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory

MAX_API_KEY_LIFETIME_DAYS = 365


class PasswordConfirmation(Protocol):
    """``AuthService.confirm_password``: a password check that counts like a sign-in."""

    async def __call__(
        self, principal: Principal, password: str, meta: RequestMeta, *, purpose: str
    ) -> str: ...


async def erase_user(
    uow: UnitOfWork,
    user: User,
    *,
    audit: AuditRecorder,
    actor: Principal,
    meta: RequestMeta,
    now: datetime,
    reason: str,
) -> None:
    """Erase a person (GDPR art. 17): leave every organization - refused for the
    sole owner of one - with their API keys revoked, end every session, forget
    the recovery codes and passkeys and anonymise the account. The caller
    records the erasure itself and commits."""
    for org_id in await uow.memberships.list_org_ids_for_user(user.id):
        await uow.switch_tenant(org_id)
        membership = await uow.memberships.get(org_id, user.id)
        if membership is None:
            continue
        if membership.role is Role.OWNER and await uow.memberships.count_owners(org_id) <= 1:
            raise ConflictError(
                "Transfer ownership or delete your organizations first.", code="sole_owner"
            )
        await uow.memberships.delete(membership)
        revoked = await uow.api_keys.revoke_created_by(org_id, user.id, now=now)
        # Each organization's own chain shows the member leaving.
        await audit.record(
            uow.audit,
            action=AuditAction.MEMBER_REMOVED,
            principal=actor,
            meta=meta,
            org_id=org_id,
            resource_type="membership",
            resource_id=membership.id,
            metadata={"user_id": str(user.id), "reason": reason, "api_keys_revoked": revoked},
        )
    await uow.switch_tenant(None)
    await uow.sessions.revoke_all_for_user(user.id, now=now, reason="account_deleted")
    await uow.recovery_codes.delete_for_user(user.id)
    await uow.webauthn_credentials.delete_for_user(user.id)
    user.anonymize(now)


@dataclass(frozen=True, slots=True)
class CreatedApiKey:
    key: ApiKey
    token: str  # returned exactly once; only a keyed hash is stored


class AccountService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        token_hasher: TokenHasher,
        confirm_password: PasswordConfirmation,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._token_hasher = token_hasher
        self._confirm_password = confirm_password

    async def get_profile(self, principal: Principal) -> User:
        if principal.user_id is None:
            raise NotFoundError()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get(principal.user_id)
            if user is None:
                raise NotFoundError()
            return user

    async def update_profile(self, principal: Principal, *, full_name: str) -> User:
        if principal.user_id is None:
            raise NotFoundError()
        name = clean_text(full_name, max_length=120)
        if not name:
            raise InvalidInputError("Full name is required.")
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get_for_update(principal.user_id)
            if user is None:
                raise NotFoundError()
            user.full_name = name
            user.updated_at = self._clock.now()
            await uow.commit()
            return user

    async def delete_account(
        self, principal: Principal, *, password: str, meta: RequestMeta
    ) -> None:
        """Erase personal data. Refused while the user is the sole owner of an org."""
        user_id = principal.user_id
        if user_id is None:
            raise NotFoundError()
        # Only from a signed-in session; a wrong password counts toward lockout.
        verified = await self._confirm_password(
            principal, password, meta, purpose="account_deletion"
        )
        now = self._clock.now()
        async with self._uow_factory(TenantScope(user_id=user_id)) as uow:
            user = await uow.users.get_for_update(user_id)
            if user is None:
                raise NotFoundError()
            if user.password_hash != verified:  # changed since it was confirmed
                raise PermissionDeniedError("The password is incorrect.", code="invalid_password")
            await erase_user(
                uow,
                user,
                audit=self._audit,
                actor=principal,
                meta=meta,
                now=now,
                reason="account_deleted",
            )
            # The erasure itself belongs to the platform chain: record it as the
            # user acting outside any organization (``org_id=None`` alone would
            # fall back to the organization the session was scoped to).
            await self._audit.record(
                uow.audit,
                action=AuditAction.ACCOUNT_DELETED,
                principal=replace(principal, org_id=None, role=None, permissions=frozenset()),
                meta=meta,
                resource_type="user",
                resource_id=user_id,
            )
            await uow.commit()

    # ------------------------------------------------------------ API keys

    async def create_api_key(
        self,
        principal: Principal,
        *,
        name: str,
        role: Role,
        scopes: list[str],
        expires_in_days: int,
        meta: RequestMeta,
    ) -> CreatedApiKey:
        org_id = principal.require_org()
        granted_scopes = validate_api_key_grant(principal, role=role, scopes=scopes)
        if not 1 <= expires_in_days <= MAX_API_KEY_LIFETIME_DAYS:
            raise InvalidInputError(
                f"expires_in_days must be between 1 and {MAX_API_KEY_LIFETIME_DAYS}."
            )
        clean_name = clean_text(name, max_length=100)
        if not clean_name:
            raise InvalidInputError("A name is required.")
        credential = generate_credential(CredentialKind.API_KEY)
        now = self._clock.now()
        key = ApiKey(
            id=uuid7(),
            org_id=org_id,
            name=clean_name,
            key_prefix=credential.prefix,
            key_hash=self._token_hasher.hash(credential.token),
            role=role,
            scopes=granted_scopes,
            created_by=principal.user_id,
            created_at=now,
            expires_at=now + timedelta(days=expires_in_days),
        )
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            await uow.api_keys.add(key)
            await self._audit.record(
                uow.audit,
                action=AuditAction.API_KEY_CREATED,
                principal=principal,
                meta=meta,
                resource_type="api_key",
                resource_id=key.id,
                metadata={
                    "role": role,
                    "scopes": granted_scopes,
                    "expires_in_days": expires_in_days,
                },
            )
            await uow.commit()
        return CreatedApiKey(key=key, token=credential.token)

    async def list_api_keys(self, principal: Principal, page: PageRequest) -> Page[ApiKey]:
        principal.require(Permission.API_KEYS_MANAGE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.api_keys.list_page(org_id, page)

    async def revoke_api_key(
        self, principal: Principal, *, key_id: UUID, meta: RequestMeta
    ) -> None:
        principal.require(Permission.API_KEYS_MANAGE)
        org_id = principal.require_org()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            key = await uow.api_keys.get(org_id, key_id)
            if key is None:
                raise NotFoundError()
            if key.revoked_at is None:
                key.revoked_at = now
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.API_KEY_REVOKED,
                    principal=principal,
                    meta=meta,
                    resource_type="api_key",
                    resource_id=key.id,
                )
                await uow.commit()

"""SCIM 2.0 provisioning (RFC 7643/7644): an organization's identity provider
creates, updates and deactivates its members.

* A SCIM token (``nxp_…``) belongs to one organization. An owner creates it
  from a signed-in session; it is shown once and stored as a keyed hash. It
  works on ``/scim/v2`` only - never on the rest of the API - and only for its
  own organization (explicit filters on top of row-level security).
* Accounts are the platform's; a directory entry (:class:`DirectoryUser`) is
  one organization's view of one. ``userName`` is the account's e-mail address
  and must be in a domain the organization has verified (docs/SSO.md): SCIM
  never touches an address outside the organization's own domains.
* A new account has no password (an unusable hash): the person signs in
  through the organization's identity provider, or sets a password with a
  reset link sent to the address.
* ``active: false`` and DELETE remove the membership and revoke the member's
  API keys there - exactly like removing a member. SCIM never creates,
  deactivates or removes an owner; the memberships it creates get the
  organization's default SSO role (viewer or analyst). Roles are managed in
  the application, and an existing member keeps their role.
* Names sent by SCIM are kept on the directory entry. The account's own
  profile, which every organization of the person shows, is set only when
  SCIM creates the account.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import (
    ConflictError,
    InvalidInputError,
    NotFoundError,
    PermissionDeniedError,
)
from nexusflow.core.ids import uuid7
from nexusflow.core.text import clean_text
from nexusflow.domain.audit.model import AuditAction, AuditResult
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal, PrincipalType
from nexusflow.domain.authorization.roles import Role
from nexusflow.domain.identity.api_keys import CredentialKind, generate_credential
from nexusflow.domain.identity.directory import (
    MAX_PAGE_SIZE,
    DirectoryFilter,
    DirectoryPage,
    DirectoryUser,
    DirectoryUserChanges,
    DirectoryUserInput,
    ScimToken,
    new_directory_account,
    normalize_user_name,
)
from nexusflow.domain.identity.sso import SsoConnection, email_domain
from nexusflow.domain.organizations.model import Membership
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.security import TokenHasher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory

MAX_TOKEN_LIFETIME_DAYS = 365
MAX_TOKENS_PER_ORGANIZATION = 10
_MAX_EXTERNAL_ID = 255


@dataclass(frozen=True, slots=True)
class CreatedScimToken:
    token: ScimToken
    secret: str  # returned exactly once; only a keyed hash is stored


def _require_owner_session(principal: Principal) -> UUID:
    """SCIM tokens are managed by owners, from a signed-in session: a machine
    credential never mints the credential that provisions people."""
    if principal.type is not PrincipalType.USER or principal.session_id is None:
        raise PermissionDeniedError(
            "This action requires a signed-in user session.", code="session_required"
        )
    if principal.role is not Role.OWNER:
        raise PermissionDeniedError(
            "Only owners manage SCIM provisioning tokens.", code="owner_required"
        )
    return principal.require_org()


def _scim_org(principal: Principal) -> UUID:
    if principal.type is not PrincipalType.SCIM or principal.org_id is None:
        raise PermissionDeniedError(internal_detail="not a SCIM principal")
    return principal.org_id


def _optional_text(value: str | None, *, max_length: int) -> str | None:
    if value is None:
        return None
    cleaned = clean_text(value, max_length=max_length)
    return cleaned or None


def _external_id(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > _MAX_EXTERNAL_ID or not cleaned.isprintable():
        raise InvalidInputError("externalId is too long or not printable.", code="invalidValue")
    return cleaned


def _account_name(data: DirectoryUserInput, email: str) -> str:
    parts = " ".join(p for p in (data.given_name, data.family_name) if p)
    for candidate in (data.display_name, data.formatted_name, parts):
        cleaned = clean_text(candidate or "", max_length=120)
        if cleaned:
            return cleaned
    return clean_text(email.split("@", 1)[0], max_length=120) or "Member"


class ProvisioningService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        token_hasher: TokenHasher,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._hasher = token_hasher

    # ------------------------------------------------------------ tokens

    async def create_token(
        self, principal: Principal, *, name: str, expires_in_days: int, meta: RequestMeta
    ) -> CreatedScimToken:
        org_id = _require_owner_session(principal)
        if not 1 <= expires_in_days <= MAX_TOKEN_LIFETIME_DAYS:
            raise InvalidInputError(
                f"expires_in_days must be between 1 and {MAX_TOKEN_LIFETIME_DAYS}.",
                code="invalid_lifetime",
            )
        clean_name = clean_text(name, max_length=100)
        if not clean_name:
            raise InvalidInputError("A name is required.", code="name_required")
        credential = generate_credential(CredentialKind.SCIM_TOKEN)
        now = self._clock.now()
        token = ScimToken(
            id=uuid7(),
            org_id=org_id,
            name=clean_name,
            token_prefix=credential.prefix,
            token_hash=self._hasher.hash(credential.token),
            created_by=principal.user_id,
            created_at=now,
            expires_at=now + timedelta(days=expires_in_days),
        )
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            live = [t for t in await uow.scim_tokens.list_for_org(org_id) if t.is_usable(now)]
            if len(live) >= MAX_TOKENS_PER_ORGANIZATION:
                raise ConflictError(
                    f"An organization has at most {MAX_TOKENS_PER_ORGANIZATION} live SCIM "
                    "tokens: revoke one first.",
                    code="too_many_tokens",
                )
            await uow.scim_tokens.add(token)
            await self._audit.record(
                uow.audit,
                action=AuditAction.SCIM_TOKEN_CREATED,
                principal=principal,
                meta=meta,
                resource_type="scim_token",
                resource_id=token.id,
                metadata={
                    "name": token.name,
                    "prefix": token.token_prefix,
                    "expires_in_days": expires_in_days,
                },
            )
            await uow.commit()
        return CreatedScimToken(token=token, secret=credential.token)

    async def list_tokens(self, principal: Principal) -> list[ScimToken]:
        org_id = _require_owner_session(principal)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.scim_tokens.list_for_org(org_id)

    async def revoke_token(self, principal: Principal, token_id: UUID, meta: RequestMeta) -> None:
        org_id = _require_owner_session(principal)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            token = await uow.scim_tokens.get(org_id, token_id)
            if token is None:
                raise NotFoundError()
            if token.revoked_at is None:
                token.revoked_at = self._clock.now()
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.SCIM_TOKEN_REVOKED,
                    principal=principal,
                    meta=meta,
                    resource_type="scim_token",
                    resource_id=token.id,
                    metadata={"name": token.name, "prefix": token.token_prefix},
                )
                await uow.commit()

    # ------------------------------------------------------------ users

    async def list_users(
        self,
        principal: Principal,
        *,
        directory_filter: DirectoryFilter | None,
        start_index: int,
        count: int,
    ) -> DirectoryPage:
        org_id = _scim_org(principal)
        start = max(start_index, 1)
        limit = min(max(count, 0), MAX_PAGE_SIZE)
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            total, items = await uow.scim_users.list_page(
                org_id, directory_filter=directory_filter, offset=start - 1, limit=limit
            )
        return DirectoryPage(total=total, start_index=start, items=items)

    async def get_user(self, principal: Principal, record_id: UUID) -> DirectoryUser:
        org_id = _scim_org(principal)
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            record = await uow.scim_users.get(org_id, record_id)
        if record is None:
            raise NotFoundError()
        return record

    async def create_user(
        self, principal: Principal, data: DirectoryUserInput, meta: RequestMeta
    ) -> DirectoryUser:
        org_id = _scim_org(principal)
        email = normalize_user_name(data.user_name)
        external_id = _external_id(data.external_id)
        now = self._clock.now()
        # Accounts are found by address before any tenant is involved: the
        # authentication context (as at sign-in), with explicit organization filters.
        async with self._uow_factory(TenantScope(org_id=org_id, auth_context=True)) as uow:
            connection = await uow.sso_connections.get_for_org(org_id)
            await self._require_domain(uow, principal, meta, connection, email)
            if external_id is not None and await uow.scim_users.get_by_external_id(
                org_id, external_id
            ):
                raise ConflictError("externalId is already in use.", code="uniqueness")
            user = await uow.users.get_by_email(email, for_update=True)
            account_created = user is None
            if user is None:
                user = new_directory_account(email, _account_name(data, email), now)
                await uow.users.add(user)
            elif await uow.scim_users.get_by_user(org_id, user.id) is not None:
                raise ConflictError("The user is already provisioned.", code="uniqueness")
            record = DirectoryUser(
                id=uuid7(),
                org_id=org_id,
                user_id=user.id,
                user_name=email,
                external_id=external_id,
                display_name=_optional_text(data.display_name, max_length=120),
                given_name=_optional_text(data.given_name, max_length=120),
                family_name=_optional_text(data.family_name, max_length=120),
                formatted_name=_optional_text(data.formatted_name, max_length=200),
                active=False,
                created_at=now,
                updated_at=now,
            )
            await uow.scim_users.add(record)
            if data.active:
                await self._activate(uow, principal, meta, connection, record, now)
            await self._audit.record(
                uow.audit,
                action=AuditAction.SCIM_USER_CREATED,
                principal=principal,
                meta=meta,
                resource_type="scim_user",
                resource_id=record.id,
                metadata={
                    "user_id": str(user.id),
                    "account_created": account_created,
                    "active": record.active,
                },
            )
            await uow.commit()
        return record

    async def replace_user(
        self, principal: Principal, record_id: UUID, data: DirectoryUserInput, meta: RequestMeta
    ) -> DirectoryUser:
        changes = DirectoryUserChanges(
            {
                "user_name": data.user_name,
                "external_id": data.external_id,
                "display_name": data.display_name,
                "given_name": data.given_name,
                "family_name": data.family_name,
                "formatted_name": data.formatted_name,
                "active": data.active,
            }
        )
        return await self.patch_user(principal, record_id, changes, meta)

    async def patch_user(
        self,
        principal: Principal,
        record_id: UUID,
        changes: DirectoryUserChanges,
        meta: RequestMeta,
    ) -> DirectoryUser:
        org_id = _scim_org(principal)
        now = self._clock.now()
        async with self._uow_factory(TenantScope(org_id=org_id, auth_context=True)) as uow:
            record = await uow.scim_users.get(org_id, record_id, for_update=True)
            if record is None:
                raise NotFoundError()
            changed = await self._apply(uow, org_id, record, changes)
            activity = changes.values.get("active")
            if activity is True and not record.active:
                connection = await uow.sso_connections.get_for_org(org_id)
                await self._require_domain(uow, principal, meta, connection, record.user_name)
                await self._activate(uow, principal, meta, connection, record, now)
                changed.append("active")
            elif activity is False and record.active:
                await self._deactivate(uow, principal, meta, record, now)
                changed.append("active")
            if changed:
                record.updated_at = now
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.SCIM_USER_UPDATED,
                    principal=principal,
                    meta=meta,
                    resource_type="scim_user",
                    resource_id=record.id,
                    metadata={"user_id": str(record.user_id), "changed": sorted(changed)},
                )
            await uow.commit()
        return record

    async def delete_user(self, principal: Principal, record_id: UUID, meta: RequestMeta) -> None:
        org_id = _scim_org(principal)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            record = await uow.scim_users.get(org_id, record_id, for_update=True)
            if record is None:
                raise NotFoundError()
            if record.active:
                await self._deactivate(uow, principal, meta, record, now)
            await uow.scim_users.delete(record)
            await self._audit.record(
                uow.audit,
                action=AuditAction.SCIM_USER_DELETED,
                principal=principal,
                meta=meta,
                resource_type="scim_user",
                resource_id=record.id,
                metadata={"user_id": str(record.user_id)},
            )
            await uow.commit()

    # ---------------------------------------------------------- helpers

    async def _apply(
        self, uow: UnitOfWork, org_id: UUID, record: DirectoryUser, changes: DirectoryUserChanges
    ) -> list[str]:
        changed: list[str] = []
        values = changes.values
        if "user_name" in values and normalize_user_name(values["user_name"]) != record.user_name:
            # The address is the account's sign-in identifier, shared by every
            # organization of the person: an organization cannot change it.
            raise InvalidInputError(
                "userName cannot be changed: deprovision the user and provision the new address.",
                code="mutability",
            )
        if "external_id" in values:
            external_id = _external_id(values["external_id"])
            if external_id != record.external_id:
                other = (
                    await uow.scim_users.get_by_external_id(org_id, external_id)
                    if external_id is not None
                    else None
                )
                if other is not None and other.id != record.id:
                    raise ConflictError("externalId is already in use.", code="uniqueness")
                record.external_id = external_id
                changed.append("externalId")
        for key, limit, label in (
            ("display_name", 120, "displayName"),
            ("given_name", 120, "name.givenName"),
            ("family_name", 120, "name.familyName"),
            ("formatted_name", 200, "name.formatted"),
        ):
            if key in values:
                value = _optional_text(values[key], max_length=limit)
                if value != getattr(record, key):
                    setattr(record, key, value)
                    changed.append(label)
        return changed

    async def _require_domain(
        self,
        uow: UnitOfWork,
        principal: Principal,
        meta: RequestMeta,
        connection: SsoConnection | None,
        email: str,
    ) -> None:
        domain = email_domain(email)
        if connection is None or domain is None or not connection.accepts_domain(domain):
            await self._refused(
                principal,
                meta,
                "domain_not_verified" if connection is not None else "sso_not_configured",
                {"email_domain": domain},
            )
            raise InvalidInputError(
                "userName must be an address in one of the organization's verified domains "
                "(configure single sign-on and verify the domain first).",
                code="invalidValue",
            )

    async def _activate(
        self,
        uow: UnitOfWork,
        principal: Principal,
        meta: RequestMeta,
        connection: SsoConnection | None,
        record: DirectoryUser,
        now: datetime,
    ) -> None:
        if connection is None:  # guarded by _require_domain
            raise InvalidInputError("Single sign-on is not configured.", code="invalidValue")
        membership = await uow.memberships.get(record.org_id, record.user_id)
        if membership is None:
            membership = Membership(
                id=uuid7(),
                org_id=record.org_id,
                user_id=record.user_id,
                role=connection.default_role,
                created_at=now,
                updated_at=now,
            )
            await uow.memberships.add(membership)
            await self._audit.record(
                uow.audit,
                action=AuditAction.MEMBER_JOINED,
                principal=principal,
                meta=meta,
                resource_type="membership",
                resource_id=membership.id,
                metadata={
                    "user_id": str(record.user_id),
                    "role": membership.role,
                    "via": "scim",
                },
            )
        if not record.active:
            record.active = True
            if record.created_at != now:  # an existing entry, not one created just now
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.SCIM_USER_REACTIVATED,
                    principal=principal,
                    meta=meta,
                    resource_type="scim_user",
                    resource_id=record.id,
                    metadata={"user_id": str(record.user_id)},
                )

    async def _deactivate(
        self,
        uow: UnitOfWork,
        principal: Principal,
        meta: RequestMeta,
        record: DirectoryUser,
        now: datetime,
    ) -> None:
        """Deprovision: remove the membership and revoke the member's API keys
        there (their sessions lose the organization at once: every request
        checks the membership). Owners are managed in the application only."""
        membership = await uow.memberships.get(record.org_id, record.user_id)
        if membership is not None:
            if membership.role is Role.OWNER:
                await self._refused(
                    principal, meta, "owner_protected", {"user_id": str(record.user_id)}
                )
                raise PermissionDeniedError(
                    "SCIM cannot deactivate or remove an owner; transfer ownership in the "
                    "application first.",
                    code="scim_owner_protected",
                )
            await uow.memberships.delete(membership)
            revoked = await uow.api_keys.revoke_created_by(record.org_id, record.user_id, now=now)
            await self._audit.record(
                uow.audit,
                action=AuditAction.MEMBER_REMOVED,
                principal=principal,
                meta=meta,
                resource_type="membership",
                resource_id=membership.id,
                metadata={
                    "user_id": str(record.user_id),
                    "via": "scim",
                    "api_keys_revoked": revoked,
                },
            )
        record.active = False
        await self._audit.record(
            uow.audit,
            action=AuditAction.SCIM_USER_DEACTIVATED,
            principal=principal,
            meta=meta,
            resource_type="scim_user",
            resource_id=record.id,
            metadata={"user_id": str(record.user_id), "membership_removed": membership is not None},
        )

    async def _refused(
        self, principal: Principal, meta: RequestMeta, reason: str, metadata: dict[str, Any]
    ) -> None:
        """Refused provisioning requests are audited in their own transaction
        (the request's own changes roll back)."""
        async with self._uow_factory(TenantScope.system(principal.org_id)) as uow:
            await self._audit.record(
                uow.audit,
                action=AuditAction.SCIM_REQUEST_REFUSED,
                principal=principal,
                meta=meta,
                result=AuditResult.DENIED,
                resource_type="organization",
                resource_id=principal.org_id,
                metadata={"reason": reason, **metadata},
            )
            await uow.commit()

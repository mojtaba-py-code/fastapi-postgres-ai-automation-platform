"""Data-subject rights: a person's copy of their data, and erasure on request.

UK GDPR / GDPR articles 15 and 20 (access and portability) and 17 (erasure).
The export holds the personal data the platform keeps about the account
itself - profile, organizations, sessions, API keys and the account's own
actions in its organizations' audit trails. An organization's business data
belongs to the organization, the controller, which exports it (dataset
exports), not to the person.

People erase their own account from a signed-in session
(``AccountService.delete_account``); an operator does it on a request made
outside the platform (``nexusflow user erase``), and exports on such a
request as well (``nexusflow user export``), then with the account's entries
in the platform's own audit chain too.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import InvalidInputError, NotFoundError, PermissionDeniedError
from nexusflow.core.jsonutil import JSONObject, JSONValue
from nexusflow.core.pagination import Cursor, PageRequest, decode_cursor
from nexusflow.core.text import clean_text
from nexusflow.domain.audit.model import PLATFORM_CHAIN, AuditAction, AuditLogEntry
from nexusflow.domain.audit.ports import AuditFilter
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.identity.account_service import erase_user
from nexusflow.domain.identity.auth_service import normalize_email
from nexusflow.domain.identity.login_risk import describe_client
from nexusflow.domain.identity.model import ApiKey, User
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory

EXPORT_FORMAT = "nexusflow-personal-data/1"
MAX_SESSIONS = 500
MAX_API_KEYS = 500
MAX_ACTIVITY_PER_ORGANIZATION = 1000
MAX_PLATFORM_ENTRIES_SCANNED = 200_000
_PAGE = 200


def _when(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


class PrivacyService:
    def __init__(
        self, *, uow_factory: UnitOfWorkFactory, clock: Clock, audit: AuditRecorder
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit

    async def export_own(self, principal: Principal, meta: RequestMeta) -> JSONObject:
        """The signed-in person's copy of their data (only from a session: an
        API key must not hand out its creator's sessions and addresses)."""
        if principal.session_id is None or principal.user_id is None:
            raise PermissionDeniedError(
                "This action requires a signed-in user session.", code="session_required"
            )
        if principal.sso_org_id is not None:
            # The copy covers every organization of the person: an organization's
            # identity provider does not hand it out. Sign in with the account's
            # password (a reset link sets one) - or ask the operator.
            raise PermissionDeniedError(
                "Sign in with your password to export your data: a single sign-on session "
                "reaches its organization only.",
                code="sso_session_restricted",
            )
        document = await self._export(principal.user_id, platform_chain=False)
        async with self._uow_factory(TenantScope(user_id=principal.user_id)) as uow:
            await self._audit.record(
                uow.audit,
                action=AuditAction.PERSONAL_DATA_EXPORTED,
                principal=replace(principal, org_id=None, role=None, permissions=frozenset()),
                meta=meta,
                resource_type="user",
                resource_id=principal.user_id,
            )
            await uow.commit()
        return document

    async def export_for(self, email: str, meta: RequestMeta) -> JSONObject:
        """Operator path: an access request received outside the platform. It
        also lists the account's entries in the platform audit chain."""
        user = await self._find(email)
        document = await self._export(user.id, platform_chain=True)
        await self._operator_audit(AuditAction.PERSONAL_DATA_EXPORTED, user.id, meta, {})
        return document

    async def erase_for(self, email: str, *, reason: str, meta: RequestMeta) -> UUID:
        """Operator path: an erasure request received outside the platform (the
        person cannot sign in). Refused, as in the app, while the person is
        the sole owner of an organization."""
        cleaned = clean_text(reason, max_length=200)
        if len(cleaned) < 3:
            raise InvalidInputError("A reason is required.", code="reason_required")
        user = await self._find(email)
        now = self._clock.now()
        async with self._uow_factory(TenantScope(user_id=user.id)) as uow:
            account = await uow.users.get_for_update(user.id)
            if account is None:
                raise NotFoundError()
            await erase_user(
                uow,
                account,
                audit=self._audit,
                actor=Principal.system(),
                meta=meta,
                now=now,
                reason="erasure_request",
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.ACCOUNT_DELETED,
                principal=Principal.system(),
                meta=meta,
                resource_type="user",
                resource_id=user.id,
                metadata={"by": "operator", "reason": cleaned},
            )
            await uow.commit()
        return user.id

    # ---------------------------------------------------------------- helpers

    async def _find(self, email: str) -> User:
        async with self._uow_factory(TenantScope.auth()) as uow:
            user = await uow.users.get_by_email(normalize_email(email))
        if user is None:
            raise NotFoundError("No account has this e-mail address.")
        return user

    async def _operator_audit(
        self, action: AuditAction, user_id: UUID, meta: RequestMeta, metadata: JSONObject
    ) -> None:
        async with self._uow_factory(TenantScope.system(None)) as uow:
            await self._audit.record(
                uow.audit,
                action=action,
                principal=Principal.system(),
                meta=meta,
                resource_type="user",
                resource_id=user_id,
                metadata={"by": "operator", **metadata},
            )
            await uow.commit()

    async def _export(self, user_id: UUID, *, platform_chain: bool) -> JSONObject:
        notes: list[JSONValue] = [
            (
                "An organization's business data (datasets, records, reports) belongs to "
                "the organization and is exported by it."
            ),
            (
                f"Activity lists at most the {MAX_ACTIVITY_PER_ORGANIZATION} most recent "
                "entries per organization, for the organizations the account belongs to now."
            ),
        ]
        async with self._uow_factory(TenantScope(user_id=user_id)) as uow:
            user = await uow.users.get(user_id)
            if user is None:
                raise NotFoundError()
            sessions = await uow.sessions.list_for_user(user_id, limit=MAX_SESSIONS)
            identities = await uow.sso_identities.list_for_user(user_id, MAX_SESSIONS)
            directory = await uow.scim_users.list_for_user(user_id, MAX_SESSIONS)
            org_ids = await uow.memberships.list_org_ids_for_user(user_id)
            organizations: list[JSONValue] = []
            api_keys: list[JSONValue] = []
            activity: list[JSONValue] = []
            for org_id in org_ids:
                await uow.switch_tenant(org_id)
                membership = await uow.memberships.get(org_id, user_id)
                organization = await uow.organizations.get(org_id)
                if membership is None or organization is None:
                    continue
                organizations.append(
                    {
                        "id": str(org_id),
                        "name": organization.name,
                        "role": membership.role.value,
                        "member_since": _when(membership.created_at),
                    }
                )
                keys = await uow.api_keys.list_created_by(org_id, user_id, MAX_API_KEYS)
                api_keys.extend(_api_key(key) for key in keys)
                activity.extend(await _activity(uow, org_id, user_id))
            platform: list[JSONValue] = []
            if platform_chain:
                await uow.switch_tenant(None)
                platform = await _platform_activity(uow, user_id)
        document: JSONObject = {
            "format": EXPORT_FORMAT,
            "generated_at": self._clock.now().isoformat(),
            "account": {
                "id": str(user.id),
                "email": user.email,
                "full_name": user.full_name,
                "status": user.status.value,
                "created_at": _when(user.created_at),
                "email_verified_at": _when(user.email_verified_at),
                "last_login_at": _when(user.last_login_at),
                "password_changed_at": _when(user.password_changed_at),
                "mfa_enabled": user.mfa_enabled,
            },
            "organizations": organizations,
            "sessions": [
                {
                    "id": str(s.id),
                    "created_at": _when(s.created_at),
                    "last_used_at": _when(s.last_used_at),
                    "expires_at": _when(s.expires_at),
                    "revoked_at": _when(s.revoked_at),
                    "revoke_reason": s.revoke_reason,
                    "ip": s.ip,
                    "device": describe_client(s.user_agent),
                    "user_agent": s.user_agent,
                    "mfa_verified": s.mfa_verified,
                    "single_sign_on_organization_id": str(s.sso_org_id) if s.sso_org_id else None,
                }
                for s in sessions
            ],
            "identity_provider_links": [
                {
                    "organization_id": str(i.org_id),
                    "issuer": i.issuer,
                    "subject": i.subject,
                    "email": i.email,
                    "linked_at": _when(i.created_at),
                    "last_sign_in_at": _when(i.last_login_at),
                }
                for i in identities
            ],
            "directory_entries": [
                {
                    "organization_id": str(d.org_id),
                    "user_name": d.user_name,
                    "external_id": d.external_id,
                    "display_name": d.display_name,
                    "given_name": d.given_name,
                    "family_name": d.family_name,
                    "active": d.active,
                    "created_at": _when(d.created_at),
                }
                for d in directory
            ],
            "api_keys": api_keys,
            "activity": activity,
            "notes": notes,
        }
        if platform_chain:
            document["platform_activity"] = platform
        return document


def _api_key(key: ApiKey) -> JSONObject:
    return {
        "id": str(key.id),
        "organization_id": str(key.org_id),
        "name": key.name,
        "role": key.role.value,
        "scopes": list(key.scopes),
        "created_at": _when(key.created_at),
        "expires_at": _when(key.expires_at),
        "last_used_at": _when(key.last_used_at),
        "revoked_at": _when(key.revoked_at),
    }


def _entry(entry: AuditLogEntry) -> JSONObject:
    return {
        "organization_id": str(entry.org_id) if entry.org_id else None,
        "occurred_at": entry.occurred_at.isoformat(),
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "result": entry.result,
        "ip": entry.ip,
        "user_agent": entry.user_agent,
    }


async def _activity(uow: UnitOfWork, org_id: UUID, user_id: UUID) -> list[JSONValue]:
    found: list[JSONValue] = []
    cursor: Cursor | None = None
    while len(found) < MAX_ACTIVITY_PER_ORGANIZATION:
        page = await uow.audit.list_page(
            org_id, AuditFilter(actor_id=user_id), PageRequest(limit=_PAGE, cursor=cursor)
        )
        found.extend(_entry(entry) for entry in page.items)
        if page.next_cursor is None:
            break
        cursor = decode_cursor(page.next_cursor)
    return found[:MAX_ACTIVITY_PER_ORGANIZATION]


async def _platform_activity(uow: UnitOfWork, user_id: UUID) -> list[JSONValue]:
    found: list[JSONValue] = []
    scanned, next_seq = 0, 1
    while scanned < MAX_PLATFORM_ENTRIES_SCANNED:
        batch = await uow.audit.chain(PLATFORM_CHAIN, from_seq=next_seq, limit=1000)
        if not batch:
            break
        scanned += len(batch)
        found.extend(_entry(e) for e in batch if e.actor_id == user_id)
        next_seq = batch[-1].seq + 1
    return found

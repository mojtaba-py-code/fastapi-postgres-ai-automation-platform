"""Organization, membership and invitation use cases."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from nexusflow.core.clock import Clock
from nexusflow.core.errors import ConflictError, InvalidInputError, NotFoundError
from nexusflow.core.ids import uuid7
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.core.text import clean_text
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.policies import (
    ensure_can_assign_role,
    ensure_not_self,
    ensure_owner_remains,
)
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission, Role
from nexusflow.domain.identity.auth_service import normalize_email
from nexusflow.domain.organizations.model import (
    Invitation,
    Membership,
    MembershipView,
    Organization,
    OrganizationSettings,
    OrganizationStatus,
    OrganizationView,
)
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.security import TokenHasher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWorkFactory

DELETION_GRACE_PERIOD = timedelta(days=7)


class OrganizationService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        token_hasher: TokenHasher,
        invitation_ttl_seconds: int,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._token_hasher = token_hasher
        self._invitation_ttl = timedelta(seconds=invitation_ttl_seconds)

    # ----------------------------------------------------------- organization

    async def get_current(self, principal: Principal) -> Organization:
        principal.require(Permission.ORG_READ)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            org = await uow.organizations.get(org_id)
            if org is None:
                raise NotFoundError()
            return org

    async def list_for_user(self, principal: Principal) -> list[OrganizationView]:
        """The caller's organizations - from a session an identity provider
        opened, only that provider's organization."""
        if principal.user_id is None:
            return []
        async with self._uow_factory(TenantScope(user_id=principal.user_id)) as uow:
            views = await uow.organizations.list_for_user(principal.user_id)
        if principal.sso_org_id is not None:
            return [view for view in views if view.org_id == principal.sso_org_id]
        return views

    async def update(
        self,
        principal: Principal,
        *,
        name: str | None,
        settings: Mapping[str, Any] | None,
        meta: RequestMeta,
    ) -> Organization:
        """``settings`` is a *partial* update merged into the current policy.

        ``automation_frozen`` is not accepted here: freezing has its own audited,
        reason-carrying operation, so a routine settings change can never lift
        an incident freeze as a side effect. Neither is ``sso_required``: it
        belongs to the single sign-on configuration, which checks it cannot
        lock the organization out.
        """
        principal.require(Permission.ORG_UPDATE)
        org_id = principal.require_org()
        now = self._clock.now()
        if settings is not None and "automation_frozen" in settings:
            raise InvalidInputError(
                "Use the automation-freeze operation to change automation_frozen.",
                code="use_automation_freeze",
            )
        if settings is not None and "sso_required" in settings:
            raise InvalidInputError(
                "Use the single sign-on configuration to change sso_required.",
                code="use_sso_configuration",
            )
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            org = await uow.organizations.get_for_update(org_id)
            if org is None:
                raise NotFoundError()
            changes: dict[str, Any] = {}
            if name is not None:
                cleaned = clean_text(name, max_length=120)
                if not cleaned:
                    raise InvalidInputError("Organization name is required.")
                org.name = cleaned
                changes["name"] = cleaned
            if settings:
                before = org.policy
                try:
                    merged = OrganizationSettings.model_validate(
                        {**before.model_dump(mode="json"), **settings}
                    )
                except ValidationError as exc:
                    raise InvalidInputError(
                        "Invalid organization settings.", code="invalid_settings"
                    ) from exc
                if merged.allowed_ip_ranges != before.allowed_ip_ranges and not merged.allows_ip(
                    meta.ip
                ):
                    # Never let an administrator lock the organization out by mistake.
                    raise InvalidInputError(
                        "The network allowlist must include the address you are using.",
                        code="would_lock_you_out",
                    )
                org.update_policy(merged, now)
                changes["settings"] = {
                    key: value
                    for key, value in merged.model_dump(mode="json").items()
                    if getattr(before, key) != getattr(merged, key)
                }
            org.updated_at = now
            await self._audit.record(
                uow.audit,
                action=AuditAction.ORG_UPDATED,
                principal=principal,
                meta=meta,
                resource_type="organization",
                resource_id=org.id,
                metadata=changes,
            )
            await uow.commit()
            return org

    async def set_automation_frozen(
        self, principal: Principal, *, frozen: bool, reason: str, meta: RequestMeta
    ) -> Organization:
        """Incident kill switch: stop every automated workflow of the tenant."""
        principal.require(Permission.WORKFLOWS_DISABLE)
        org_id = principal.require_org()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            org = await uow.organizations.get_for_update(org_id)
            if org is None:
                raise NotFoundError()
            org.update_policy(org.policy.model_copy(update={"automation_frozen": frozen}), now)
            await self._audit.record(
                uow.audit,
                action=AuditAction.ORG_AUTOMATION_FROZEN
                if frozen
                else AuditAction.ORG_AUTOMATION_UNFROZEN,
                principal=principal,
                meta=meta,
                resource_type="organization",
                resource_id=org.id,
                metadata={"reason": clean_text(reason, max_length=200)},
            )
            await uow.commit()
            return org

    async def clear_network_allowlist(
        self, org_id: UUID, *, reason: str, meta: RequestMeta
    ) -> Organization:
        """Operator recovery for an organization locked out by its own allowlist.

        Reachable only from the operator CLI, never from the tenant API. The
        organization's own audit trail records it, with the reason, so its
        administrators see exactly what was changed and why.
        """
        cleaned = clean_text(reason, max_length=200)
        if len(cleaned) < 3:
            raise InvalidInputError("A reason is required.", code="reason_required")
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            org = await uow.organizations.get_for_update(org_id)
            if org is None:
                raise NotFoundError()
            removed = org.policy.allowed_ip_ranges or []
            org.update_policy(org.policy.model_copy(update={"allowed_ip_ranges": None}), now)
            org.updated_at = now
            await self._audit.record(
                uow.audit,
                action=AuditAction.ORG_NETWORK_ALLOWLIST_CLEARED,
                principal=Principal.system(),
                meta=meta,
                org_id=org.id,
                resource_type="organization",
                resource_id=org.id,
                metadata={"reason": cleaned, "removed": removed},
            )
            await uow.commit()
            return org

    async def request_deletion(
        self, principal: Principal, *, confirm_slug: str, meta: RequestMeta
    ) -> Organization:
        principal.require(Permission.ORG_DELETE)
        org_id = principal.require_org()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            org = await uow.organizations.get_for_update(org_id)
            if org is None:
                raise NotFoundError()
            if confirm_slug != org.slug:
                raise InvalidInputError(
                    "Type the organization slug to confirm deletion.", code="confirmation_mismatch"
                )
            org.status = OrganizationStatus.PENDING_DELETION
            org.deletion_requested_at = now
            org.updated_at = now
            await uow.outbox.add(
                new_message(
                    TaskName.PURGE_ORGANIZATION,
                    {"org_id": str(org.id)},
                    org_id=org.id,
                    now=now,
                    delay=DELETION_GRACE_PERIOD,
                )
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.ORG_DELETION_REQUESTED,
                principal=principal,
                meta=meta,
                resource_type="organization",
                resource_id=org.id,
                metadata={"purge_after": (now + DELETION_GRACE_PERIOD).isoformat()},
            )
            await uow.commit()
            return org

    # ------------------------------------------------------------- members

    async def list_members(self, principal: Principal, page: PageRequest) -> Page[MembershipView]:
        principal.require(Permission.MEMBERS_READ)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.memberships.list_views(org_id, page)

    async def change_role(
        self, principal: Principal, *, membership_id: UUID, role: Role, meta: RequestMeta
    ) -> Membership:
        org_id = principal.require_org()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            membership = await uow.memberships.get_by_id(org_id, membership_id)
            if membership is None:
                raise NotFoundError()
            ensure_not_self(principal, membership.user_id)
            ensure_can_assign_role(principal, current=membership.role, new=role)
            if membership.role is Role.OWNER and role is not Role.OWNER:
                ensure_owner_remains(
                    await uow.memberships.count_owners(org_id), removing_owner=True
                )
            previous = membership.role
            membership.role = role
            membership.updated_at = now
            await self._audit.record(
                uow.audit,
                action=AuditAction.MEMBER_ROLE_CHANGED,
                principal=principal,
                meta=meta,
                resource_type="membership",
                resource_id=membership.id,
                metadata={"user_id": str(membership.user_id), "from": previous, "to": role},
            )
            await uow.commit()
            return membership

    async def remove_member(
        self, principal: Principal, *, membership_id: UUID, meta: RequestMeta
    ) -> None:
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            membership = await uow.memberships.get_by_id(org_id, membership_id)
            if membership is None:
                raise NotFoundError()
            leaving_self = membership.user_id == principal.user_id
            if not leaving_self:
                ensure_can_assign_role(principal, current=membership.role, new=membership.role)
            if membership.role is Role.OWNER:
                ensure_owner_remains(
                    await uow.memberships.count_owners(org_id), removing_owner=True
                )
            await uow.memberships.delete(membership)
            # Authentication already refuses keys of former members; revoking
            # them as well keeps the key list truthful for the admins.
            revoked = await uow.api_keys.revoke_created_by(
                org_id, membership.user_id, now=self._clock.now()
            )
            # The organization's directory (SCIM) sees the person as inactive
            # now; its identity provider re-activates them only on purpose.
            entry = await uow.scim_users.get_by_user(org_id, membership.user_id)
            if entry is not None and entry.active:
                entry.active = False
                entry.updated_at = self._clock.now()
            await self._audit.record(
                uow.audit,
                action=AuditAction.MEMBER_REMOVED,
                principal=principal,
                meta=meta,
                resource_type="membership",
                resource_id=membership.id,
                metadata={
                    "user_id": str(membership.user_id),
                    "self": leaving_self,
                    "api_keys_revoked": revoked,
                },
            )
            await uow.commit()

    # --------------------------------------------------------- invitations

    async def invite(
        self, principal: Principal, *, email: str, role: Role, meta: RequestMeta
    ) -> Invitation:
        org_id = principal.require_org()
        ensure_can_assign_role(principal, current=None, new=role)
        email_n = normalize_email(email)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            if await uow.invitations.find_pending_by_email(org_id, email_n) is not None:
                raise ConflictError(
                    "A pending invitation already exists for this email.", code="invitation_pending"
                )
            invitation = Invitation(
                id=uuid7(),
                org_id=org_id,
                email=email_n,
                role=role,
                token_hash=None,  # the mail worker generates the token (never exposed here)
                invited_by=principal.user_id,
                created_at=now,
                expires_at=now + self._invitation_ttl,
            )
            await uow.invitations.add(invitation)
            await uow.outbox.add(
                new_message(
                    TaskName.SEND_INVITATION,
                    {"invitation_id": str(invitation.id), "org_id": str(org_id)},
                    org_id=org_id,
                    now=now,
                )
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.MEMBER_INVITED,
                principal=principal,
                meta=meta,
                resource_type="invitation",
                resource_id=invitation.id,
                metadata={"role": role, "email_domain": email_n.split("@")[-1]},
            )
            await uow.commit()
            return invitation

    async def list_invitations(self, principal: Principal, page: PageRequest) -> Page[Invitation]:
        principal.require(Permission.MEMBERS_MANAGE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.invitations.list_pending(org_id, page)

    async def revoke_invitation(
        self, principal: Principal, *, invitation_id: UUID, meta: RequestMeta
    ) -> None:
        principal.require(Permission.MEMBERS_MANAGE)
        org_id = principal.require_org()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            invitation = await uow.invitations.get(org_id, invitation_id)
            if invitation is None or not invitation.is_pending(now):
                raise NotFoundError()
            invitation.revoked_at = now
            await self._audit.record(
                uow.audit,
                action=AuditAction.MEMBER_INVITATION_REVOKED,
                principal=principal,
                meta=meta,
                resource_type="invitation",
                resource_id=invitation.id,
            )
            await uow.commit()

    async def accept_invitation(
        self, principal: Principal, *, token: str, meta: RequestMeta
    ) -> Membership:
        """Existing users join an organization. The invitation must be addressed
        to the authenticated account's email (links cannot be hijacked)."""
        user_id = principal.user_id
        if user_id is None or not token or len(token) > 256:
            raise InvalidInputError(
                "The invitation is invalid or has expired.", code="invalid_invitation"
            )
        now = self._clock.now()
        async with self._uow_factory(TenantScope(user_id=user_id, auth_context=True)) as uow:
            invitation = await uow.invitations.find_by_token_hash(self._token_hasher.hash(token))
            user = await uow.users.get(user_id)
            if (
                invitation is None
                or user is None
                or not invitation.is_pending(now)
                or invitation.email != user.email
            ):
                raise InvalidInputError(
                    "The invitation is invalid or has expired.", code="invalid_invitation"
                )
            await uow.switch_tenant(invitation.org_id)
            if await uow.memberships.get(invitation.org_id, user_id) is not None:
                raise ConflictError("You are already a member of this organization.")
            membership = Membership(
                id=uuid7(),
                org_id=invitation.org_id,
                user_id=user_id,
                role=invitation.role,
                invited_by=invitation.invited_by,
                created_at=now,
                updated_at=now,
            )
            invitation.accepted_at = now
            await uow.memberships.add(membership)
            await self._audit.record(
                uow.audit,
                action=AuditAction.MEMBER_JOINED,
                principal=principal,
                meta=meta,
                org_id=invitation.org_id,
                resource_type="membership",
                resource_id=membership.id,
                metadata={"role": invitation.role},
            )
            await uow.commit()
            return membership

"""/api/v1/users, /organizations, /api-keys and /audit."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import AwareDatetime

from nexusflow.apps.api.dependencies import (
    ContainerDep,
    CurrentPrincipal,
    DefaultPage,
    Meta,
    page_params,
    require,
)
from nexusflow.apps.api.schemas.common import ERROR_RESPONSES, PageResponse
from nexusflow.apps.api.schemas.identity import (
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    AuditEntryResponse,
    AuditVerificationResponse,
    AutomationFreezeRequest,
    ChangeRoleRequest,
    CreateApiKeyRequest,
    InvitationResponse,
    InviteRequest,
    MemberResponse,
    OrganizationDeletionRequest,
    OrganizationResponse,
    OrganizationSummary,
    PasswordConfirmation,
    SessionResponse,
    UpdateOrganizationRequest,
    UpdateProfileRequest,
    UserResponse,
)
from nexusflow.core.pagination import PageRequest, SortSpec
from nexusflow.domain.audit.ports import AuditFilter
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.identity.login_risk import describe_client

users = APIRouter(prefix="/users", tags=["users"], responses=ERROR_RESPONSES)
organizations = APIRouter(
    prefix="/organizations", tags=["organizations"], responses=ERROR_RESPONSES
)
api_keys = APIRouter(prefix="/api-keys", tags=["api-keys"], responses=ERROR_RESPONSES)
audit = APIRouter(prefix="/audit", tags=["audit"], responses=ERROR_RESPONSES)


# ------------------------------------------------------------------- users


@users.get(
    "",
    response_model=PageResponse[MemberResponse],
    dependencies=[Depends(require(Permission.MEMBERS_READ))],
    summary="Users of the current organization (same as /organizations/current/members)",
)
async def list_users(
    principal: CurrentPrincipal, container: ContainerDep, page: DefaultPage
) -> PageResponse[MemberResponse]:
    result = await container.organizations.list_members(principal, page)
    return PageResponse[MemberResponse](
        items=[MemberResponse.model_validate(m) for m in result.items],
        next_cursor=result.next_cursor,
    )


@users.get("/me", response_model=UserResponse)
async def get_me(principal: CurrentPrincipal, container: ContainerDep) -> UserResponse:
    return UserResponse.model_validate(await container.accounts.get_profile(principal))


@users.patch("/me", response_model=UserResponse)
async def update_me(
    body: UpdateProfileRequest, principal: CurrentPrincipal, container: ContainerDep
) -> UserResponse:
    user = await container.accounts.update_profile(principal, full_name=body.full_name)
    return UserResponse.model_validate(user)


@users.get(
    "/me/sessions",
    response_model=list[SessionResponse],
    summary="My signed-in sessions (devices), most recently used first",
)
async def my_sessions(
    principal: CurrentPrincipal, container: ContainerDep
) -> list[SessionResponse]:
    return [
        SessionResponse(
            id=session.id,
            current=session.id == principal.session_id,
            device=describe_client(session.user_agent),
            ip=session.ip,
            mfa_verified=session.mfa_verified,
            created_at=session.created_at,
            last_used_at=session.last_used_at,
            expires_at=session.expires_at,
        )
        for session in await container.auth.list_sessions(principal)
    ]


@users.delete(
    "/me/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="End one of my sessions (its tokens stop working at once)",
)
async def revoke_my_session(
    session_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.auth.revoke_session(principal, session_id, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@users.post("/me/delete", status_code=status.HTTP_204_NO_CONTENT, summary="Erase my account")
async def delete_me(
    body: PasswordConfirmation, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.accounts.delete_account(principal, password=body.password, meta=meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------ organizations


@organizations.get("", response_model=list[OrganizationSummary])
async def list_my_organizations(
    principal: CurrentPrincipal, container: ContainerDep
) -> list[OrganizationSummary]:
    views = await container.organizations.list_for_user(principal)
    return [OrganizationSummary.model_validate(v) for v in views]


@organizations.get("/current", response_model=OrganizationResponse)
async def get_current_organization(
    principal: CurrentPrincipal, container: ContainerDep
) -> OrganizationResponse:
    return OrganizationResponse.model_validate(await container.organizations.get_current(principal))


@organizations.patch(
    "/current",
    response_model=OrganizationResponse,
    dependencies=[Depends(require(Permission.ORG_UPDATE))],
)
async def update_current_organization(
    body: UpdateOrganizationRequest,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> OrganizationResponse:
    # exclude_unset: an explicit null (e.g. clearing the domain allowlist) is a
    # change, an omitted field is not.
    patch = body.settings.model_dump(exclude_unset=True) if body.settings else None
    org = await container.organizations.update(principal, name=body.name, settings=patch, meta=meta)
    return OrganizationResponse.model_validate(org)


@organizations.post(
    "/current/automation-freeze",
    response_model=OrganizationResponse,
    dependencies=[Depends(require(Permission.WORKFLOWS_DISABLE))],
    summary="Incident kill switch for all automation of this organization",
)
async def freeze_automation(
    body: AutomationFreezeRequest, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> OrganizationResponse:
    org = await container.organizations.set_automation_frozen(
        principal, frozen=body.frozen, reason=body.reason, meta=meta
    )
    return OrganizationResponse.model_validate(org)


@organizations.post(
    "/current/deletion",
    response_model=OrganizationResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require(Permission.ORG_DELETE))],
)
async def request_organization_deletion(
    body: OrganizationDeletionRequest,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> OrganizationResponse:
    org = await container.organizations.request_deletion(
        principal, confirm_slug=body.confirm_slug, meta=meta
    )
    return OrganizationResponse.model_validate(org)


@organizations.get(
    "/current/members",
    response_model=PageResponse[MemberResponse],
    dependencies=[Depends(require(Permission.MEMBERS_READ))],
)
async def list_members(
    principal: CurrentPrincipal, container: ContainerDep, page: DefaultPage
) -> PageResponse[MemberResponse]:
    result = await container.organizations.list_members(principal, page)
    return PageResponse[MemberResponse](
        items=[MemberResponse.model_validate(m) for m in result.items],
        next_cursor=result.next_cursor,
    )


@organizations.patch(
    "/current/members/{membership_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.MEMBERS_MANAGE))],
)
async def change_member_role(
    membership_id: UUID,
    body: ChangeRoleRequest,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> Response:
    await container.organizations.change_role(
        principal, membership_id=membership_id, role=body.role, meta=meta
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@organizations.delete("/current/members/{membership_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    membership_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.organizations.remove_member(principal, membership_id=membership_id, meta=meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@organizations.post(
    "/current/invitations",
    response_model=InvitationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.MEMBERS_MANAGE))],
)
async def invite_member(
    body: InviteRequest, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> InvitationResponse:
    invitation = await container.organizations.invite(
        principal, email=str(body.email), role=body.role, meta=meta
    )
    return InvitationResponse.model_validate(invitation)


@organizations.get(
    "/current/invitations",
    response_model=PageResponse[InvitationResponse],
    dependencies=[Depends(require(Permission.MEMBERS_MANAGE))],
)
async def list_invitations(
    principal: CurrentPrincipal, container: ContainerDep, page: DefaultPage
) -> PageResponse[InvitationResponse]:
    result = await container.organizations.list_invitations(principal, page)
    return PageResponse[InvitationResponse](
        items=[InvitationResponse.model_validate(i) for i in result.items],
        next_cursor=result.next_cursor,
    )


@organizations.delete(
    "/current/invitations/{invitation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.MEMBERS_MANAGE))],
)
async def revoke_invitation(
    invitation_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.organizations.revoke_invitation(
        principal, invitation_id=invitation_id, meta=meta
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ----------------------------------------------------------------- API keys


@api_keys.post(
    "",
    response_model=ApiKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.API_KEYS_MANAGE))],
)
async def create_api_key(
    body: CreateApiKeyRequest, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> ApiKeyCreatedResponse:
    created = await container.accounts.create_api_key(
        principal,
        name=body.name,
        role=body.role,
        scopes=[scope.value for scope in body.scopes],
        expires_in_days=body.expires_in_days,
        meta=meta,
    )
    base = ApiKeyResponse.model_validate(created.key)
    return ApiKeyCreatedResponse(**base.model_dump(), token=created.token)


@api_keys.get(
    "",
    response_model=PageResponse[ApiKeyResponse],
    dependencies=[Depends(require(Permission.API_KEYS_MANAGE))],
)
async def list_api_keys(
    principal: CurrentPrincipal,
    container: ContainerDep,
    page: Annotated[PageRequest, Depends(page_params(frozenset({"created_at", "name"})))],
) -> PageResponse[ApiKeyResponse]:
    result = await container.accounts.list_api_keys(principal, page)
    return PageResponse[ApiKeyResponse](
        items=[ApiKeyResponse.model_validate(k) for k in result.items],
        next_cursor=result.next_cursor,
    )


@api_keys.delete(
    "/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.API_KEYS_MANAGE))],
)
async def revoke_api_key(
    key_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.accounts.revoke_api_key(principal, key_id=key_id, meta=meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# -------------------------------------------------------------------- audit


@audit.get(
    "",
    response_model=PageResponse[AuditEntryResponse],
    dependencies=[Depends(require(Permission.AUDIT_READ))],
)
async def list_audit_entries(
    *,
    principal: CurrentPrincipal,
    container: ContainerDep,
    page: Annotated[
        PageRequest,
        Depends(page_params(frozenset({"occurred_at"}), SortSpec("occurred_at", descending=True))),
    ],
    action: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z_.]+$")] = None,
    actor_id: UUID | None = None,
    resource_type: Annotated[str | None, Query(max_length=40, pattern=r"^[a-z_]+$")] = None,
    resource_id: Annotated[str | None, Query(max_length=64)] = None,
    result: Annotated[str | None, Query(pattern=r"^(success|failure|denied)$")] = None,
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
) -> PageResponse[AuditEntryResponse]:
    filters = AuditFilter(
        action=action,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        since=since,
        until=until,
    )
    entries = await container.audit_log.list_entries(principal, filters, page)
    return PageResponse[AuditEntryResponse](
        items=[AuditEntryResponse.model_validate(e) for e in entries.items],
        next_cursor=entries.next_cursor,
    )


@audit.get(
    "/verify",
    response_model=AuditVerificationResponse,
    dependencies=[Depends(require(Permission.AUDIT_READ))],
    summary="Recompute this organization's audit hash chain",
)
async def verify_audit_chain(
    principal: CurrentPrincipal, container: ContainerDep
) -> AuditVerificationResponse:
    result = await container.audit_log.verify_integrity(principal)
    return AuditVerificationResponse(
        ok=result.ok,
        checked=result.checked,
        first_invalid_seq=result.first_invalid_seq,
        reason=result.reason,
    )

"""/api/v1/organizations/current/sso and /scim-tokens - an organization's
identity provider (OpenID Connect) and its SCIM provisioning tokens.

Configuration needs an owner's or administrator's signed-in session (never an
API key); SCIM tokens are managed by owners only. The client secret and the
tokens are write-only: never returned (a new token is shown once).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Response, status

from nexusflow.apps.api.dependencies import ContainerDep, CurrentPrincipal, Meta, require
from nexusflow.apps.api.schemas.common import ERROR_RESPONSES
from nexusflow.apps.api.schemas.sso import (
    CreateScimTokenRequest,
    ScimTokenCreatedResponse,
    ScimTokenResponse,
    SsoConfigurationRequest,
    SsoConfigurationResponse,
    SsoDomainCheckResponse,
    SsoDomainResponse,
    SsoDomainVerificationResponse,
)
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.identity.sso_service import SsoConfiguration

router = APIRouter(
    prefix="/organizations/current",
    tags=["single sign-on"],
    responses=ERROR_RESPONSES,
    dependencies=[Depends(require(Permission.ORG_UPDATE))],
)


def _configuration(view: SsoConfiguration) -> SsoConfigurationResponse:
    connection = view.connection
    return SsoConfigurationResponse(
        issuer=connection.issuer,
        client_id=connection.client_id,
        allowed_domains=list(connection.allowed_domains),
        domains=[
            SsoDomainResponse(
                domain=status_.domain,
                verified=status_.verified,
                txt_record_name=status_.record_name,
                txt_record_value=status_.record_value,
            )
            for status_ in view.domains
        ],
        default_role=connection.default_role,
        sso_required=view.sso_required,
        trust_idp_mfa=connection.trust_idp_mfa,
        redirect_uri=view.redirect_uri,
        created_at=connection.created_at,
        updated_at=connection.updated_at,
    )


@router.get("/sso", response_model=SsoConfigurationResponse, summary="The identity provider")
async def get_sso(principal: CurrentPrincipal, container: ContainerDep) -> SsoConfigurationResponse:
    return _configuration(await container.sso.get_configuration(principal))


@router.put(
    "/sso",
    response_model=SsoConfigurationResponse,
    summary="Configure (or replace) the identity provider",
)
async def configure_sso(
    body: SsoConfigurationRequest, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> SsoConfigurationResponse:
    view = await container.sso.configure(
        principal,
        issuer=body.issuer,
        client_id=body.client_id,
        client_secret=body.client_secret,
        allowed_domains=body.allowed_domains,
        default_role=body.default_role,
        sso_required=body.sso_required,
        trust_idp_mfa=body.trust_idp_mfa,
        meta=meta,
    )
    return _configuration(view)


@router.delete(
    "/sso",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove the identity provider (its sessions end)",
)
async def remove_sso(principal: CurrentPrincipal, container: ContainerDep, meta: Meta) -> Response:
    await container.sso.remove(principal, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/sso/domains/verify",
    response_model=SsoDomainVerificationResponse,
    summary="Check the domains' TXT records; a match verifies the domain",
)
async def verify_sso_domains(
    principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> SsoDomainVerificationResponse:
    view, checks = await container.sso.verify_domains(principal, meta)
    return SsoDomainVerificationResponse(
        configuration=_configuration(view),
        checks=[SsoDomainCheckResponse(domain=c.domain, result=c.result) for c in checks],
    )


# ------------------------------------------------------------ SCIM tokens


@router.post(
    "/scim-tokens",
    response_model=ScimTokenCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a SCIM provisioning token (owners; shown once)",
)
async def create_scim_token(
    body: CreateScimTokenRequest, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> ScimTokenCreatedResponse:
    created = await container.provisioning.create_token(
        principal, name=body.name, expires_in_days=body.expires_in_days, meta=meta
    )
    base = ScimTokenResponse.model_validate(created.token)
    return ScimTokenCreatedResponse(**base.model_dump(), token=created.secret)


@router.get(
    "/scim-tokens",
    response_model=list[ScimTokenResponse],
    summary="SCIM provisioning tokens (owners)",
)
async def list_scim_tokens(
    principal: CurrentPrincipal, container: ContainerDep
) -> list[ScimTokenResponse]:
    tokens = await container.provisioning.list_tokens(principal)
    return [ScimTokenResponse.model_validate(token) for token in tokens]


@router.delete(
    "/scim-tokens/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a SCIM provisioning token (owners)",
)
async def revoke_scim_token(
    token_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.provisioning.revoke_token(principal, token_id, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

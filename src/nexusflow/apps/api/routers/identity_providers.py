"""/api/v1/organizations/current/sso - an organization's identity provider
(OpenID Connect).

Configuration needs an owner's or administrator's signed-in session (never an
API key). The client secret is write-only: never returned.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response, status

from nexusflow.apps.api.dependencies import ContainerDep, CurrentPrincipal, Meta, require
from nexusflow.apps.api.schemas.common import ERROR_RESPONSES
from nexusflow.apps.api.schemas.sso import (
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

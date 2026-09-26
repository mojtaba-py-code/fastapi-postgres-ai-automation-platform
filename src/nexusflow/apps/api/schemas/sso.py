"""Schemas for single sign-on (OpenID Connect)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from nexusflow.apps.api.schemas.common import RequestModel, ResponseModel
from nexusflow.domain.authorization.roles import Role

# ----------------------------------------------------------------- sign-in


class SsoStartRequest(RequestModel):
    organization: str = Field(min_length=1, max_length=63, description="The organization's slug.")


class SsoStartResponse(ResponseModel):
    authorization_url: str = Field(description="Send the browser here.")
    state: str = Field(description="Comes back on the redirect; compare it before the callback.")
    binding: str = Field(
        description=(
            "Keep it in memory or sessionStorage - never in a URL - and send it with the "
            "callback: only the client that started the sign-in can finish it."
        )
    )
    expires_in: int


class SsoCallbackRequest(RequestModel):
    code: str = Field(min_length=1, max_length=2048, repr=False)
    state: str = Field(min_length=1, max_length=256, repr=False)
    binding: str = Field(min_length=1, max_length=256, repr=False)


# ----------------------------------------------------------- configuration


class SsoConfigurationRequest(RequestModel):
    """The organization's identity provider. The client secret is write-only:
    required when single sign-on is first configured, optional afterwards (the
    stored one is kept)."""

    issuer: str = Field(min_length=1, max_length=512)
    client_id: str = Field(min_length=1, max_length=255)
    client_secret: str | None = Field(default=None, min_length=1, max_length=1024, repr=False)
    allowed_domains: list[str] = Field(min_length=1, max_length=20)
    default_role: Role = Role.VIEWER
    sso_required: bool = False
    trust_idp_mfa: bool = False


class SsoDomainResponse(ResponseModel):
    domain: str
    verified: bool
    txt_record_name: str = Field(description="Publish this TXT record to prove the domain.")
    txt_record_value: str


class SsoConfigurationResponse(ResponseModel):
    issuer: str
    client_id: str
    client_secret_set: Literal[True] = Field(
        default=True, description="The secret itself is never returned."
    )
    allowed_domains: list[str]
    domains: list[SsoDomainResponse]
    default_role: Role
    sso_required: bool
    trust_idp_mfa: bool
    redirect_uri: str = Field(description="Register exactly this URI at the identity provider.")
    created_at: datetime
    updated_at: datetime


class SsoDomainCheckResponse(ResponseModel):
    domain: str
    result: Literal["verified", "already_verified", "record_not_found", "lookup_failed"]


class SsoDomainVerificationResponse(ResponseModel):
    configuration: SsoConfigurationResponse
    checks: list[SsoDomainCheckResponse]

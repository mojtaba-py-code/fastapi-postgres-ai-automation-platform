"""/api/v1/auth - registration, login, MFA, token refresh, password flows."""

from __future__ import annotations

import hashlib
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Response, status

from nexusflow.apps.api.dependencies import (
    ContainerDep,
    CurrentPrincipal,
    Meta,
    MfaSetupPrincipal,
    StateDep,
    budget_identity,
    client_ip,
    rate_limited,
)
from nexusflow.apps.api.schemas.common import ERROR_RESPONSES
from nexusflow.apps.api.schemas.identity import (
    AcceptInvitationRequest,
    AuthenticatorSelection,
    CompleteRegistrationRequest,
    CredentialDescriptorJson,
    CredentialParameters,
    InvitedRegistrationRequest,
    LoginRequest,
    MfaChallengeResponse,
    MfaCodeRequest,
    MfaDisableRequest,
    MfaEnrollResponse,
    MfaRecoveryCodesResponse,
    MfaTokenRequest,
    MfaVerifyRequest,
    PasskeyCreationOptions,
    PasskeyCreationOptionsResponse,
    PasskeyRegisteredResponse,
    PasskeyRegistrationRequest,
    PasskeyRenameRequest,
    PasskeyRequestOptions,
    PasskeyRequestOptionsResponse,
    PasskeyResponse,
    PasskeySignInRequest,
    PasskeyUserEntity,
    PasswordChangeRequest,
    PasswordConfirmation,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    RegistrationStartedResponse,
    RelyingPartyEntity,
    SwitchOrganizationRequest,
    TokenResponse,
)
from nexusflow.core.errors import AuthenticationError, InvalidInputError
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.identity.auth_service import LoginResult, TokenPair, normalize_email
from nexusflow.domain.identity.login_risk import LoginRisk
from nexusflow.domain.identity.model import WebAuthnCredential
from nexusflow.domain.identity.webauthn import (
    ALGORITHM_NAMES,
    AssertionResponse,
    AttestationResponse,
    CredentialDescriptor,
    b64url,
)
from nexusflow.infrastructure.observability import metrics

router = APIRouter(prefix="/auth", tags=["auth"], responses=ERROR_RESPONSES)


def _tokens(pair: TokenPair) -> TokenResponse:
    return TokenResponse(
        access_token=pair.access_token,
        expires_in=pair.expires_in,
        refresh_token=pair.refresh_token,
        organization_id=pair.org_id,
    )


def _count_risk(pair: TokenPair | None) -> None:
    """Unfamiliar and suspicious sign-ins, for the ``SuspiciousSignIns`` alert."""
    if pair is not None and pair.login_risk in (LoginRisk.UNFAMILIAR, LoginRisk.SUSPICIOUS):
        metrics.AUTH_EVENTS.labels(event=f"{pair.login_risk}_login", result="detected").inc()


def _login_response(result: LoginResult) -> TokenResponse | MfaChallengeResponse:
    _count_risk(result.tokens)
    if result.tokens is not None:
        return _tokens(result.tokens)
    if result.mfa_challenge is None or result.mfa_challenge_expires_in is None:
        raise AuthenticationError()
    return MfaChallengeResponse.model_validate(
        {
            "mfa_token": result.mfa_challenge,
            "expires_in": result.mfa_challenge_expires_in,
            "methods": list(result.mfa_methods),
        }
    )


def _account_key(email: str) -> str:
    return "acct:" + hashlib.sha256(normalize_email(email).encode()).hexdigest()


async def _limit_account(state: StateDep, email: str) -> None:
    rule = state.container.settings.rate_limits.rules["auth.login.account"]
    await state.limiter.enforce("auth.login.account", _account_key(email), rule)


@router.post(
    "/register",
    response_model=RegistrationStartedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limited("auth.register"))],
    summary="Start a sign-up: a link to finish it is mailed to the address",
)
async def register(
    body: RegisterRequest, container: ContainerDep, state: StateDep, meta: Meta
) -> RegistrationStartedResponse:
    rule = state.container.settings.rate_limits.rules["auth.register.account"]
    await state.limiter.enforce("auth.register.account", _account_key(str(body.email)), rule)
    await container.auth.start_signup(email=str(body.email), meta=meta)
    metrics.AUTH_EVENTS.labels(event="signup_started", result="success").inc()
    return RegistrationStartedResponse()


@router.post(
    "/register/complete",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limited("auth.register.complete"))],
    summary="Finish a sign-up with the mailed link: the account and its organization",
)
async def complete_registration(
    body: CompleteRegistrationRequest, container: ContainerDep, meta: Meta
) -> TokenResponse:
    pair = await container.auth.complete_signup(
        token=body.token,
        password=body.password,
        full_name=body.full_name,
        organization_name=body.organization_name,
        meta=meta,
    )
    metrics.AUTH_EVENTS.labels(event="register", result="success").inc()
    return _tokens(pair)


@router.post(
    "/register/invitation",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limited("auth.register.complete"))],
    summary="Create an account from an invitation (existing accounts use /invitations/accept)",
)
async def register_invited(
    body: InvitedRegistrationRequest, container: ContainerDep, meta: Meta
) -> TokenResponse:
    pair = await container.auth.register_invited(
        token=body.token, password=body.password, full_name=body.full_name, meta=meta
    )
    metrics.AUTH_EVENTS.labels(event="register", result="success").inc()
    return _tokens(pair)


@router.post(
    "/login",
    response_model=TokenResponse | MfaChallengeResponse,
    dependencies=[Depends(rate_limited("auth.login.ip"))],
)
async def login(
    body: LoginRequest, container: ContainerDep, state: StateDep, meta: Meta
) -> TokenResponse | MfaChallengeResponse:
    await _limit_account(state, str(body.email))
    try:
        result = await container.auth.login(
            email=str(body.email), password=body.password, org_id=body.organization_id, meta=meta
        )
    except AuthenticationError:
        metrics.AUTH_EVENTS.labels(event="login", result="failure").inc()
        raise
    metrics.AUTH_EVENTS.labels(event="login", result="success").inc()
    return _login_response(result)


@router.post(
    "/token",
    response_model=TokenResponse | MfaChallengeResponse,
    dependencies=[Depends(rate_limited("auth.login.ip"))],
    summary="OAuth2-compatible token endpoint (password and refresh_token grants)",
)
async def oauth2_token(
    container: ContainerDep,
    state: StateDep,
    meta: Meta,
    grant_type: Annotated[str, Form(pattern="^(password|refresh_token)$")],
    username: Annotated[str | None, Form(max_length=254)] = None,
    password: Annotated[str | None, Form(max_length=1024)] = None,
    refresh_token: Annotated[str | None, Form(max_length=256)] = None,
) -> TokenResponse | MfaChallengeResponse:
    if grant_type == "refresh_token":
        if not refresh_token:
            raise InvalidInputError("refresh_token is required.", code="invalid_request")
        return _tokens(await container.auth.refresh(refresh_token=refresh_token, meta=meta))
    if not username or not password:
        raise InvalidInputError("username and password are required.", code="invalid_request")
    await _limit_account(state, username)
    result = await container.auth.login(email=username, password=password, org_id=None, meta=meta)
    return _login_response(result)


@router.post(
    "/mfa/verify",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limited("auth.mfa"))],
)
async def verify_mfa(body: MfaVerifyRequest, container: ContainerDep, meta: Meta) -> TokenResponse:
    pair = await container.auth.verify_mfa(
        challenge_token=body.mfa_token, code=body.code, meta=meta
    )
    _count_risk(pair)
    return _tokens(pair)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limited("auth.refresh"))],
)
async def refresh(body: RefreshRequest, container: ContainerDep, meta: Meta) -> TokenResponse:
    return _tokens(await container.auth.refresh(refresh_token=body.refresh_token, meta=meta))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(principal: CurrentPrincipal, container: ContainerDep, meta: Meta) -> Response:
    await container.auth.logout(principal, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_everywhere(
    principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.auth.logout_everywhere(principal, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/switch-organization", response_model=TokenResponse)
async def switch_organization(
    body: SwitchOrganizationRequest,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> TokenResponse:
    return _tokens(await container.auth.switch_organization(principal, body.organization_id, meta))


@router.post("/password/change", response_model=TokenResponse)
async def change_password(
    body: PasswordChangeRequest,
    principal: CurrentPrincipal,
    container: ContainerDep,
    state: StateDep,
    meta: Meta,
) -> TokenResponse:
    # Per user, not per address: a stolen token is used from anywhere.
    rule = state.container.settings.rate_limits.rules["auth.password_change"]
    await state.limiter.enforce("auth.password_change", budget_identity(principal), rule)
    pair = await container.auth.change_password(
        principal, current_password=body.current_password, new_password=body.new_password, meta=meta
    )
    return _tokens(pair)


@router.post(
    "/password/reset-request",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limited("auth.password_reset"))],
    summary="Always returns 202 - never reveals whether the account exists",
)
async def request_password_reset(
    body: PasswordResetRequest, container: ContainerDep, state: StateDep, meta: Meta
) -> dict[str, str]:
    rule = state.container.settings.rate_limits.rules["auth.password_reset"]
    await state.limiter.enforce("auth.password_reset", _account_key(str(body.email)), rule)
    await container.auth.request_password_reset(email=str(body.email), meta=meta)
    return {"status": "accepted"}


@router.post(
    "/password/reset",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(rate_limited("auth.password_reset"))],
)
async def reset_password(
    body: PasswordResetConfirmRequest, container: ContainerDep, meta: Meta
) -> Response:
    await container.auth.reset_password(token=body.token, new_password=body.new_password, meta=meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/mfa/enroll",
    response_model=MfaEnrollResponse,
    dependencies=[Depends(rate_limited("auth.mfa", by=client_ip))],
)
async def begin_mfa_enrollment(
    body: PasswordConfirmation, principal: MfaSetupPrincipal, container: ContainerDep, meta: Meta
) -> MfaEnrollResponse:
    enrollment = await container.auth.begin_mfa_enrollment(
        principal, password=body.password, meta=meta
    )
    return MfaEnrollResponse(secret=enrollment.secret, provisioning_uri=enrollment.provisioning_uri)


@router.post("/mfa/confirm", response_model=MfaRecoveryCodesResponse)
async def confirm_mfa_enrollment(
    body: MfaCodeRequest, principal: MfaSetupPrincipal, container: ContainerDep, meta: Meta
) -> MfaRecoveryCodesResponse:
    codes = await container.auth.confirm_mfa_enrollment(principal, code=body.code, meta=meta)
    return MfaRecoveryCodesResponse(recovery_codes=codes)


@router.post(
    "/mfa/disable",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(rate_limited("auth.mfa"))],
)
async def disable_mfa(
    body: MfaDisableRequest, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.auth.disable_mfa(principal, password=body.password, code=body.code, meta=meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------ passkeys


async def _limit_passkeys(state: StateDep, principal: Principal) -> None:
    """Per person, whichever session or address the requests come from."""
    rule = state.container.settings.rate_limits.rules["auth.webauthn.manage"]
    await state.limiter.enforce("auth.webauthn.manage", budget_identity(principal), rule)


def _descriptors(items: tuple[CredentialDescriptor, ...]) -> list[CredentialDescriptorJson]:
    return [CredentialDescriptorJson(id=b64url(d.id), transports=list(d.transports)) for d in items]


def _passkey(passkey: WebAuthnCredential) -> PasskeyResponse:
    return PasskeyResponse(
        id=passkey.id,
        name=passkey.name,
        algorithm=ALGORITHM_NAMES.get(passkey.algorithm, str(passkey.algorithm)),
        transports=list(passkey.transports),
        backup_eligible=passkey.backup_eligible,
        backed_up=passkey.backed_up,
        created_at=passkey.created_at,
        last_used_at=passkey.last_used_at,
    )


@router.post(
    "/webauthn/register/begin",
    response_model=PasskeyCreationOptionsResponse,
    summary="Start registering a passkey (password confirmation; options for the browser)",
)
async def begin_passkey_registration(
    body: PasswordConfirmation,
    principal: MfaSetupPrincipal,
    container: ContainerDep,
    state: StateDep,
    meta: Meta,
) -> PasskeyCreationOptionsResponse:
    await _limit_passkeys(state, principal)
    options = await container.passkeys.begin_registration(
        principal, password=body.password, meta=meta
    )
    return PasskeyCreationOptionsResponse(
        options=PasskeyCreationOptions(
            rp=RelyingPartyEntity(id=options.rp.id, name=options.rp.name),
            user=PasskeyUserEntity(
                id=b64url(options.user_handle),
                name=options.user_name,
                display_name=options.user_display_name,
            ),
            challenge=b64url(options.challenge),
            pub_key_cred_params=[CredentialParameters(alg=alg) for alg in options.algorithms],
            timeout=options.timeout_ms,
            exclude_credentials=_descriptors(options.exclude),
            authenticator_selection=AuthenticatorSelection(),
        ),
        expires_in=options.timeout_ms // 1000,
    )


@router.post(
    "/webauthn/register/finish",
    response_model=PasskeyRegisteredResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Finish registering a passkey with the browser's attestation",
)
async def finish_passkey_registration(
    body: PasskeyRegistrationRequest,
    principal: MfaSetupPrincipal,
    container: ContainerDep,
    state: StateDep,
    meta: Meta,
) -> PasskeyRegisteredResponse:
    await _limit_passkeys(state, principal)
    credential = body.credential
    registered = await container.passkeys.finish_registration(
        principal,
        response=AttestationResponse(
            raw_id=credential.raw_id,
            client_data_json=credential.response.client_data_json,
            attestation_object=credential.response.attestation_object,
        ),
        transports=tuple(credential.response.transports),
        name=body.name,
        meta=meta,
    )
    metrics.AUTH_EVENTS.labels(event="passkey_registered", result="success").inc()
    return PasskeyRegisteredResponse(
        passkey=_passkey(registered.passkey), recovery_codes=registered.recovery_codes or None
    )


@router.get(
    "/webauthn/credentials",
    response_model=list[PasskeyResponse],
    summary="My passkeys (no key material)",
)
async def list_passkeys(
    principal: MfaSetupPrincipal, container: ContainerDep, state: StateDep
) -> list[PasskeyResponse]:
    await _limit_passkeys(state, principal)
    return [_passkey(passkey) for passkey in await container.passkeys.list_passkeys(principal)]


@router.patch(
    "/webauthn/credentials/{passkey_id}",
    response_model=PasskeyResponse,
    summary="Rename one of my passkeys",
)
async def rename_passkey(
    passkey_id: UUID,
    body: PasskeyRenameRequest,
    principal: MfaSetupPrincipal,
    container: ContainerDep,
    state: StateDep,
    meta: Meta,
) -> PasskeyResponse:
    await _limit_passkeys(state, principal)
    passkey = await container.passkeys.rename(principal, passkey_id, name=body.name, meta=meta)
    return _passkey(passkey)


@router.post(
    "/webauthn/credentials/{passkey_id}/delete",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove one of my passkeys (password confirmation; never the last factor)",
)
async def remove_passkey(
    passkey_id: UUID,
    body: PasswordConfirmation,
    principal: MfaSetupPrincipal,
    container: ContainerDep,
    state: StateDep,
    meta: Meta,
) -> Response:
    await _limit_passkeys(state, principal)
    await container.passkeys.remove(principal, passkey_id, password=body.password, meta=meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/mfa/webauthn/begin",
    response_model=PasskeyRequestOptionsResponse,
    dependencies=[Depends(rate_limited("auth.webauthn.sign_in"))],
    summary="Second factor with a passkey: options for the browser (after the password step)",
)
async def begin_passkey_sign_in(
    body: MfaTokenRequest, container: ContainerDep, meta: Meta
) -> PasskeyRequestOptionsResponse:
    options = await container.auth.begin_passkey_sign_in(challenge_token=body.mfa_token, meta=meta)
    return PasskeyRequestOptionsResponse(
        options=PasskeyRequestOptions(
            challenge=b64url(options.challenge),
            timeout=options.timeout_ms,
            rp_id=options.rp_id,
            allow_credentials=_descriptors(options.allow),
        ),
        expires_in=options.timeout_ms // 1000,
    )


@router.post(
    "/mfa/webauthn/verify",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limited("auth.webauthn.sign_in"))],
    summary="Second factor with a passkey: the browser's assertion completes the sign-in",
)
async def verify_passkey_sign_in(
    body: PasskeySignInRequest, container: ContainerDep, meta: Meta
) -> TokenResponse:
    credential = body.credential
    try:
        pair = await container.auth.verify_passkey_sign_in(
            challenge_token=body.mfa_token,
            response=AssertionResponse(
                raw_id=credential.raw_id,
                client_data_json=credential.response.client_data_json,
                authenticator_data=credential.response.authenticator_data,
                signature=credential.response.signature,
                user_handle=credential.response.user_handle,
            ),
            meta=meta,
        )
    except AuthenticationError:
        metrics.AUTH_EVENTS.labels(event="passkey_sign_in", result="failure").inc()
        raise
    metrics.AUTH_EVENTS.labels(event="passkey_sign_in", result="success").inc()
    _count_risk(pair)
    return _tokens(pair)


@router.post("/invitations/accept", status_code=status.HTTP_204_NO_CONTENT)
async def accept_invitation(
    body: AcceptInvitationRequest, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.organizations.accept_invitation(principal, token=body.token, meta=meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

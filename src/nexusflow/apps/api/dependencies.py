"""FastAPI dependencies: authentication, authorization, rate limits, paging."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated

import structlog
from fastapi import Depends, Header, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis

from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import AuthenticationError
from nexusflow.core.pagination import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    PageRequest,
    SortSpec,
    decode_cursor,
    parse_sort,
)
from nexusflow.domain.authorization.principal import Principal, PrincipalType
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.infrastructure.redis.client import FeatureFlags, ReplayGuard
from nexusflow.infrastructure.redis.rate_limit import RateLimiter

_bearer = HTTPBearer(auto_error=False, description="JWT access token or NexusFlow API key")


@dataclass
class ApiState:
    container: Container
    redis: Redis
    limiter: RateLimiter
    replay_guard: ReplayGuard
    flags: FeatureFlags


def get_state(request: Request) -> ApiState:
    state: ApiState = request.app.state.api
    return state


def get_container(state: Annotated[ApiState, Depends(get_state)]) -> Container:
    return state.container


def get_meta(request: Request) -> RequestMeta:
    return RequestMeta.create(
        request_id=getattr(request.state, "request_id", None),
        ip=getattr(request.state, "client_ip", None),
        user_agent=request.headers.get("user-agent"),
    )


def client_ip(request: Request) -> str:
    return str(getattr(request.state, "client_ip", None) or "unknown")


async def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    state: Annotated[ApiState, Depends(get_state)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise AuthenticationError("Authentication is required.", code="authentication_required")
    principal = await state.container.authenticator.authenticate(
        credentials.credentials.strip(), client_ip=getattr(request.state, "client_ip", None)
    )
    request.state.principal = principal
    structlog.contextvars.bind_contextvars(
        principal_type=principal.type.value,
        principal_id=str(principal.id),
        org_id=str(principal.org_id) if principal.org_id else None,
    )
    return principal


async def get_tenant_principal(
    principal: Annotated[Principal, Depends(get_principal)],
) -> Principal:
    """Tenant APIs never accept platform service tokens (those use /internal)."""
    if principal.type is PrincipalType.SERVICE:
        raise AuthenticationError(
            "Service tokens are not valid for this API.", code="invalid_token"
        )
    return principal


async def apply_api_rate_limit(
    request: Request,
    principal: Annotated[Principal, Depends(get_tenant_principal)],
    state: Annotated[ApiState, Depends(get_state)],
) -> None:
    scope = "api.read" if request.method in ("GET", "HEAD", "OPTIONS") else "api.write"
    rule = state.container.settings.rate_limits.rules[scope]
    await state.limiter.enforce(scope, f"{principal.type}:{principal.id}", rule)


CurrentPrincipal = Annotated[Principal, Depends(get_tenant_principal)]
Meta = Annotated[RequestMeta, Depends(get_meta)]
ContainerDep = Annotated[Container, Depends(get_container)]
StateDep = Annotated[ApiState, Depends(get_state)]
IdempotencyKey = Annotated[
    str | None,
    Header(
        alias="Idempotency-Key",
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
        description="Retries with the same key return the original result instead of repeating it.",
    ),
]


def require(permission: Permission) -> Callable[[Principal], Awaitable[Principal]]:
    """Route-level permission gate (services re-check: defence in depth)."""

    async def dependency(principal: CurrentPrincipal) -> Principal:
        principal.require(permission)
        return principal

    return dependency


def require_any(*permissions: Permission) -> Callable[[Principal], Awaitable[Principal]]:
    """Gate for endpoints whose exact permission depends on the payload."""

    async def dependency(principal: CurrentPrincipal) -> Principal:
        if not any(principal.has(permission) for permission in permissions):
            principal.require(permissions[0])
        return principal

    return dependency


def budget_identity(principal: Principal) -> str:
    """Whose budget a costly request spends (AI analyses, exports): the person
    behind an API key, so creating more keys does not multiply the limit."""
    user_id = principal.actor_user_id
    return f"user:{user_id}" if user_id is not None else f"{principal.type}:{principal.id}"


def rate_limited(
    scope: str, *, by: Callable[[Request], str] = client_ip
) -> Callable[..., Awaitable[None]]:
    async def dependency(request: Request, state: StateDep) -> None:
        rule = state.container.settings.rate_limits.rules[scope]
        await state.limiter.enforce(scope, by(request), rule)

    return dependency


_NEWEST_FIRST = SortSpec("created_at", descending=True)


def page_params(
    allowed_sorts: frozenset[str] = frozenset({"created_at"}),
    default_sort: SortSpec = _NEWEST_FIRST,
) -> Callable[..., PageRequest]:
    def dependency(
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
        sort: Annotated[str | None, Query(max_length=64, pattern=r"^-?[a-z_]{1,48}$")] = None,
    ) -> PageRequest:
        return PageRequest(
            limit=limit,
            cursor=decode_cursor(cursor) if cursor else None,
            sort=parse_sort(sort, allowed=allowed_sorts, default=default_sort),
        )

    return dependency


DefaultPage = Annotated[PageRequest, Depends(page_params())]

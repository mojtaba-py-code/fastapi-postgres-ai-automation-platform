"""/scim/v2 - SCIM 2.0 provisioning of an organization's users (RFC 7644).

Authenticated only by an organization's SCIM token (``nxp_…``), which works
nowhere else; every request is rate-limited per token (fail closed) and every
change is audited in the organization's trail. Requests and responses use
``application/scim+json`` (``application/json`` is accepted too); every error
is answered in the SCIM Error schema. Bodies are capped (see ``main.py``) and
parsed with depth limits.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Coroutine
from typing import Annotated, Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from nexusflow.apps.api.dependencies import ContainerDep, Meta, StateDep
from nexusflow.apps.api.scim_protocol import (
    MEDIA_TYPE,
    SCIM_TYPES,
    USER_SCHEMA,
    ScimError,
    error_document,
    list_response,
    parse_filter,
    parse_patch,
    parse_user,
    service_provider_config,
    user_resource,
    user_resource_type,
    user_schema,
)
from nexusflow.core.errors import (
    AuthenticationError,
    ConflictError,
    InvalidInputError,
    NexusFlowError,
    NotFoundError,
    PayloadTooLargeError,
    PermissionDeniedError,
    RateLimitedError,
    ServiceUnavailableError,
    TransientError,
    UnsupportedMediaTypeError,
)
from nexusflow.core.ids import parse_uuid
from nexusflow.core.jsonutil import JSONValue, loads_limited
from nexusflow.domain.authorization.principal import Principal
from nexusflow.infrastructure.observability import metrics
from nexusflow.infrastructure.observability.logging import get_logger

# A SCIM request carries one User or one PatchOp: a few kilobytes.
MAX_BODY_BYTES = 64 * 1024
BODY_PATH = r"^/scim/v2/.*$"
DOCUMENTATION = "https://github.com/mojtaba-py-code/fastapi-postgres-ai-automation-platform/blob/main/docs/SSO.md"
_ACCEPTED_TYPES = frozenset({MEDIA_TYPE, "application/json"})
_bearer = HTTPBearer(auto_error=False, description="A SCIM token (nxp_…)")
_log = get_logger("nexusflow.api.scim")


def scim_json(
    document: JSONValue, status_code: int = 200, headers: dict[str, str] | None = None
) -> Response:
    return Response(
        content=json.dumps(document, ensure_ascii=False),
        status_code=status_code,
        media_type=MEDIA_TYPE,
        headers=headers,
    )


def _error(
    status_code: int,
    detail: str,
    scim_type: str | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    return scim_json(error_document(status_code, detail, scim_type), status_code, headers)


# Platform errors in the SCIM Error schema: status, and the detail shown (None:
# the error's own message, safe for clients by construction).
_STATUSES: tuple[tuple[type[NexusFlowError], int, str | None], ...] = (
    (NotFoundError, 404, "The resource was not found."),
    (ConflictError, 409, None),
    (PayloadTooLargeError, 413, None),
    (UnsupportedMediaTypeError, 415, None),
    (ServiceUnavailableError, 503, "The service is temporarily unavailable."),
    (TransientError, 503, "The service is temporarily unavailable."),
)


def _from_exception(exc: Exception) -> Response | None:
    """The SCIM answer for an error, or ``None`` to let the platform's handler
    (500, logged) take it."""
    if isinstance(exc, ScimError):
        return _error(exc.status, exc.detail, exc.scim_type)
    if isinstance(exc, RequestValidationError):
        return _error(400, "The request has an invalid parameter.", "invalidValue")
    if isinstance(exc, AuthenticationError):
        return _error(
            401, "Authentication failed.", headers={"WWW-Authenticate": 'Bearer realm="scim"'}
        )
    if isinstance(exc, RateLimitedError):
        return _error(429, exc.message, headers={"Retry-After": str(exc.retry_after_seconds)})
    if isinstance(exc, PermissionDeniedError):
        metrics.AUTHORIZATION_DENIALS.labels(permission=exc.code).inc()
        return _error(403, exc.message)
    if isinstance(exc, InvalidInputError):
        return _error(400, exc.message, exc.code if exc.code in SCIM_TYPES else "invalidValue")
    for error_type, status_code, detail in _STATUSES:
        if isinstance(exc, error_type):
            scim_type = "uniqueness" if status_code == 409 else None
            return _error(status_code, detail or exc.message, scim_type)
    return None


class ScimRoute(APIRoute):
    """Every error of a SCIM route - from authentication, validation or the
    service - answered in the SCIM Error schema."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def scim_handler(request: Request) -> Response:
            try:
                return await handler(request)
            except Exception as exc:
                response = _from_exception(exc)
                if response is None:
                    raise
                _log.info(
                    "scim_request_failed",
                    status=response.status_code,
                    error_type=type(exc).__name__,
                    detail=getattr(exc, "internal_detail", None),
                )
                return response

        return scim_handler


router = APIRouter(prefix="/scim/v2", tags=["scim"], route_class=ScimRoute)


async def scim_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    state: StateDep,
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise AuthenticationError("Authentication is required.", code="authentication_required")
    principal = await state.container.authenticator.authenticate_scim(
        credentials.credentials.strip(), client_ip=getattr(request.state, "client_ip", None)
    )
    structlog.contextvars.bind_contextvars(
        principal_type=principal.type.value,
        principal_id=str(principal.id),
        org_id=str(principal.org_id),
    )
    rule = state.container.settings.rate_limits.rules["scim.token"]
    await state.limiter.enforce("scim.token", f"scim:{principal.id}", rule)
    return principal


ScimPrincipal = Annotated[Principal, Depends(scim_principal)]


def _base_url(request: Request) -> str:
    container = request.app.state.api.container
    base: str = container.settings.app.public_base_url.rstrip("/")
    return base


async def _json_body(request: Request) -> JSONValue:
    content_type = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if content_type not in _ACCEPTED_TYPES:
        raise UnsupportedMediaTypeError(f"Send {MEDIA_TYPE}.")
    body = await request.body()
    if not body:
        raise ScimError(400, "The request has no body.", "invalidSyntax")
    try:
        return loads_limited(body, max_bytes=MAX_BODY_BYTES, max_depth=8)
    except InvalidInputError as exc:
        raise ScimError(400, "The body is not valid JSON.", "invalidSyntax") from exc


def _record_id(raw: str) -> UUID:
    record_id = parse_uuid(raw)
    if record_id is None:
        raise NotFoundError()
    return record_id


# ------------------------------------------------------------ discovery


@router.get("/ServiceProviderConfig", summary="What this SCIM service provider supports")
async def get_service_provider_config(principal: ScimPrincipal, request: Request) -> Response:
    return scim_json(service_provider_config(_base_url(request), DOCUMENTATION))


@router.get("/ResourceTypes", summary="Resource types (User only)")
async def list_resource_types(principal: ScimPrincipal, request: Request) -> Response:
    resources: list[JSONValue] = [user_resource_type(_base_url(request))]
    return scim_json(list_response(resources, total=1, start_index=1))


@router.get("/ResourceTypes/{name}", summary="One resource type")
async def get_resource_type(name: str, principal: ScimPrincipal, request: Request) -> Response:
    if name != "User":
        raise NotFoundError()
    return scim_json(user_resource_type(_base_url(request)))


@router.get("/Schemas", summary="Schemas (the core User schema)")
async def list_schemas(principal: ScimPrincipal, request: Request) -> Response:
    resources: list[JSONValue] = [user_schema(_base_url(request))]
    return scim_json(list_response(resources, total=1, start_index=1))


@router.get("/Schemas/{schema_id}", summary="One schema")
async def get_schema(schema_id: str, principal: ScimPrincipal, request: Request) -> Response:
    if schema_id != USER_SCHEMA:
        raise NotFoundError()
    return scim_json(user_schema(_base_url(request)))


# ----------------------------------------------------------------- users


@router.get("/Users", summary="Users, filtered and paginated")
async def list_users(
    principal: ScimPrincipal,
    container: ContainerDep,
    request: Request,
    filter_: Annotated[str | None, Query(alias="filter", max_length=512)] = None,
    start_index: Annotated[int, Query(alias="startIndex")] = 1,
    count: Annotated[int, Query()] = 100,
) -> Response:
    page = await container.provisioning.list_users(
        principal,
        directory_filter=parse_filter(filter_),
        start_index=start_index,
        count=count,
    )
    base = _base_url(request)
    resources: list[JSONValue] = [user_resource(record, base) for record in page.items]
    return scim_json(list_response(resources, total=page.total, start_index=page.start_index))


@router.post("/Users", status_code=status.HTTP_201_CREATED, summary="Provision a user")
async def create_user(
    principal: ScimPrincipal, container: ContainerDep, request: Request, meta: Meta
) -> Response:
    data = parse_user(await _json_body(request))
    record = await container.provisioning.create_user(principal, data, meta)
    base = _base_url(request)
    return scim_json(
        user_resource(record, base),
        status.HTTP_201_CREATED,
        headers={"Location": f"{base}/scim/v2/Users/{record.id}"},
    )


@router.get("/Users/{record_id}", summary="One user")
async def get_user(
    record_id: str, principal: ScimPrincipal, container: ContainerDep, request: Request
) -> Response:
    record = await container.provisioning.get_user(principal, _record_id(record_id))
    return scim_json(user_resource(record, _base_url(request)))


@router.put("/Users/{record_id}", summary="Replace a user")
async def replace_user(
    record_id: str,
    principal: ScimPrincipal,
    container: ContainerDep,
    request: Request,
    meta: Meta,
) -> Response:
    identifier = _record_id(record_id)
    data = parse_user(await _json_body(request))
    record = await container.provisioning.replace_user(principal, identifier, data, meta)
    return scim_json(user_resource(record, _base_url(request)))


@router.patch(
    "/Users/{record_id}", summary="Change a user (add/replace; active: false deprovisions)"
)
async def patch_user(
    record_id: str,
    principal: ScimPrincipal,
    container: ContainerDep,
    request: Request,
    meta: Meta,
) -> Response:
    identifier = _record_id(record_id)
    changes = parse_patch(await _json_body(request))
    record = await container.provisioning.patch_user(principal, identifier, changes, meta)
    return scim_json(user_resource(record, _base_url(request)))


@router.delete(
    "/Users/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deprovision a user (the membership; never the account)",
)
async def delete_user(
    record_id: str, principal: ScimPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.provisioning.delete_user(principal, _record_id(record_id), meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

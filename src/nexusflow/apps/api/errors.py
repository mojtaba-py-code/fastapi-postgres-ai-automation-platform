"""Exception -> HTTP response mapping with a single, safe error schema.

Clients only ever see a stable error code, a generic message and the request
id. Internal detail (stack traces, SQL, upstream bodies, validation *inputs*)
stays in server-side logs, correlated by the same request id.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError
from starlette.exceptions import HTTPException as StarletteHTTPException

from nexusflow.core.errors import (
    AuthenticationError,
    ConflictError,
    ErrorDetail,
    InvalidInputError,
    NexusFlowError,
    NotFoundError,
    PayloadTooLargeError,
    PermanentError,
    PermissionDeniedError,
    RateLimitedError,
    ServiceUnavailableError,
    TransientError,
    UnsupportedMediaTypeError,
)
from nexusflow.infrastructure.observability import metrics
from nexusflow.infrastructure.observability.logging import get_logger

_log = get_logger("nexusflow.api.errors")

_STATUS_BY_TYPE: tuple[tuple[type[NexusFlowError], int], ...] = (
    (AuthenticationError, 401),
    (PermissionDeniedError, 403),
    (NotFoundError, 404),
    (ConflictError, 409),
    (PayloadTooLargeError, 413),
    (UnsupportedMediaTypeError, 415),
    (InvalidInputError, 422),
    (RateLimitedError, 429),
    (ServiceUnavailableError, 503),
    (TransientError, 503),
    (PermanentError, 502),
)
_HTTP_CODES = {
    400: "bad_request",
    401: "authentication_required",
    403: "permission_denied",
    404: "not_found",
    405: "method_not_allowed",
    406: "not_acceptable",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    429: "rate_limited",
}


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return str(value) if value else None


def error_body(
    code: str, message: str, request: Request, details: tuple[ErrorDetail, ...] = ()
) -> dict[str, Any]:
    body: dict[str, Any] = {"error": code, "message": message, "request_id": _request_id(request)}
    if details:
        body["details"] = [
            {"field": d.field, "message": d.message, "code": d.code} for d in details
        ]
    return body


def status_for(exc: NexusFlowError) -> int:
    for error_type, status in _STATUS_BY_TYPE:
        if isinstance(exc, error_type):
            return status
    return 500


async def _handle_domain_error(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, NexusFlowError):  # pragma: no cover - registered for NexusFlowError
        return await _handle_unexpected(request, exc)
    status = status_for(exc)
    headers: dict[str, str] = {}
    if isinstance(exc, AuthenticationError):
        headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
    if isinstance(exc, RateLimitedError):
        headers["Retry-After"] = str(exc.retry_after_seconds)
    if isinstance(exc, PermissionDeniedError):
        metrics.AUTHORIZATION_DENIALS.labels(permission=exc.code).inc()
    level = "error" if status >= 500 else "info"
    getattr(_log, level)(
        "request_failed",
        error_code=exc.code,
        status=status,
        detail=exc.internal_detail,
        exc_info=status >= 500,
    )
    if status >= 500 and status != 503:
        return JSONResponse(
            error_body(
                "upstream_error" if status == 502 else "internal_server_error",
                "An unexpected error occurred.",
                request,
            ),
            status_code=status,
        )
    return JSONResponse(
        error_body(exc.code, exc.message, request, exc.details), status_code=status, headers=headers
    )


async def _handle_validation_error(request: Request, exc: Exception) -> JSONResponse:
    errors = exc.errors() if isinstance(exc, RequestValidationError) else []
    details = tuple(
        ErrorDetail(
            # Never echo the offending input (it may be a password or token).
            message=str(error.get("msg", "Invalid value."))[:200],
            code=str(error.get("type", "invalid"))[:64],
            field=".".join(str(part) for part in error.get("loc", ())[1:])[:128] or None,
        )
        for error in errors[:20]
    )
    return JSONResponse(
        error_body("validation_failed", "The request contains invalid data.", request, details),
        status_code=422,
    )


async def _handle_http_exception(request: Request, exc: Exception) -> JSONResponse:
    status = exc.status_code if isinstance(exc, StarletteHTTPException) else 500
    code = _HTTP_CODES.get(status, "http_error")
    message = "The requested resource was not found." if status == 404 else "The request failed."
    headers = getattr(exc, "headers", None)
    return JSONResponse(error_body(code, message, request), status_code=status, headers=headers)


async def _handle_database_error(request: Request, exc: Exception) -> JSONResponse:
    """SQLSTATE class 22 ("data exception") means a value the database cannot take.

    Inputs are validated long before they reach SQL, so this is a safety net:
    a value that slipped through is still the client's error, not a 500. The
    asyncpg dialect reports these as a generic ``DBAPIError``, hence the
    SQLSTATE check. The statement and its parameters are never logged or
    returned. Every other database error stays a 500.
    """
    orig = getattr(exc, "orig", None)
    sqlstate = str(getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None) or "")
    if not sqlstate.startswith("22"):
        raise exc
    _log.warning("database_rejected_value", sqlstate=sqlstate)
    return JSONResponse(
        error_body("invalid_value", "The request contains a value that cannot be stored.", request),
        status_code=422,
    )


async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
    _log.error("unhandled_exception", error_type=type(exc).__name__, exc_info=exc)
    return JSONResponse(
        error_body("internal_server_error", "An unexpected error occurred.", request),
        status_code=500,
    )


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(NexusFlowError, _handle_domain_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(StarletteHTTPException, _handle_http_exception)
    app.add_exception_handler(DBAPIError, _handle_database_error)
    app.add_exception_handler(Exception, _handle_unexpected)

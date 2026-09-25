"""Application error hierarchy.

Every error carries a stable, machine-readable ``code`` and a ``message`` that is
safe to show to API clients. Internal diagnostics (SQL, stack traces, upstream
responses) must never be placed in ``message``; they belong in ``internal_detail``,
which is only ever written to protected server-side logs.

The HTTP layer maps these classes to status codes (see ``apps.api.errors``); the
core layer deliberately knows nothing about HTTP.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ErrorDetail:
    """A client-safe description of a single problem (usually a field error)."""

    message: str
    code: str = "invalid"
    field: str | None = None


class NexusFlowError(Exception):
    """Base class for all application errors."""

    default_code: str = "internal_error"
    default_message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        details: Sequence[ErrorDetail] = (),
        internal_detail: str | None = None,
    ) -> None:
        self.code = code or self.default_code
        self.message = message or self.default_message
        self.details = tuple(details)
        self.internal_detail = internal_detail
        super().__init__(self.message)


class InvalidInputError(NexusFlowError):
    """The request is well-formed but violates a validation or business rule."""

    default_code = "validation_failed"
    default_message = "The request contains invalid data."


class NotFoundError(NexusFlowError):
    """The resource does not exist *or* the caller may not know that it exists.

    Cross-tenant lookups deliberately raise this instead of a permission error so
    that resource identifiers cannot be probed across organizations (anti-IDOR).
    """

    default_code = "not_found"
    default_message = "The requested resource was not found."


class ConflictError(NexusFlowError):
    """The request conflicts with the current state (duplicates, stale versions)."""

    default_code = "conflict"
    default_message = "The request conflicts with the current state of the resource."


class AuthenticationError(NexusFlowError):
    """Credentials are missing, malformed, expired or revoked."""

    default_code = "authentication_required"
    default_message = "Authentication is required."


class PermissionDeniedError(NexusFlowError):
    """The authenticated principal is not allowed to perform the operation."""

    default_code = "permission_denied"
    default_message = "You do not have permission to perform this action."


class RateLimitedError(NexusFlowError):
    """Too many requests for the given scope."""

    default_code = "rate_limited"
    default_message = "Too many requests. Please retry later."

    def __init__(self, retry_after_seconds: int, message: str | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = max(1, retry_after_seconds)


class PayloadTooLargeError(NexusFlowError):
    default_code = "payload_too_large"
    default_message = "The request payload is too large."


class UnsupportedMediaTypeError(NexusFlowError):
    default_code = "unsupported_media_type"
    default_message = "The content type is not supported."


class PolicyViolationError(InvalidInputError):
    """Input rejected by a security policy (e.g. an SSRF-unsafe URL)."""

    default_code = "policy_violation"
    default_message = "The request was rejected by a security policy."


class ServiceUnavailableError(NexusFlowError):
    """A dependency is unavailable; the operation may succeed later."""

    default_code = "service_unavailable"
    default_message = "The service is temporarily unavailable."


class TransientError(NexusFlowError):
    """A failure that is safe to retry (network hiccup, 5xx, lock timeout).

    Background jobs only auto-retry errors of this type; everything else is
    treated as permanent and routed to the dead-letter store.
    """

    default_code = "transient_failure"
    default_message = "A temporary failure occurred."


class PermanentError(NexusFlowError):
    """A failure that will not succeed on retry (bad config, policy violation)."""

    default_code = "permanent_failure"
    default_message = "The operation failed permanently."

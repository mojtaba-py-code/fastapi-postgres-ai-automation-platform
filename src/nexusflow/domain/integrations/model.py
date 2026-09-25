"""Integration credentials (the tenant's secret vault).

Secrets are encrypted with envelope AES-256-GCM bound to
``org|integration|kind`` context, are write-only through the API (never
returned), and can be rotated, revoked or quarantined. A quarantined
integration fails closed everywhere it is referenced - the incident-response
switch for a leaked credential.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from nexusflow.core.errors import InvalidInputError

_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
_PRINTABLE = re.compile(r"^[\x21-\x7e]+$")
SLACK_WEBHOOK = re.compile(
    r"^https://hooks\.slack\.com/services/[A-Za-z0-9]{6,20}/[A-Za-z0-9]{6,20}/[A-Za-z0-9]{16,64}$"
)
TELEGRAM_TOKEN = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,64}$")
_FORBIDDEN_AUTH_HEADERS = frozenset(
    {"host", "content-length", "transfer-encoding", "connection", "cookie", "proxy-authorization"}
)


class IntegrationKind(StrEnum):
    HTTP_BEARER = "http_bearer"
    HTTP_BASIC = "http_basic"
    HTTP_HEADER = "http_header"
    SLACK_WEBHOOK = "slack_webhook"
    TELEGRAM_BOT = "telegram_bot"
    WEBHOOK_SIGNING = "webhook_signing"


class IntegrationStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    QUARANTINED = "quarantined"


SOURCE_AUTH_KINDS = frozenset(
    {IntegrationKind.HTTP_BEARER, IntegrationKind.HTTP_BASIC, IntegrationKind.HTTP_HEADER}
)


def validate_secret(kind: IntegrationKind, secret: str, metadata: dict[str, Any]) -> dict[str, Any]:
    """Validate a secret for its kind; returns the normalized non-secret metadata."""
    if not secret or len(secret) > 4096:
        raise InvalidInputError("The secret is empty or too long.", code="invalid_secret")
    clean_meta: dict[str, Any] = {}
    if kind is IntegrationKind.HTTP_BEARER:
        if not _PRINTABLE.fullmatch(secret) or len(secret) < 8:
            raise InvalidInputError(
                "Bearer tokens must be 8+ printable characters.", code="invalid_secret"
            )
    elif kind is IntegrationKind.HTTP_BASIC:
        username = str(metadata.get("username", ""))
        if not 0 < len(username) <= 200 or ":" in username or not username.isprintable():
            raise InvalidInputError("A valid username is required.", code="invalid_metadata")
        if not secret.isprintable():
            raise InvalidInputError(
                "The password contains invalid characters.", code="invalid_secret"
            )
        clean_meta["username"] = username
    elif kind is IntegrationKind.HTTP_HEADER:
        header = str(metadata.get("header_name", ""))
        if not _HEADER_NAME.fullmatch(header) or header.lower() in _FORBIDDEN_AUTH_HEADERS:
            raise InvalidInputError("A valid header_name is required.", code="invalid_metadata")
        if not _PRINTABLE.fullmatch(secret.replace(" ", "!")):
            raise InvalidInputError(
                "The header value contains invalid characters.", code="invalid_secret"
            )
        clean_meta["header_name"] = header
    elif kind is IntegrationKind.SLACK_WEBHOOK:
        if not SLACK_WEBHOOK.fullmatch(secret):
            raise InvalidInputError(
                "Expected a https://hooks.slack.com/services/... URL.", code="invalid_secret"
            )
    elif kind is IntegrationKind.TELEGRAM_BOT:
        if not TELEGRAM_TOKEN.fullmatch(secret):
            raise InvalidInputError("Expected a Telegram bot token.", code="invalid_secret")
    elif len(secret) < 32:  # IntegrationKind.WEBHOOK_SIGNING
        raise InvalidInputError(
            "Signing secrets need at least 32 characters.", code="invalid_secret"
        )
    return clean_meta


def encryption_context(org_id: UUID, integration_id: UUID, kind: IntegrationKind) -> str:
    return f"org:{org_id}|integration:{integration_id}|kind:{kind.value}"


@dataclass(eq=False, kw_only=True)
class Integration:
    id: UUID
    org_id: UUID
    name: str
    kind: IntegrationKind
    status: IntegrationStatus = IntegrationStatus.ACTIVE
    secret_ciphertext: bytes
    secret_key_id: str
    secret_fingerprint: str
    secret_hint: str
    metadata: dict[str, Any] = field(default_factory=dict)
    created_by: UUID | None = None
    created_at: datetime
    updated_at: datetime
    rotated_at: datetime | None = None
    last_used_at: datetime | None = None

    @property
    def is_usable(self) -> bool:
        return self.status is IntegrationStatus.ACTIVE

    @property
    def context(self) -> str:
        return encryption_context(self.org_id, self.id, self.kind)


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    """Decrypted credential handed to an outbound client - never persisted."""

    kind: IntegrationKind
    secret: str
    metadata: dict[str, Any]

    def auth_headers(self) -> dict[str, str]:
        if self.kind is IntegrationKind.HTTP_BEARER:
            return {"Authorization": f"Bearer {self.secret}"}
        if self.kind is IntegrationKind.HTTP_BASIC:
            raw = f"{self.metadata['username']}:{self.secret}".encode()
            return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
        if self.kind is IntegrationKind.HTTP_HEADER:
            return {str(self.metadata["header_name"]): self.secret}
        return {}

    def __repr__(self) -> str:  # never render the secret
        return f"ResolvedCredential(kind={self.kind.value}, secret='***')"

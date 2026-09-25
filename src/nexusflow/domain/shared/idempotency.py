"""Client idempotency keys (the ``Idempotency-Key`` header of API commands).

* A key is stored as a SHA-256 digest of the whole key: bounded whatever its
  length (two long keys never collide by truncation), and no client string is
  kept. Each kind of command (source run, workflow run, analysis, report)
  stores its keys with its own resources, so kinds never meet.
* A key names one request. Repeated with the same parameters it returns the
  original resource; used for anything else - another dataset, source,
  workflow or report period - it is refused (409 ``idempotency_key_reused``),
  never answered with another resource.
* Keys are honoured for ``retention.idempotency_keys_hours``; the retention
  job releases older ones, after which the key starts a new request.
"""

from __future__ import annotations

import hashlib
import re

from nexusflow.core.errors import ConflictError, InvalidInputError

CLIENT_KEY_PREFIX = "req:"
_CLIENT_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


def client_key(raw: str) -> str:
    """How a client's key is stored (and looked up)."""
    if not _CLIENT_KEY.fullmatch(raw):
        raise InvalidInputError(
            "Idempotency-Key must be 8-128 characters of [A-Za-z0-9-_.:].",
            code="invalid_idempotency_key",
        )
    return CLIENT_KEY_PREFIX + hashlib.sha256(raw.encode("ascii")).hexdigest()


def ensure_same_request(same: bool) -> None:
    """Refuse a key that was used before for a different request."""
    if not same:
        raise ConflictError(
            "This Idempotency-Key was already used for a different request.",
            code="idempotency_key_reused",
        )

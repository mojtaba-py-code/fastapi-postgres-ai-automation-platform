"""Safe JSON helpers.

``json.loads`` is recursive; attacker-controlled, deeply nested documents can
exhaust the interpreter stack or memory. :func:`loads_limited` bounds size and
nesting depth *before* parsing, and :func:`canonical_json` produces the stable
serialization used for hashing (deduplication keys, audit chain, idempotency).
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

from nexusflow.core.errors import InvalidInputError, PayloadTooLargeError

type JSONScalar = str | int | float | bool | None
type JSONValue = JSONScalar | list[JSONValue] | dict[str, JSONValue]
type JSONObject = dict[str, JSONValue]


def _default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, (UUID, Decimal)):
        return str(value)
    if isinstance(value, Enum):
        return str(value.value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace, ASCII only."""
    return json.dumps(
        value,
        default=_default,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def content_hash(value: Any) -> str:
    """SHA-256 hex digest of the canonical JSON form of ``value``."""
    return hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def max_nesting_depth(data: bytes) -> int:
    """Return the maximum ``{``/``[`` nesting depth of a JSON document.

    A single linear scan that correctly skips string literals (including
    escaped quotes). It does not validate the document; ``json.loads`` does.
    """
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):  # { [
            depth += 1
            deepest = max(deepest, depth)
        elif byte in (0x7D, 0x5D):  # } ]
            depth -= 1
    return deepest


def loads_limited(data: bytes, *, max_bytes: int, max_depth: int = 32) -> JSONValue:
    """Parse untrusted JSON with size and depth limits."""
    if len(data) > max_bytes:
        raise PayloadTooLargeError()
    if max_nesting_depth(data) > max_depth:
        raise InvalidInputError("JSON document is nested too deeply.", code="json_too_deep")
    try:
        parsed: JSONValue = json.loads(data, parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidInputError("Malformed JSON document.", code="malformed_json") from exc
    return parsed


def _reject_constant(name: str) -> None:
    # NaN / Infinity are not valid JSON and break canonical hashing.
    raise ValueError(f"Invalid JSON constant: {name}")

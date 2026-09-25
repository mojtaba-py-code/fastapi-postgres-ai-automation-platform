"""Keyset (cursor) pagination primitives.

Offset pagination degrades linearly and lets clients request arbitrarily deep
pages; keyset pagination is O(log n) per page. Cursors are opaque base64url
JSON documents holding the last row's sort value and id. They are validated
strictly on decode and only ever used as bound query parameters.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from nexusflow.core.errors import InvalidInputError
from nexusflow.core.ids import parse_uuid

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
_MAX_CURSOR_LENGTH = 512
_INT64_MIN, _INT64_MAX = -(2**63), 2**63 - 1

type SortValue = str | int | float | None


@dataclass(frozen=True, slots=True)
class Cursor:
    sort_value: SortValue
    last_id: UUID


@dataclass(frozen=True, slots=True)
class SortSpec:
    field: str
    descending: bool = True


@dataclass(frozen=True, slots=True)
class PageRequest:
    limit: int = DEFAULT_PAGE_SIZE
    cursor: Cursor | None = None
    sort: SortSpec = SortSpec("created_at", descending=True)

    def __post_init__(self) -> None:
        if not 1 <= self.limit <= MAX_PAGE_SIZE:
            raise InvalidInputError(
                f"limit must be between 1 and {MAX_PAGE_SIZE}.", code="invalid_limit"
            )


@dataclass(frozen=True, slots=True)
class Page[T]:
    items: list[T]
    next_cursor: str | None


def encode_cursor(sort_value: SortValue | datetime, last_id: UUID) -> str:
    value: SortValue = sort_value.isoformat() if isinstance(sort_value, datetime) else sort_value
    raw = json.dumps({"v": value, "i": str(last_id)}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_cursor(token: str) -> Cursor:
    invalid = InvalidInputError("The pagination cursor is invalid.", code="invalid_cursor")
    if not token or len(token) > _MAX_CURSOR_LENGTH:
        raise invalid
    try:
        padded = token + "=" * (-len(token) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
        raise invalid from exc
    if not isinstance(payload, dict) or set(payload) != {"v", "i"}:
        raise invalid
    value = payload["v"]
    if value is not None and not isinstance(value, (str, int, float)):
        raise invalid
    if isinstance(value, bool) or not _bindable(value):
        raise invalid
    last_id = parse_uuid(payload["i"]) if isinstance(payload["i"], str) else None
    if last_id is None:
        raise invalid
    return Cursor(sort_value=value, last_id=last_id)


def _bindable(value: SortValue) -> bool:
    """Whether the database can receive ``value`` as a query parameter at all.

    Cursors are client-controlled: values PostgreSQL cannot represent (NaN,
    out-of-range integers, NUL characters, lone UTF-16 surrogates) must be a
    client error, never a driver exception (HTTP 500).
    """
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, int):
        return _INT64_MIN <= value <= _INT64_MAX
    if isinstance(value, str):
        if "\x00" in value:
            return False
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
    return True


def parse_sort(raw: str | None, *, allowed: frozenset[str], default: SortSpec) -> SortSpec:
    """Parse ``field`` / ``-field`` against an allowlist of sortable columns."""
    if not raw:
        return default
    descending = raw.startswith("-")
    field = raw[1:] if descending else raw
    if field not in allowed:
        raise InvalidInputError(
            f"Unsupported sort field. Allowed: {', '.join(sorted(allowed))}.",
            code="invalid_sort",
        )
    return SortSpec(field=field, descending=descending)

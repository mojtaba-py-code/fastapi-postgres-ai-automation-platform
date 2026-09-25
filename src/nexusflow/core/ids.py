"""Identifier generation.

Primary keys are UUIDv7 (RFC 9562): time-ordered, so B-tree indexes stay compact,
while still carrying 74 bits of CSPRNG randomness. Authorization never relies on
identifiers being unguessable; unguessability is only defence in depth.
"""

from __future__ import annotations

import secrets
import time
from uuid import UUID

_MAX_TIMESTAMP_MS = (1 << 48) - 1


def uuid7(timestamp_ms: int | None = None) -> UUID:
    """Return a new RFC 9562 version 7 UUID."""
    ts = time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    if not 0 <= ts <= _MAX_TIMESTAMP_MS:
        raise ValueError("timestamp out of range for UUIDv7")
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    value = (ts << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return UUID(int=value)


def parse_uuid(value: str) -> UUID | None:
    """Parse a canonical UUID string, returning ``None`` for anything else."""
    if len(value) != 36:
        return None
    try:
        return UUID(value)
    except ValueError:
        return None

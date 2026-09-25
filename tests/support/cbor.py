"""A small CBOR encoder for tests: the platform only ever decodes CBOR.

``encode`` writes the shortest form, keeps the order of map entries as given
and accepts :class:`Raw` for bytes that must go into the output exactly as
written - hostile encodings the platform has to refuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Raw:
    """Already-encoded CBOR, embedded as is."""

    data: bytes


def head(major: int, argument: int) -> bytes:
    """The initial byte and argument of a data item, in the shortest form."""
    if argument < 24:
        return bytes([(major << 5) | argument])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < 1 << (8 * size):
            return bytes([(major << 5) | info]) + argument.to_bytes(size, "big")
    raise ValueError("argument too large for CBOR")


def encode(value: Any) -> bytes:  # noqa: PLR0911 - one branch per CBOR type
    if isinstance(value, Raw):
        return value.data
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return head(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(encode(k) + encode(v) for k, v in value.items())
    raise TypeError(f"cannot encode {type(value).__name__}")

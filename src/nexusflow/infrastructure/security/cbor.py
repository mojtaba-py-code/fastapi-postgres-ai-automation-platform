"""A strict, minimal CBOR (RFC 8949) decoder for WebAuthn.

A WebAuthn client hands the relying party two CBOR structures: the
attestation object at registration and, inside the authenticator data, the
credential's public key as a COSE key. Both come from the client, so this
decoder treats its input as hostile and accepts only what those structures
need:

* major types 0 to 5 (integers, byte and text strings, arrays, maps) and, of
  major type 7, only ``false``, ``true`` and ``null`` - no tags, no
  floating-point numbers, no ``undefined`` or other simple values;
* definite lengths only: no indefinite-length strings or containers, no
  "break";
* map keys that are integers or text strings, each at most once (``1`` and
  ``"1"`` are different keys; ``1`` written in two widths is the same key);
* text strings that are valid UTF-8 (no surrogates, no overlong forms);
* bounded work: a maximum input size, nesting depth and number of data items,
  and no declared length or count larger than the bytes that remain - a few
  bytes can never make it allocate or loop much;
* nothing after the item (:func:`decode`), or the offset where the item ended
  (:func:`decode_prefix`, for the COSE key inside the authenticator data).

Integers and lengths are not required to use their shortest form (clients do
not all re-encode canonically), and map keys may come in any order.

Anything else raises :class:`CborError`, and no input raises anything else
(the unit tests feed it random, truncated and hostile inputs).
"""

from __future__ import annotations

from dataclasses import dataclass

type CborKey = int | str
type CborValue = int | bytes | str | bool | list[CborValue] | dict[CborKey, CborValue] | None


class CborError(ValueError):
    """The input is not a CBOR data item this decoder accepts."""


@dataclass(frozen=True, slots=True)
class CborLimits:
    max_size: int = 64 * 1024  # bytes of input
    max_depth: int = 4  # nested arrays and maps
    max_items: int = 512  # data items, map keys included


DEFAULT_LIMITS = CborLimits()

_UNSIGNED, _NEGATIVE, _BYTES, _TEXT, _ARRAY, _MAP, _TAG, _SIMPLE = range(8)
_SIMPLE_VALUES: dict[int, bool | None] = {20: False, 21: True, 22: None}
_FLOATS = frozenset({25, 26, 27})
_INDEFINITE = 31
_ARGUMENT_SIZES = {24: 1, 25: 2, 26: 4, 27: 8}
_KEY_TYPES = frozenset({_UNSIGNED, _NEGATIVE, _TEXT})


def decode(data: bytes, *, limits: CborLimits = DEFAULT_LIMITS) -> CborValue:
    """The single data item that ``data`` consists of."""
    value, end = decode_prefix(data, 0, limits=limits)
    if end != len(data):
        raise CborError("trailing bytes after the data item")
    return value


def decode_prefix(
    data: bytes, offset: int = 0, *, limits: CborLimits = DEFAULT_LIMITS
) -> tuple[CborValue, int]:
    """The data item starting at ``offset``, and the offset just after it."""
    if not isinstance(data, bytes):
        raise CborError("input must be bytes")
    if len(data) > limits.max_size:
        raise CborError("input too large")
    if not 0 <= offset < len(data):
        raise CborError("no data item at this offset")
    return _Reader(data, limits).item(offset, 0)


class _Reader:
    __slots__ = ("_data", "_items", "_limits")

    def __init__(self, data: bytes, limits: CborLimits) -> None:
        self._data = data
        self._limits = limits
        self._items = 0

    def item(self, offset: int, depth: int) -> tuple[CborValue, int]:
        self._items += 1
        if self._items > self._limits.max_items:
            raise CborError("too many data items")
        major, info, offset = self._head(offset)
        if major == _SIMPLE:
            return _simple(info), offset
        if major == _TAG:
            raise CborError("tags are not accepted")
        if info == _INDEFINITE:
            raise CborError("indefinite lengths are not accepted")
        argument, offset = self._argument(info, offset)
        if major == _UNSIGNED:
            return argument, offset
        if major == _NEGATIVE:
            return -1 - argument, offset
        if major == _BYTES:
            return self._take(argument, offset)
        if major == _TEXT:
            raw, end = self._take(argument, offset)
            try:
                return raw.decode("utf-8"), end
            except UnicodeDecodeError as exc:
                raise CborError("text is not valid UTF-8") from exc
        if depth >= self._limits.max_depth:
            raise CborError("nested too deeply")
        if major == _ARRAY:
            return self._array(argument, offset, depth + 1)
        return self._map(argument, offset, depth + 1)

    def _head(self, offset: int) -> tuple[int, int, int]:
        if offset >= len(self._data):
            raise CborError("truncated data item")
        initial = self._data[offset]
        return initial >> 5, initial & 0x1F, offset + 1

    def _argument(self, info: int, offset: int) -> tuple[int, int]:
        if info < 24:
            return info, offset
        size = _ARGUMENT_SIZES.get(info)
        if size is None:
            raise CborError("reserved additional information")
        end = offset + size
        if end > len(self._data):
            raise CborError("truncated data item")
        return int.from_bytes(self._data[offset:end], "big"), end

    def _take(self, length: int, offset: int) -> tuple[bytes, int]:
        if length > len(self._data) - offset:
            raise CborError("declared length exceeds the input")
        end = offset + length
        return self._data[offset:end], end

    def _array(self, count: int, offset: int, depth: int) -> tuple[CborValue, int]:
        # Every item takes at least one byte: a count beyond what remains is a lie.
        if count > len(self._data) - offset:
            raise CborError("declared length exceeds the input")
        items: list[CborValue] = []
        for _ in range(count):
            value, offset = self.item(offset, depth)
            items.append(value)
        return items, offset

    def _map(self, count: int, offset: int, depth: int) -> tuple[CborValue, int]:
        if count > (len(self._data) - offset) // 2:
            raise CborError("declared length exceeds the input")
        entries: dict[CborKey, CborValue] = {}
        for _ in range(count):
            key, offset = self._key(offset, depth)
            if key in entries:
                raise CborError("duplicate map key")
            value, offset = self.item(offset, depth)
            entries[key] = value
        return entries, offset

    def _key(self, offset: int, depth: int) -> tuple[CborKey, int]:
        if offset >= len(self._data):
            raise CborError("truncated data item")
        if self._data[offset] >> 5 not in _KEY_TYPES:
            raise CborError("map keys must be integers or text strings")
        key, end = self.item(offset, depth)
        if not isinstance(key, (int, str)) or isinstance(key, bool):  # pragma: no cover
            raise CborError("map keys must be integers or text strings")
        return key, end


def _simple(info: int) -> bool | None:
    if info in _SIMPLE_VALUES:
        return _SIMPLE_VALUES[info]
    if info in _FLOATS:
        raise CborError("floating-point numbers are not accepted")
    if info == _INDEFINITE:
        raise CborError("unexpected break")
    raise CborError("simple value not accepted")

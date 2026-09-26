"""The strict CBOR decoder behind WebAuthn (``infrastructure.security.cbor``).

It decodes the subset WebAuthn needs (RFC 8949 appendix A vectors of that
subset), refuses everything else - tags, floats, indefinite lengths, simple
values other than false/true/null, duplicate or non-scalar map keys, invalid
UTF-8 - and stays bounded on hostile input: truncation, declared lengths far
beyond the input, deep nesting, too many items, oversized input and trailing
bytes all end in ``CborError``, and no input raises anything else.
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nexusflow.infrastructure.security.cbor import (
    CborError,
    CborLimits,
    CborValue,
    decode,
    decode_prefix,
)
from tests.support.cbor import encode

pytestmark = pytest.mark.security

# RFC 8949 appendix A: the vectors within the accepted subset.
ACCEPTED = [
    ("00", 0),
    ("01", 1),
    ("0a", 10),
    ("17", 23),
    ("1818", 24),
    ("1819", 25),
    ("1864", 100),
    ("1903e8", 1000),
    ("1a000f4240", 1_000_000),
    ("1b000000e8d4a51000", 1_000_000_000_000),
    ("1bffffffffffffffff", 18_446_744_073_709_551_615),
    ("20", -1),
    ("29", -10),
    ("3863", -100),
    ("3903e7", -1000),
    ("3bffffffffffffffff", -18_446_744_073_709_551_616),
    ("f4", False),
    ("f5", True),
    ("f6", None),
    ("40", b""),
    ("4401020304", b"\x01\x02\x03\x04"),
    ("60", ""),
    ("6161", "a"),
    ("6449455446", "IETF"),
    ("62225c", '"\\'),
    ("62c3bc", "ü"),
    ("63e6b0b4", "水"),
    ("64f0908591", "\U00010151"),
    ("80", []),
    ("83010203", [1, 2, 3]),
    ("8301820203820405", [1, [2, 3], [4, 5]]),
    (
        "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
        list(range(1, 26)),
    ),
    ("a0", {}),
    ("a201020304", {1: 2, 3: 4}),
    ("a26161016162820203", {"a": 1, "b": [2, 3]}),
    ("826161a161626163", ["a", {"b": "c"}]),
    (
        "a56161614161626142616361436164614461656145",
        {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"},
    ),
]

# RFC 8949 appendix A: the vectors outside it, each refused.
REFUSED = [
    "f90000",  # half-precision float
    "f93c00",
    "fa47c35000",  # single-precision float
    "fb3ff199999999999a",  # double-precision float
    "fb7ff8000000000000",  # NaN
    "f7",  # undefined
    "f0",  # simple(16)
    "f8ff",  # simple(255)
    "f818",  # simple(24), one-byte form
    "c074323031332d30332d32315432303a30343a30305a",  # tag 0: date/time
    "c11a514b67b0",  # tag 1: epoch
    "c249010000000000000000",  # tag 2: bignum
    "d74401020304",  # tag 23
    "d818456449455446",  # tag 24: embedded CBOR
    "5f42010243030405ff",  # indefinite-length byte string
    "7f657374726561646d696e67ff",  # indefinite-length text
    "9fff",  # indefinite-length array
    "9f018202039f0405ffff",
    "83018202039f0405ff",
    "bf61610161629f0203ffff",  # indefinite-length map
    "bf6346756ef563416d7421ff",
    "ff",  # a lone break
]


def _typed(value: Any) -> Any:
    """``True == 1`` in Python; compare decoded values with their types."""
    if isinstance(value, list):
        return ("list", [_typed(item) for item in value])
    if isinstance(value, dict):
        return ("map", {(type(k).__name__, k): _typed(v) for k, v in value.items()})
    return (type(value).__name__, value)


class TestTheAcceptedSubset:
    @pytest.mark.parametrize(("hex_input", "expected"), ACCEPTED)
    def test_rfc_8949_vectors(self, hex_input: str, expected: CborValue) -> None:
        assert _typed(decode(bytes.fromhex(hex_input))) == _typed(expected)

    def test_a_webauthn_attestation_object_and_cose_key(self) -> None:
        cose = {1: 2, 3: -7, -1: 1, -2: b"x" * 32, -3: b"y" * 32}
        attestation = {"fmt": "none", "attStmt": {}, "authData": b"\x00" * 37 + encode(cose)}
        decoded = decode(encode(attestation))
        assert decoded == attestation
        assert decode(encode(cose)) == cose

    def test_integers_and_lengths_need_not_use_the_shortest_form(self) -> None:
        assert decode(bytes.fromhex("1b0000000000000001")) == 1
        assert decode(bytes.fromhex("3800")) == -1
        assert decode(bytes.fromhex("59000161")) == b"a"
        assert decode(bytes.fromhex("98020102")) == [1, 2]

    def test_one_and_the_text_one_are_different_keys(self) -> None:
        assert decode(encode({1: "int", "1": "text"})) == {1: "int", "1": "text"}

    def test_negative_integer_keys_are_accepted(self) -> None:
        assert decode(bytes.fromhex("a12000")) == {-1: 0}

    def test_decode_prefix_returns_where_the_item_ends(self) -> None:
        data = encode({1: 2}) + encode({"ext": True})
        first, end = decode_prefix(data)
        assert first == {1: 2}
        second, tail = decode_prefix(data, end)
        assert second == {"ext": True}
        assert tail == len(data)


class TestRefusedInput:
    @pytest.mark.parametrize("hex_input", REFUSED)
    def test_types_and_encodings_outside_the_subset(self, hex_input: str) -> None:
        with pytest.raises(CborError):
            decode(bytes.fromhex(hex_input))

    @pytest.mark.parametrize("initial", [0x1C, 0x1D, 0x1E, 0x3C, 0x5D, 0x7E, 0x9C, 0xBD])
    def test_reserved_additional_information(self, initial: int) -> None:
        with pytest.raises(CborError, match="reserved"):
            decode(bytes([initial]) + b"\x00" * 8)

    @pytest.mark.parametrize("initial", [0x1F, 0x3F])
    def test_integers_cannot_be_indefinite(self, initial: int) -> None:
        with pytest.raises(CborError, match="indefinite"):
            decode(bytes([initial, 0x00]))

    @pytest.mark.parametrize(
        "hex_input",
        [
            "62c328",  # invalid continuation byte
            "63eda080",  # a UTF-16 surrogate
            "62c0af",  # overlong "/"
            "61ff",
            "a162c32800",  # the same, as a map key
        ],
    )
    def test_text_must_be_valid_utf8(self, hex_input: str) -> None:
        with pytest.raises(CborError, match="UTF-8"):
            decode(bytes.fromhex(hex_input))

    @pytest.mark.parametrize(
        "hex_input",
        [
            "a2010101 02",  # 1 twice
            "a2616101616102",  # "a" twice
            "a201011801 02",  # 1 in its short and its one-byte form
            "a2200120 02",  # -1 twice
        ],
    )
    def test_duplicate_map_keys(self, hex_input: str) -> None:
        with pytest.raises(CborError, match="duplicate"):
            decode(bytes.fromhex(hex_input.replace(" ", "")))

    @pytest.mark.parametrize(
        "hex_input",
        [
            "a14100 00",  # a byte-string key
            "a1f500",  # true
            "a1f600",  # null
            "a18000",  # an array
            "a1a000",  # a map
            "a1c10000",  # a tagged key
            "a1f90000 00",  # a float
        ],
    )
    def test_map_keys_must_be_integers_or_text(self, hex_input: str) -> None:
        with pytest.raises(CborError, match="map keys"):
            decode(bytes.fromhex(hex_input.replace(" ", "")))

    @pytest.mark.parametrize(
        "value",
        [
            {"fmt": "none", "attStmt": {}, "authData": b"\x01" * 40},
            {1: 2, 3: -7, -1: 1, -2: b"x" * 32, -3: b"y" * 32},
            [1, "two", b"three", [4, {5: 6}], None, True],
            "text",
            b"bytes",
            -1000,
        ],
    )
    def test_every_truncation_is_refused(self, value: CborValue) -> None:
        data = encode(value)
        for cut in range(len(data)):
            with pytest.raises(CborError):
                decode(data[:cut])

    def test_trailing_bytes_are_refused(self) -> None:
        with pytest.raises(CborError, match="trailing"):
            decode(encode({1: 2}) + b"\x00")
        with pytest.raises(CborError, match="trailing"):
            decode(b"\xf6\xf6")

    @pytest.mark.parametrize(
        "hex_input",
        [
            "5bffffffffffffffff",  # a byte string of 2**64 - 1 bytes
            "7bffffffffffffffff",  # text
            "9bffffffffffffffff",  # an array of 2**64 - 1 items
            "bbffffffffffffffff",  # a map of 2**64 - 1 pairs
            "5a7fffffff00",
            "9a7fffffff00",
            "ba7fffffff0000",
            "a3010203",  # three pairs, two items left
            "8301",  # three items, one left
            "4501020304",  # five bytes, four left
        ],
    )
    def test_declared_lengths_beyond_the_input(self, hex_input: str) -> None:
        with pytest.raises(CborError):
            decode(bytes.fromhex(hex_input))

    def test_nesting_is_bounded(self) -> None:
        limits = CborLimits(max_depth=4)
        assert decode(b"\x81" * 4 + b"\x00", limits=limits) == [[[[0]]]]
        with pytest.raises(CborError, match="deeply"):
            decode(b"\x81" * 5 + b"\x00", limits=limits)
        with pytest.raises(CborError, match="deeply"):
            decode(b"\xa1\x01" * 5 + b"\x00", limits=limits)
        # Far deeper than the interpreter's recursion limit: refused, not a crash.
        with pytest.raises(CborError):
            decode(b"\x81" * 50_000 + b"\x00", limits=CborLimits(max_size=100_000))

    def test_the_number_of_items_is_bounded(self) -> None:
        many = encode(list(range(20)))
        assert decode(many, limits=CborLimits(max_items=21)) == list(range(20))
        with pytest.raises(CborError, match="too many"):
            decode(many, limits=CborLimits(max_items=20))
        # Map keys count as items as well.
        with pytest.raises(CborError, match="too many"):
            decode(encode(dict.fromkeys(range(10), 0)), limits=CborLimits(max_items=20))

    def test_the_input_size_is_bounded(self) -> None:
        data = encode(b"\x00" * 100)
        assert decode(data, limits=CborLimits(max_size=len(data))) == b"\x00" * 100
        with pytest.raises(CborError, match="too large"):
            decode(data, limits=CborLimits(max_size=len(data) - 1))

    @pytest.mark.parametrize("data", [b"", bytearray(b"\x00"), "00", memoryview(b"\x00")])
    def test_only_non_empty_bytes_are_decoded(self, data: Any) -> None:
        with pytest.raises(CborError):
            decode(data)

    @pytest.mark.parametrize("offset", [-1, 1, 5])
    def test_a_prefix_needs_an_offset_inside_the_input(self, offset: int) -> None:
        with pytest.raises(CborError):
            decode_prefix(b"\x00", offset)


_KEYS = st.one_of(st.integers(-(2**64), 2**64 - 1), st.text(max_size=8))
_VALUES = st.recursive(
    st.one_of(
        st.integers(-(2**64), 2**64 - 1),
        st.binary(max_size=40),
        st.text(max_size=16),
        st.booleans(),
        st.none(),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=4), st.dictionaries(_KEYS, children, max_size=4)
    ),
    max_leaves=24,
)
_GENEROUS = CborLimits(max_size=1 << 20, max_depth=64, max_items=10_000)


class TestProperties:
    @settings(max_examples=300, deadline=None)
    @given(_VALUES)
    def test_what_is_encoded_decodes_to_the_same_value(self, value: CborValue) -> None:
        assert _typed(decode(encode(value), limits=_GENEROUS)) == _typed(value)

    @settings(max_examples=1000, deadline=None)
    @given(st.binary(max_size=200))
    def test_arbitrary_bytes_decode_or_raise_cbor_error_only(self, data: bytes) -> None:
        with contextlib.suppress(CborError):
            decode(data)

    @settings(max_examples=300, deadline=None)
    @given(_VALUES, st.data())
    def test_a_corrupted_encoding_decodes_or_raises_cbor_error_only(
        self, value: CborValue, data: st.DataObject
    ) -> None:
        encoded = bytearray(encode(value))
        position = data.draw(st.integers(0, len(encoded) - 1))
        encoded[position] = data.draw(st.integers(0, 255))
        with contextlib.suppress(CborError):
            decode(bytes(encoded), limits=_GENEROUS)

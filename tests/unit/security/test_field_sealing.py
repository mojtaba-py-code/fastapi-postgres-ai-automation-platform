"""Sealing sensitive field values: round trips, context binding, tampering, rotation."""

from __future__ import annotations

import base64
import os
from typing import Any
from uuid import UUID, uuid4

import pytest

from nexusflow.domain.records.sealing import (
    KEY_ID,
    SEALED,
    SealedValueError,
    contains_sealed,
    field_context,
    is_sealed,
    open_data,
    open_diff,
    open_value,
    rewrap_value,
    seal_data,
    seal_diff,
    seal_value,
)
from nexusflow.infrastructure.security.crypto import DecryptionError, EnvelopeCipher

ORG, DATASET, RECORD = uuid4(), uuid4(), uuid4()
IDS: dict[str, UUID] = {"org_id": ORG, "dataset_id": DATASET, "record_id": RECORD}


def _cipher(active: str = "kek-1", **extra: bytes) -> EnvelopeCipher:
    return EnvelopeCipher({"kek-1": KEY_1, **extra}, active)


KEY_1, KEY_2 = os.urandom(32), os.urandom(32)


class TestValues:
    @pytest.mark.parametrize(
        "value",
        ["a@b.example", "", "ünïcødé 🔐", 0, -17, 3.25, True, False, "12.50", "x" * 10_000],
    )
    def test_every_scalar_round_trips_with_its_type(self, value: object) -> None:
        cipher = _cipher()
        context = field_context(ORG, DATASET, RECORD, "email")
        sealed = seal_value(cipher, value, context)
        assert is_sealed(sealed)
        assert sealed[KEY_ID] == "kek-1"
        opened = open_value(cipher, sealed, context)
        assert opened == value
        assert type(opened) is type(value)

    def test_the_ciphertext_never_contains_the_value(self) -> None:
        sealed = seal_value(_cipher(), "alice@supplier.example", "ctx")
        assert "alice" not in sealed[SEALED]
        assert "alice" not in base64.b64decode(sealed[SEALED]).decode("latin-1")

    def test_sealing_is_randomised(self) -> None:
        cipher = _cipher()
        assert seal_value(cipher, "same", "ctx") != seal_value(cipher, "same", "ctx")

    @pytest.mark.parametrize(
        "other",
        [
            field_context(ORG, DATASET, uuid4(), "email"),  # another record
            field_context(ORG, DATASET, RECORD, "phone"),  # another field
            field_context(uuid4(), DATASET, RECORD, "email"),  # another tenant
            field_context(ORG, uuid4(), RECORD, "email"),  # another dataset
        ],
    )
    def test_a_value_only_opens_in_its_own_context(self, other: str) -> None:
        cipher = _cipher()
        sealed = seal_value(cipher, "secret", field_context(ORG, DATASET, RECORD, "email"))
        with pytest.raises(DecryptionError):
            open_value(cipher, sealed, other)

    def test_plain_values_pass_through(self) -> None:
        assert open_value(_cipher(), "plain", "ctx") == "plain"
        assert open_value(_cipher(), None, "ctx") is None

    @pytest.mark.parametrize(
        "marker",
        [
            {SEALED: "not base64 at all!", KEY_ID: "kek-1"},
            {SEALED: base64.b64encode(b"NF\x01\x05kek-1" + b"\x00" * 100).decode(), KEY_ID: "x"},
        ],
    )
    def test_a_corrupted_marker_fails_closed(self, marker: dict[str, str]) -> None:
        with pytest.raises((SealedValueError, DecryptionError)):
            open_value(_cipher(), marker, "ctx")

    @pytest.mark.parametrize(
        "value",
        [
            {SEALED: "x"},  # one key
            {SEALED: "x", KEY_ID: "k", "extra": 1},  # three keys
            {SEALED: 1, KEY_ID: "k"},  # not a string
            {"$Sealed": "x", KEY_ID: "k"},
            ["$sealed", "kid"],
        ],
    )
    def test_only_the_exact_marker_shape_counts_as_sealed(self, value: Any) -> None:
        assert not is_sealed(value)


class TestRecords:
    def test_only_present_sensitive_values_are_sealed(self) -> None:
        cipher = _cipher()
        data = {"sku": "A-1", "email": "a@b.example", "phone": None, "title": "Lamp"}
        sealed = seal_data(cipher, data, frozenset({"email", "phone", "absent"}), **IDS)
        assert sealed["sku"] == "A-1"
        assert sealed["title"] == "Lamp"
        assert sealed["phone"] is None  # nothing to hide
        assert is_sealed(sealed["email"])
        assert set(sealed) == set(data)  # no field is added
        assert open_data(cipher, sealed, **IDS) == data

    def test_sealing_twice_does_not_seal_a_sealed_value_again(self) -> None:
        cipher = _cipher()
        once = seal_data(cipher, {"email": "a@b.example"}, frozenset({"email"}), **IDS)
        twice = seal_data(cipher, once, frozenset({"email"}), **IDS)
        assert twice == once

    def test_opening_needs_no_schema(self) -> None:
        # A field that stopped being sensitive still opens: the marker describes itself.
        cipher = _cipher()
        sealed = seal_data(cipher, {"email": "a@b.example"}, frozenset({"email"}), **IDS)
        assert open_data(cipher, sealed, **IDS) == {"email": "a@b.example"}


class TestDiffs:
    def test_every_value_of_a_sensitive_field_is_sealed_including_the_percentage(self) -> None:
        cipher = _cipher()
        diff = {
            "salary": {"old": "1000", "new": "1200", "pct": 20.0},
            "title": {"old": "A", "new": "B"},
            "email": {"old": None, "new": "a@b.example"},
        }
        sealed = seal_diff(cipher, diff, frozenset({"salary", "email"}), **IDS)
        assert all(is_sealed(v) for v in sealed["salary"].values())
        assert sealed["title"] == {"old": "A", "new": "B"}
        assert sealed["email"]["old"] is None
        assert is_sealed(sealed["email"]["new"])
        assert contains_sealed(sealed)
        assert open_diff(cipher, sealed, **IDS) == diff

    def test_a_diff_without_sensitive_fields_is_untouched(self) -> None:
        diff = {"title": {"old": "A", "new": "B"}}
        assert seal_diff(_cipher(), diff, frozenset({"email"}), **IDS) == diff
        assert not contains_sealed(diff)


class TestRotation:
    def test_rewrapping_moves_a_value_to_the_active_key(self) -> None:
        context = field_context(ORG, DATASET, RECORD, "email")
        sealed = seal_value(_cipher(), "a@b.example", context)
        rotated = _cipher("kek-2", **{"kek-2": KEY_2})
        rewrapped = rewrap_value(rotated, sealed, context)
        assert is_sealed(rewrapped)
        assert rewrapped[KEY_ID] == "kek-2"  # type: ignore[index]
        retired = EnvelopeCipher({"kek-2": KEY_2}, "kek-2")  # the old key is gone
        assert open_value(retired, rewrapped, context) == "a@b.example"
        with pytest.raises(DecryptionError):
            open_value(retired, sealed, context)

    def test_rewrapping_leaves_plain_values_alone(self) -> None:
        assert rewrap_value(_cipher(), "plain", "ctx") == "plain"

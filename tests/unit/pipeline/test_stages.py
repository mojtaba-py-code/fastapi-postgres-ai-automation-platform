"""The ingestion pipeline, stage by stage: validate, normalize, clean, deduplicate, enrich."""

from __future__ import annotations

from typing import Any

import pytest

from nexusflow.domain.catalog.model import DatasetSchema, FieldSpec, FieldType
from nexusflow.domain.pipeline.stages import (
    MAX_ISSUES,
    ItemRejectedError,
    clean,
    deduplicate,
    enrich,
    normalize,
    normalize_value,
    run_pipeline,
    validate,
    without_tracking_parameters,
)

SCHEMA = DatasetSchema(
    key_field="sku",
    fields=[
        FieldSpec(name="sku", type=FieldType.STRING, required=True),
        FieldSpec(name="title", type=FieldType.STRING, required=True, max_length=40),
        FieldSpec(name="notes", type=FieldType.TEXT),
        FieldSpec(name="price", type=FieldType.DECIMAL),
        FieldSpec(name="stock", type=FieldType.INTEGER),
        FieldSpec(name="available", type=FieldType.BOOLEAN),
        FieldSpec(name="listed_at", type=FieldType.DATETIME),
        FieldSpec(name="url", type=FieldType.URL),
        FieldSpec(name="tier", type=FieldType.ENUM, enum_values=["Gold", "Silver"]),
    ],
)
ZERO_WIDTH_SPACE = chr(0x200B)
NUL = chr(0)


def _spec(name: str) -> FieldSpec:
    spec = SCHEMA.field(name)
    assert spec is not None
    return spec


def _rejected(call: Any, *args: Any) -> tuple[str | None, str]:
    with pytest.raises(ItemRejectedError) as exc:
        call(*args)
    return exc.value.field, exc.value.code


class TestValidate:
    def test_only_declared_fields_go_on(self) -> None:
        item = validate(SCHEMA, {"sku": "A-1", "title": "Widget", "password": "x", "ip": "1.2.3.4"})
        assert item == {"sku": "A-1", "title": "Widget"}

    def test_blank_optional_values_are_skipped(self) -> None:
        item = validate(SCHEMA, {"sku": "A-1", "title": "W", "notes": "   ", "price": None})
        assert item == {"sku": "A-1", "title": "W"}

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (["not", "an", "object"], (None, "not_an_object")),
            ({"sku": "A-1"}, ("title", "missing_required")),
            ({"sku": "  ", "title": "W"}, ("sku", "missing_required")),
        ],
    )
    def test_rejections_name_the_field(self, raw: Any, expected: tuple[str | None, str]) -> None:
        assert _rejected(validate, SCHEMA, raw) == expected


class TestNormalize:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("1,234", 1234),
            ("1.234,00", 1234),
            (" 42 ", 42),
            (7.0, 7),
        ],
    )
    def test_integers(self, value: Any, expected: int) -> None:
        assert normalize_value(_spec("stock"), value) == expected

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("1.234,56", "1234.56"),  # European separators
            ("1,234.56", "1234.56"),
            ("12,5", "12.5"),
            ("EUR 9.90", "9.9"),
            ("2.50", "2.5"),
            (0.1, "0.1"),  # via str(), never binary float noise
            ("1e-999999", "0"),  # at most 18 fractional digits, never a huge string
            ("0.1234567890123456789", "0.123456789012345679"),
            ("1e18", "1000000000000000000"),
        ],
    )
    def test_decimals_are_canonical_strings(self, value: Any, expected: str) -> None:
        assert normalize_value(_spec("price"), value) == expected

    @pytest.mark.parametrize("value", ["abc", "NaN", "Infinity", "1e19", True])
    def test_unusable_numbers_are_rejected(self, value: Any) -> None:
        assert _rejected(normalize_value, _spec("price"), value) == ("price", "invalid_number")

    def test_integers_must_be_whole_and_safe(self) -> None:
        assert _rejected(normalize_value, _spec("stock"), "1.5") == ("stock", "invalid_integer")
        assert _rejected(normalize_value, _spec("stock"), 2**53) == ("stock", "invalid_integer")

    @pytest.mark.parametrize(
        ("value", "expected"), [("Yes", True), ("off", False), (1, True), (False, False)]
    )
    def test_booleans(self, value: Any, expected: bool) -> None:
        assert normalize_value(_spec("available"), value) is expected

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("2026-03-01T10:00:00", "2026-03-01T10:00:00+00:00"),  # naive means UTC
            ("2026-03-01T13:30:00+03:30", "2026-03-01T10:00:00+00:00"),
            ("2026-03-01T10:00:00Z", "2026-03-01T10:00:00+00:00"),
            (0, "1970-01-01T00:00:00+00:00"),
        ],
    )
    def test_datetimes_are_utc(self, value: Any, expected: str) -> None:
        assert normalize_value(_spec("listed_at"), value) == expected

    def test_urls_are_canonical(self) -> None:
        url = normalize_value(_spec("url"), "HTTPS://Shop.EXAMPLE.com?id=1#reviews")
        assert url == "https://shop.example.com/?id=1"

    @pytest.mark.parametrize(
        "value", ["javascript:alert(1)", "ftp://x.example/", "https://user@x.example/", "nope"]
    )
    def test_unsafe_or_invalid_urls_are_rejected(self, value: str) -> None:
        assert _rejected(normalize_value, _spec("url"), value) == ("url", "invalid_url")

    def test_enums_take_the_declared_spelling(self) -> None:
        assert normalize_value(_spec("tier"), " gold ") == "Gold"
        assert _rejected(normalize_value, _spec("tier"), "bronze") == ("tier", "invalid_enum")

    def test_text_is_cleaned_and_bounded(self) -> None:
        raw = f"  Blue{ZERO_WIDTH_SPACE}   Widget{NUL} "
        assert normalize_value(_spec("title"), raw) == "Blue Widget"
        assert _rejected(normalize_value, _spec("title"), "x" * 41) == ("title", "too_long")
        notes = normalize_value(_spec("notes"), "line one\r\n\r\n\r\nline   two")
        assert notes == "line one\n\nline two"

    def test_structured_values_are_not_strings(self) -> None:
        assert _rejected(normalize_value, _spec("title"), {"a": 1}) == ("title", "invalid_type")

    def test_normalize_keeps_only_present_fields(self) -> None:
        assert normalize(SCHEMA, {"sku": " A-1 ", "stock": "3"}) == {"sku": "A-1", "stock": 3}


class TestClean:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (
                "https://shop.example.com/p/1?utm_source=news&utm_medium=email&color=blue",
                "https://shop.example.com/p/1?color=blue",
            ),
            (
                "https://shop.example.com/p/1?gclid=abc&size=M&fbclid=xyz&UTM_Campaign=q3",
                "https://shop.example.com/p/1?size=M",
            ),
            ("https://shop.example.com/p/1?utm_source=x", "https://shop.example.com/p/1"),
            # Other parameters are kept exactly as they were encoded.
            (
                "https://shop.example.com/s?q=a%20b+c&page=2",
                "https://shop.example.com/s?q=a%20b+c&page=2",
            ),
            ("https://shop.example.com/p/1", "https://shop.example.com/p/1"),
        ],
    )
    def test_tracking_parameters_are_removed(self, url: str, expected: str) -> None:
        assert without_tracking_parameters(url) == expected

    def test_values_that_normalised_to_nothing_are_dropped(self) -> None:
        record = clean(SCHEMA, {"sku": "A-1", "title": "W", "notes": ""})
        assert record == {"sku": "A-1", "title": "W"}

    def test_a_required_value_that_normalised_to_nothing_rejects_the_item(self) -> None:
        assert _rejected(clean, SCHEMA, {"sku": "A-1", "title": ""}) == (
            "title",
            "missing_required",
        )
        assert _rejected(clean, SCHEMA, {"sku": "", "title": "W"}) == ("sku", "missing_key")

    def test_urls_are_cleaned_in_records(self) -> None:
        record = clean(SCHEMA, {"sku": "A-1", "title": "W", "url": "https://x.example/?utm_id=1"})
        assert record["url"] == "https://x.example/"


class TestDeduplicateAndEnrich:
    def test_the_last_occurrence_wins(self) -> None:
        unique, dropped = deduplicate(
            [("a", {"v": 1}), ("b", {"v": 2}), ("a", {"v": 3}), ("a", {"v": 4})]
        )
        assert unique == {"a": {"v": 4}, "b": {"v": 2}}
        assert dropped == 2

    def test_the_fingerprint_ignores_key_order_and_sees_every_value(self) -> None:
        first = enrich("A-1", {"price": "1.5", "title": "W"})
        assert first.content_hash == enrich("A-1", {"title": "W", "price": "1.5"}).content_hash
        assert first.content_hash != enrich("A-1", {"title": "W", "price": "1.6"}).content_hash

    def test_keys_are_bounded(self) -> None:
        assert len(enrich("k" * 2000, {}).key) == 512


class TestRunPipeline:
    def test_every_stage_in_order(self) -> None:
        items: list[Any] = [
            {"sku": "A-1", "title": "Widget", "price": "9,90", "secret": "dropped"},
            {"sku": "A-2", "title": "Gadget", "url": "https://x.example/g?utm_source=ad"},
            {"sku": "A-1", "title": "Widget v2", "price": "10.90"},
            {"sku": "A-3"},
            "garbage",
        ]
        result = run_pipeline(SCHEMA, items, max_items=100)
        assert [record.key for record in result.records] == ["A-1", "A-2"]
        assert result.records[0].data == {"sku": "A-1", "title": "Widget v2", "price": "10.9"}
        assert result.records[1].data["url"] == "https://x.example/g"
        assert (result.received, result.valid, result.invalid, result.duplicates) == (5, 2, 2, 1)
        assert [(i.index, i.field, i.code) for i in result.issues] == [
            (3, "title", "missing_required"),
            (4, None, "not_an_object"),
        ]
        assert result.invalid_ratio == pytest.approx(0.4)

    def test_the_item_cap_marks_the_snapshot_truncated(self) -> None:
        items = ({"sku": f"S-{n}", "title": "W"} for n in range(10))
        result = run_pipeline(SCHEMA, items, max_items=3)
        assert (result.received, result.valid, result.truncated) == (3, 3, True)

    def test_issues_are_capped(self) -> None:
        result = run_pipeline(SCHEMA, [{}] * (MAX_ISSUES + 50), max_items=1000)
        assert result.invalid == MAX_ISSUES + 50
        assert len(result.issues) == MAX_ISSUES
        issues = result.stats()["issues"]
        assert isinstance(issues, list)
        assert len(issues) == 20

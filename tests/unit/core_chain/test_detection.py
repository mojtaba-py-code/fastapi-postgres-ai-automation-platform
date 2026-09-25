"""Change detection (``nexusflow.domain.records.detection``).

``diff_versions`` compares two versions of a record and scores the difference:
created / updated / deleted / unchanged versions, the dataset's change policy
(tracked vs ignored fields), percentage thresholds (default and per field), the
absolute ``delta`` and the zero-baseline rule, missing / ``None`` / nested
values, golden change records and properties checked with Hypothesis.
"""

from __future__ import annotations

import copy
import json
from decimal import Decimal
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nexusflow.core.jsonutil import JSONValue, canonical_json
from nexusflow.domain.catalog.model import DatasetSchema
from nexusflow.domain.records.detection import DetectedChange, diff_versions
from nexusflow.domain.records.model import ChangeType, Significance

LOW, MEDIUM, HIGH, CRITICAL = (
    Significance.LOW,
    Significance.MEDIUM,
    Significance.HIGH,
    Significance.CRITICAL,
)

FIELDS: list[dict[str, Any]] = [
    {"name": "sku", "type": "string", "required": True},
    {"name": "title", "type": "string"},
    {"name": "price", "type": "decimal"},
    {"name": "stock", "type": "integer"},
    {"name": "available", "type": "boolean"},
    {"name": "listed_at", "type": "datetime"},
    {"name": "views", "type": "integer"},
    {"name": "supplier_email", "type": "string", "sensitive": True},
]
FIELD_NAMES = [spec["name"] for spec in FIELDS]

type Record = dict[str, JSONValue]


def make_schema(**change_policy: Any) -> DatasetSchema:
    return DatasetSchema.model_validate(
        {"fields": FIELDS, "key_field": "sku", "change_policy": change_policy}
    )


SCHEMA = make_schema()


def updated(before: Record, after: Record, schema: DatasetSchema = SCHEMA) -> DetectedChange:
    change = diff_versions(schema, before, after)
    assert change is not None
    assert change.change_type is ChangeType.UPDATED
    return change


class TestCreatedAndDeleted:
    def test_a_new_record_lists_its_tracked_fields_as_created(self) -> None:
        change = diff_versions(SCHEMA, None, {"sku": "A-1", "title": "Widget", "price": "9.99"})
        assert change == DetectedChange(
            ChangeType.CREATED,
            {"price": {"old": None, "new": "9.99"}, "title": {"old": None, "new": "Widget"}},
            MEDIUM,
            50,
        )

    def test_a_new_record_is_reported_even_when_only_its_key_is_known(self) -> None:
        assert diff_versions(SCHEMA, None, {"sku": "A-1"}) == DetectedChange(
            ChangeType.CREATED, {}, MEDIUM, 50
        )

    def test_a_removed_record_lists_its_last_tracked_values(self) -> None:
        change = diff_versions(SCHEMA, {"sku": "A-1", "title": "Widget", "available": True}, None)
        assert change == DetectedChange(
            ChangeType.DELETED,
            {"available": {"old": True, "new": None}, "title": {"old": "Widget", "new": None}},
            MEDIUM,
            55,
        )

    def test_creation_and_deletion_scores_do_not_depend_on_the_content(self) -> None:
        full: Record = {
            "sku": "A-1",
            "title": "Widget",
            "price": "1000000",
            "stock": 0,
            "available": False,
            "listed_at": "2026-09-01T00:00:00+00:00",
            "views": 10**6,
            "supplier_email": "buyer@supplier.example",
        }
        created = diff_versions(SCHEMA, None, full)
        deleted = diff_versions(SCHEMA, full, None)
        assert created is not None and deleted is not None
        assert (created.significance, created.score) == (MEDIUM, 50)
        assert (deleted.significance, deleted.score) == (MEDIUM, 55)
        assert set(created.diff) == set(deleted.diff) == set(FIELD_NAMES) - {"sku"}

    def test_two_missing_versions_are_no_change(self) -> None:
        assert diff_versions(SCHEMA, None, None) is None

    def test_only_tracked_fields_are_listed_on_creation_and_deletion(self) -> None:
        schema = make_schema(tracked_fields=["price", "views"], ignored_fields=["views"])
        record: Record = {"sku": "A-1", "title": "Widget", "price": "9.99", "views": 3}
        created = diff_versions(schema, None, record)
        deleted = diff_versions(schema, record, None)
        assert created is not None and deleted is not None
        assert created.diff == {"price": {"old": None, "new": "9.99"}}
        assert deleted.diff == {"price": {"old": "9.99", "new": None}}


class TestUnchanged:
    def test_identical_versions_are_no_change(self) -> None:
        record: Record = {"sku": "A-1", "title": "Widget", "price": "9.99", "available": True}
        assert diff_versions(SCHEMA, record, dict(record)) is None

    def test_equal_but_distinct_nested_values_are_no_change(self) -> None:
        record: Record = {"sku": "A-1", "title": {"en": "Widget", "tags": ["a", {"b": None}]}}
        assert diff_versions(SCHEMA, record, copy.deepcopy(record)) is None

    def test_the_key_field_is_not_tracked(self) -> None:
        assert diff_versions(SCHEMA, {"sku": "A-1"}, {"sku": "A-2"}) is None

    def test_a_null_field_and_a_missing_field_are_the_same(self) -> None:
        assert diff_versions(SCHEMA, {"sku": "A-1", "title": None}, {"sku": "A-1"}) is None


class TestChangePolicy:
    def test_ignored_fields_never_produce_a_change(self) -> None:
        schema = make_schema(ignored_fields=["views", "listed_at"])
        before: Record = {"views": 1, "listed_at": "2026-09-01T00:00:00+00:00", "title": "A"}
        volatile_only: Record = {**before, "views": 2, "listed_at": "2026-09-02T00:00:00+00:00"}
        assert diff_versions(schema, before, volatile_only) is None
        change = updated(before, {**volatile_only, "title": "B"}, schema)
        assert change.diff == {"title": {"old": "A", "new": "B"}}

    def test_a_tracked_field_allowlist_limits_detection(self) -> None:
        schema = make_schema(tracked_fields=["price"])
        assert diff_versions(schema, {"title": "A"}, {"title": "B"}) is None
        change = updated({"title": "A", "price": "10"}, {"title": "B", "price": "11"}, schema)
        assert set(change.diff) == {"price"}

    def test_ignoring_wins_over_tracking(self) -> None:
        schema = make_schema(tracked_fields=["price", "title"], ignored_fields=["title"])
        assert schema.tracked_fields == frozenset({"price"})
        assert diff_versions(schema, {"title": "A"}, {"title": "B"}) is None

    def test_sensitive_fields_are_still_diffed_and_masked_only_when_read(self) -> None:
        change = updated({"supplier_email": "a@x.example"}, {"supplier_email": "b@x.example"})
        assert change.diff == {"supplier_email": {"old": "a@x.example", "new": "b@x.example"}}

    def test_an_explicitly_empty_allowlist_tracks_nothing(self) -> None:
        schema = make_schema(tracked_fields=[])
        assert diff_versions(schema, {"title": "A"}, {"title": "B"}) is None


class TestNumericSignificance:
    @pytest.mark.parametrize(
        ("new", "pct", "level"),
        [
            ("104.99", 4.99, LOW),
            ("105", 5.0, MEDIUM),  # every threshold is inclusive
            ("119.99", 19.99, MEDIUM),
            ("120", 20.0, HIGH),
            ("149.99", 49.99, HIGH),
            ("150", 50.0, CRITICAL),
            ("95", -5.0, MEDIUM),  # decreases are scored by their magnitude
            ("80", -20.0, HIGH),
            ("50", -50.0, CRITICAL),
            ("0", -100.0, CRITICAL),
        ],
    )
    def test_default_thresholds_are_5_20_and_50_percent(
        self, new: str, pct: float, level: Significance
    ) -> None:
        change = updated({"price": "100"}, {"price": new})
        assert change.significance is level
        assert change.diff["price"]["pct"] == pct

    @pytest.mark.parametrize(
        ("new", "level"),
        [("100.99", LOW), ("101", MEDIUM), ("102", HIGH), ("103", CRITICAL)],
    )
    def test_per_field_thresholds_override_the_defaults(
        self, new: str, level: Significance
    ) -> None:
        schema = make_schema(
            numeric_thresholds={"price": {"medium_pct": 1, "high_pct": 2, "critical_pct": 3}}
        )
        assert updated({"price": "100"}, {"price": new}, schema).significance is level

    def test_fields_without_their_own_thresholds_keep_the_defaults(self) -> None:
        schema = make_schema(
            numeric_thresholds={"price": {"medium_pct": 1, "high_pct": 2, "critical_pct": 3}}
        )
        assert updated({"stock": 100}, {"stock": 103}, schema).significance is LOW

    def test_percentages_are_relative_to_the_old_value_and_rounded(self) -> None:
        change = updated({"price": "10.50"}, {"price": "12"})
        assert change.diff["price"] == {"old": "10.50", "new": "12", "delta": "1.5", "pct": 14.29}
        assert change.significance is MEDIUM

    @pytest.mark.parametrize(
        ("old", "new", "delta"),
        [
            ("100", "1100", "1000"),  # never in scientific notation ("1E+3")
            ("10.50", "12", "1.5"),
            ("100", "99.999", "-0.001"),
            ("2.50", "2.5", "0"),
            (0.1, 0.2, "0.1"),  # floats are read through their decimal representation
            (10, 15, "5"),
        ],
    )
    def test_the_delta_is_the_exact_absolute_difference(
        self, old: JSONValue, new: JSONValue, delta: str
    ) -> None:
        field = "stock" if isinstance(old, int) else "price"
        assert updated({field: old}, {field: new}).diff[field]["delta"] == delta

    @pytest.mark.parametrize("new", ["5", "-0.01", "0.000001"])
    def test_a_zero_baseline_is_high_and_has_no_percentage(self, new: str) -> None:
        change = updated({"price": "0"}, {"price": new})
        assert change.significance is HIGH
        assert change.diff["price"] == {"old": "0", "new": new, "delta": new}

    def test_a_negative_baseline_is_scored_by_its_magnitude(self) -> None:
        rising = updated({"price": "-100"}, {"price": "-50"})
        falling = updated({"price": "-100"}, {"price": "-150"})
        assert (rising.diff["price"]["pct"], rising.significance) == (50.0, CRITICAL)
        assert (falling.diff["price"]["pct"], falling.significance) == (-50.0, CRITICAL)

    def test_integer_fields_keep_their_values_and_are_scored_like_decimals(self) -> None:
        change = updated({"stock": 10}, {"stock": 11})
        assert change.diff == {"stock": {"old": 10, "new": 11, "delta": "1", "pct": 10.0}}
        assert change.significance is MEDIUM

    @pytest.mark.parametrize(
        ("old", "new"),
        [
            ("n/a", "5"),
            ("5", "n/a"),
            (None, "5"),  # a value appearing is not a percentage change
            ("5", None),
            (True, "5"),  # booleans are never numbers
            ({"amount": 1}, "5"),
            (["1"], "5"),
        ],
    )
    def test_values_that_are_not_numbers_are_low_without_numeric_details(
        self, old: JSONValue, new: JSONValue
    ) -> None:
        change = updated({"price": old}, {"price": new})
        assert change.significance is LOW
        assert change.diff == {"price": {"old": old, "new": new}}

    @pytest.mark.parametrize(
        "exponent",
        [
            pytest.param(-307, id="ratio-overflows-float"),
            pytest.param(-999_999, id="ratio-overflows-decimal"),
        ],
    )
    def test_extreme_decimals_accepted_by_ingestion_still_yield_a_storable_change(
        self, exponent: int
    ) -> None:
        # How ingestion stores the (accepted, finite, <= 1e18) input "1e<exponent>".
        tiny = format(Decimal(f"1e{exponent}"), "f")
        change = updated({"price": tiny}, {"price": "1000000000000000000"})
        assert change.significance is CRITICAL
        stored = json.loads(canonical_json(change.diff))  # JSONB, like canonical JSON, has no inf
        assert stored["price"]["new"] == "1000000000000000000"
        assert stored["price"]["pct"] == 1_000_000.0  # reported, capped
        assert len(stored["price"]["delta"]) <= 40


class TestOtherFieldTypes:
    @pytest.mark.parametrize(("old", "new"), [(True, False), (False, True), (None, True)])
    def test_boolean_flips_are_medium(self, old: bool | None, new: bool) -> None:
        change = updated({"available": old}, {"available": new})
        assert (change.significance, change.score) == (MEDIUM, 50)
        assert change.diff == {"available": {"old": old, "new": new}}

    @pytest.mark.parametrize(
        ("field", "old", "new"),
        [
            ("title", "Widget", "Widget Pro"),
            ("listed_at", "2026-09-01T00:00:00+00:00", "2026-09-02T00:00:00+00:00"),
            ("supplier_email", "a@x.example", "b@x.example"),
        ],
    )
    def test_text_and_date_changes_are_low(self, field: str, old: str, new: str) -> None:
        change = updated({field: old}, {field: new})
        assert (change.significance, change.score) == (LOW, 20)
        assert change.diff == {field: {"old": old, "new": new}}


class TestScoring:
    @pytest.mark.parametrize(
        ("before", "after", "level", "score"),
        [
            ({"title": "A", "price": "100"}, {"title": "B", "price": "125"}, HIGH, 77),
            (
                {"title": "A", "listed_at": "x", "supplier_email": "a@x.example"},
                {"title": "B", "listed_at": "y", "supplier_email": "b@x.example"},
                LOW,
                24,
            ),
            ({"price": "100", "stock": 10}, {"price": "200", "stock": 20}, CRITICAL, 97),
            (
                {"title": "A", "price": "100", "stock": 1, "available": True},
                {"title": "B", "price": "200", "stock": 2, "available": False},
                CRITICAL,
                100,  # 95 + 3 * 2, capped
            ),
        ],
    )
    def test_the_most_significant_field_sets_the_level_and_each_extra_field_adds_two(
        self, before: Record, after: Record, level: Significance, score: int
    ) -> None:
        change = updated(before, after)
        assert (change.significance, change.score) == (level, score)

    def test_the_score_never_exceeds_100(self) -> None:
        before: Record = {name: "1" for name in FIELD_NAMES if name != "sku"}
        after: Record = {name: "3" for name in FIELD_NAMES if name != "sku"}
        change = updated(before, after)
        assert len(change.diff) == len(FIELD_NAMES) - 1
        assert (change.significance, change.score) == (CRITICAL, 100)

    def test_diff_entries_are_ordered_by_field_name(self) -> None:
        change = updated(
            {"views": 1, "title": "A", "price": "1", "available": True},
            {"views": 2, "title": "B", "price": "2", "available": False},
        )
        assert list(change.diff) == ["available", "price", "title", "views"]


class TestMissingAndNestedValues:
    def test_a_field_that_appears_is_a_change_from_null(self) -> None:
        change = updated({"sku": "A-1"}, {"sku": "A-1", "title": "Widget"})
        assert change.diff == {"title": {"old": None, "new": "Widget"}}

    def test_a_field_that_disappears_is_a_change_to_null(self) -> None:
        change = updated({"sku": "A-1", "title": "Widget"}, {"sku": "A-1"})
        assert change.diff == {"title": {"old": "Widget", "new": None}}

    def test_nested_values_are_compared_structurally_and_kept_whole(self) -> None:
        old: JSONValue = {"en": "Widget", "tags": ["x"]}
        new: JSONValue = {"en": "Widget", "tags": ["x", "y"]}
        change = updated({"title": old}, {"title": new})
        assert change.diff == {"title": {"old": old, "new": new}}
        assert change.significance is LOW

    def test_list_order_matters(self) -> None:
        assert updated({"title": ["a", "b"]}, {"title": ["b", "a"]}).score == 20


# Golden change records: the exact JSON stored for representative versions of a
# dataset that ignores a volatile counter and uses its own price thresholds.
GOLDEN_SCHEMA = make_schema(
    ignored_fields=["views"],
    numeric_thresholds={"price": {"medium_pct": 2, "high_pct": 10, "critical_pct": 25}},
)
GOLDEN: list[tuple[str, Record | None, Record | None, str | None]] = [
    (
        "listing_appears",
        None,
        {"sku": "A-1", "title": "Widget", "price": "9.99", "views": 0},
        (
            '{"change_type":"created","diff":{"price":{"new":"9.99","old":null},'
            '"title":{"new":"Widget","old":null}},"score":50,"significance":"medium"}'
        ),
    ),
    (
        "listing_disappears",
        {"sku": "A-1", "title": "Widget", "available": True, "views": 7},
        None,
        (
            '{"change_type":"deleted","diff":{"available":{"new":null,"old":true},'
            '"title":{"new":null,"old":"Widget"}},"score":55,"significance":"medium"}'
        ),
    ),
    (
        "price_cut_and_restock",
        {"sku": "A-1", "price": "20", "stock": 0, "views": 1},
        {"sku": "A-1", "price": "15", "stock": 12, "views": 2},
        (
            '{"change_type":"updated","diff":{"price":{"delta":"-5","new":"15","old":"20",'
            '"pct":-25.0},"stock":{"delta":"12","new":12,"old":0}},"score":97,'
            '"significance":"critical"}'
        ),
    ),
    (
        "small_price_move",
        {"sku": "A-1", "price": "100"},
        {"sku": "A-1", "price": "102.5"},
        (
            '{"change_type":"updated","diff":{"price":{"delta":"2.5","new":"102.5",'
            '"old":"100","pct":2.5}},"score":50,"significance":"medium"}'
        ),
    ),
    (
        "availability_flip",
        {"sku": "A-1", "available": True, "views": 10},
        {"sku": "A-1", "available": False, "views": 99},
        (
            '{"change_type":"updated","diff":{"available":{"new":false,"old":true}},'
            '"score":50,"significance":"medium"}'
        ),
    ),
    (
        "title_edit",
        {"sku": "A-1", "title": "Widget"},
        {"sku": "A-1", "title": "Widget Pro"},
        (
            '{"change_type":"updated","diff":{"title":{"new":"Widget Pro","old":"Widget"}},'
            '"score":20,"significance":"low"}'
        ),
    ),
    ("volatile_counter_only", {"sku": "A-1", "views": 1}, {"sku": "A-1", "views": 2}, None),
]


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [pytest.param(before, after, expected, id=name) for name, before, after, expected in GOLDEN],
)
def test_golden_change_records(
    before: Record | None, after: Record | None, expected: str | None
) -> None:
    change = diff_versions(GOLDEN_SCHEMA, before, after)
    stored = (
        None
        if change is None
        else canonical_json(
            {
                "change_type": change.change_type,
                "diff": change.diff,
                "significance": change.significance,
                "score": change.score,
            }
        )
    )
    assert stored == expected


# Values as they may appear in stored record data (JSON; NaN and infinities are
# rejected by the JSON parser and by canonical hashing, so they never occur).
_SCALARS = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**15), max_value=10**15)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=12)
)
_VALUES = st.recursive(
    _SCALARS,
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=4), children, max_size=3)
    ),
    max_leaves=8,
)
_RECORDS = st.dictionaries(st.sampled_from(FIELD_NAMES), _VALUES)


class TestProperties:
    # No wall-clock deadline: it only makes property tests flaky on busy hosts.
    @settings(deadline=None)
    @given(_RECORDS)
    def test_a_version_diffed_with_a_copy_of_itself_is_never_a_change(self, record: Record) -> None:
        assert diff_versions(SCHEMA, record, copy.deepcopy(record)) is None

    @settings(deadline=None)
    @given(_RECORDS, _RECORDS)
    def test_diffing_backwards_reports_the_same_fields_with_old_and_new_swapped(
        self, before: Record, after: Record
    ) -> None:
        forward = diff_versions(SCHEMA, before, after)
        backward = diff_versions(SCHEMA, after, before)
        if forward is None or backward is None:
            assert forward is backward is None
            return
        assert set(forward.diff) == set(backward.diff)
        for name, entry in forward.diff.items():
            assert (entry["old"], entry["new"]) == (
                backward.diff[name]["new"],
                backward.diff[name]["old"],
            )

    @settings(deadline=None)
    @given(_RECORDS, _RECORDS)
    def test_updates_only_list_tracked_fields_in_order_with_a_bounded_score(
        self, before: Record, after: Record
    ) -> None:
        change = diff_versions(SCHEMA, before, after)
        if change is None:
            return
        assert change.change_type is ChangeType.UPDATED
        assert set(change.diff) <= SCHEMA.tracked_fields
        assert list(change.diff) == sorted(change.diff)
        assert 20 <= change.score <= 100

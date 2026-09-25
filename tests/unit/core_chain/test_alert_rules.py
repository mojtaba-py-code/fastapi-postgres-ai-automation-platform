"""Alert rules (``nexusflow.domain.alerts.model``).

Every condition type (``change_type``, ``significance_at_least``,
``field_changed``, ``numeric_change``, ``insight_risk_at_least``,
``run_failed``) is evaluated against matching and non-matching subjects,
including boundaries; stored conditions round-trip through the discriminated
union; and the de-duplication key is stable (golden value, cooldown windows,
what does and does not influence it).
"""

from __future__ import annotations

import itertools
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

import pytest
from pydantic import ValidationError

from nexusflow.domain.alerts.model import (
    CONDITION_ADAPTER,
    AlertCondition,
    AlertRule,
    AlertSubject,
    ChangeTypeCondition,
    FieldChangedCondition,
    InsightRiskCondition,
    NumericChangeCondition,
    RunFailedCondition,
    SignificanceCondition,
    dedup_key,
    matches,
)
from nexusflow.domain.intelligence.model import RiskLevel
from nexusflow.domain.records.model import ChangeType, Significance

CREATED, UPDATED, DELETED = ChangeType.CREATED, ChangeType.UPDATED, ChangeType.DELETED
RULE_ID = UUID("0190a5d0-0000-7000-8000-000000000001")
RECORD_ID = UUID("0190a5d0-0000-7000-8000-00000000a001")
DATASET_ID = UUID(int=2)
NOON = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def change(
    change_type: ChangeType = UPDATED,
    significance: Significance = Significance.MEDIUM,
    diff: dict[str, Any] | None = None,
) -> AlertSubject:
    return AlertSubject(
        subject_type="change",
        subject_id=UUID(int=1),
        dataset_id=DATASET_ID,
        dedup_identity=f"{RECORD_ID}:{change_type.value}",
        change_type=change_type,
        significance=significance,
        diff=diff or {},
        title=f"{change_type.value} A-1",
    )


def insight(risk: RiskLevel | None) -> AlertSubject:
    return AlertSubject(
        subject_type="insight",
        subject_id=UUID(int=3),
        dataset_id=DATASET_ID,
        dedup_identity=f"insight:{UUID(int=3)}",
        risk_level=risk,
    )


def run() -> AlertSubject:
    return AlertSubject(
        subject_type="run",
        subject_id=UUID(int=4),
        dataset_id=DATASET_ID,
        dedup_identity=f"source:{UUID(int=5)}",
    )


def price_moved(pct: float) -> dict[str, Any]:
    return {"price": {"old": "100", "new": str(100 + pct), "delta": str(pct), "pct": pct}}


class TestChangeTypeCondition:
    @pytest.mark.parametrize(
        ("types", "actual", "expected"),
        [
            ([CREATED], CREATED, True),
            ([CREATED], UPDATED, False),
            ([CREATED], DELETED, False),
            ([CREATED, DELETED], DELETED, True),
            ([CREATED, DELETED], UPDATED, False),
            ([CREATED, UPDATED, DELETED], UPDATED, True),
        ],
    )
    def test_matches_the_listed_change_types(
        self, types: list[ChangeType], actual: ChangeType, expected: bool
    ) -> None:
        assert matches(ChangeTypeCondition(change_types=types), change(actual)) is expected

    def test_only_change_subjects_can_match(self) -> None:
        condition = ChangeTypeCondition(change_types=[CREATED, UPDATED, DELETED])
        assert not matches(condition, replace(run(), change_type=CREATED))
        assert not matches(condition, replace(insight(RiskLevel.HIGH), change_type=CREATED))

    @pytest.mark.parametrize(
        "change_types", [[], ["created", "updated", "deleted", "created"], ["renamed"]]
    )
    def test_invalid_type_lists_are_rejected(self, change_types: list[str]) -> None:
        with pytest.raises(ValidationError):
            ChangeTypeCondition.model_validate({"change_types": change_types})


class TestSignificanceCondition:
    @pytest.mark.parametrize(
        ("level", "actual"), list(itertools.product(Significance, Significance))
    )
    def test_matches_changes_at_or_above_the_level(
        self, level: Significance, actual: Significance
    ) -> None:
        order = list(Significance)  # low < medium < high < critical
        expected = order.index(actual) >= order.index(level)
        assert matches(SignificanceCondition(level=level), change(significance=actual)) is expected

    @pytest.mark.parametrize("subject", [insight(RiskLevel.CRITICAL), run()])
    def test_subjects_without_a_significance_never_match(self, subject: AlertSubject) -> None:
        assert not matches(SignificanceCondition(level=Significance.LOW), subject)


class TestFieldChangedCondition:
    def test_matches_when_the_field_is_in_the_diff(self) -> None:
        subject = change(
            diff={"price": {"old": "1", "new": "2"}, "title": {"old": "a", "new": "b"}}
        )
        assert matches(FieldChangedCondition(field="price"), subject)

    @pytest.mark.parametrize("diff", [{}, {"title": {"old": "a", "new": "b"}}])
    def test_does_not_match_other_fields(self, diff: dict[str, Any]) -> None:
        assert not matches(FieldChangedCondition(field="price"), change(diff=diff))

    def test_a_masked_sensitive_field_still_counts_as_changed(self) -> None:
        subject = change(diff={"supplier_email": {"old": "[masked]", "new": "[masked]"}})
        assert matches(FieldChangedCondition(field="supplier_email"), subject)

    def test_only_change_subjects_can_match(self) -> None:
        subject = replace(insight(RiskLevel.HIGH), diff=price_moved(10))
        assert not matches(FieldChangedCondition(field="price"), subject)

    @pytest.mark.parametrize("change_type", [ChangeType.CREATED, ChangeType.DELETED])
    def test_new_and_removed_records_are_not_field_changes(self, change_type: ChangeType) -> None:
        # Their diffs list every field (old or new is None): importing a catalogue
        # must not raise one "availability changed" alert per product.
        subject = change(change_type, diff={"in_stock": {"old": None, "new": True}})
        assert not matches(FieldChangedCondition(field="in_stock"), subject)

    def test_conditions_see_the_complete_diff_of_a_sensitive_field(self) -> None:
        subject = replace(
            change(diff={"cost": {"old": "[masked]", "new": "[masked]"}}),
            match_diff={"cost": {"old": "100", "new": "150", "pct": 50.0}},
        )
        assert matches(NumericChangeCondition(field="cost", min_pct=10), subject)
        assert subject.diff["cost"]["new"] == "[masked]"  # what the alert shows

    @pytest.mark.parametrize("name", ["Price", "1price", "price-eur", "", "p" * 64, "_price"])
    def test_field_names_must_be_schema_field_names(self, name: str) -> None:
        with pytest.raises(ValidationError):
            FieldChangedCondition(field=name)

    def test_the_longest_schema_field_name_is_accepted(self) -> None:
        assert FieldChangedCondition(field="p" * 63).field == "p" * 63


class TestNumericChangeCondition:
    @pytest.mark.parametrize(
        ("direction", "min_pct", "pct", "expected"),
        [
            ("increase", 0, 25.0, True),
            ("increase", 0, -25.0, False),
            ("increase", 0, 0.0, False),  # zero is neither an increase ...
            ("decrease", 0, -25.0, True),
            ("decrease", 0, 25.0, False),
            ("decrease", 0, 0.0, False),  # ... nor a decrease
            ("any", 0, 25.0, True),
            ("any", 0, -25.0, True),
            ("any", 0, 0.0, True),
            ("increase", 10, 10.0, True),  # the minimum is inclusive
            ("increase", 10, 9.99, False),
            ("decrease", 10, -10.0, True),
            ("decrease", 10, -9.99, False),
            ("any", 10, -10.0, True),
            ("any", 10, 9.99, False),
        ],
    )
    def test_direction_and_minimum_percentage(
        self,
        direction: Literal["increase", "decrease", "any"],
        min_pct: float,
        pct: float,
        expected: bool,
    ) -> None:
        condition = NumericChangeCondition(field="price", direction=direction, min_pct=min_pct)
        assert matches(condition, change(diff=price_moved(pct))) is expected

    @pytest.mark.parametrize(
        "diff",
        [
            pytest.param({}, id="field-unchanged"),
            pytest.param({"stock": {"old": 1, "new": 2, "delta": "1", "pct": 100.0}}, id="other"),
            pytest.param({"price": {"old": None, "new": "9.99"}}, id="created"),
            pytest.param({"price": {"old": "0", "new": "5", "delta": "5"}}, id="zero-baseline"),
            pytest.param({"price": {"old": "[masked]", "new": "[masked]"}}, id="masked"),
            pytest.param({"price": "25%"}, id="not-an-entry"),
        ],
    )
    def test_entries_without_a_percentage_never_match(self, diff: dict[str, Any]) -> None:
        assert not matches(NumericChangeCondition(field="price"), change(diff=diff))

    def test_runs_and_insights_never_match(self) -> None:
        condition = NumericChangeCondition(field="price")
        assert not matches(condition, run())
        assert not matches(condition, insight(RiskLevel.CRITICAL))

    def test_defaults_match_any_recorded_percentage(self) -> None:
        condition = NumericChangeCondition(field="price")
        assert (condition.direction, condition.min_pct) == ("any", 0)

    @pytest.mark.parametrize(
        "overrides",
        [{"min_pct": -1}, {"min_pct": 100_001}, {"direction": "sideways"}, {"field": "Price"}],
    )
    def test_invalid_parameters_are_rejected(self, overrides: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            NumericChangeCondition.model_validate({"field": "price", **overrides})


class TestInsightRiskCondition:
    @pytest.mark.parametrize(("level", "actual"), list(itertools.product(RiskLevel, RiskLevel)))
    def test_matches_insights_at_or_above_the_level(
        self, level: RiskLevel, actual: RiskLevel
    ) -> None:
        order = list(RiskLevel)  # low < medium < high < critical
        expected = order.index(actual) >= order.index(level)
        assert matches(InsightRiskCondition(level=level), insight(actual)) is expected

    @pytest.mark.parametrize(
        "subject", [insight(None), change(significance=Significance.CRITICAL), run()]
    )
    def test_subjects_without_a_risk_level_never_match(self, subject: AlertSubject) -> None:
        assert not matches(InsightRiskCondition(level=RiskLevel.LOW), subject)


class TestRunFailedCondition:
    def test_matches_failed_runs_only(self) -> None:
        condition = RunFailedCondition()
        assert matches(condition, run())
        assert not matches(condition, change(CREATED))
        assert not matches(condition, insight(RiskLevel.CRITICAL))


CONDITIONS: list[AlertCondition] = [
    ChangeTypeCondition(change_types=[CREATED, DELETED]),
    SignificanceCondition(level=Significance.HIGH),
    FieldChangedCondition(field="price"),
    NumericChangeCondition(field="price", direction="decrease", min_pct=12.5),
    InsightRiskCondition(level=RiskLevel.MEDIUM),
    RunFailedCondition(),
]


class TestStoredConditions:
    @pytest.mark.parametrize("condition", CONDITIONS, ids=lambda c: c.type)
    def test_every_condition_type_round_trips_through_its_stored_form(
        self, condition: AlertCondition
    ) -> None:
        stored = condition.model_dump(mode="json")
        assert stored["type"] == condition.type
        rule = AlertRule(
            id=RULE_ID,
            org_id=UUID(int=9),
            project_id=UUID(int=8),
            name="rule",
            condition=stored,
            created_at=NOON,
            updated_at=NOON,
        )
        parsed = rule.parsed_condition
        assert type(parsed) is type(condition)
        assert parsed == condition == CONDITION_ADAPTER.validate_python(stored)

    @pytest.mark.parametrize(
        "stored",
        [
            {},
            {"type": "sql", "query": "DELETE FROM alerts"},
            {"type": "change_type"},
            {"type": "run_failed", "extra": True},
            {"type": "significance_at_least", "level": "extreme"},
        ],
    )
    def test_unknown_or_malformed_conditions_are_rejected(self, stored: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            CONDITION_ADAPTER.validate_python(stored)


class TestDedupKey:
    def key(
        self,
        subject: AlertSubject | None = None,
        *,
        rule_id: UUID = RULE_ID,
        cooldown_minutes: int = 60,
        now: datetime = NOON,
    ) -> str:
        return dedup_key(rule_id, subject or change(), cooldown_minutes=cooldown_minutes, now=now)

    def test_golden_value(self) -> None:
        # sha256("<rule id>|change|<record id>:updated|<hours since the epoch>"). The key is
        # persisted under a unique constraint, so it must not change between releases.
        assert self.key() == "03621afd3c8245319fd9b935cac2e7175e5c59d02740e2df132c713b15e806c3"

    def test_is_a_sha256_hex_digest_that_fits_the_column(self) -> None:
        key = self.key()
        assert len(key) == 64
        assert set(key) <= set("0123456789abcdef")

    def test_one_key_per_rule_and_subject_within_a_cooldown_window(self) -> None:
        assert self.key(now=NOON) == self.key(now=NOON + timedelta(minutes=59, seconds=59))
        assert self.key(now=NOON) != self.key(now=NOON + timedelta(minutes=60))

    def test_windows_are_fixed_epoch_aligned_buckets(self) -> None:
        just_before = NOON - timedelta(seconds=1)
        assert self.key(now=just_before) != self.key(now=NOON)  # one second apart

    def test_longer_cooldowns_merge_more_events(self) -> None:
        day = 24 * 60
        assert self.key(cooldown_minutes=day, now=NOON) == self.key(
            cooldown_minutes=day, now=NOON + timedelta(hours=11, minutes=59)
        )

    def test_cooldowns_below_a_minute_use_one_minute_windows(self) -> None:
        assert self.key(cooldown_minutes=0) == self.key(cooldown_minutes=1)
        assert self.key(cooldown_minutes=0) == self.key(
            cooldown_minutes=0, now=NOON + timedelta(seconds=59)
        )
        assert self.key(cooldown_minutes=0) != self.key(
            cooldown_minutes=0, now=NOON + timedelta(seconds=60)
        )

    def test_the_instant_not_its_timezone_determines_the_window(self) -> None:
        tehran_offset = timezone(timedelta(hours=3, minutes=30))
        assert self.key(now=NOON.astimezone(tehran_offset)) == self.key(now=NOON)

    def test_only_the_dedup_identity_of_a_subject_matters(self) -> None:
        other_change_of_the_same_record = replace(
            change(),
            subject_id=UUID(int=99),
            significance=Significance.CRITICAL,
            diff=price_moved(80),
            title="updated A-1 again",
            body="different text",
        )
        assert self.key(other_change_of_the_same_record) == self.key(change())

    def test_rule_subject_type_and_identity_each_change_the_key(self) -> None:
        base = self.key()
        assert self.key(rule_id=UUID(int=7)) != base
        assert self.key(replace(change(), subject_type="run")) != base
        assert self.key(change(DELETED)) != base

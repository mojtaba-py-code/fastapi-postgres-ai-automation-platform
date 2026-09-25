"""The offline analyser (``nexusflow.domain.intelligence.offline``).

Used instead of an external AI provider until a tenant opts in to external
processing, and always for restricted datasets. Covered here: the
exact output for known input, determinism, empty input, how findings, risk and
recommendations are derived, and that the output passes the validation the
intelligence service applies to model output and fits the schema providers
are asked to follow.
"""

from __future__ import annotations

import copy
import itertools
import secrets
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nexusflow.domain.intelligence.model import AnalysisOutput, Finding, RiskLevel
from nexusflow.domain.intelligence.offline import offline_analysis
from nexusflow.domain.intelligence.prompting import output_schema
from nexusflow.domain.intelligence.validation import validate_output

DATASET = "Competitor prices"


def prepared(
    number: int,
    *,
    record_key: str,
    change_type: str = "updated",
    significance: str = "medium",
    score: int = 50,
    diff: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A change as the intelligence service hands it to an analyser."""
    return {
        "id": f"0190a5d0-0000-7000-8000-{number:012d}",
        "record_key": record_key,
        "change_type": change_type,
        "significance": significance,
        "score": score,
        "detected_at": "2026-09-01T12:00:00+00:00",
        "diff": diff if diff is not None else {},
    }


PRICE_RISE = prepared(
    1,
    record_key="A-1",
    significance="high",
    score=77,
    diff={
        "price": {"old": "100", "new": "125", "delta": "25", "pct": 25.0},
        "title": {"old": "Widget", "new": "Widget Pro"},
    },
)
PRICE_CUT = prepared(
    2,
    record_key="B-2",
    score=52,
    diff={"price": {"old": "10", "new": "9", "delta": "-1", "pct": -10.0}},
)
NEW_LISTING = prepared(
    3, record_key="C-3", change_type="created", diff={"title": {"old": None, "new": "Gadget"}}
)
REMOVED_LISTING = prepared(
    4,
    record_key="D-4",
    change_type="deleted",
    score=55,
    diff={"title": {"old": "Old", "new": None}},
)
CHANGES = [PRICE_RISE, PRICE_CUT, NEW_LISTING, REMOVED_LISTING]

GOLDEN = AnalysisOutput(
    summary=(
        "4 changes detected in 'Competitor prices': 2 updated, 1 created, 1 removed. "
        "Highest significance: high."
    ),
    risk_level=RiskLevel.HIGH,
    confidence=0.6,
    findings=[
        Finding(
            title="Updated: A-1",
            detail="'A-1' changed: price +25.0% (100 -> 125); title: Widget -> Widget Pro.",
            impact="high",
            change_refs=[PRICE_RISE["id"]],
        ),
        Finding(
            title="Record removed: D-4",
            detail="The record 'D-4' is no longer present in the source.",
            impact="medium",
            change_refs=[REMOVED_LISTING["id"]],
        ),
        Finding(
            title="Updated: B-2",
            detail="'B-2' changed: price -10.0% (10 -> 9).",
            impact="medium",
            change_refs=[PRICE_CUT["id"]],
        ),
        Finding(
            title="New record: C-3",
            detail="A new record 'C-3' appeared in the dataset.",
            impact="medium",
            change_refs=[NEW_LISTING["id"]],
        ),
    ],
    recommendations=[
        "Review the increase in price on A-1 (+25.0%).",
        "Review the decrease in price on B-2 (-10.0%).",
        "Investigate why D-4 disappeared from its source.",
        "Assess the newly listed record C-3.",
    ],
)


class TestOutput:
    def test_no_changes_is_a_confident_low_risk_all_clear(self) -> None:
        assert offline_analysis([], dataset_name=DATASET) == AnalysisOutput(
            summary="No new changes were detected in 'Competitor prices' for this period.",
            risk_level=RiskLevel.LOW,
            confidence=1.0,
        )

    def test_golden_summary_findings_and_recommendations(self) -> None:
        assert offline_analysis(CHANGES, dataset_name=DATASET) == GOLDEN

    def test_the_output_is_deterministic(self) -> None:
        first = offline_analysis(CHANGES, dataset_name=DATASET)
        second = offline_analysis(copy.deepcopy(CHANGES), dataset_name=DATASET)
        assert first.model_dump_json() == second.model_dump_json()

    def test_the_input_order_does_not_matter(self) -> None:
        outputs = {
            offline_analysis(list(order), dataset_name=DATASET).model_dump_json()
            for order in itertools.permutations(CHANGES)
        }
        assert outputs == {GOLDEN.model_dump_json()}

    def test_the_input_is_not_modified(self) -> None:
        snapshot = copy.deepcopy(CHANGES)
        offline_analysis(CHANGES, dataset_name=DATASET)
        assert snapshot == CHANGES


class TestFindingsAndRisk:
    def test_findings_are_the_five_highest_scored_changes(self) -> None:
        changes = [prepared(n, record_key=f"K-{n}", score=n * 10) for n in range(1, 8)]
        output = offline_analysis(changes, dataset_name=DATASET)
        assert [f.change_refs for f in output.findings] == [
            [changes[n]["id"]] for n in (6, 5, 4, 3, 2)
        ]

    def test_the_risk_reflects_every_change_not_only_the_findings(self) -> None:
        loud = [prepared(n, record_key=f"K-{n}", significance="low", score=90) for n in range(5)]
        quiet_but_critical = prepared(9, record_key="K-9", significance="critical", score=0)
        output = offline_analysis([*loud, quiet_but_critical], dataset_name=DATASET)
        assert output.risk_level is RiskLevel.CRITICAL
        assert quiet_but_critical["id"] not in {r for f in output.findings for r in f.change_refs}
        assert output.summary.endswith("Highest significance: critical.")

    @pytest.mark.parametrize(
        ("significances", "risk"),
        [
            (["low"], RiskLevel.LOW),
            (["low", "medium"], RiskLevel.MEDIUM),
            (["medium", "high", "low"], RiskLevel.HIGH),
            (["critical", "low"], RiskLevel.CRITICAL),
            (["unknown"], RiskLevel.LOW),  # unrecognised levels are ignored
        ],
    )
    def test_risk_is_the_highest_significance(
        self, significances: list[str], risk: RiskLevel
    ) -> None:
        changes = [
            prepared(n, record_key=f"K-{n}", significance=level)
            for n, level in enumerate(significances)
        ]
        assert offline_analysis(changes, dataset_name=DATASET).risk_level is risk

    @pytest.mark.parametrize(
        ("significance", "impact"),
        [
            ("critical", "high"),
            ("high", "high"),
            ("medium", "medium"),
            ("low", "low"),
            ("?", "low"),
        ],
    )
    def test_finding_impact_follows_the_significance(self, significance: str, impact: str) -> None:
        change = prepared(1, record_key="K-1", significance=significance)
        [finding] = offline_analysis([change], dataset_name=DATASET).findings
        assert finding.impact == impact

    def test_update_details_cover_the_first_four_diff_entries(self) -> None:
        diff: dict[str, Any] = {
            "a_price": {"old": "10", "new": "11", "delta": "1", "pct": 10.0},
            "b_note": "not an entry",  # skipped
            "c_title": {"old": "x", "new": "y"},
            "d_stock": {"old": 3, "new": 0, "delta": "-3", "pct": -100.0},
            "e_flag": {"old": True, "new": False},
            "f_extra": {"old": "p", "new": "q"},
        }
        [finding] = offline_analysis(
            [prepared(1, record_key="K-1", diff=diff)], dataset_name=DATASET
        ).findings
        assert finding.detail == (
            "'K-1' changed: a_price +10.0% (10 -> 11); c_title: x -> y; d_stock -100.0% (3 -> 0)."
        )

    def test_an_update_without_details_is_still_described(self) -> None:
        [finding] = offline_analysis([prepared(1, record_key="K-1")], dataset_name=DATASET).findings
        assert finding.detail == "'K-1' changed: tracked fields changed."

    def test_missing_keys_fall_back_to_neutral_values(self) -> None:
        change = {"id": "c-1", "change_type": "created", "significance": "high"}
        output = offline_analysis([change], dataset_name=DATASET)
        assert output.findings[0].title == "New record: record"
        assert output.risk_level is RiskLevel.HIGH

    def test_long_record_keys_are_shortened(self) -> None:
        [finding] = offline_analysis(
            [prepared(1, record_key="K" * 600, change_type="deleted")], dataset_name=DATASET
        ).findings
        assert finding.title == "Record removed: " + "K" * 80


class TestRecommendations:
    def test_rises_and_falls_count_every_value_and_name_the_largest(self) -> None:
        changes = [
            prepared(1, record_key="K-1", diff={"price": {"pct": -5.0}, "stock": {"pct": -1}}),
            prepared(2, record_key="K-2", diff={"price": {"pct": 5.0}}),
            prepared(3, record_key="K-3", diff={"price": {"pct": -0.5}}),
        ]
        output = offline_analysis(changes, dataset_name=DATASET)
        assert output.recommendations == [
            "Review the increase in price on K-2 (+5.0%).",
            "Review 3 decreases in tracked values; the largest is price on K-1 (-5.0%).",
        ]

    def test_listings_that_appear_or_disappear_are_counted(self) -> None:
        changes = [
            prepared(1, record_key="K-1", change_type="created"),
            prepared(2, record_key="K-2", change_type="created"),
            prepared(3, record_key="K-3", change_type="deleted"),
        ]
        assert offline_analysis(changes, dataset_name=DATASET).recommendations == [
            "Investigate why K-3 disappeared from its source.",
            "Assess 2 newly listed records.",
        ]

    def test_a_single_increase_is_named(self) -> None:
        change = prepared(1, record_key="K-1", diff={"price": {"pct": 12.0}})
        assert offline_analysis([change], dataset_name=DATASET).recommendations == [
            "Review the increase in price on K-1 (+12.0%)."
        ]

    def test_text_changes_alone_need_no_recommendation(self) -> None:
        change = prepared(1, record_key="K-1", diff={"title": {"old": "a", "new": "b"}})
        assert offline_analysis([change], dataset_name=DATASET).recommendations == []


def _conforms(value: Any, schema: dict[str, Any], defs: dict[str, Any]) -> bool:  # noqa: PLR0911
    """Minimal JSON-schema check for the subset ``output_schema()`` uses."""
    if "$ref" in schema:
        return _conforms(value, defs[schema["$ref"].rsplit("/", 1)[-1]], defs)
    if "enum" in schema and value not in schema["enum"]:
        return False
    kind = schema.get("type")
    if kind == "object":
        properties: dict[str, Any] = schema.get("properties", {})
        if not isinstance(value, dict) or not set(schema.get("required", [])) <= set(value):
            return False
        if schema.get("additionalProperties") is False and not set(value) <= set(properties):
            return False
        return all(_conforms(value[key], properties[key], defs) for key in value)
    if kind == "array":
        return (
            isinstance(value, list)
            and len(value) <= schema.get("maxItems", len(value))
            and all(_conforms(item, schema.get("items", {}), defs) for item in value)
        )
    if kind == "string":
        return isinstance(value, str) and (
            schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value))
        )
    if kind == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    return True


class TestValidity:
    @pytest.mark.parametrize("changes", [[], CHANGES], ids=["empty", "changes"])
    def test_output_passes_the_validation_applied_to_model_output(
        self, changes: list[dict[str, Any]]
    ) -> None:
        output = offline_analysis(changes, dataset_name=DATASET)
        validated = validate_output(
            output.model_dump_json(),
            boundary=secrets.token_hex(12),
            allowed_change_ids=frozenset(c["id"] for c in changes),
            allowed_hosts=frozenset(),
        )
        assert validated == output

    @pytest.mark.parametrize("changes", [[], CHANGES], ids=["empty", "changes"])
    def test_output_fits_the_schema_given_to_ai_providers(
        self, changes: list[dict[str, Any]]
    ) -> None:
        schema = output_schema()
        document = offline_analysis(changes, dataset_name=DATASET).model_dump(mode="json")
        assert _conforms(document, schema, schema["$defs"])
        assert not _conforms({**document, "verdict": "buy"}, schema, schema["$defs"])
        assert not _conforms({**document, "risk_level": "extreme"}, schema, schema["$defs"])


_ENTRIES = st.fixed_dictionaries(
    {"old": st.none() | st.text(max_size=8), "new": st.none() | st.text(max_size=8)},
    optional={"pct": st.floats(min_value=-1e6, max_value=1e6, allow_nan=False)},
)
_PREPARED = st.fixed_dictionaries(
    {
        "id": st.uuids().map(str),
        "record_key": st.text(max_size=100),
        "change_type": st.sampled_from(["created", "updated", "deleted"]),
        "significance": st.sampled_from(["low", "medium", "high", "critical"]),
        "score": st.integers(min_value=0, max_value=100),
        "detected_at": st.just("2026-09-01T12:00:00+00:00"),
        "diff": st.dictionaries(
            st.from_regex(r"[a-z][a-z0-9_]{0,15}", fullmatch=True), _ENTRIES, max_size=6
        ),
    }
)
_LEVELS = ["low", "medium", "high", "critical"]


@settings(deadline=None)  # wall-clock deadlines are flaky on busy CI/Windows hosts
@given(
    st.lists(_PREPARED, max_size=12, unique_by=lambda change: change["id"]),
    st.text(min_size=1, max_size=120),
)
def test_any_prepared_changes_yield_output_the_service_would_accept(
    changes: list[dict[str, Any]], dataset_name: str
) -> None:
    output = offline_analysis(changes, dataset_name=dataset_name)
    ids = frozenset(change["id"] for change in changes)
    validated = validate_output(
        output.model_dump_json(),
        boundary=secrets.token_hex(12),
        allowed_change_ids=ids,
        allowed_hosts=frozenset(),
    )
    assert [f.change_refs for f in validated.findings] == [f.change_refs for f in output.findings]
    assert len(output.findings) == min(5, len(changes))
    assert all(f.change_refs[0] in ids and len(f.change_refs) == 1 for f in output.findings)
    highest = max((c["significance"] for c in changes), key=_LEVELS.index, default="low")
    assert output.risk_level == highest

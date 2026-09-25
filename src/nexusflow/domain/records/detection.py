"""Change detection: diff two record versions and score significance.

Only *tracked* fields (per the dataset's change policy) produce changes, so
volatile attributes (timestamps, view counters) do not create alert noise.
Numeric fields get relative deltas scored against configurable thresholds.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext
from typing import Any

from nexusflow.core.jsonutil import JSONValue
from nexusflow.domain.catalog.model import DatasetSchema, FieldType, NumericThreshold
from nexusflow.domain.records.model import ChangeType, Significance

_DEFAULT_THRESHOLD = NumericThreshold()
# A relative change is reported as at most +/- one million percent: beyond that
# the number carries no information, and the ratio of an extreme pair of
# values would otherwise overflow (Decimal) or become infinite (float), which
# JSONB cannot store - failing the detection batch on every retry.
_PCT_CAP = Decimal(1_000_000)
_FRACTION_DIGITS = Decimal("1e-18")  # the precision ingestion stores
_BASE_SCORE = {
    Significance.LOW: 20,
    Significance.MEDIUM: 50,
    Significance.HIGH: 75,
    Significance.CRITICAL: 95,
}


@dataclass(frozen=True, slots=True)
class DetectedChange:
    change_type: ChangeType
    diff: dict[str, Any]
    significance: Significance
    score: int


def _as_decimal(value: JSONValue) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return None


def _numeric_significance(
    old: JSONValue, new: JSONValue, threshold: NumericThreshold
) -> tuple[Significance, dict[str, Any]]:
    before, after = _as_decimal(old), _as_decimal(new)
    if before is None or after is None:
        return Significance.LOW, {}
    delta = after - before
    details: dict[str, Any] = {"delta": _plain(delta)}
    if before == 0:
        return (Significance.HIGH if after != 0 else Significance.LOW), details
    try:
        ratio = delta / abs(before) * 100
    except ArithmeticError:  # decimal.Overflow on an absurd magnitude gap
        ratio = _PCT_CAP if delta > 0 else -_PCT_CAP
    pct = float(max(-_PCT_CAP, min(_PCT_CAP, ratio)))
    details["pct"] = round(pct, 2)
    magnitude = abs(pct)
    if magnitude >= threshold.critical_pct:
        return Significance.CRITICAL, details
    if magnitude >= threshold.high_pct:
        return Significance.HIGH, details
    if magnitude >= threshold.medium_pct:
        return Significance.MEDIUM, details
    return Significance.LOW, details


def _plain(number: Decimal) -> str:
    """Fixed-point text with at most 18 fractional digits (never '1e-999999' expanded)."""
    with localcontext() as context:
        context.prec = 80  # enough for 1e18 with 18 fractional digits, and then some
        if number.is_finite() and number.as_tuple().exponent < -18:  # type: ignore[operator]
            number = number.quantize(_FRACTION_DIGITS)
        return format(number.normalize(), "f")


def diff_versions(
    schema: DatasetSchema,
    before: dict[str, JSONValue] | None,
    after: dict[str, JSONValue] | None,
) -> DetectedChange | None:
    tracked = schema.tracked_fields
    if before is None and after is not None:
        created = {f: {"old": None, "new": after[f]} for f in sorted(tracked) if f in after}
        return DetectedChange(ChangeType.CREATED, created, Significance.MEDIUM, 50)
    if before is not None and after is None:
        deleted = {f: {"old": before[f], "new": None} for f in sorted(tracked) if f in before}
        return DetectedChange(ChangeType.DELETED, deleted, Significance.MEDIUM, 55)
    if before is None or after is None:
        return None
    diff: dict[str, Any] = {}
    significance = Significance.LOW
    for name in sorted(tracked):
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        entry: dict[str, Any] = {"old": old, "new": new}
        spec = schema.field(name)
        level = Significance.LOW
        if spec is not None and spec.type in (FieldType.INTEGER, FieldType.DECIMAL):
            threshold = schema.change_policy.numeric_thresholds.get(name, _DEFAULT_THRESHOLD)
            level, details = _numeric_significance(old, new, threshold)
            entry.update(details)
        elif spec is not None and spec.type is FieldType.BOOLEAN:
            level = Significance.MEDIUM  # e.g. availability flips
        diff[name] = entry
        if level.rank > significance.rank:
            significance = level
    if not diff:
        return None
    score = min(100, _BASE_SCORE[significance] + 2 * (len(diff) - 1))
    return DetectedChange(ChangeType.UPDATED, diff, significance, score)

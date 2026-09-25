"""Change analytics: volume, trend and unusual days.

Pure functions over change counts that the database aggregates (per UTC day,
type and significance), so a busy period is summarized from *every* change,
not from a sample. Robust statistics (median and median absolute deviation)
keep one extreme day from hiding the next, and minimum counts keep a quiet
dataset's "3 changes instead of 1" from being an anomaly.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from statistics import median
from typing import Any
from uuid import UUID

from nexusflow.domain.records.model import ChangeType, ChangeVolume, Significance

# Reports and analytics cover at most this long a period.
MAX_PERIOD = timedelta(days=366)
# A day is unusual when its robust z-score exceeds this (Iglewicz & Hoaglin)...
MODIFIED_Z_THRESHOLD = 3.5
# ...or, when most days are identical (MAD = 0), when it is this many times the norm.
SPIKE_FACTOR = 3.0
# Below this many changes a day is never flagged.
MIN_SPIKE_CHANGES = 5
_MIN_DAYS = 4  # fewer days are no baseline
_MAX_DAYS = MAX_PERIOD.days + 1  # a period not aligned to midnight spans one more day


@dataclass(frozen=True, slots=True)
class VolumeSummary:
    """How many changes a period had, how they spread over its days, and what stands out."""

    totals: dict[str, int]  # "changes" plus one entry per change type
    by_significance: dict[str, int]
    daily: list[tuple[str, int]]  # every UTC day of the period, quiet days included
    unusual_days: list[dict[str, Any]]
    trend_note: str


@dataclass(frozen=True, slots=True)
class ChangeAnalytics:
    """Change volume of a project, or of one of its datasets, over a period."""

    project_id: UUID
    dataset_id: UUID | None
    period_start: datetime
    period_end: datetime
    volume: VolumeSummary


def summarize_volume(
    volume: Iterable[ChangeVolume], start: datetime, end: datetime
) -> VolumeSummary:
    """Totals, the daily series and its unusual days from aggregated counts.

    Every type and significance level is present (zero when there were none),
    so consumers see a stable shape.
    """
    by_type: Counter[str] = Counter()
    by_significance: Counter[str] = Counter()
    by_day: Counter[str] = Counter()
    for row in volume:
        by_type[row.change_type.value] += row.count
        by_significance[row.significance.value] += row.count
        by_day[row.day.isoformat()] += row.count
    daily = every_day(start, end, by_day)
    return VolumeSummary(
        totals={"changes": by_type.total(), **{t.value: by_type[t.value] for t in ChangeType}},
        by_significance={s.value: by_significance[s.value] for s in Significance},
        daily=daily,
        unusual_days=volume_spikes(daily),
        trend_note=trend_note(daily),
    )


def headline(summary: VolumeSummary, scope: str) -> str:
    """One sentence on the period's changes, from the counts of all of them."""
    totals = summary.totals
    if totals["changes"] == 0:
        return f"No changes were detected in '{scope}' in this period."
    highest = next(
        level
        for level in sorted(Significance, key=lambda s: s.rank, reverse=True)
        if summary.by_significance[level.value] or level is Significance.LOW
    )
    noun = "change" if totals["changes"] == 1 else "changes"
    return (
        f"{totals['changes']} {noun} detected in '{scope}': {totals['updated']} updated, "
        f"{totals['created']} created, {totals['deleted']} removed. "
        f"Highest significance: {highest.value}."
    )


def every_day(
    start: datetime, end: datetime, counts: Mapping[str, int], *, max_days: int = _MAX_DAYS
) -> list[tuple[str, int]]:
    """Daily counts including the quiet days: a trend without zeros overstates activity.

    Days are UTC calendar days (change timestamps are stored in UTC) and the
    period end is exclusive, as in the queries that select the changes.
    """
    days: list[tuple[str, int]] = []
    day = as_utc(start).date()
    last = (as_utc(end) - timedelta(microseconds=1)).date()
    while day <= last and len(days) < max_days:
        days.append((day.isoformat(), counts.get(day.isoformat(), 0)))
        day += timedelta(days=1)
    return days


def as_utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def volume_spikes(daily: list[tuple[str, int]]) -> list[dict[str, Any]]:
    """Days with unusually many changes compared with the rest of the period."""
    if len(daily) < _MIN_DAYS:
        return []
    counts = [count for _, count in daily]
    center = median(counts)
    deviation = median(abs(count - center) for count in counts)
    spikes: list[dict[str, Any]] = []
    for day, count in daily:
        if count < MIN_SPIKE_CHANGES or count <= center:
            continue
        if deviation > 0:
            score = 0.6745 * (count - center) / deviation
            unusual = score > MODIFIED_Z_THRESHOLD
        else:
            score = None
            unusual = count >= SPIKE_FACTOR * max(center, 1)
        if unusual:
            spikes.append(
                {
                    "date": day,
                    "changes": count,
                    "baseline": center,
                    "score": round(score, 1) if score is not None else None,
                }
            )
    return spikes


def trend_note(daily: list[tuple[str, int]]) -> str:
    """One sentence on how change volume moved across the period.

    The halves are compared by their daily averages: with an odd number of
    days the second half is a day longer, and comparing totals would call a
    flat week a rise.
    """
    if len(daily) < 2:
        return "Not enough days in the period to describe a trend."
    half = len(daily) // 2
    first_days, second_days = daily[:half], daily[half:]
    first = sum(count for _, count in first_days) / len(first_days)
    second = sum(count for _, count in second_days) / len(second_days)
    if first == second == 0:
        return "No changes were detected in the period."
    if first == 0:
        return "All detected changes fall in the second half of the period."
    delta = (second - first) / first
    if abs(delta) < 0.1:
        return "Change volume was stable across the period."
    direction = "rose" if delta > 0 else "fell"
    return f"Change volume {direction} {abs(delta):.0%} from the first to the second half."

"""Deterministic, local analysis used when external AI processing is disabled.

Privacy by default: an organization's data is only sent to an external AI
provider after it opts in (``ai_external_processing``). Until then - or when
no provider is configured - insights are produced by this statistical
summarizer, so the product still works fully offline.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Literal

from nexusflow.domain.intelligence.model import AnalysisOutput, Finding, RiskLevel

_RISK_BY_SIGNIFICANCE = {
    "critical": RiskLevel.CRITICAL,
    "high": RiskLevel.HIGH,
    "medium": RiskLevel.MEDIUM,
    "low": RiskLevel.LOW,
}
_ORDER = ("critical", "high", "medium", "low")
_IMPACT: dict[str, Literal["low", "medium", "high"]] = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def _describe(change: dict[str, Any]) -> tuple[str, str]:
    key = str(change.get("record_key", "record"))[:80]
    kind = change.get("change_type")
    if kind == "created":
        return f"New record: {key}", f"A new record '{key}' appeared in the dataset."
    if kind == "deleted":
        return f"Record removed: {key}", f"The record '{key}' is no longer present in the source."
    parts = []
    for field_name, entry in list(dict(change.get("diff", {})).items())[:4]:
        if isinstance(entry, dict) and "pct" in entry:
            parts.append(
                f"{field_name} {entry['pct']:+.1f}% ({entry.get('old')} -> {entry.get('new')})"
            )
        elif isinstance(entry, dict):
            parts.append(f"{field_name}: {entry.get('old')} -> {entry.get('new')}")
    detail = "; ".join(parts) or "tracked fields changed"
    return f"Updated: {key}", f"'{key}' changed: {detail}."


def offline_analysis(changes: list[dict[str, Any]], *, dataset_name: str) -> AnalysisOutput:
    if not changes:
        return AnalysisOutput(
            summary=f"No new changes were detected in '{dataset_name}' for this period.",
            risk_level=RiskLevel.LOW,
            confidence=1.0,
        )
    types = Counter(str(c.get("change_type")) for c in changes)
    levels = Counter(str(c.get("significance")) for c in changes)
    top_level = next((level for level in _ORDER if levels.get(level)), "low")
    ranked = sorted(changes, key=lambda c: -int(c.get("score", 0)))[:5]
    findings = []
    for change in ranked:
        title, detail = _describe(change)
        impact = _IMPACT.get(str(change.get("significance")), "low")
        findings.append(
            Finding(
                title=title[:160],
                detail=detail[:1200],
                impact=impact,
                change_refs=[str(change["id"])],
            )
        )
    recommendations = [*_move_recommendations(changes)]
    removed = [c for c in changes if c.get("change_type") == "deleted"]
    if len(removed) == 1:
        recommendations.append(f"Investigate why {_key(removed[0])} disappeared from its source.")
    elif removed:
        recommendations.append(
            f"Investigate {len(removed)} records that disappeared from their sources."
        )
    created = [c for c in changes if c.get("change_type") == "created"]
    if len(created) == 1:
        recommendations.append(f"Assess the newly listed record {_key(created[0])}.")
    elif created:
        recommendations.append(f"Assess {len(created)} newly listed records.")
    summary = (
        f"{_plural(len(changes), 'change', 'changes')} detected in '{dataset_name}': "
        f"{types.get('updated', 0)} updated, {types.get('created', 0)} created, "
        f"{types.get('deleted', 0)} removed. Highest significance: {top_level}."
    )
    return AnalysisOutput(
        summary=summary,
        risk_level=_RISK_BY_SIGNIFICANCE[top_level],
        confidence=0.6,
        findings=findings,
        recommendations=recommendations[:10],
    )


def _key(change: dict[str, Any]) -> str:
    return str(change.get("record_key", "record"))[:80]


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _move_recommendations(changes: list[dict[str, Any]]) -> list[str]:
    """One line per direction of numeric change, naming the largest move."""
    moves = [
        (float(entry["pct"]), str(name), _key(change))
        for change in changes
        for name, entry in dict(change.get("diff", {})).items()
        if isinstance(entry, dict)
        and isinstance(entry.get("pct"), (int, float))
        and not isinstance(entry.get("pct"), bool)
    ]
    lines = []
    for label, chosen, pick in (
        ("increase", [m for m in moves if m[0] > 0], max),
        ("decrease", [m for m in moves if m[0] < 0], min),
    ):
        if not chosen:
            continue
        pct, name, key = pick(chosen)
        if len(chosen) == 1:
            lines.append(f"Review the {label} in {name} on {key} ({pct:+.1f}%).")
        else:
            lines.append(
                f"Review {len(chosen)} {label}s in tracked values; "
                f"the largest is {name} on {key} ({pct:+.1f}%)."
            )
    return lines

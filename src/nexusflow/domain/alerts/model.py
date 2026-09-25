"""Alert rules, fired alerts and pure rule evaluation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from nexusflow.domain.intelligence.model import RiskLevel
from nexusflow.domain.records.model import ChangeType, Significance

_RISK_RANK = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ChangeTypeCondition(_Strict):
    type: Literal["change_type"] = "change_type"
    change_types: list[ChangeType] = Field(min_length=1, max_length=3)


class SignificanceCondition(_Strict):
    type: Literal["significance_at_least"] = "significance_at_least"
    level: Significance


class FieldChangedCondition(_Strict):
    type: Literal["field_changed"] = "field_changed"
    field: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")


class NumericChangeCondition(_Strict):
    type: Literal["numeric_change"] = "numeric_change"
    field: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")
    direction: Literal["increase", "decrease", "any"] = "any"
    min_pct: float = Field(default=0, ge=0, le=100_000)


class InsightRiskCondition(_Strict):
    type: Literal["insight_risk_at_least"] = "insight_risk_at_least"
    level: RiskLevel


class RunFailedCondition(_Strict):
    type: Literal["run_failed"] = "run_failed"


type AlertCondition = (
    ChangeTypeCondition
    | SignificanceCondition
    | FieldChangedCondition
    | NumericChangeCondition
    | InsightRiskCondition
    | RunFailedCondition
)
CONDITION_ADAPTER: TypeAdapter[AlertCondition] = TypeAdapter(
    Annotated[
        ChangeTypeCondition
        | SignificanceCondition
        | FieldChangedCondition
        | NumericChangeCondition
        | InsightRiskCondition
        | RunFailedCondition,
        Field(discriminator="type"),
    ]
)

SubjectType = Literal["change", "insight", "run"]


@dataclass(frozen=True, slots=True)
class AlertSubject:
    """Uniform view of what an alert rule is evaluated against."""

    subject_type: SubjectType
    subject_id: UUID
    dataset_id: UUID | None
    dedup_identity: str
    change_type: ChangeType | None = None
    significance: Significance | None = None
    # What the alert may show: sensitive fields masked.
    diff: dict[str, Any] = field(default_factory=dict)
    # What conditions are evaluated against: the complete diff, so a rule on a
    # sensitive field still fires. It is never rendered, stored or sent.
    match_diff: dict[str, Any] | None = None
    risk_level: RiskLevel | None = None
    title: str = ""
    body: str = ""

    @property
    def condition_diff(self) -> dict[str, Any]:
        return self.diff if self.match_diff is None else self.match_diff


def matches(condition: AlertCondition, subject: AlertSubject) -> bool:  # noqa: PLR0911 - one return per condition
    match condition:
        case ChangeTypeCondition(change_types=types):
            return subject.subject_type == "change" and subject.change_type in types
        case SignificanceCondition(level=level):
            return subject.significance is not None and subject.significance.rank >= level.rank
        case FieldChangedCondition(field=name):
            # Only an update changes a field. Created and deleted records list every
            # field in their diff; a rule for new records uses change_type instead.
            return subject.change_type is ChangeType.UPDATED and name in subject.condition_diff
        case NumericChangeCondition(field=name, direction=direction, min_pct=min_pct):
            entry = subject.condition_diff.get(name)
            if not isinstance(entry, dict) or "pct" not in entry:
                return False
            pct = float(entry["pct"])
            if direction == "increase" and pct <= 0:
                return False
            if direction == "decrease" and pct >= 0:
                return False
            return abs(pct) >= min_pct
        case InsightRiskCondition(level=level):
            return (
                subject.risk_level is not None
                and _RISK_RANK[subject.risk_level] >= _RISK_RANK[level]
            )
        case RunFailedCondition():
            return subject.subject_type == "run"


def dedup_key(rule_id: UUID, subject: AlertSubject, *, cooldown_minutes: int, now: datetime) -> str:
    """Same rule + same subject within one cooldown window => one alert."""
    window = int(now.timestamp() // max(60, cooldown_minutes * 60))
    raw = f"{rule_id}|{subject.subject_type}|{subject.dedup_identity}|{window}"
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass(eq=False, kw_only=True)
class AlertRule:
    id: UUID
    org_id: UUID
    project_id: UUID
    dataset_id: UUID | None = None
    name: str
    enabled: bool = True
    condition: dict[str, Any] = field(default_factory=dict)
    severity: AlertSeverity = AlertSeverity.WARNING
    channel_ids: list[UUID] = field(default_factory=list)
    cooldown_minutes: int = 60
    created_by: UUID | None = None
    created_at: datetime
    updated_at: datetime

    @property
    def parsed_condition(self) -> AlertCondition:
        return CONDITION_ADAPTER.validate_python(self.condition)


@dataclass(eq=False, kw_only=True)
class Alert:
    id: UUID
    org_id: UUID
    rule_id: UUID
    severity: AlertSeverity
    title: str
    body: str
    dedup_key: str
    subject_type: str
    subject_id: UUID
    status: AlertStatus = AlertStatus.OPEN
    triggered_at: datetime
    acknowledged_by: UUID | None = None
    acknowledged_at: datetime | None = None

"""AI-generated insights and their strictly validated output contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class InsightStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"  # model output failed validation / policy checks


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Finding(_Strict):
    title: str = Field(min_length=1, max_length=160)
    detail: str = Field(min_length=1, max_length=1200)
    impact: Literal["low", "medium", "high"]
    change_refs: list[str] = Field(default_factory=list, max_length=50)


class AnalysisOutput(_Strict):
    """The only shape accepted from a model. Anything else is rejected."""

    summary: str = Field(min_length=1, max_length=2000)
    risk_level: RiskLevel
    confidence: float = Field(ge=0, le=1)
    findings: list[Finding] = Field(default_factory=list, max_length=20)
    recommendations: list[str] = Field(default_factory=list, max_length=10)


@dataclass(eq=False, kw_only=True)
class Insight:
    id: UUID
    org_id: UUID
    project_id: UUID
    dataset_id: UUID
    status: InsightStatus = InsightStatus.PENDING
    idempotency_key: str
    provider: str | None = None
    model: str | None = None
    prompt_version: str | None = None
    input_hash: str | None = None
    summary: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    risk_level: RiskLevel | None = None
    confidence: float | None = None
    change_count: int = 0
    usage: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    requested_by: UUID | None = None
    period_start: datetime | None = None
    period_end: datetime | None = None
    created_at: datetime
    completed_at: datetime | None = None
    # Set when a worker claims the analysis: the reaper's clock, and a fencing
    # token so a worker whose claim was reaped cannot overwrite a newer run.
    started_at: datetime | None = None
    attempts: int = 0

    def start(self, now: datetime) -> None:
        self.status = InsightStatus.RUNNING
        self.started_at = now
        self.attempts += 1

    def is_claimed_by(self, started_at: datetime | None) -> bool:
        return self.status is InsightStatus.RUNNING and self.started_at == started_at

    def complete(
        self,
        output: AnalysisOutput,
        *,
        provider: str,
        model: str,
        usage: dict[str, Any],
        now: datetime,
    ) -> None:
        self.status = InsightStatus.COMPLETED
        self.summary = output.summary
        self.findings = [f.model_dump() for f in output.findings]
        self.recommendations = list(output.recommendations)
        self.risk_level = output.risk_level
        self.confidence = output.confidence
        self.provider = provider
        self.model = model
        self.usage = usage
        self.completed_at = now

    def reject(
        self, code: str, now: datetime, *, status: InsightStatus = InsightStatus.REJECTED
    ) -> None:
        self.status = status
        self.error_code = code[:64]
        self.completed_at = now

    def reopen(self) -> None:
        """FAILED -> PENDING: retried from the dead-letter store."""
        if self.status is InsightStatus.FAILED:
            self.status = InsightStatus.PENDING
            self.error_code = None
            self.completed_at = None

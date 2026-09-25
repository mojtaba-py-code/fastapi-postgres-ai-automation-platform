"""Generated reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID


class ReportFormat(StrEnum):
    JSON = "json"
    CSV = "csv"
    XLSX = "xlsx"
    PDF = "pdf"


class ReportStatus(StrEnum):
    PENDING = "pending"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"
    EXPIRED = "expired"


MEDIA_TYPES: dict[ReportFormat, str] = {
    ReportFormat.JSON: "application/json",
    ReportFormat.CSV: "text/csv; charset=utf-8",
    ReportFormat.XLSX: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ReportFormat.PDF: "application/pdf",
}


@dataclass(eq=False, kw_only=True)
class Report:
    id: UUID
    org_id: UUID
    project_id: UUID
    dataset_id: UUID | None = None
    title: str
    format: ReportFormat
    period_start: datetime
    period_end: datetime
    status: ReportStatus = ReportStatus.PENDING
    storage_key: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    idempotency_key: str | None = None
    requested_by: UUID | None = None
    error_code: str | None = None
    created_at: datetime
    completed_at: datetime | None = None
    expires_at: datetime | None = None


def report_storage_key(org_id: UUID, report_id: UUID, fmt: ReportFormat) -> str:
    return f"reports/{org_id}/{report_id}.{fmt.value}"


@dataclass(frozen=True, slots=True)
class ReportContent:
    """Everything a renderer needs; renderers never query the database."""

    title: str
    organization: str
    project: str
    dataset: str | None
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    executive_summary: str
    totals: dict[str, int]
    by_significance: dict[str, int]
    daily_trend: list[tuple[str, int]]
    changes: list[dict[str, Any]] = field(default_factory=list)
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    insights: list[dict[str, Any]] = field(default_factory=list)
    sources: list[dict[str, str]] = field(default_factory=list)
    # Days with unusually many changes, and one sentence on the volume trend.
    volume_anomalies: list[dict[str, Any]] = field(default_factory=list)
    trend_note: str = ""

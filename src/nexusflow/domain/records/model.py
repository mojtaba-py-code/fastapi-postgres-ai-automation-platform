"""Stored records, their version history and detected changes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID


@dataclass(eq=False, kw_only=True)
class Record:
    id: UUID
    org_id: UUID
    dataset_id: UUID
    record_key: str
    data: dict[str, Any] = field(default_factory=dict)
    content_hash: str
    version: int = 1
    source_id: UUID | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    last_run_id: UUID | None = None
    deleted_at: datetime | None = None


@dataclass(eq=False, kw_only=True)
class RecordVersion:
    id: UUID
    org_id: UUID
    dataset_id: UUID
    record_id: UUID
    version: int
    data: dict[str, Any] = field(default_factory=dict)
    content_hash: str
    run_id: UUID | None = None
    captured_at: datetime
    is_deletion: bool = False
    diffed: bool = False


class ChangeType(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"


class Significance(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {
    Significance.LOW: 1,
    Significance.MEDIUM: 2,
    Significance.HIGH: 3,
    Significance.CRITICAL: 4,
}


@dataclass(eq=False, kw_only=True)
class Change:
    id: UUID
    org_id: UUID
    dataset_id: UUID
    record_id: UUID
    record_key: str
    run_id: UUID | None = None
    change_type: ChangeType
    from_version: int | None = None
    to_version: int
    diff: dict[str, Any] = field(default_factory=dict)
    significance: Significance
    score: int
    detected_at: datetime
    insight_id: UUID | None = None
    alerts_evaluated: bool = False


@dataclass(frozen=True, slots=True)
class ChangeVolume:
    """How many changes of one type and significance a scope had on one UTC day."""

    day: date
    change_type: ChangeType
    significance: Significance
    count: int

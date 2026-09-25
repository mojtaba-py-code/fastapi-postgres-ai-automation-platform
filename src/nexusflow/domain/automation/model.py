"""Tenant automation workflows, their runs, and the dead-letter store."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID

MIN_INTERVAL_MINUTES = 5
MAX_INTERVAL_MINUTES = 7 * 24 * 60


class WorkflowStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"  # kill switch: requires an explicit re-enable


class WorkflowTrigger(StrEnum):
    SCHEDULE = "schedule"
    MANUAL = "manual"


class WorkflowRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkflowStep(StrEnum):
    COLLECT = "collect"
    DETECT = "detect"
    ANALYZE = "analyze"
    ALERT = "alert"


@dataclass(eq=False, kw_only=True)
class Workflow:
    id: UUID
    org_id: UUID
    project_id: UUID
    name: str
    description: str | None = None
    trigger: WorkflowTrigger = WorkflowTrigger.SCHEDULE
    schedule_interval_minutes: int | None = None
    source_ids: list[UUID] = field(default_factory=list)
    analyze: bool = True
    alert: bool = True
    status: WorkflowStatus = WorkflowStatus.ACTIVE
    disabled_reason: str | None = None
    disabled_by: UUID | None = None
    disabled_at: datetime | None = None
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    created_by: UUID | None = None
    created_at: datetime
    updated_at: datetime
    version: int = 1

    @property
    def is_runnable(self) -> bool:
        return self.status is WorkflowStatus.ACTIVE

    def schedule_next(self, now: datetime) -> None:
        if self.trigger is WorkflowTrigger.SCHEDULE and self.schedule_interval_minutes:
            self.next_run_at = now + timedelta(minutes=self.schedule_interval_minutes)
        else:
            self.next_run_at = None

    def slot_key(self, now: datetime) -> str:
        """Idempotency key for a scheduled run: one run per workflow per slot."""
        interval = max(self.schedule_interval_minutes or 1, 1) * 60
        return f"wf:{self.id}:{int(now.timestamp() // interval)}"

    def disable(self, *, reason: str, by: UUID | None, now: datetime) -> None:
        self.status = WorkflowStatus.DISABLED
        self.disabled_reason = reason[:200]
        self.disabled_by = by
        self.disabled_at = now
        self.next_run_at = None
        self.updated_at = now
        self.version += 1


@dataclass(eq=False, kw_only=True)
class WorkflowRun:
    id: UUID
    org_id: UUID
    workflow_id: UUID
    trigger: WorkflowTrigger
    status: WorkflowRunStatus = WorkflowRunStatus.PENDING
    idempotency_key: str
    current_step: WorkflowStep | None = None
    step_results: dict[str, Any] = field(default_factory=dict)
    n8n_execution_id: str | None = None
    error_code: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            WorkflowRunStatus.SUCCEEDED,
            WorkflowRunStatus.FAILED,
            WorkflowRunStatus.CANCELLED,
        )

    def record_step(self, step: WorkflowStep, result: dict[str, Any], now: datetime) -> None:
        if self.status is WorkflowRunStatus.PENDING:
            self.status = WorkflowRunStatus.RUNNING
            self.started_at = now
        self.current_step = step
        self.step_results = {**self.step_results, step.value: {**result, "at": now.isoformat()}}

    def finish(
        self, status: WorkflowRunStatus, now: datetime, *, error_code: str | None = None
    ) -> None:
        self.status = status
        self.error_code = error_code
        self.finished_at = now


class DeadLetterStatus(StrEnum):
    OPEN = "open"
    RETRIED = "retried"
    DISCARDED = "discarded"


@dataclass(eq=False, kw_only=True)
class DeadLetter:
    id: UUID
    org_id: UUID | None
    origin: str
    task_name: str
    reference_type: str | None = None
    reference_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    error_code: str
    error_message: str | None = None
    attempts: int = 1
    status: DeadLetterStatus = DeadLetterStatus.OPEN
    first_failed_at: datetime
    last_failed_at: datetime
    resolved_at: datetime | None = None
    resolved_by: UUID | None = None

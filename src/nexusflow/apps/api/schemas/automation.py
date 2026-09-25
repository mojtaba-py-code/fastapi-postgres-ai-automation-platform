"""Schemas for the internal automation API (n8n -> platform).

Responses carry identifiers, states and counters only - never tenant content -
so a compromised automation layer cannot use these endpoints to read data.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import Field

from nexusflow.apps.api.schemas.common import RequestModel, ResponseModel
from nexusflow.domain.automation.model import WorkflowRunStatus
from nexusflow.domain.intelligence.model import InsightStatus, RiskLevel
from nexusflow.domain.records.model import Significance


class DispatchRequest(RequestModel):
    limit: int = Field(default=100, ge=1, le=500)


class DispatchedRunOut(ResponseModel):
    org_id: UUID
    workflow_id: UUID
    workflow_run_id: UUID


class DispatchResponse(ResponseModel):
    dispatched: list[DispatchedRunOut]


class WorkflowRunStatusOut(ResponseModel):
    workflow_run_id: UUID
    status: WorkflowRunStatus
    collections: dict[str, int]
    pending: int
    sources: list[UUID]


class DatasetStep(RequestModel):
    org_id: UUID
    dataset_id: UUID


class OrganizationStep(RequestModel):
    org_id: UUID


class DetectionOut(ResponseModel):
    dataset_id: UUID
    versions_processed: int
    changes_created: int
    max_significance: Significance | None
    analyze: bool


class SweepRequest(RequestModel):
    limit: int = Field(default=200, ge=1, le=1000)


class SweepOut(ResponseModel):
    enqueued: int


class AnalysisQueuedOut(ResponseModel):
    insight_id: UUID | None
    queued: bool


class InsightStatusOut(ResponseModel):
    insight_id: UUID
    status: InsightStatus
    risk_level: RiskLevel | None
    error_code: str | None


class AlertEvaluationOut(ResponseModel):
    alerts_created: int


class FailureReport(RequestModel):
    org_id: UUID | None = None
    workflow: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9 ._:()-]+$")
    node: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9 ._:()-]+$")
    execution_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    # n8n's ``execution.retryOf``: set when the failed execution was itself a
    # retry. The platform counts attempts per retry chain - it never trusts a
    # caller-supplied attempt number.
    retry_of: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    error_message: str = Field(default="", max_length=4000)
    idempotent: bool = False


class FailureDecisionOut(ResponseModel):
    retry: bool
    delay_seconds: float
    dead_letter_id: UUID | None


class OperatorAlertIn(RequestModel):
    severity: Literal["info", "warning", "critical"]
    summary: str = Field(min_length=1, max_length=500)

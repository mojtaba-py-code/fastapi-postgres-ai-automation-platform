"""Schemas for the business resources. Secrets are write-only everywhere."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from nexusflow.apps.api.schemas.common import RequestModel, ResponseModel
from nexusflow.domain.alerts.model import (
    AlertSeverity,
    AlertStatus,
    ChangeTypeCondition,
    FieldChangedCondition,
    InsightRiskCondition,
    NumericChangeCondition,
    RunFailedCondition,
    SignificanceCondition,
)
from nexusflow.domain.automation.model import (
    DeadLetterStatus,
    WorkflowRunStatus,
    WorkflowStatus,
    WorkflowTrigger,
)
from nexusflow.domain.catalog.model import DataClassification, DatasetSchema, ProjectStatus
from nexusflow.domain.integrations.model import IntegrationKind, IntegrationStatus
from nexusflow.domain.intelligence.model import InsightStatus, RiskLevel
from nexusflow.domain.notifications.model import (
    ChannelKind,
    EmailChannelConfig,
    SlackChannelConfig,
    TelegramChannelConfig,
    WebhookChannelConfig,
)
from nexusflow.domain.records.model import ChangeType, Significance
from nexusflow.domain.reports.model import ReportFormat, ReportStatus
from nexusflow.domain.sources.model import (
    FileUploadConfig,
    RestApiConfig,
    RunStatus,
    RunTrigger,
    SourceKind,
    SourceStatus,
    WebhookConfig,
    WebsiteConfig,
)
from nexusflow.domain.uploads.model import UploadStatus
from nexusflow.domain.webhooks.model import EndpointStatus

Name = Annotated[str, Field(min_length=1, max_length=120)]
Description = Annotated[str | None, Field(default=None, max_length=1000)]
SourceConfigIn = Annotated[
    WebsiteConfig | RestApiConfig | WebhookConfig | FileUploadConfig, Field(discriminator="kind")
]
ChannelConfigIn = Annotated[
    EmailChannelConfig | SlackChannelConfig | TelegramChannelConfig | WebhookChannelConfig,
    Field(discriminator="kind"),
]
ConditionIn = Annotated[
    ChangeTypeCondition
    | SignificanceCondition
    | FieldChangedCondition
    | NumericChangeCondition
    | InsightRiskCondition
    | RunFailedCondition,
    Field(discriminator="type"),
]

# ---------------------------------------------------------------- catalog


class ProjectCreate(RequestModel):
    name: Name
    description: Description = None


class ProjectUpdate(RequestModel):
    name: Name | None = None
    description: Description = None
    status: ProjectStatus | None = None


class ProjectOut(ResponseModel):
    id: UUID
    name: str
    description: str | None
    status: ProjectStatus
    created_at: datetime
    updated_at: datetime


class DatasetCreate(RequestModel):
    project_id: UUID
    name: Name
    description: Description = None
    schema_: DatasetSchema = Field(alias="schema")
    classification: DataClassification = DataClassification.INTERNAL
    retention_days: int = Field(default=180, ge=7, le=3650)


class DatasetUpdate(RequestModel):
    description: Description = None
    classification: DataClassification | None = None
    retention_days: int | None = Field(default=None, ge=7, le=3650)
    schema_: DatasetSchema | None = Field(default=None, alias="schema")


class DatasetOut(ResponseModel):
    id: UUID
    project_id: UUID
    name: str
    description: str | None
    schema_: dict[str, Any] = Field(validation_alias="schema", serialization_alias="schema")
    classification: DataClassification
    retention_days: int
    created_at: datetime
    updated_at: datetime


class RecordOut(ResponseModel):
    id: UUID
    dataset_id: UUID
    record_key: str
    data: dict[str, Any]
    version: int
    first_seen_at: datetime
    last_seen_at: datetime
    deleted_at: datetime | None


class RecordVersionOut(ResponseModel):
    version: int
    data: dict[str, Any]
    captured_at: datetime
    is_deletion: bool


class RecordHistoryOut(ResponseModel):
    record: RecordOut
    versions: list[RecordVersionOut]


class ChangeOut(ResponseModel):
    id: UUID
    dataset_id: UUID
    record_id: UUID
    record_key: str
    change_type: ChangeType
    from_version: int | None
    to_version: int
    diff: dict[str, Any]
    significance: Significance
    score: int
    detected_at: datetime
    insight_id: UUID | None


# ---------------------------------------------------------------- sources


class SourceCreate(RequestModel):
    project_id: UUID
    dataset_id: UUID
    name: Name
    config: SourceConfigIn
    integration_id: UUID | None = None


class SourceUpdate(RequestModel):
    name: Name | None = None
    config: SourceConfigIn | None = None
    integration_id: UUID | None = None
    clear_integration: bool = False
    status: Literal["active", "paused", "quarantined"] | None = None


class SourceOut(ResponseModel):
    id: UUID
    project_id: UUID
    dataset_id: UUID
    name: str
    kind: SourceKind
    config: dict[str, Any]
    integration_id: UUID | None
    status: SourceStatus
    consecutive_failures: int
    last_run_at: datetime | None
    last_success_at: datetime | None
    created_at: datetime


class RunOut(ResponseModel):
    id: UUID
    source_id: UUID
    workflow_run_id: UUID | None
    trigger: RunTrigger
    status: RunStatus
    attempt: int
    stats: dict[str, Any]
    error_code: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class UploadOut(ResponseModel):
    id: UUID
    source_id: UUID
    original_filename: str
    content_type: str
    size_bytes: int
    sha256: str
    status: UploadStatus
    rejection_reason: str | None
    row_count: int | None
    run_id: UUID | None
    created_at: datetime
    processed_at: datetime | None


# ----------------------------------------------------------- integrations


class IntegrationCreate(RequestModel):
    name: Annotated[str, Field(min_length=1, max_length=100)]
    kind: IntegrationKind
    secret: str | None = Field(default=None, min_length=1, max_length=4096, repr=False)
    metadata: dict[str, str] = Field(default_factory=dict, max_length=10)


class IntegrationRotate(RequestModel):
    secret: str = Field(min_length=1, max_length=4096, repr=False)
    metadata: dict[str, str] | None = Field(default=None, max_length=10)


class IntegrationStatusChange(RequestModel):
    status: IntegrationStatus
    reason: str = Field(min_length=3, max_length=200)


class IntegrationOut(ResponseModel):
    id: UUID
    name: str
    kind: IntegrationKind
    status: IntegrationStatus
    secret_hint: str
    secret_fingerprint: str
    metadata: dict[str, Any]
    created_at: datetime
    rotated_at: datetime | None
    last_used_at: datetime | None


class IntegrationCreatedOut(IntegrationOut):
    generated_secret: str | None = Field(default=None, description="Shown exactly once.")


class WebhookEndpointCreate(RequestModel):
    source_id: UUID
    name: Annotated[str, Field(min_length=1, max_length=100)]


class WebhookEndpointOut(ResponseModel):
    id: UUID
    source_id: UUID
    name: str
    status: EndpointStatus
    created_at: datetime
    last_received_at: datetime | None


class WebhookEndpointCreatedOut(WebhookEndpointOut):
    url: str
    secret: str = Field(description="Signing secret, shown exactly once.")


class WebhookStatusChange(RequestModel):
    status: EndpointStatus


class WebhookReceiptOut(ResponseModel):
    status: Literal["accepted", "duplicate"]
    run_id: UUID | None


# ---------------------------------------------------- intelligence & alerts


class AnalysisCreate(RequestModel):
    dataset_id: UUID


class InsightOut(ResponseModel):
    id: UUID
    dataset_id: UUID
    status: InsightStatus
    provider: str | None
    model: str | None
    summary: str | None
    findings: list[dict[str, Any]]
    recommendations: list[str]
    risk_level: RiskLevel | None
    confidence: float | None
    change_count: int
    error_code: str | None
    created_at: datetime
    completed_at: datetime | None


class AlertRuleCreate(RequestModel):
    project_id: UUID
    dataset_id: UUID | None = None
    name: Name
    condition: ConditionIn
    severity: AlertSeverity = AlertSeverity.WARNING
    channel_ids: list[UUID] = Field(default_factory=list, max_length=10)
    cooldown_minutes: int = Field(default=60, ge=1, le=10080)


class AlertRuleUpdate(RequestModel):
    enabled: bool | None = None
    severity: AlertSeverity | None = None
    channel_ids: list[UUID] | None = Field(default=None, max_length=10)
    cooldown_minutes: int | None = Field(default=None, ge=1, le=10080)


class AlertRuleOut(ResponseModel):
    id: UUID
    project_id: UUID
    dataset_id: UUID | None
    name: str
    enabled: bool
    condition: dict[str, Any]
    severity: AlertSeverity
    channel_ids: list[UUID]
    cooldown_minutes: int
    created_at: datetime


class AlertOut(ResponseModel):
    id: UUID
    rule_id: UUID
    severity: AlertSeverity
    title: str
    body: str
    subject_type: str
    subject_id: UUID
    status: AlertStatus
    triggered_at: datetime
    acknowledged_at: datetime | None


class AlertAcknowledge(RequestModel):
    resolve: bool = False


class ChannelCreate(RequestModel):
    name: Annotated[str, Field(min_length=1, max_length=100)]
    config: ChannelConfigIn
    integration_id: UUID | None = None


class ChannelUpdate(RequestModel):
    enabled: bool


class ChannelOut(ResponseModel):
    id: UUID
    name: str
    kind: ChannelKind
    config: dict[str, Any]
    integration_id: UUID | None
    enabled: bool
    created_at: datetime


# ---------------------------------------------------------------- reports


class ReportCreate(RequestModel):
    project_id: UUID
    dataset_id: UUID | None = None
    title: str | None = Field(default=None, max_length=200)
    format: ReportFormat
    period_start: AwareDatetime
    period_end: AwareDatetime


class ReportOut(ResponseModel):
    id: UUID
    project_id: UUID
    dataset_id: UUID | None
    title: str
    format: ReportFormat
    status: ReportStatus
    period_start: datetime
    period_end: datetime
    size_bytes: int | None
    sha256: str | None
    error_code: str | None
    created_at: datetime
    completed_at: datetime | None
    expires_at: datetime | None


# -------------------------------------------------------------- analytics


class DailyVolumeOut(ResponseModel):
    date: str = Field(description="UTC calendar day (ISO 8601).")
    changes: int


class UnusualDayOut(ResponseModel):
    date: str = Field(description="UTC calendar day (ISO 8601).")
    changes: int
    baseline: float = Field(description="The period's median number of changes per day.")
    score: float | None = Field(
        description="Robust z-score (median absolute deviation); null when most days are equal."
    )


class ChangeAnalyticsOut(ResponseModel):
    project_id: UUID
    dataset_id: UUID | None
    period_start: datetime
    period_end: datetime
    totals: dict[str, int] = Field(description="All changes, and per change type.")
    by_significance: dict[str, int]
    daily: list[DailyVolumeOut] = Field(description="Every day of the period, quiet days too.")
    unusual_days: list[UnusualDayOut]
    trend_note: str


# -------------------------------------------------------------- workflows


class WorkflowCreate(RequestModel):
    project_id: UUID
    name: Name
    description: Description = None
    trigger: WorkflowTrigger = WorkflowTrigger.SCHEDULE
    schedule_interval_minutes: int | None = Field(default=None, ge=5, le=10080)
    source_ids: list[UUID] = Field(min_length=1, max_length=50)
    analyze: bool = True
    alert: bool = True


class WorkflowUpdate(RequestModel):
    name: Name | None = None
    description: Description = None
    schedule_interval_minutes: int | None = Field(default=None, ge=5, le=10080)
    source_ids: list[UUID] | None = Field(default=None, min_length=1, max_length=50)
    analyze: bool | None = None
    alert: bool | None = None
    expected_version: int | None = Field(default=None, ge=1)


class WorkflowStatusChange(RequestModel):
    status: WorkflowStatus
    reason: str | None = Field(default=None, min_length=3, max_length=200)


class WorkflowOut(ResponseModel):
    id: UUID
    project_id: UUID
    name: str
    description: str | None
    trigger: WorkflowTrigger
    schedule_interval_minutes: int | None
    source_ids: list[UUID]
    analyze: bool
    alert: bool
    status: WorkflowStatus
    disabled_reason: str | None
    next_run_at: datetime | None
    last_run_at: datetime | None
    version: int
    created_at: datetime


class WorkflowRunOut(ResponseModel):
    id: UUID
    workflow_id: UUID
    trigger: WorkflowTrigger
    status: WorkflowRunStatus
    current_step: str | None
    step_results: dict[str, Any]
    error_code: str | None
    created_at: datetime
    finished_at: datetime | None


class DeadLetterOut(ResponseModel):
    id: UUID
    origin: str
    task_name: str
    reference_type: str | None
    reference_id: str | None
    error_code: str
    error_message: str | None
    attempts: int
    status: DeadLetterStatus
    first_failed_at: datetime
    resolved_at: datetime | None

"""Tables for the business-data contexts (all tenant-scoped, all under RLS)."""

from __future__ import annotations

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB

from nexusflow.domain.alerts.model import AlertSeverity, AlertStatus
from nexusflow.domain.automation.model import (
    DeadLetterStatus,
    WorkflowRunStatus,
    WorkflowStatus,
    WorkflowStep,
    WorkflowTrigger,
)
from nexusflow.domain.catalog.model import DataClassification, ProjectStatus
from nexusflow.domain.integrations.model import IntegrationKind, IntegrationStatus
from nexusflow.domain.intelligence.model import InsightStatus, RiskLevel
from nexusflow.domain.notifications.model import ChannelKind, DeliveryState
from nexusflow.domain.records.model import ChangeType, Significance
from nexusflow.domain.reports.model import ReportFormat, ReportStatus
from nexusflow.domain.sources.model import RunStatus, RunTrigger, SourceKind, SourceStatus
from nexusflow.domain.uploads.model import UploadStatus
from nexusflow.domain.webhooks.model import DeliveryStatus, EndpointStatus
from nexusflow.infrastructure.database.metadata import enum_check, metadata
from nexusflow.infrastructure.database.types import StrEnumType

TS = DateTime(timezone=True)


def _org() -> Column[object]:
    return Column(
        "org_id", Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )


projects = Table(
    "projects",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("name", String(120), nullable=False),
    Column("description", String(1000)),
    Column("status", StrEnumType(ProjectStatus, 20), nullable=False),
    Column("created_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    UniqueConstraint("org_id", "name"),
    enum_check("status", ProjectStatus),
)

datasets = Table(
    "datasets",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("project_id", Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
    Column("name", String(120), nullable=False),
    Column("description", String(1000)),
    Column("schema", JSONB, nullable=False),
    Column("classification", StrEnumType(DataClassification, 20), nullable=False),
    Column("retention_days", Integer, nullable=False),
    Column("created_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    Column("deleted_at", TS),
    UniqueConstraint("project_id", "name"),
    enum_check("classification", DataClassification),
    CheckConstraint("retention_days BETWEEN 7 AND 3650", name="retention_range"),
    Index("ix_datasets_org_project", "org_id", "project_id"),
)

integrations = Table(
    "integrations",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("name", String(100), nullable=False),
    Column("kind", StrEnumType(IntegrationKind, 32), nullable=False),
    Column("status", StrEnumType(IntegrationStatus, 20), nullable=False),
    Column("secret_ciphertext", LargeBinary, nullable=False),
    Column("secret_key_id", String(32), nullable=False),
    Column("secret_fingerprint", String(16), nullable=False),
    Column("secret_hint", String(16), nullable=False),
    Column("metadata", JSONB, nullable=False),
    Column("created_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    Column("rotated_at", TS),
    Column("last_used_at", TS),
    UniqueConstraint("org_id", "name"),
    enum_check("kind", IntegrationKind),
    enum_check("status", IntegrationStatus),
)

sources = Table(
    "sources",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("project_id", Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
    Column("dataset_id", Uuid, ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False),
    Column("name", String(120), nullable=False),
    Column("kind", StrEnumType(SourceKind, 20), nullable=False),
    Column("config", JSONB, nullable=False),
    Column("integration_id", Uuid, ForeignKey("integrations.id", ondelete="SET NULL")),
    Column("status", StrEnumType(SourceStatus, 20), nullable=False),
    Column("consecutive_failures", Integer, nullable=False),
    Column("last_run_at", TS),
    Column("last_success_at", TS),
    Column("created_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    UniqueConstraint("project_id", "name"),
    enum_check("kind", SourceKind),
    enum_check("status", SourceStatus),
    Index("ix_sources_org_dataset", "org_id", "dataset_id"),
)

workflows = Table(
    "workflows",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("project_id", Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
    Column("name", String(120), nullable=False),
    Column("description", String(1000)),
    Column("trigger", StrEnumType(WorkflowTrigger, 20), nullable=False),
    Column("schedule_interval_minutes", Integer),
    Column("source_ids", ARRAY(Uuid), nullable=False),
    Column("analyze", Boolean, nullable=False),
    Column("alert", Boolean, nullable=False),
    Column("status", StrEnumType(WorkflowStatus, 20), nullable=False),
    Column("disabled_reason", String(200)),
    Column("disabled_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("disabled_at", TS),
    Column("next_run_at", TS),
    Column("last_run_at", TS),
    Column("created_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    Column("version", Integer, nullable=False),
    UniqueConstraint("project_id", "name"),
    enum_check("trigger", WorkflowTrigger),
    enum_check("status", WorkflowStatus),
    CheckConstraint(
        "schedule_interval_minutes IS NULL OR schedule_interval_minutes BETWEEN 5 AND 10080",
        name="interval_range",
    ),
    Index(
        "ix_workflows_due",
        "next_run_at",
        postgresql_where=text("status = 'active' AND trigger = 'schedule'"),
    ),
)

workflow_runs = Table(
    "workflow_runs",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("workflow_id", Uuid, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False),
    Column("trigger", StrEnumType(WorkflowTrigger, 20), nullable=False),
    Column("status", StrEnumType(WorkflowRunStatus, 20), nullable=False),
    Column("idempotency_key", String(128), nullable=False),
    Column("current_step", StrEnumType(WorkflowStep, 20)),
    Column("step_results", JSONB, nullable=False),
    Column("n8n_execution_id", String(64)),
    Column("error_code", String(64)),
    Column("created_at", TS, nullable=False),
    Column("started_at", TS),
    Column("finished_at", TS),
    UniqueConstraint("org_id", "idempotency_key"),
    enum_check("trigger", WorkflowTrigger),
    enum_check("status", WorkflowRunStatus),
    enum_check("current_step", WorkflowStep, nullable=True),
    Index("ix_workflow_runs_workflow", "workflow_id", "created_at"),
)

collection_runs = Table(
    "collection_runs",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("source_id", Uuid, ForeignKey("sources.id", ondelete="CASCADE"), nullable=False),
    Column("workflow_run_id", Uuid, ForeignKey("workflow_runs.id", ondelete="SET NULL")),
    Column("trigger", StrEnumType(RunTrigger, 20), nullable=False),
    Column("status", StrEnumType(RunStatus, 20), nullable=False),
    Column("idempotency_key", String(128)),
    Column("attempt", Integer, nullable=False),
    Column("stats", JSONB, nullable=False),
    Column("error_code", String(64)),
    Column("error_detail", String(500)),
    Column("created_at", TS, nullable=False),
    Column("started_at", TS),
    Column("finished_at", TS),
    enum_check("trigger", RunTrigger),
    enum_check("status", RunStatus),
    Index("ix_collection_runs_source", "source_id", "created_at"),
    Index(
        "uq_collection_runs_idempotency",
        "org_id",
        "idempotency_key",
        unique=True,
        postgresql_where=text("idempotency_key IS NOT NULL"),
    ),
)

run_payloads = Table(
    "run_payloads",
    metadata,
    Column("run_id", Uuid, ForeignKey("collection_runs.id", ondelete="CASCADE"), primary_key=True),
    _org(),
    Column("items", JSONB, nullable=False),
    Column("created_at", TS, nullable=False),
)

records = Table(
    "records",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("dataset_id", Uuid, ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False),
    Column("record_key", String(512), nullable=False),
    Column("data", JSONB, nullable=False),
    Column("content_hash", String(64), nullable=False),
    Column("version", Integer, nullable=False),
    Column("source_id", Uuid, ForeignKey("sources.id", ondelete="SET NULL")),
    Column("first_seen_at", TS, nullable=False),
    Column("last_seen_at", TS, nullable=False),
    Column("last_run_id", Uuid),
    Column("deleted_at", TS),
    UniqueConstraint("dataset_id", "record_key"),
    Index("ix_records_org_dataset_seen", "org_id", "dataset_id", "last_seen_at"),
)

record_versions = Table(
    "record_versions",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("dataset_id", Uuid, ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False),
    Column("record_id", Uuid, ForeignKey("records.id", ondelete="CASCADE"), nullable=False),
    Column("version", Integer, nullable=False),
    Column("data", JSONB, nullable=False),
    Column("content_hash", String(64), nullable=False),
    Column("run_id", Uuid),
    Column("captured_at", TS, nullable=False),
    Column("is_deletion", Boolean, nullable=False),
    Column("diffed", Boolean, nullable=False),
    UniqueConstraint("record_id", "version"),
    Index(
        "ix_record_versions_pending",
        "dataset_id",
        "captured_at",
        postgresql_where=text("NOT diffed"),
    ),
)

insights = Table(
    "insights",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("project_id", Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
    Column("dataset_id", Uuid, ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False),
    Column("status", StrEnumType(InsightStatus, 20), nullable=False),
    Column("idempotency_key", String(128), nullable=False),
    Column("provider", String(32)),
    Column("model", String(64)),
    Column("prompt_version", String(20)),
    Column("input_hash", String(64)),
    Column("summary", Text),
    Column("findings", JSONB, nullable=False),
    Column("recommendations", JSONB, nullable=False),
    Column("risk_level", StrEnumType(RiskLevel, 10)),
    Column("confidence", Float),
    Column("change_count", Integer, nullable=False),
    Column("usage", JSONB, nullable=False),
    Column("error_code", String(64)),
    Column("requested_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("period_start", TS),
    Column("period_end", TS),
    Column("created_at", TS, nullable=False),
    Column("completed_at", TS),
    Column("started_at", TS),
    Column("attempts", Integer, nullable=False, server_default=text("0")),
    UniqueConstraint("org_id", "idempotency_key"),
    enum_check("status", InsightStatus),
    enum_check("risk_level", RiskLevel, nullable=True),
    Index("ix_insights_org_dataset", "org_id", "dataset_id", "created_at"),
    Index(
        "ix_insights_running",
        "org_id",
        "started_at",
        postgresql_where=text("status = 'running'"),
    ),
)

changes = Table(
    "changes",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("dataset_id", Uuid, ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False),
    Column("record_id", Uuid, ForeignKey("records.id", ondelete="CASCADE"), nullable=False),
    Column("record_key", String(512), nullable=False),
    Column("run_id", Uuid),
    Column("change_type", StrEnumType(ChangeType, 10), nullable=False),
    Column("from_version", Integer),
    Column("to_version", Integer, nullable=False),
    Column("diff", JSONB, nullable=False),
    Column("significance", StrEnumType(Significance, 10), nullable=False),
    Column("score", SmallInteger, nullable=False),
    Column("detected_at", TS, nullable=False),
    Column("insight_id", Uuid, ForeignKey("insights.id", ondelete="SET NULL")),
    Column("alerts_evaluated", Boolean, nullable=False),
    UniqueConstraint("record_id", "to_version"),
    enum_check("change_type", ChangeType),
    enum_check("significance", Significance),
    Index("ix_changes_org_dataset_detected", "org_id", "dataset_id", "detected_at"),
    Index(
        "ix_changes_unanalyzed",
        "dataset_id",
        postgresql_where=text("insight_id IS NULL"),
    ),
    Index(
        "ix_changes_alert_pending",
        "org_id",
        postgresql_where=text("NOT alerts_evaluated"),
    ),
)

notification_channels = Table(
    "notification_channels",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("name", String(100), nullable=False),
    Column("kind", StrEnumType(ChannelKind, 20), nullable=False),
    Column("config", JSONB, nullable=False),
    Column("integration_id", Uuid, ForeignKey("integrations.id", ondelete="SET NULL")),
    Column("enabled", Boolean, nullable=False),
    Column("created_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    UniqueConstraint("org_id", "name"),
    enum_check("kind", ChannelKind),
)

alert_rules = Table(
    "alert_rules",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("project_id", Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
    Column("dataset_id", Uuid, ForeignKey("datasets.id", ondelete="CASCADE")),
    Column("name", String(120), nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("condition", JSONB, nullable=False),
    Column("severity", StrEnumType(AlertSeverity, 10), nullable=False),
    Column("channel_ids", ARRAY(Uuid), nullable=False),
    Column("cooldown_minutes", Integer, nullable=False),
    Column("created_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    UniqueConstraint("project_id", "name"),
    enum_check("severity", AlertSeverity),
    CheckConstraint("cooldown_minutes BETWEEN 1 AND 10080", name="cooldown_range"),
)

alerts = Table(
    "alerts",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("rule_id", Uuid, ForeignKey("alert_rules.id", ondelete="CASCADE"), nullable=False),
    Column("severity", StrEnumType(AlertSeverity, 10), nullable=False),
    Column("title", String(200), nullable=False),
    Column("body", Text, nullable=False),
    Column("dedup_key", String(64), nullable=False),
    Column("subject_type", String(20), nullable=False),
    Column("subject_id", Uuid, nullable=False),
    Column("status", StrEnumType(AlertStatus, 20), nullable=False),
    Column("triggered_at", TS, nullable=False),
    Column("acknowledged_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("acknowledged_at", TS),
    UniqueConstraint("org_id", "dedup_key"),
    enum_check("severity", AlertSeverity),
    enum_check("status", AlertStatus),
    Index("ix_alerts_org_triggered", "org_id", "triggered_at"),
)

notification_deliveries = Table(
    "notification_deliveries",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("alert_id", Uuid, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
    Column(
        "channel_id",
        Uuid,
        ForeignKey("notification_channels.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("status", StrEnumType(DeliveryState, 20), nullable=False),
    Column("attempts", Integer, nullable=False),
    Column("next_attempt_at", TS),
    Column("last_error_code", String(64)),
    Column("delivered_at", TS),
    Column("claimed_at", TS),
    Column("created_at", TS, nullable=False),
    UniqueConstraint("alert_id", "channel_id"),
    enum_check("status", DeliveryState),
)

reports = Table(
    "reports",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("project_id", Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
    Column("dataset_id", Uuid, ForeignKey("datasets.id", ondelete="CASCADE")),
    Column("title", String(200), nullable=False),
    Column("format", StrEnumType(ReportFormat, 10), nullable=False),
    Column("period_start", TS, nullable=False),
    Column("period_end", TS, nullable=False),
    Column("status", StrEnumType(ReportStatus, 20), nullable=False),
    Column("storage_key", String(160)),
    Column("size_bytes", BigInteger),
    Column("sha256", String(64)),
    Column("idempotency_key", String(128)),
    Column("requested_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("error_code", String(64)),
    Column("created_at", TS, nullable=False),
    Column("completed_at", TS),
    Column("expires_at", TS),
    enum_check("format", ReportFormat),
    enum_check("status", ReportStatus),
    CheckConstraint("period_end > period_start", name="period_order"),
    Index(
        "uq_reports_idempotency",
        "org_id",
        "idempotency_key",
        unique=True,
        postgresql_where=text("idempotency_key IS NOT NULL"),
    ),
)

webhook_endpoints = Table(
    "webhook_endpoints",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("source_id", Uuid, ForeignKey("sources.id", ondelete="CASCADE"), nullable=False),
    Column("name", String(100), nullable=False),
    Column("status", StrEnumType(EndpointStatus, 20), nullable=False),
    Column("secret_ciphertext", LargeBinary, nullable=False),
    Column("previous_secret_ciphertext", LargeBinary),
    Column("previous_secret_expires_at", TS),
    Column("created_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    Column("last_received_at", TS),
    enum_check("status", EndpointStatus),
)

inbound_webhook_events = Table(
    "inbound_webhook_events",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column(
        "endpoint_id",
        Uuid,
        ForeignKey("webhook_endpoints.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("delivery_id", String(128), nullable=False),
    Column("received_at", TS, nullable=False),
    Column("payload_sha256", String(64), nullable=False),
    Column("payload_size", Integer, nullable=False),
    Column("item_count", Integer, nullable=False),
    Column("status", StrEnumType(DeliveryStatus, 20), nullable=False),
    Column("run_id", Uuid, ForeignKey("collection_runs.id", ondelete="SET NULL")),
    UniqueConstraint("endpoint_id", "delivery_id"),
    enum_check("status", DeliveryStatus),
)

uploads = Table(
    "uploads",
    metadata,
    Column("id", Uuid, primary_key=True),
    _org(),
    Column("source_id", Uuid, ForeignKey("sources.id", ondelete="CASCADE"), nullable=False),
    Column("original_filename", String(200), nullable=False),
    Column("storage_key", String(160), nullable=False),
    Column("content_type", String(100), nullable=False),
    Column("size_bytes", BigInteger, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("status", StrEnumType(UploadStatus, 20), nullable=False),
    Column("rejection_reason", String(64)),
    Column("row_count", Integer),
    Column("uploaded_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    Column("run_id", Uuid, ForeignKey("collection_runs.id", ondelete="SET NULL")),
    Column("created_at", TS, nullable=False),
    Column("processed_at", TS),
    # One *live* upload per file and source; a failed or rejected file can be
    # uploaded again (its old row stays as history).
    Index(
        "uq_uploads_live_sha256",
        "source_id",
        "sha256",
        unique=True,
        postgresql_where=text("status NOT IN ('failed', 'rejected')"),
    ),
    enum_check("status", UploadStatus),
)

dead_letters = Table(
    "dead_letters",
    metadata,
    Column("id", Uuid, primary_key=True),
    Column("org_id", Uuid, ForeignKey("organizations.id", ondelete="CASCADE")),
    Column("origin", String(20), nullable=False),
    Column("task_name", String(100), nullable=False),
    Column("reference_type", String(40)),
    Column("reference_id", String(64)),
    Column("payload", JSONB, nullable=False),
    Column("error_code", String(64), nullable=False),
    Column("error_message", String(500)),
    Column("attempts", Integer, nullable=False),
    Column("status", StrEnumType(DeadLetterStatus, 20), nullable=False),
    Column("first_failed_at", TS, nullable=False),
    Column("last_failed_at", TS, nullable=False),
    Column("resolved_at", TS),
    Column("resolved_by", Uuid, ForeignKey("users.id", ondelete="SET NULL")),
    enum_check("status", DeadLetterStatus),
    CheckConstraint("origin IN ('celery', 'n8n')", name="origin"),
    Index("ix_dead_letters_org_status", "org_id", "status"),
)


def _index(name: str, table: Table, *columns: str, where: str | None = None) -> None:
    Index(name, *(table.c[c] for c in columns), postgresql_where=text(where) if where else None)


# Migration 0007 (review E-1, E-2, E-6): children of deleted rows, the
# organization purge, per-tenant maintenance and change listings.
_index("ix_inbound_webhook_events_run", inbound_webhook_events, "run_id")
_index("ix_uploads_run", uploads, "run_id")
_index("ix_collection_runs_workflow_run", collection_runs, "workflow_run_id")
_index("ix_changes_insight", changes, "insight_id", where="insight_id IS NOT NULL")
_index("ix_alerts_rule", alerts, "rule_id")
_index("ix_alert_rules_dataset", alert_rules, "dataset_id")
_index("ix_notification_deliveries_channel", notification_deliveries, "channel_id")
_index("ix_records_source", records, "source_id", where="source_id IS NOT NULL")
_index("ix_sources_dataset", sources, "dataset_id")
_index("ix_sources_integration", sources, "integration_id", where="integration_id IS NOT NULL")
_index(
    "ix_notification_channels_integration",
    notification_channels,
    "integration_id",
    where="integration_id IS NOT NULL",
)
_index("ix_insights_dataset", insights, "dataset_id")
_index("ix_insights_project", insights, "project_id")
_index("ix_reports_dataset", reports, "dataset_id")
_index("ix_reports_project", reports, "project_id")
_index("ix_webhook_endpoints_source", webhook_endpoints, "source_id")
_index("ix_record_versions_org", record_versions, "org_id")
_index("ix_run_payloads_org", run_payloads, "org_id")
_index("ix_uploads_org", uploads, "org_id", "created_at")
_index("ix_webhook_endpoints_org", webhook_endpoints, "org_id")
_index("ix_workflows_org", workflows, "org_id")
_index("ix_alert_rules_org", alert_rules, "org_id")
_index("ix_collection_runs_org_created", collection_runs, "org_id", "created_at")
_index(
    "ix_collection_runs_running",
    collection_runs,
    "org_id",
    "started_at",
    where="status = 'running'",
)
_index("ix_inbound_webhook_events_org_received", inbound_webhook_events, "org_id", "received_at")
_index("ix_notification_deliveries_org_created", notification_deliveries, "org_id", "created_at")
_index(
    "ix_notification_deliveries_sending",
    notification_deliveries,
    "org_id",
    "claimed_at",
    where="status = 'sending'",
)
_index("ix_reports_org_status_created", reports, "org_id", "status", "created_at")
_index("ix_reports_ready_expiry", reports, "org_id", "expires_at", where="status = 'ready'")
_index("ix_record_versions_retention", record_versions, "dataset_id", "captured_at", where="diffed")
_index("ix_changes_org_detected", changes, "org_id", "detected_at", "id")
_index("ix_changes_org_score", changes, "org_id", "score", "id")

"""Business data: projects, datasets, sources, records, changes, insights,
alerting, notifications, reports, workflows, uploads and webhooks.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-24

Every table carries ``org_id`` and gets FORCE row-level security pinned to the
tenant context. A handful of SECURITY DEFINER functions expose *identifiers
only* across tenants for the platform scheduler and maintenance jobs.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from nexusflow.infrastructure.database.rls import (
    app_role,
    enable_rls,
    grant,
    split_sql,
    tenant_policy,
)

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _create_tables() -> None:
    op.create_table(
        "dead_letters",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=True),
        sa.Column("origin", sa.String(length=20), nullable=False),
        sa.Column("task_name", sa.String(length=100), nullable=False),
        sa.Column("reference_type", sa.String(length=40), nullable=True),
        sa.Column("reference_id", sa.String(length=64), nullable=True),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=False),
        sa.Column("error_message", sa.String(length=500), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("first_failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.Uuid(), nullable=True),
        sa.CheckConstraint("origin IN ('celery', 'n8n')", name=op.f("ck_dead_letters_origin")),
        sa.CheckConstraint(
            "status IN ('open', 'retried', 'discarded')", name=op.f("ck_dead_letters_status")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_dead_letters_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["resolved_by"],
            ["users.id"],
            name=op.f("fk_dead_letters_resolved_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_dead_letters")),
    )
    op.create_index(
        "ix_dead_letters_org_status", "dead_letters", ["org_id", "status"], unique=False
    )
    op.create_table(
        "integrations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("secret_key_id", sa.String(length=32), nullable=False),
        sa.Column("secret_fingerprint", sa.String(length=16), nullable=False),
        sa.Column("secret_hint", sa.String(length=16), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "kind IN ('http_bearer', 'http_basic', 'http_header', 'slack_webhook', 'telegram_bot', 'webhook_signing')",
            name=op.f("ck_integrations_kind"),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked', 'quarantined')", name=op.f("ck_integrations_status")
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_integrations_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_integrations_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integrations")),
        sa.UniqueConstraint("org_id", "name", name=op.f("uq_integrations_org_id")),
    )
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('active', 'archived')", name=op.f("ck_projects_status")),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_projects_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_projects_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_projects")),
        sa.UniqueConstraint("org_id", "name", name=op.f("uq_projects_org_id")),
    )
    op.create_table(
        "datasets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        sa.Column("schema", postgresql.JSONB(), nullable=False),
        sa.Column("classification", sa.String(length=20), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "classification IN ('public', 'internal', 'confidential', 'restricted')",
            name=op.f("ck_datasets_classification"),
        ),
        sa.CheckConstraint(
            "retention_days BETWEEN 7 AND 3650", name=op.f("ck_datasets_retention_range")
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_datasets_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_datasets_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_datasets_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_datasets")),
        sa.UniqueConstraint("project_id", "name", name=op.f("uq_datasets_project_id")),
    )
    op.create_index("ix_datasets_org_project", "datasets", ["org_id", "project_id"], unique=False)
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("integration_id", sa.Uuid(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('email', 'slack', 'telegram', 'webhook')",
            name=op.f("ck_notification_channels_kind"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_notification_channels_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"],
            ["integrations.id"],
            name=op.f("fk_notification_channels_integration_id_integrations"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_notification_channels_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_channels")),
        sa.UniqueConstraint("org_id", "name", name=op.f("uq_notification_channels_org_id")),
    )
    op.create_table(
        "workflows",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("schedule_interval_minutes", sa.Integer(), nullable=True),
        sa.Column("source_ids", sa.ARRAY(sa.Uuid()), nullable=False),
        sa.Column("analyze", sa.Boolean(), nullable=False),
        sa.Column("alert", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("disabled_reason", sa.String(length=200), nullable=True),
        sa.Column("disabled_by", sa.Uuid(), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'paused', 'disabled')", name=op.f("ck_workflows_status")
        ),
        sa.CheckConstraint("trigger IN ('schedule', 'manual')", name=op.f("ck_workflows_trigger")),
        sa.CheckConstraint(
            "schedule_interval_minutes IS NULL OR schedule_interval_minutes BETWEEN 5 AND 10080",
            name=op.f("ck_workflows_interval_range"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_workflows_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["disabled_by"],
            ["users.id"],
            name=op.f("fk_workflows_disabled_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_workflows_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_workflows_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_workflows")),
        sa.UniqueConstraint("project_id", "name", name=op.f("uq_workflows_project_id")),
    )
    op.create_index(
        "ix_workflows_due",
        "workflows",
        ["next_run_at"],
        unique=False,
        postgresql_where=sa.text("status = 'active' AND trigger = 'schedule'"),
    )
    op.create_table(
        "alert_rules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("dataset_id", sa.Uuid(), nullable=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("condition", postgresql.JSONB(), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("channel_ids", sa.ARRAY(sa.Uuid()), nullable=False),
        sa.Column("cooldown_minutes", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "severity IN ('info', 'warning', 'critical')", name=op.f("ck_alert_rules_severity")
        ),
        sa.CheckConstraint(
            "cooldown_minutes BETWEEN 1 AND 10080", name=op.f("ck_alert_rules_cooldown_range")
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_alert_rules_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["datasets.id"],
            name=op.f("fk_alert_rules_dataset_id_datasets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_alert_rules_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_alert_rules_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_rules")),
        sa.UniqueConstraint("project_id", "name", name=op.f("uq_alert_rules_project_id")),
    )
    op.create_table(
        "insights",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("dataset_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=True),
        sa.Column("model", sa.String(length=64), nullable=True),
        sa.Column("prompt_version", sa.String(length=20), nullable=True),
        sa.Column("input_hash", sa.String(length=64), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("findings", postgresql.JSONB(), nullable=False),
        sa.Column("recommendations", postgresql.JSONB(), nullable=False),
        sa.Column("risk_level", sa.String(length=10), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("change_count", sa.Integer(), nullable=False),
        sa.Column("usage", postgresql.JSONB(), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("requested_by", sa.Uuid(), nullable=True),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "risk_level IS NULL OR risk_level IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_insights_risk_level"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed', 'rejected')",
            name=op.f("ck_insights_status"),
        ),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["datasets.id"],
            name=op.f("fk_insights_dataset_id_datasets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_insights_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_insights_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"],
            ["users.id"],
            name=op.f("fk_insights_requested_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_insights")),
        sa.UniqueConstraint("org_id", "idempotency_key", name=op.f("uq_insights_org_id")),
    )
    op.create_index(
        "ix_insights_org_dataset", "insights", ["org_id", "dataset_id", "created_at"], unique=False
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("dataset_id", sa.Uuid(), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("format", sa.String(length=10), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("storage_key", sa.String(length=160), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
        sa.Column("requested_by", sa.Uuid(), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "format IN ('json', 'csv', 'xlsx', 'pdf')", name=op.f("ck_reports_format")
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'generating', 'ready', 'failed', 'expired')",
            name=op.f("ck_reports_status"),
        ),
        sa.CheckConstraint("period_end > period_start", name=op.f("ck_reports_period_order")),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["datasets.id"],
            name=op.f("fk_reports_dataset_id_datasets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_reports_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_reports_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"],
            ["users.id"],
            name=op.f("fk_reports_requested_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reports")),
    )
    op.create_index(
        "uq_reports_idempotency",
        "reports",
        ["org_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.create_table(
        "sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("dataset_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("integration_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('website', 'rest_api', 'webhook', 'file_upload')",
            name=op.f("ck_sources_kind"),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'paused', 'error', 'quarantined')", name=op.f("ck_sources_status")
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_sources_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["datasets.id"],
            name=op.f("fk_sources_dataset_id_datasets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"],
            ["integrations.id"],
            name=op.f("fk_sources_integration_id_integrations"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_sources_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_sources_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sources")),
        sa.UniqueConstraint("project_id", "name", name=op.f("uq_sources_project_id")),
    )
    op.create_index("ix_sources_org_dataset", "sources", ["org_id", "dataset_id"], unique=False)
    op.create_table(
        "workflow_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("workflow_id", sa.Uuid(), nullable=False),
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("current_step", sa.String(length=20), nullable=True),
        sa.Column("step_results", postgresql.JSONB(), nullable=False),
        sa.Column("n8n_execution_id", sa.String(length=64), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "current_step IS NULL OR current_step IN ('collect', 'detect', 'analyze', 'alert')",
            name=op.f("ck_workflow_runs_current_step"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')",
            name=op.f("ck_workflow_runs_status"),
        ),
        sa.CheckConstraint(
            "trigger IN ('schedule', 'manual')", name=op.f("ck_workflow_runs_trigger")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_workflow_runs_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_id"],
            ["workflows.id"],
            name=op.f("fk_workflow_runs_workflow_id_workflows"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_workflow_runs")),
        sa.UniqueConstraint("org_id", "idempotency_key", name=op.f("uq_workflow_runs_org_id")),
    )
    op.create_index(
        "ix_workflow_runs_workflow", "workflow_runs", ["workflow_id", "created_at"], unique=False
    )
    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("subject_type", sa.String(length=20), nullable=False),
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_by", sa.Uuid(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "severity IN ('info', 'warning', 'critical')", name=op.f("ck_alerts_severity")
        ),
        sa.CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved')", name=op.f("ck_alerts_status")
        ),
        sa.ForeignKeyConstraint(
            ["acknowledged_by"],
            ["users.id"],
            name=op.f("fk_alerts_acknowledged_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_alerts_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["alert_rules.id"],
            name=op.f("fk_alerts_rule_id_alert_rules"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
        sa.UniqueConstraint("org_id", "dedup_key", name=op.f("uq_alerts_org_id")),
    )
    op.create_index("ix_alerts_org_triggered", "alerts", ["org_id", "triggered_at"], unique=False)
    op.create_table(
        "collection_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("workflow_run_id", sa.Uuid(), nullable=True),
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("stats", postgresql.JSONB(), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_detail", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')",
            name=op.f("ck_collection_runs_status"),
        ),
        sa.CheckConstraint(
            "trigger IN ('manual', 'schedule', 'webhook', 'upload', 'automation')",
            name=op.f("ck_collection_runs_trigger"),
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_collection_runs_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_collection_runs_source_id_sources"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_run_id"],
            ["workflow_runs.id"],
            name=op.f("fk_collection_runs_workflow_run_id_workflow_runs"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_collection_runs")),
    )
    op.create_index(
        "ix_collection_runs_source", "collection_runs", ["source_id", "created_at"], unique=False
    )
    op.create_index(
        "uq_collection_runs_idempotency",
        "collection_runs",
        ["org_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.create_table(
        "records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("dataset_id", sa.Uuid(), nullable=False),
        sa.Column("record_key", sa.String(length=512), nullable=False),
        sa.Column("data", postgresql.JSONB(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_id", sa.Uuid(), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["datasets.id"],
            name=op.f("fk_records_dataset_id_datasets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_records_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_records_source_id_sources"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_records")),
        sa.UniqueConstraint("dataset_id", "record_key", name=op.f("uq_records_dataset_id")),
    )
    op.create_index(
        "ix_records_org_dataset_seen",
        "records",
        ["org_id", "dataset_id", "last_seen_at"],
        unique=False,
    )
    op.create_table(
        "webhook_endpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("previous_secret_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("previous_secret_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_received_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'disabled')", name=op.f("ck_webhook_endpoints_status")
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_webhook_endpoints_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_webhook_endpoints_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_webhook_endpoints_source_id_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_webhook_endpoints")),
    )
    op.create_table(
        "changes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("dataset_id", sa.Uuid(), nullable=False),
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("record_key", sa.String(length=512), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("change_type", sa.String(length=10), nullable=False),
        sa.Column("from_version", sa.Integer(), nullable=True),
        sa.Column("to_version", sa.Integer(), nullable=False),
        sa.Column("diff", postgresql.JSONB(), nullable=False),
        sa.Column("significance", sa.String(length=10), nullable=False),
        sa.Column("score", sa.SmallInteger(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("insight_id", sa.Uuid(), nullable=True),
        sa.Column("alerts_evaluated", sa.Boolean(), nullable=False),
        sa.CheckConstraint(
            "change_type IN ('created', 'updated', 'deleted')", name=op.f("ck_changes_change_type")
        ),
        sa.CheckConstraint(
            "significance IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_changes_significance"),
        ),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["datasets.id"],
            name=op.f("fk_changes_dataset_id_datasets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["insight_id"],
            ["insights.id"],
            name=op.f("fk_changes_insight_id_insights"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_changes_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["record_id"],
            ["records.id"],
            name=op.f("fk_changes_record_id_records"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_changes")),
        sa.UniqueConstraint("record_id", "to_version", name=op.f("uq_changes_record_id")),
    )
    op.create_index(
        "ix_changes_alert_pending",
        "changes",
        ["org_id"],
        unique=False,
        postgresql_where=sa.text("NOT alerts_evaluated"),
    )
    op.create_index(
        "ix_changes_org_dataset_detected",
        "changes",
        ["org_id", "dataset_id", "detected_at"],
        unique=False,
    )
    op.create_index(
        "ix_changes_unanalyzed",
        "changes",
        ["dataset_id"],
        unique=False,
        postgresql_where=sa.text("insight_id IS NULL"),
    )
    op.create_table(
        "inbound_webhook_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("delivery_id", sa.String(length=128), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("payload_size", sa.Integer(), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "status IN ('accepted', 'processed', 'failed')",
            name=op.f("ck_inbound_webhook_events_status"),
        ),
        sa.ForeignKeyConstraint(
            ["endpoint_id"],
            ["webhook_endpoints.id"],
            name=op.f("fk_inbound_webhook_events_endpoint_id_webhook_endpoints"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_inbound_webhook_events_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["collection_runs.id"],
            name=op.f("fk_inbound_webhook_events_run_id_collection_runs"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inbound_webhook_events")),
        sa.UniqueConstraint(
            "endpoint_id", "delivery_id", name=op.f("uq_inbound_webhook_events_endpoint_id")
        ),
    )
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("channel_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'sending', 'delivered', 'failed', 'dead')",
            name=op.f("ck_notification_deliveries_status"),
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_notification_deliveries_alert_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["channel_id"],
            ["notification_channels.id"],
            name=op.f("fk_notification_deliveries_channel_id_notification_channels"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_notification_deliveries_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_deliveries")),
        sa.UniqueConstraint(
            "alert_id", "channel_id", name=op.f("uq_notification_deliveries_alert_id")
        ),
    )
    op.create_table(
        "record_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("dataset_id", sa.Uuid(), nullable=False),
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("data", postgresql.JSONB(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deletion", sa.Boolean(), nullable=False),
        sa.Column("diffed", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["datasets.id"],
            name=op.f("fk_record_versions_dataset_id_datasets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_record_versions_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["record_id"],
            ["records.id"],
            name=op.f("fk_record_versions_record_id_records"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_record_versions")),
        sa.UniqueConstraint("record_id", "version", name=op.f("uq_record_versions_record_id")),
    )
    op.create_index(
        "ix_record_versions_pending",
        "record_versions",
        ["dataset_id", "captured_at"],
        unique=False,
        postgresql_where=sa.text("NOT diffed"),
    )
    op.create_table(
        "run_payloads",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("items", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_run_payloads_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["collection_runs.id"],
            name=op.f("fk_run_payloads_run_id_collection_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("run_id", name=op.f("pk_run_payloads")),
    )
    op.create_table(
        "uploads",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("original_filename", sa.String(length=200), nullable=False),
        sa.Column("storage_key", sa.String(length=160), nullable=False),
        sa.Column("content_type", sa.String(length=100), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("rejection_reason", sa.String(length=64), nullable=True),
        sa.Column("row_count", sa.Integer(), nullable=True),
        sa.Column("uploaded_by", sa.Uuid(), nullable=True),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('accepted', 'rejected', 'processing', 'processed', 'failed')",
            name=op.f("ck_uploads_status"),
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_uploads_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["collection_runs.id"],
            name=op.f("fk_uploads_run_id_collection_runs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_uploads_source_id_sources"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by"],
            ["users.id"],
            name=op.f("fk_uploads_uploaded_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_uploads")),
    )
    op.create_index(
        "uq_uploads_live_sha256",
        "uploads",
        ["source_id", "sha256"],
        unique=True,
        postgresql_where=sa.text("status NOT IN ('failed', 'rejected')"),
    )


def _drop_tables() -> None:
    op.drop_index(
        "uq_uploads_live_sha256",
        table_name="uploads",
        postgresql_where=sa.text("status NOT IN ('failed', 'rejected')"),
    )
    op.drop_table("uploads")
    op.drop_table("run_payloads")
    op.drop_index(
        "ix_record_versions_pending",
        table_name="record_versions",
        postgresql_where=sa.text("NOT diffed"),
    )
    op.drop_table("record_versions")
    op.drop_table("notification_deliveries")
    op.drop_table("inbound_webhook_events")
    op.drop_index(
        "ix_changes_unanalyzed",
        table_name="changes",
        postgresql_where=sa.text("insight_id IS NULL"),
    )
    op.drop_index("ix_changes_org_dataset_detected", table_name="changes")
    op.drop_index(
        "ix_changes_alert_pending",
        table_name="changes",
        postgresql_where=sa.text("NOT alerts_evaluated"),
    )
    op.drop_table("changes")
    op.drop_table("webhook_endpoints")
    op.drop_index("ix_records_org_dataset_seen", table_name="records")
    op.drop_table("records")
    op.drop_index(
        "uq_collection_runs_idempotency",
        table_name="collection_runs",
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.drop_index("ix_collection_runs_source", table_name="collection_runs")
    op.drop_table("collection_runs")
    op.drop_index("ix_alerts_org_triggered", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index("ix_workflow_runs_workflow", table_name="workflow_runs")
    op.drop_table("workflow_runs")
    op.drop_index("ix_sources_org_dataset", table_name="sources")
    op.drop_table("sources")
    op.drop_index(
        "uq_reports_idempotency",
        table_name="reports",
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.drop_table("reports")
    op.drop_index("ix_insights_org_dataset", table_name="insights")
    op.drop_table("insights")
    op.drop_table("alert_rules")
    op.drop_index(
        "ix_workflows_due",
        table_name="workflows",
        postgresql_where=sa.text("status = 'active' AND trigger = 'schedule'"),
    )
    op.drop_table("workflows")
    op.drop_table("notification_channels")
    op.drop_index("ix_datasets_org_project", table_name="datasets")
    op.drop_table("datasets")
    op.drop_table("projects")
    op.drop_table("integrations")
    op.drop_index("ix_dead_letters_org_status", table_name="dead_letters")
    op.drop_table("dead_letters")


TENANT_TABLES = (
    "projects",
    "datasets",
    "integrations",
    "sources",
    "workflows",
    "workflow_runs",
    "collection_runs",
    "run_payloads",
    "records",
    "record_versions",
    "insights",
    "changes",
    "notification_channels",
    "alert_rules",
    "alerts",
    "notification_deliveries",
    "reports",
    "webhook_endpoints",
    "inbound_webhook_events",
    "uploads",
)

_REQUIRE_BYPASSRLS = """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'the migration role must have BYPASSRLS (it owns the SECURITY DEFINER '
                        'functions used by the scheduler and maintenance jobs)';
    END IF;
END
$$;
"""

_FUNCTIONS = """
CREATE OR REPLACE FUNCTION nf_due_workflows(p_now timestamptz, p_limit integer)
    RETURNS TABLE (org_id uuid, workflow_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT w.org_id, w.id
      FROM public.workflows w
      JOIN public.organizations o ON o.id = w.org_id
     WHERE w.status = 'active'
       AND w.trigger = 'schedule'
       AND w.next_run_at IS NOT NULL
       AND w.next_run_at <= p_now
       AND o.status = 'active'
       AND COALESCE((o.settings ->> 'automation_frozen')::boolean, false) = false
     ORDER BY w.next_run_at
     LIMIT LEAST(GREATEST(p_limit, 1), 500)
$$;

CREATE OR REPLACE FUNCTION nf_pending_detection(p_limit integer)
    RETURNS TABLE (org_id uuid, dataset_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT DISTINCT v.org_id, v.dataset_id
      FROM public.record_versions v
     WHERE NOT v.diffed
     LIMIT LEAST(GREATEST(p_limit, 1), 1000)
$$;

CREATE OR REPLACE FUNCTION nf_tenant_ids(p_statuses text[])
    RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT id FROM public.organizations WHERE status = ANY (p_statuses)
$$;

CREATE OR REPLACE FUNCTION nf_orgs_due_for_purge(p_before timestamptz)
    RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT id FROM public.organizations
     WHERE status = 'pending_deletion' AND deletion_requested_at < p_before
$$;
"""

_FUNCTION_SIGNATURES = (
    "nf_due_workflows(timestamptz, integer)",
    "nf_pending_detection(integer)",
    "nf_tenant_ids(text[])",
    "nf_orgs_due_for_purge(timestamptz)",
)


def _create_security() -> None:
    role = app_role()
    statements: list[str] = [_REQUIRE_BYPASSRLS, *split_sql(_FUNCTIONS)]
    for signature in _FUNCTION_SIGNATURES:
        statements.append(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
        statements.append(f"GRANT EXECUTE ON FUNCTION {signature} TO {role}")
    for table in TENANT_TABLES:
        statements.extend(enable_rls(table))
        statements.append(tenant_policy(table))
        statements.append(grant(table, "SELECT, INSERT, UPDATE, DELETE", role))
    # Dead letters may be platform-level (org_id NULL): writable from any context,
    # but tenants only ever read their own rows.
    statements.extend(enable_rls("dead_letters"))
    statements.append(
        "CREATE POLICY dead_letters_tenant ON dead_letters "
        "USING (org_id = nf_current_org()) "
        "WITH CHECK (org_id IS NULL OR org_id = nf_current_org())"
    )
    statements.append(grant("dead_letters", "SELECT, INSERT, UPDATE", role))
    for statement in statements:
        op.execute(statement)


def upgrade() -> None:
    _create_tables()
    _create_security()


def downgrade() -> None:
    for signature in _FUNCTION_SIGNATURES:
        op.execute(f"DROP FUNCTION IF EXISTS {signature}")
    _drop_tables()

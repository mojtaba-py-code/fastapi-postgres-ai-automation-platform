"""Indexes for deletes, maintenance and listings; audit purge by chain prefix.

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-26

Review findings E-1, E-2, E-5 and E-6, measured on PostgreSQL with the
application role's 15 s statement timeout:

* Foreign keys whose parent rows are deleted had no index on the child
  column: every deleted run, insight, rule, channel, source or dataset made
  PostgreSQL scan the whole child table across all tenants, so the daily
  retention (and deleting a busy source, and purging a dataset or an
  organization) ran into the timeout and rolled back - after which that
  tenant's retention never ran again. Foreign keys to ``users`` stay
  unindexed on purpose: users are anonymised, never deleted.
* The reaper, the retention and the change listing scanned whole tables for
  one tenant's rows: partial and tenant-led indexes now serve them.
* ``nf_purge_audit_logs`` deleted by ``occurred_at``, which the client stamps
  before the chain lock orders the appends - a cutoff between two concurrent
  events could delete seq n+1 and keep n, a gap the daily verification then
  reports as tampering for ever. It now deletes only a prefix of each chain.

The indexes are built CONCURRENTLY (outside a transaction), so an existing
database keeps serving writes while they are built. A build that fails leaves
an INVALID index: drop it and run the migration again.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# name, table, columns, partial predicate
INDEXES: tuple[tuple[str, str, list[str], str | None], ...] = (
    # E-1: children of rows that are deleted (retention, user deletes, purges)
    ("ix_inbound_webhook_events_run", "inbound_webhook_events", ["run_id"], None),
    ("ix_uploads_run", "uploads", ["run_id"], None),
    ("ix_collection_runs_workflow_run", "collection_runs", ["workflow_run_id"], None),
    ("ix_changes_insight", "changes", ["insight_id"], "insight_id IS NOT NULL"),
    ("ix_alerts_rule", "alerts", ["rule_id"], None),
    ("ix_alert_rules_dataset", "alert_rules", ["dataset_id"], None),
    ("ix_notification_deliveries_channel", "notification_deliveries", ["channel_id"], None),
    ("ix_records_source", "records", ["source_id"], "source_id IS NOT NULL"),
    ("ix_sources_dataset", "sources", ["dataset_id"], None),
    ("ix_sources_integration", "sources", ["integration_id"], "integration_id IS NOT NULL"),
    (
        "ix_notification_channels_integration",
        "notification_channels",
        ["integration_id"],
        "integration_id IS NOT NULL",
    ),
    ("ix_insights_dataset", "insights", ["dataset_id"], None),
    ("ix_insights_project", "insights", ["project_id"], None),
    ("ix_reports_dataset", "reports", ["dataset_id"], None),
    ("ix_reports_project", "reports", ["project_id"], None),
    ("ix_webhook_endpoints_source", "webhook_endpoints", ["source_id"], None),
    # E-1: the organization purge deletes by org_id
    ("ix_record_versions_org", "record_versions", ["org_id"], None),
    ("ix_run_payloads_org", "run_payloads", ["org_id"], None),
    ("ix_uploads_org", "uploads", ["org_id", "created_at"], None),
    ("ix_webhook_endpoints_org", "webhook_endpoints", ["org_id"], None),
    ("ix_workflows_org", "workflows", ["org_id"], None),
    ("ix_alert_rules_org", "alert_rules", ["org_id"], None),
    ("ix_user_sessions_org", "user_sessions", ["org_id"], "org_id IS NOT NULL"),
    # E-2: retention and the reaper, per tenant
    ("ix_collection_runs_org_created", "collection_runs", ["org_id", "created_at"], None),
    (
        "ix_collection_runs_running",
        "collection_runs",
        ["org_id", "started_at"],
        "status = 'running'",
    ),
    (
        "ix_inbound_webhook_events_org_received",
        "inbound_webhook_events",
        ["org_id", "received_at"],
        None,
    ),
    (
        "ix_notification_deliveries_org_created",
        "notification_deliveries",
        ["org_id", "created_at"],
        None,
    ),
    (
        "ix_notification_deliveries_sending",
        "notification_deliveries",
        ["org_id", "claimed_at"],
        "status = 'sending'",
    ),
    ("ix_reports_org_status_created", "reports", ["org_id", "status", "created_at"], None),
    ("ix_reports_ready_expiry", "reports", ["org_id", "expires_at"], "status = 'ready'"),
    ("ix_record_versions_retention", "record_versions", ["dataset_id", "captured_at"], "diffed"),
    # E-6: listing changes by time or by score without sorting the history
    ("ix_changes_org_detected", "changes", ["org_id", "detected_at", "id"], None),
    ("ix_changes_org_score", "changes", ["org_id", "score", "id"], None),
)

_PREFIX_PURGE = """
CREATE OR REPLACE FUNCTION nf_purge_audit_logs(p_before timestamptz) RETURNS bigint
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
DECLARE
    v_count bigint;
BEGIN
    PERFORM set_config('nexusflow.audit_purge', 'on', true);
    -- Only a prefix of each chain: everything before the first entry that is
    -- recent enough to keep. occurred_at is stamped before the chain lock
    -- orders appends, so a cut by time alone could leave a gap in seq.
    WITH keep_from AS (
        SELECT chain_key, min(seq) FILTER (WHERE occurred_at >= p_before) AS seq
          FROM public.audit_logs
         GROUP BY chain_key
    )
    DELETE FROM public.audit_logs a
     USING keep_from k
     WHERE a.chain_key = k.chain_key
       AND a.occurred_at < p_before
       AND (k.seq IS NULL OR a.seq < k.seq);
    GET DIAGNOSTICS v_count = ROW_COUNT;
    PERFORM set_config('nexusflow.audit_purge', 'off', true);
    RETURN v_count;
END;
$$;
"""

_TIME_PURGE = """
CREATE OR REPLACE FUNCTION nf_purge_audit_logs(p_before timestamptz) RETURNS bigint
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
DECLARE
    v_count bigint;
BEGIN
    PERFORM set_config('nexusflow.audit_purge', 'on', true);
    DELETE FROM public.audit_logs WHERE occurred_at < p_before;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    PERFORM set_config('nexusflow.audit_purge', 'off', true);
    RETURN v_count;
END;
$$;
"""


def upgrade() -> None:
    # CREATE OR REPLACE keeps the function's owner and grants (none: operators
    # call it as the migrator).
    op.execute(_PREFIX_PURGE)
    with op.get_context().autocommit_block():
        for name, table, columns, where in INDEXES:
            op.create_index(
                name,
                table,
                columns,
                unique=False,
                postgresql_where=sa.text(where) if where else None,
                postgresql_concurrently=True,
                if_not_exists=True,
            )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        for name, table, _columns, _where in reversed(INDEXES):
            op.drop_index(name, table_name=table, postgresql_concurrently=True, if_exists=True)
    op.execute(_TIME_PURGE)

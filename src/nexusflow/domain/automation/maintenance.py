"""Platform maintenance: retention, reapers and tenant/dataset purges.

Runs as scheduled platform jobs (Celery beat), iterating tenants through a
SECURITY DEFINER function that returns identifiers only, then working inside
each tenant's own RLS context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.pagination import PageRequest
from nexusflow.core.resilience import backoff_delay
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.automation.dead_letters import stage_dead_letter
from nexusflow.domain.intelligence.model import InsightStatus
from nexusflow.domain.notifications.model import MAX_DELIVERY_ATTEMPTS, DeliveryState
from nexusflow.domain.notifications.service import delivery_dead_letter
from nexusflow.domain.pipeline.ingestion import release_upload
from nexusflow.domain.reports.model import ReportStatus
from nexusflow.domain.shared.context import SYSTEM_META
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.ports import FileStorage
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWorkFactory

STUCK_RUN_AFTER = timedelta(minutes=30)
STUCK_DELIVERY_AFTER = timedelta(minutes=15)
STUCK_REPORT_AFTER = timedelta(hours=1)
STUCK_INSIGHT_AFTER = timedelta(minutes=30)  # an analysis takes minutes, not half an hour
MAX_RUN_ATTEMPTS = 3
MAX_ANALYSIS_ATTEMPTS = 3
ORG_PURGE_GRACE = timedelta(days=7)


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    collection_runs_days: int
    webhook_events_days: int
    notification_deliveries_days: int
    dead_letters_days: int
    outbox_days: int = 7


@dataclass(slots=True)
class MaintenanceReport:
    purged: dict[str, int] = field(default_factory=dict)
    requeued_runs: int = 0
    failed_runs: int = 0
    reset_deliveries: int = 0
    dead_deliveries: int = 0
    failed_reports: int = 0
    requeued_insights: int = 0
    failed_insights: int = 0


class MaintenanceService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        storage: FileStorage,
        policy: RetentionPolicy,
        audit: AuditRecorder,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._storage = storage
        self._policy = policy
        self._audit = audit

    async def tenants(self) -> list[UUID]:
        async with self._uow_factory(TenantScope.system(None)) as uow:
            return await uow.data.system.tenant_ids(["active", "suspended", "pending_deletion"])

    async def rewrap_sealed(self, org_id: UUID, *, active_key_id: str, batch: int = 200) -> int:
        """Key rotation: move one batch of a tenant's sealed data to the active
        key-encryption key (records, versions, change diffs and stored files)."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            count = await uow.data.records.rewrap_sealed(org_id, active_key_id, limit=batch)
            count += await uow.data.changes.rewrap_sealed(org_id, active_key_id, limit=batch)
            await uow.commit()
        return count + await self._storage.rewrap(org_id, limit=batch)

    async def apply_retention(self, org_id: UUID) -> MaintenanceReport:
        now = self._clock.now()
        report = MaintenanceReport()
        policy = self._policy
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            maintenance = uow.data.maintenance
            report.purged["collection_runs"] = await maintenance.purge(
                org_id, "collection_runs", now - timedelta(days=policy.collection_runs_days)
            )
            report.purged["webhook_events"] = await maintenance.purge(
                org_id, "inbound_webhook_events", now - timedelta(days=policy.webhook_events_days)
            )
            report.purged["notification_deliveries"] = await maintenance.purge(
                org_id,
                "notification_deliveries",
                now - timedelta(days=policy.notification_deliveries_days),
            )
            report.purged["dead_letters"] = await maintenance.purge(
                org_id, "dead_letters", now - timedelta(days=policy.dead_letters_days)
            )
            datasets = await uow.data.datasets.list_page(org_id, PageRequest(limit=200))
            versions = 0
            for dataset in datasets.items:
                versions += await uow.data.records.purge_versions_before(
                    org_id, dataset.id, now - timedelta(days=dataset.retention_days)
                )
            report.purged["record_versions"] = versions
            if any(report.purged.values()):
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.RETENTION_PURGED,
                    principal=Principal.system(org_id),
                    meta=SYSTEM_META,
                    resource_type="organization",
                    resource_id=org_id,
                    metadata={name: count for name, count in report.purged.items() if count},
                )
            await uow.commit()
        return report

    async def apply_platform_retention(self) -> int:
        """Purge old dead letters that belong to no tenant; returns the count."""
        cutoff = self._clock.now() - timedelta(days=self._policy.dead_letters_days)
        async with self._uow_factory(TenantScope.system(None)) as uow:
            purged = await uow.data.maintenance.purge(None, "dead_letters", cutoff)
            await uow.commit()
        return purged

    async def purge_scratch(self) -> int:
        """Remove plaintext copies of stored files a killed process left behind."""
        return await self._storage.purge_scratch()

    async def reap(self, org_id: UUID) -> MaintenanceReport:
        """Recover work stuck by crashed workers (idempotent re-queue)."""
        now = self._clock.now()
        report = MaintenanceReport()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            for run in await uow.data.runs.list_stale(
                org_id, started_before=now - STUCK_RUN_AFTER, limit=100
            ):
                if run.attempt >= MAX_RUN_ATTEMPTS:
                    run.fail(now, code="worker_lost", detail="exceeded retry attempts")
                    await release_upload(uow, run, now, reason="worker_lost")
                    report.failed_runs += 1
                    continue
                run.requeue()
                await uow.outbox.add(
                    new_message(
                        TaskName.COLLECT_SOURCE,
                        {"org_id": str(org_id), "run_id": str(run.id)},
                        org_id=org_id,
                        now=now,
                    )
                )
                report.requeued_runs += 1
            stuck = await uow.data.maintenance.stuck_deliveries(
                org_id, before=now - STUCK_DELIVERY_AFTER, limit=100
            )
            for delivery in stuck:
                if delivery.attempts >= MAX_DELIVERY_ATTEMPTS:
                    # Every attempt died with its worker (a poison message): stop here.
                    delivery.mark_failed("worker_lost", retry_at=None)
                    letter = delivery_dead_letter(delivery, "worker_lost", now)
                    await stage_dead_letter(uow, letter, now=now)
                    report.dead_deliveries += 1
                    continue
                wait = timedelta(
                    seconds=backoff_delay(delivery.attempts, base_seconds=30, cap_seconds=3600)
                )
                delivery.status = DeliveryState.FAILED
                delivery.next_attempt_at = now + wait
                await uow.outbox.add(
                    new_message(
                        TaskName.DELIVER_NOTIFICATION,
                        {"org_id": str(org_id), "delivery_id": str(delivery.id)},
                        org_id=org_id,
                        now=now,
                        delay=wait,
                    )
                )
                report.reset_deliveries += 1
            for insight in await uow.data.insights.stuck(
                org_id, started_before=now - STUCK_INSIGHT_AFTER, limit=100
            ):
                if insight.attempts >= MAX_ANALYSIS_ATTEMPTS:
                    insight.reject("worker_lost", now, status=InsightStatus.FAILED)
                    report.failed_insights += 1
                    continue
                insight.status = InsightStatus.PENDING  # its worker is gone; claim it afresh
                await uow.outbox.add(
                    new_message(
                        TaskName.ANALYZE_CHANGES,
                        {"org_id": str(org_id), "insight_id": str(insight.id)},
                        org_id=org_id,
                        now=now,
                    )
                )
                report.requeued_insights += 1
            stuck_reports = await uow.data.reports.stuck(
                org_id, created_before=now - STUCK_REPORT_AFTER, limit=100
            )
            for stuck_report in stuck_reports:
                # The generating worker died; a new request re-renders from scratch.
                stuck_report.status = ReportStatus.FAILED
                stuck_report.error_code = "worker_lost"
                stuck_report.completed_at = now
                report.failed_reports += 1
            await uow.commit()
        return report

    async def purge_dataset(self, org_id: UUID, dataset_id: UUID) -> bool:
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            dataset = await uow.data.datasets.get_for_update(org_id, dataset_id)
            if dataset is None or dataset.deleted_at is None:
                return False
            await uow.data.datasets.delete(dataset)  # cascades records, versions, changes
            await self._audit.record(
                uow.audit,
                action=AuditAction.DATASET_PURGED,
                principal=Principal.system(org_id),
                meta=SYSTEM_META,
                resource_type="dataset",
                resource_id=dataset_id,
            )
            await uow.commit()
            return True

    async def purge_due_organizations(self) -> list[UUID]:
        """Hard-delete tenants whose deletion grace period has elapsed.

        Audit logs have no foreign key to organizations and are retained
        according to the audit retention policy (compliance evidence)."""
        cutoff = self._clock.now() - ORG_PURGE_GRACE
        async with self._uow_factory(TenantScope.system(None)) as uow:
            due = await uow.data.system.orgs_due_for_purge(cutoff)
        purged: list[UUID] = []
        for org_id in due:
            async with self._uow_factory(TenantScope.system(org_id)) as uow:
                keys = await uow.data.maintenance.storage_keys(org_id)
                # Recorded in the tenant's own chain, which outlives the tenant.
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.ORG_PURGED,
                    principal=Principal.system(org_id),
                    meta=SYSTEM_META,
                    resource_type="organization",
                    resource_id=org_id,
                    metadata={"files": len(keys)},
                )
                await uow.data.maintenance.delete_organization(org_id)
                await uow.commit()
            for key in keys:
                await self._storage.delete(key)
            purged.append(org_id)
        return purged

    async def cleanup_outbox(self) -> int:
        cutoff = self._clock.now() - timedelta(days=self._policy.outbox_days)
        async with self._uow_factory(TenantScope.system(None)) as uow:
            removed = await uow.data.maintenance.purge_outbox(cutoff)
            await uow.commit()
            return removed

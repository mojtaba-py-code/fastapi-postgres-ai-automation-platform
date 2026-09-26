"""Platform maintenance: retention, reapers and tenant/dataset purges.

Runs as scheduled platform jobs (Celery beat), iterating tenants through a
SECURITY DEFINER function that returns identifiers only, then working inside
each tenant's own RLS context.

Deletions of any size run as bounded batches, each its own short statement
and transaction: one cascading DELETE of a large dataset or organization
outlasts the database's statement timeout, and would fail for ever. Each
retention target and each organization purge is isolated, so one failure
never undoes (or blocks) the others.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.resilience import backoff_delay
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.automation.dead_letters import stage_dead_letter
from nexusflow.domain.automation.events import EventType, event_message
from nexusflow.domain.catalog.service import tenant_datasets
from nexusflow.domain.intelligence.model import InsightStatus
from nexusflow.domain.notifications.model import MAX_DELIVERY_ATTEMPTS, DeliveryState
from nexusflow.domain.notifications.service import delivery_dead_letter
from nexusflow.domain.pipeline.ingestion import release_upload
from nexusflow.domain.reports.model import ReportStatus
from nexusflow.domain.shared.context import SYSTEM_META
from nexusflow.domain.shared.files import file_deletions
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.ports import FileStorage
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.sources.model import CollectionRun

STUCK_RUN_AFTER = timedelta(minutes=30)
STUCK_DELIVERY_AFTER = timedelta(minutes=15)
STUCK_REPORT_AFTER = timedelta(hours=1)
STUCK_INSIGHT_AFTER = timedelta(minutes=30)  # an analysis takes minutes, not half an hour
MAX_RUN_ATTEMPTS = 3
MAX_ANALYSIS_ATTEMPTS = 3
ORG_PURGE_GRACE = timedelta(days=7)
# Expired refresh, password-reset and sign-up tokens (and started single
# sign-ons) are kept a week (for an investigation), then deleted: they can
# never be used again.
EXPIRED_TOKENS_GRACE = timedelta(days=7)
DELETE_BATCH = 1000
# The large children of a dataset, deleted before the dataset row (whose
# cascade then only meets small tables): records last, so that neither their
# versions and changes nor a SET NULL on them runs inside one huge statement.
DATASET_CHILDREN = (
    "record_versions",
    "changes",
    "records",
    "insights",
    "inbound_webhook_events",
    "collection_runs",
    "notification_deliveries",
    "alerts",
)
ORGANIZATION_CHILDREN = (*DATASET_CHILDREN, "workflow_runs")

type PurgeErrorHandler = Callable[[UUID, Exception], None]


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    collection_runs_days: int
    webhook_events_days: int
    notification_deliveries_days: int
    dead_letters_days: int
    outbox_days: int = 7
    idempotency_keys_hours: int = 24
    sessions_days: int = 90


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
        batch_size: int = DELETE_BATCH,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._storage = storage
        self._policy = policy
        self._audit = audit
        self._batch = batch_size

    async def _in_batches(
        self, org_id: UUID | None, step: Callable[[UnitOfWork, int], Awaitable[int]]
    ) -> int:
        """Run ``step`` - one delete of at most a batch of rows - in a short
        transaction of its own, until a batch comes back short; the total."""
        total = 0
        while True:
            async with self._uow_factory(TenantScope.system(org_id)) as uow:
                count = await step(uow, self._batch)
                await uow.commit()
            total += count
            if count < self._batch:
                return total

    async def _purge_children(
        self, org_id: UUID, targets: Sequence[str], *, dataset_id: UUID | None
    ) -> None:
        for target in targets:
            await self._in_batches(org_id, _delete_batch(org_id, target, dataset_id))

    async def tenants(self) -> list[UUID]:
        async with self._uow_factory(TenantScope.system(None)) as uow:
            return await uow.data.system.tenant_ids(["active", "suspended", "pending_deletion"])

    async def rewrap_sealed(self, org_id: UUID, *, active_key_id: str, batch: int = 200) -> int:
        """Key rotation: move one batch of a tenant's sealed data to the active
        key-encryption key (records, versions, change diffs and stored files).

        Rows other transactions hold are skipped, so a batch that re-wraps
        nothing does not mean nothing is left: :meth:`still_under_old_keys`
        tells."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            count = await uow.data.records.rewrap_sealed(org_id, active_key_id, limit=batch)
            count += await uow.data.changes.rewrap_sealed(org_id, active_key_id, limit=batch)
            await uow.commit()
        return count + await self._storage.rewrap(org_id, limit=batch)

    async def still_under_old_keys(self, org_id: UUID, *, active_key_id: str) -> dict[str, int]:
        """What of a tenant is still encrypted under another key than the active
        one, counted without locks (locked rows count): until all of it is zero,
        the old key must stay in the keyring. Only non-zero counts are listed."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            records, versions = await uow.data.records.count_stale_sealed(org_id, active_key_id)
            counts = {
                "integrations": await uow.data.integrations.count_needing_rewrap(
                    org_id, active_key_id
                ),
                "webhook_endpoints": await uow.data.webhook_endpoints.count_stale(
                    org_id, active_key_id
                ),
                "sso_connections": await uow.sso_connections.count_needing_rewrap(
                    org_id, active_key_id
                ),
                "records": records,
                "record_versions": versions,
                "changes": await uow.data.changes.count_stale_sealed(org_id, active_key_id),
            }
        counts["files"] = await self._storage.count_stale(org_id)
        return {name: count for name, count in counts.items() if count}

    async def apply_retention(self, org_id: UUID) -> MaintenanceReport:
        """Purge a tenant's data past its retention, target by target.

        Every target is purged in batches of its own transactions; a target
        that fails is left for the next run while the others go on, and the
        first failure is raised once the pass (and its audit record) is done.
        """
        now = self._clock.now()
        report = MaintenanceReport()
        policy = self._policy
        failures: list[Exception] = []

        async def purge(name: str, step: Callable[[UnitOfWork, int], Awaitable[int]]) -> None:
            try:
                report.purged[name] = report.purged.get(name, 0) + await self._in_batches(
                    org_id, step
                )
            except Exception as exc:  # noqa: BLE001 - isolated; raised after the others ran
                failures.append(exc)

        for name, target, days in (
            ("collection_runs", "collection_runs", policy.collection_runs_days),
            ("webhook_events", "inbound_webhook_events", policy.webhook_events_days),
            (
                "notification_deliveries",
                "notification_deliveries",
                policy.notification_deliveries_days,
            ),
        ):
            await purge(name, _retention_batch(org_id, target, now - timedelta(days=days)))
        # Dead letters are purged by a narrow SECURITY DEFINER function, all at once.
        await purge(
            "dead_letters",
            _retention_batch(
                org_id, "dead_letters", now - timedelta(days=policy.dead_letters_days)
            ),
        )
        try:
            async with self._uow_factory(TenantScope.system(org_id)) as uow:
                datasets = await tenant_datasets(uow, org_id)  # every one, however many
        except Exception as exc:  # noqa: BLE001 - isolated like the targets
            failures.append(exc)
            datasets = []
        report.purged.setdefault("record_versions", 0)
        report.purged.setdefault("changes", 0)
        for dataset in datasets:
            # A dataset's history and its changes (which hold old and new values)
            # are kept for the dataset's own retention period.
            cutoff = now - timedelta(days=dataset.retention_days)
            await purge("record_versions", _versions_batch(org_id, dataset.id, cutoff))
            await purge("changes", _changes_batch(org_id, dataset.id, cutoff))
        # Idempotency keys are honoured for a while, then released: the key
        # starts a new request again (the resources themselves stay).
        keys_cutoff = now - timedelta(hours=policy.idempotency_keys_hours)
        for target in ("collection_runs", "workflow_runs", "insights", "reports"):
            await purge("idempotency_keys", _keys_batch(org_id, target, keys_cutoff))
        if any(report.purged.values()):
            async with self._uow_factory(TenantScope.system(org_id)) as uow:
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
        if failures:
            raise failures[0]
        return report

    async def apply_platform_retention(self) -> int:
        """Purge old dead letters that belong to no tenant; returns the count."""
        cutoff = self._clock.now() - timedelta(days=self._policy.dead_letters_days)
        async with self._uow_factory(TenantScope.system(None)) as uow:
            purged = await uow.data.maintenance.purge(None, "dead_letters", cutoff)
            await uow.commit()
        return purged

    async def apply_identity_retention(self) -> dict[str, int]:
        """Delete sign-in data past its use (GDPR storage limitation): sessions -
        with their device and address - ``sessions_days`` after they expired,
        and refresh, password-reset and sign-up tokens and started single
        sign-ons a week after. In
        batches, each its own transaction; the counts are audited."""
        now = self._clock.now()
        sessions_cutoff = now - timedelta(days=self._policy.sessions_days)
        tokens_cutoff = now - EXPIRED_TOKENS_GRACE
        steps: tuple[tuple[str, Callable[[UnitOfWork, int], Awaitable[int]]], ...] = (
            ("user_sessions", lambda uow, n: uow.sessions.purge_expired(sessions_cutoff, limit=n)),
            (
                "refresh_tokens",
                lambda uow, n: uow.refresh_tokens.purge_expired(tokens_cutoff, limit=n),
            ),
            (
                "password_reset_tokens",
                lambda uow, n: uow.password_resets.purge_expired(tokens_cutoff, limit=n),
            ),
            (
                "signup_requests",
                lambda uow, n: uow.signup_requests.purge_expired(tokens_cutoff, limit=n),
            ),
            (
                "sso_login_states",
                lambda uow, n: uow.sso_states.purge_expired(tokens_cutoff, limit=n),
            ),
        )
        purged: dict[str, int] = {}
        for name, step in steps:
            total = 0
            while True:
                async with self._uow_factory(TenantScope.auth()) as uow:
                    count = await step(uow, self._batch)
                    await uow.commit()
                total += count
                if count < self._batch:
                    break
            if total:
                purged[name] = total
        if purged:
            async with self._uow_factory(TenantScope.system(None)) as uow:
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.RETENTION_PURGED,
                    principal=Principal.system(),
                    meta=SYSTEM_META,
                    resource_type="platform",
                    metadata=purged,
                )
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
                    await _fail_lost_run(uow, run, now)
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

    async def seal_sensitive(self, org_id: UUID, dataset_id: UUID) -> int:
        """Seal the stored values of a dataset's sensitive fields that are still
        in clear - after a field was marked sensitive, its old values are.

        First waits for the ingestions that may have read the schema before
        the change (change detection reads it under a share lock, so none of
        it runs with the old schema any more); then seals in batches. Returns
        how many rows still hold a value in clear - rows in use are skipped,
        so the caller retries later until none is left.
        """
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            dataset = await uow.data.datasets.get(org_id, dataset_id)
            if dataset is None or dataset.is_deleted:
                return 0
            await uow.data.sources.wait_for_ingestions(org_id, dataset_id)
            await uow.commit()
        fields = dataset.spec.sensitive_fields
        if not fields:
            return 0
        await self._in_batches(org_id, _seal_records(org_id, dataset_id, fields))
        await self._in_batches(org_id, _seal_changes(org_id, dataset_id, fields))
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            left = await uow.data.records.count_plaintext(org_id, dataset_id, fields)
            return left + await uow.data.changes.count_plaintext(org_id, dataset_id, fields)

    async def purge_dataset(self, org_id: UUID, dataset_id: UUID) -> bool:
        """Delete a soft-deleted dataset: its large tables in batches, then the
        dataset row, whose cascade takes the rest; its files after the commit."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            dataset = await uow.data.datasets.get(org_id, dataset_id)
        if dataset is None or dataset.deleted_at is None:
            return False
        await self._purge_children(org_id, DATASET_CHILDREN, dataset_id=dataset_id)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            dataset = await uow.data.datasets.get_for_update(org_id, dataset_id)
            if dataset is None or dataset.deleted_at is None:
                return False  # purged meanwhile by another delivery of this job
            # Read in the deleting transaction: an upload that commits now is
            # either seen here or refused by the cascade's locks.
            keys = await uow.data.maintenance.file_keys(org_id, dataset_id=dataset_id)
            await uow.data.datasets.delete(dataset)  # sources, uploads, reports...
            for message in file_deletions(org_id, keys, now=now):
                await uow.outbox.add(message)
            await self._audit.record(
                uow.audit,
                action=AuditAction.DATASET_PURGED,
                principal=Principal.system(org_id),
                meta=SYSTEM_META,
                resource_type="dataset",
                resource_id=dataset_id,
                metadata={"files": len(keys)},
            )
            await uow.commit()
            return True

    async def purge_due_organizations(
        self, *, on_error: PurgeErrorHandler | None = None
    ) -> list[UUID]:
        """Hard-delete tenants whose deletion grace period has elapsed, oldest
        request first. Each tenant is purged on its own: one that fails is
        reported to ``on_error`` and retried by the next run, the others go on.

        Audit logs have no foreign key to organizations and are retained
        according to the audit retention policy (compliance evidence)."""
        cutoff = self._clock.now() - ORG_PURGE_GRACE
        async with self._uow_factory(TenantScope.system(None)) as uow:
            due = await uow.data.system.orgs_due_for_purge(cutoff)
        purged: list[UUID] = []
        for org_id in await self._oldest_request_first(due):
            try:
                await self._purge_organization(org_id)
            except Exception as exc:  # noqa: BLE001 - one tenant never blocks the others
                if on_error is not None:
                    on_error(org_id, exc)
                continue
            purged.append(org_id)
        return purged

    async def _oldest_request_first(self, org_ids: Sequence[UUID]) -> list[UUID]:
        requested: dict[UUID, datetime] = {}
        for org_id in org_ids:
            async with self._uow_factory(TenantScope.system(org_id)) as uow:
                organization = await uow.organizations.get(org_id)
            when = organization.deletion_requested_at if organization else None
            requested[org_id] = when or datetime.min.replace(tzinfo=UTC)
        return sorted(org_ids, key=lambda org_id: (requested[org_id], org_id))

    async def _purge_organization(self, org_id: UUID) -> None:
        # Files first: if removing them fails, the tenant is still due and the
        # next run tries again (a tenant pending deletion never uses them again).
        files = await self._storage.delete_tenant(org_id)
        await self._purge_children(org_id, ORGANIZATION_CHILDREN, dataset_id=None)
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            # Recorded in the tenant's own chain, which outlives the tenant.
            await self._audit.record(
                uow.audit,
                action=AuditAction.ORG_PURGED,
                principal=Principal.system(org_id),
                meta=SYSTEM_META,
                resource_type="organization",
                resource_id=org_id,
                metadata={"files": files},
            )
            await uow.data.maintenance.delete_organization(org_id)
            await uow.commit()

    async def delete_files(self, org_id: UUID, keys: Sequence[str]) -> int:
        """Delete stored files whose rows were deleted (the job file_deletions
        queues). Only the tenant's own keys, and only those no row points to."""
        own = [k for k in keys if k.startswith((f"uploads/{org_id}/", f"reports/{org_id}/"))]
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            referenced = await uow.data.maintenance.referenced_keys(org_id, own)
        removed = 0
        for key in own:
            if key not in referenced:
                await self._storage.delete(key)
                removed += 1
        return removed

    async def cleanup_outbox(self) -> int:
        cutoff = self._clock.now() - timedelta(days=self._policy.outbox_days)
        return await self._in_batches(
            None, lambda uow, limit: uow.data.maintenance.purge_outbox(cutoff, limit=limit)
        )


def _delete_batch(
    org_id: UUID, target: str, dataset_id: UUID | None
) -> Callable[[UnitOfWork, int], Awaitable[int]]:
    async def step(uow: UnitOfWork, limit: int) -> int:
        return await uow.data.maintenance.delete_batch(
            org_id, target, dataset_id=dataset_id, limit=limit
        )

    return step


def _retention_batch(
    org_id: UUID, target: str, before: datetime
) -> Callable[[UnitOfWork, int], Awaitable[int]]:
    async def step(uow: UnitOfWork, limit: int) -> int:
        return await uow.data.maintenance.purge(org_id, target, before, limit=limit)

    return step


def _versions_batch(
    org_id: UUID, dataset_id: UUID, before: datetime
) -> Callable[[UnitOfWork, int], Awaitable[int]]:
    async def step(uow: UnitOfWork, limit: int) -> int:
        return await uow.data.records.purge_versions_before(org_id, dataset_id, before, limit=limit)

    return step


def _changes_batch(
    org_id: UUID, dataset_id: UUID, before: datetime
) -> Callable[[UnitOfWork, int], Awaitable[int]]:
    async def step(uow: UnitOfWork, limit: int) -> int:
        return await uow.data.changes.purge_before(org_id, dataset_id, before, limit=limit)

    return step


def _seal_records(
    org_id: UUID, dataset_id: UUID, fields: frozenset[str]
) -> Callable[[UnitOfWork, int], Awaitable[int]]:
    async def step(uow: UnitOfWork, limit: int) -> int:
        return await uow.data.records.seal_plaintext(org_id, dataset_id, fields, limit=limit)

    return step


def _seal_changes(
    org_id: UUID, dataset_id: UUID, fields: frozenset[str]
) -> Callable[[UnitOfWork, int], Awaitable[int]]:
    async def step(uow: UnitOfWork, limit: int) -> int:
        return await uow.data.changes.seal_plaintext(org_id, dataset_id, fields, limit=limit)

    return step


def _keys_batch(
    org_id: UUID, target: str, before: datetime
) -> Callable[[UnitOfWork, int], Awaitable[int]]:
    async def step(uow: UnitOfWork, limit: int) -> int:
        return await uow.data.maintenance.expire_idempotency_keys(
            org_id, target, before, limit=limit
        )

    return step


async def _fail_lost_run(uow: UnitOfWork, run: CollectionRun, now: datetime) -> None:
    """Every attempt of ``run`` died with its worker: fail it as any failed run is
    failed (``IngestionService.fail_run``), in the reaper's transaction - the
    source counts the failure, and ``collection.completed`` lets ``run_failed``
    alert rules fire and the run's workflow run finish."""
    run.fail(now, code="worker_lost", detail="exceeded retry attempts")
    await release_upload(uow, run, now, reason="worker_lost")
    source = await uow.data.sources.get_for_update(run.org_id, run.source_id)
    if source is None:
        return
    source.record_failure(now)
    await uow.outbox.add(
        event_message(
            EventType.COLLECTION_COMPLETED,
            org_id=run.org_id,
            payload={
                "run_id": str(run.id),
                "source_id": str(source.id),
                "dataset_id": str(source.dataset_id),
                "status": run.status.value,
                "workflow_run_id": str(run.workflow_run_id) if run.workflow_run_id else None,
            },
            now=now,
        )
    )

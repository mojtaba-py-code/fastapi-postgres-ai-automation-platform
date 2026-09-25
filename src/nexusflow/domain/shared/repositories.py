"""Repository ports for the business-data bounded contexts.

All methods are tenant-scoped (``org_id`` first) except :class:`SystemQueries`,
which exposes cross-tenant *identifiers only* for schedulers and maintenance.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from nexusflow.core.jsonutil import JSONValue
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.domain.alerts.model import Alert, AlertRule
from nexusflow.domain.automation.model import DeadLetter, Workflow, WorkflowRun
from nexusflow.domain.catalog.model import Dataset, Project
from nexusflow.domain.integrations.model import Integration
from nexusflow.domain.intelligence.model import Insight
from nexusflow.domain.notifications.model import NotificationChannel, NotificationDelivery
from nexusflow.domain.records.model import (
    Change,
    ChangeVolume,
    Record,
    RecordVersion,
    Significance,
)
from nexusflow.domain.reports.model import Report
from nexusflow.domain.sources.model import CollectionRun, Source
from nexusflow.domain.uploads.model import Upload
from nexusflow.domain.webhooks.model import InboundWebhookEvent, WebhookEndpoint


class TenantRepository[E](Protocol):
    async def add(self, entity: E) -> None: ...

    async def get(self, org_id: UUID, entity_id: UUID) -> E | None: ...

    async def get_for_update(self, org_id: UUID, entity_id: UUID) -> E | None: ...

    async def delete(self, entity: E) -> None: ...

    async def list_page(
        self, org_id: UUID, page: PageRequest, filters: Mapping[str, Any] | None = None
    ) -> Page[E]: ...

    async def count(self, org_id: UUID, **filters: Any) -> int: ...


class IntegrationRepository(TenantRepository[Integration], Protocol):
    async def references(self, org_id: UUID, integration_id: UUID) -> int: ...

    async def needing_rewrap(
        self, org_id: UUID, active_key_id: str, limit: int
    ) -> list[Integration]: ...


class SourceRepository(TenantRepository[Source], Protocol):
    async def lock(self, source_id: UUID) -> None: ...

    async def list_by_ids(self, org_id: UUID, ids: Sequence[UUID]) -> list[Source]: ...


class CollectionRunRepository(TenantRepository[CollectionRun], Protocol):
    async def get_by_idempotency_key(self, org_id: UUID, key: str) -> CollectionRun | None: ...

    async def list_stale(
        self, org_id: UUID, *, started_before: datetime, limit: int
    ) -> list[CollectionRun]: ...

    async def list_for_workflow_run(
        self, org_id: UUID, workflow_run_id: UUID
    ) -> list[CollectionRun]: ...

    async def latest_collected_at(self, org_id: UUID, source_id: UUID) -> datetime | None:
        """When the newest data applied from the source was collected (the
        ``collected_at`` of its succeeded runs), if any run recorded it."""
        ...


class RunPayloadRepository(Protocol):
    async def put(
        self, org_id: UUID, run_id: UUID, items: list[JSONValue], now: datetime
    ) -> None: ...

    async def take(self, org_id: UUID, run_id: UUID) -> list[JSONValue] | None: ...

    async def exists(self, org_id: UUID, run_id: UUID) -> bool: ...


class RecordRepository(Protocol):
    async def fetch_for_update(
        self, dataset_id: UUID, keys: Sequence[str]
    ) -> dict[str, Record]: ...

    async def rewrap_sealed(self, org_id: UUID, active_key_id: str, *, limit: int) -> int:
        """Re-encrypt sealed values of records and versions still under an older key."""
        ...

    async def add_many(self, records: Sequence[Record]) -> None: ...

    async def add_versions(self, versions: Sequence[RecordVersion]) -> None: ...

    async def touch(
        self, record_ids: Sequence[UUID], *, run_id: UUID, source_id: UUID, now: datetime
    ) -> None:
        """Mark unchanged records as seen by this run - and owned by its source,
        which alone infers their deletion from its full snapshots."""
        ...

    async def missing_from_run(
        self, dataset_id: UUID, source_id: UUID, run_id: UUID, *, limit: int
    ) -> list[Record]: ...

    async def count_missing_from_run(
        self, dataset_id: UUID, source_id: UUID, run_id: UUID
    ) -> int: ...

    async def get(self, org_id: UUID, record_id: UUID) -> Record | None: ...

    async def get_by_key(
        self, org_id: UUID, dataset_id: UUID, record_key: str
    ) -> Record | None: ...

    async def list_page(
        self, org_id: UUID, dataset_id: UUID, page: PageRequest, *, include_deleted: bool
    ) -> Page[Record]: ...

    async def history(
        self, org_id: UUID, record_id: UUID, *, limit: int
    ) -> list[RecordVersion]: ...

    async def pending_versions(self, dataset_id: UUID, *, limit: int) -> list[RecordVersion]: ...

    async def previous_versions(
        self, pairs: Iterable[tuple[UUID, int]]
    ) -> dict[tuple[UUID, int], RecordVersion]: ...

    async def mark_diffed(self, version_ids: Sequence[UUID]) -> None: ...

    async def keys_for(self, record_ids: Sequence[UUID]) -> dict[UUID, str]: ...

    async def batch_after(
        self, org_id: UUID, dataset_id: UUID, *, after: UUID | None, limit: int
    ) -> list[Record]: ...

    async def purge_versions_before(
        self, org_id: UUID, dataset_id: UUID, before: datetime
    ) -> int: ...


class ChangeRepository(Protocol):
    async def add_new(self, changes: Sequence[Change]) -> list[Change]: ...

    async def get(self, org_id: UUID, change_id: UUID) -> Change | None: ...

    async def list_page(
        self, org_id: UUID, page: PageRequest, filters: Mapping[str, Any]
    ) -> Page[Change]: ...

    async def unanalyzed(self, org_id: UUID, dataset_id: UUID, *, limit: int) -> list[Change]: ...

    async def assign_insight(self, change_ids: Sequence[UUID], insight_id: UUID) -> None: ...

    async def pending_alerts(self, org_id: UUID, *, limit: int) -> list[Change]: ...

    async def mark_alerts_evaluated(self, change_ids: Sequence[UUID]) -> None: ...

    async def rewrap_sealed(self, org_id: UUID, active_key_id: str, *, limit: int) -> int:
        """Re-encrypt sealed values of diffs still under an older key."""
        ...

    async def ranked_in_period(
        self,
        org_id: UUID,
        *,
        dataset_ids: Sequence[UUID],
        start: datetime,
        end: datetime,
        limit: int,
        significances: Sequence[Significance] | None = None,
    ) -> list[Change]:
        """The period's most significant changes: highest score first, then newest."""
        ...

    async def volume(
        self, org_id: UUID, *, dataset_ids: Sequence[UUID], start: datetime, end: datetime
    ) -> list[ChangeVolume]:
        """How many changes the period had, per UTC day, type and significance."""
        ...


class InsightRepository(TenantRepository[Insight], Protocol):
    async def get_by_idempotency_key(self, org_id: UUID, key: str) -> Insight | None: ...

    async def in_period(
        self, org_id: UUID, *, dataset_ids: Sequence[UUID], start: datetime, end: datetime
    ) -> list[Insight]: ...

    async def stuck(
        self, org_id: UUID, *, started_before: datetime, limit: int
    ) -> list[Insight]: ...


class AlertRuleRepository(TenantRepository[AlertRule], Protocol):
    async def enabled_for(
        self, org_id: UUID, *, dataset_id: UUID | None, project_id: UUID | None
    ) -> list[AlertRule]: ...


class AlertRepository(TenantRepository[Alert], Protocol):
    async def add_if_new(self, alert: Alert) -> bool: ...

    async def in_period(
        self, org_id: UUID, *, start: datetime, end: datetime, limit: int
    ) -> list[Alert]: ...


class ChannelRepository(TenantRepository[NotificationChannel], Protocol):
    async def list_by_ids(self, org_id: UUID, ids: Sequence[UUID]) -> list[NotificationChannel]: ...


class DeliveryRepository(TenantRepository[NotificationDelivery], Protocol):
    async def add_if_new(self, delivery: NotificationDelivery) -> bool: ...

    async def for_alert(self, org_id: UUID, alert_id: UUID) -> list[NotificationDelivery]: ...


class ReportRepository(TenantRepository[Report], Protocol):
    async def get_by_idempotency_key(self, org_id: UUID, key: str) -> Report | None: ...

    async def expired(self, org_id: UUID, now: datetime, *, limit: int) -> list[Report]: ...

    async def stuck(
        self, org_id: UUID, *, created_before: datetime, limit: int
    ) -> list[Report]: ...


class UploadRepository(TenantRepository[Upload], Protocol):
    async def find_by_hash(self, org_id: UUID, source_id: UUID, sha256: str) -> Upload | None: ...

    async def get_by_run(self, org_id: UUID, run_id: UUID) -> Upload | None: ...


class WebhookEndpointRepository(TenantRepository[WebhookEndpoint], Protocol):
    async def list_for_update(self, org_id: UUID, *, limit: int) -> list[WebhookEndpoint]: ...


class WebhookEventRepository(Protocol):
    async def add(self, event: InboundWebhookEvent) -> bool: ...

    async def exists(self, endpoint_id: UUID, delivery_id: str) -> bool: ...

    async def get(self, org_id: UUID, event_id: UUID) -> InboundWebhookEvent | None: ...


class WorkflowRepository(TenantRepository[Workflow], Protocol):
    pass


class WorkflowRunRepository(TenantRepository[WorkflowRun], Protocol):
    async def get_by_idempotency_key(self, org_id: UUID, key: str) -> WorkflowRun | None: ...


class DeadLetterRepository(TenantRepository[DeadLetter], Protocol):
    pass


class MaintenanceRepository(Protocol):
    async def purge(self, org_id: UUID | None, target: str, before: datetime) -> int: ...

    async def stuck_deliveries(
        self, org_id: UUID, *, before: datetime, limit: int
    ) -> list[NotificationDelivery]: ...

    async def storage_keys(self, org_id: UUID) -> list[str]: ...

    async def delete_organization(self, org_id: UUID) -> None: ...

    async def purge_outbox(self, before: datetime) -> int: ...


class SystemQueries(Protocol):
    """Cross-tenant identifier queries (SECURITY DEFINER functions)."""

    async def due_workflows(self, now: datetime, limit: int) -> list[tuple[UUID, UUID]]: ...

    async def pending_detection(self, limit: int) -> list[tuple[UUID, UUID]]: ...

    async def tenant_ids(self, statuses: Sequence[str]) -> list[UUID]: ...

    async def orgs_due_for_purge(self, before: datetime) -> list[UUID]: ...


class DataRepositories(Protocol):
    @property
    def projects(self) -> TenantRepository[Project]: ...

    @property
    def datasets(self) -> TenantRepository[Dataset]: ...

    @property
    def integrations(self) -> IntegrationRepository: ...

    @property
    def sources(self) -> SourceRepository: ...

    @property
    def runs(self) -> CollectionRunRepository: ...

    @property
    def payloads(self) -> RunPayloadRepository: ...

    @property
    def records(self) -> RecordRepository: ...

    @property
    def changes(self) -> ChangeRepository: ...

    @property
    def insights(self) -> InsightRepository: ...

    @property
    def alert_rules(self) -> AlertRuleRepository: ...

    @property
    def alerts(self) -> AlertRepository: ...

    @property
    def channels(self) -> ChannelRepository: ...

    @property
    def deliveries(self) -> DeliveryRepository: ...

    @property
    def reports(self) -> ReportRepository: ...

    @property
    def uploads(self) -> UploadRepository: ...

    @property
    def webhook_endpoints(self) -> WebhookEndpointRepository: ...

    @property
    def webhook_events(self) -> WebhookEventRepository: ...

    @property
    def workflows(self) -> WorkflowRepository: ...

    @property
    def workflow_runs(self) -> WorkflowRunRepository: ...

    @property
    def dead_letters(self) -> DeadLetterRepository: ...

    @property
    def system(self) -> SystemQueries: ...

    @property
    def maintenance(self) -> MaintenanceRepository: ...

"""Report requests, generation and audited download."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import ConflictError, InvalidInputError, NotFoundError
from nexusflow.core.ids import uuid7
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.core.text import clean_text, single_line
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.catalog.model import Dataset
from nexusflow.domain.catalog.service import get_dataset, mask_diff, project_datasets
from nexusflow.domain.records.model import Change, Significance
from nexusflow.domain.reports.analytics import (
    MAX_PERIOD,
    ChangeAnalytics,
    headline,
    summarize_volume,
)
from nexusflow.domain.reports.model import (
    Report,
    ReportContent,
    ReportFormat,
    ReportStatus,
    report_storage_key,
)
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.ports import FileStorage
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.sources.model import RestApiConfig, WebsiteConfig

# Change analytics cover the last 30 days unless asked otherwise.
DEFAULT_ANALYTICS_PERIOD = timedelta(days=30)
# A report counts every change of its period, and lists the most significant ones.
_TOP_CHANGES = 200
_TOP_NOTABLE = 25  # of them high or critical


class ReportRenderer(Protocol):
    def render(self, content: ReportContent, fmt: ReportFormat) -> bytes: ...


class ReportService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        storage: FileStorage,
        renderer: ReportRenderer,
        ttl_days: int,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._storage = storage
        self._renderer = renderer
        self._ttl = timedelta(days=ttl_days)

    async def request(
        self,
        principal: Principal,
        *,
        project_id: UUID,
        dataset_id: UUID | None,
        period_start: datetime,
        period_end: datetime,
        fmt: ReportFormat,
        title: str | None,
        idempotency_key: str | None,
        meta: RequestMeta,
    ) -> tuple[Report, bool]:
        principal.require(Permission.REPORTS_GENERATE)
        org_id = principal.require_org()
        _check_period(period_start, period_end)
        key = single_line(idempotency_key, 128) if idempotency_key else None
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            if key is not None:
                existing = await uow.data.reports.get_by_idempotency_key(org_id, key)
                if existing is not None:
                    return existing, False
            project = await uow.data.projects.get(org_id, project_id)
            if project is None:
                raise NotFoundError()
            if dataset_id is not None:
                dataset = await get_dataset(uow, org_id, dataset_id)
                if dataset.project_id != project_id:
                    raise NotFoundError()
            report = Report(
                id=uuid7(),
                org_id=org_id,
                project_id=project_id,
                dataset_id=dataset_id,
                title=clean_text(title or f"{project.name} report", max_length=200),
                format=fmt,
                period_start=period_start,
                period_end=period_end,
                idempotency_key=key,
                requested_by=principal.actor_user_id,
                created_at=now,
            )
            await uow.data.reports.add(report)
            await uow.outbox.add(
                new_message(
                    TaskName.GENERATE_REPORT,
                    {"org_id": str(org_id), "report_id": str(report.id)},
                    org_id=org_id,
                    now=now,
                )
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.REPORT_REQUESTED,
                principal=principal,
                meta=meta,
                resource_type="report",
                resource_id=report.id,
                metadata={"format": fmt},
            )
            await uow.commit()
        return report, True

    async def analytics(
        self,
        principal: Principal,
        *,
        project_id: UUID,
        dataset_id: UUID | None,
        period_start: datetime | None,
        period_end: datetime | None,
    ) -> ChangeAnalytics:
        """Change volume of a project (or one of its datasets), computed on request.

        Counts only - no record keys or values - so the same numbers are shown
        whatever the datasets' classification.
        """
        principal.require(Permission.CHANGES_READ)
        org_id = principal.require_org()
        end = period_end or self._clock.now()
        start = period_start or end - DEFAULT_ANALYTICS_PERIOD
        _check_period(start, end)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            datasets = await _datasets_in_scope(uow, org_id, project_id, dataset_id)
            volume = (
                await uow.data.changes.volume(
                    org_id, dataset_ids=[d.id for d in datasets], start=start, end=end
                )
                if datasets
                else []
            )
        return ChangeAnalytics(
            project_id=project_id,
            dataset_id=dataset_id,
            period_start=start,
            period_end=end,
            volume=summarize_volume(volume, start, end),
        )

    async def list(self, principal: Principal, page: PageRequest) -> Page[Report]:
        principal.require(Permission.REPORTS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.reports.list_page(principal.require_org(), page)

    async def get(self, principal: Principal, report_id: UUID) -> Report:
        principal.require(Permission.REPORTS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            report = await uow.data.reports.get(principal.require_org(), report_id)
            if report is None:
                raise NotFoundError()
            return report

    async def download(
        self, principal: Principal, report_id: UUID, meta: RequestMeta
    ) -> tuple[Report, AsyncIterator[bytes]]:
        """Audited download (data export); the file is streamed from storage."""
        principal.require(Permission.REPORTS_DOWNLOAD)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            report = await uow.data.reports.get(org_id, report_id)
            if report is None:
                raise NotFoundError()
            if report.status is not ReportStatus.READY or report.storage_key is None:
                raise ConflictError("The report is not ready.", code="report_not_ready")
            if report.expires_at is not None and report.expires_at <= self._clock.now():
                raise ConflictError("The report has expired.", code="report_expired")
            await self._audit.record(
                uow.audit,
                action=AuditAction.REPORT_DOWNLOADED,
                principal=principal,
                meta=meta,
                resource_type="report",
                resource_id=report.id,
                metadata={"format": report.format},
            )
            await uow.commit()
        return report, self._storage.stream(report.storage_key)

    # ---------------------------------------------------------------- worker

    async def generate(self, *, org_id: UUID, report_id: UUID) -> Report:
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            report = await uow.data.reports.get_for_update(org_id, report_id)
            if report is None:
                raise NotFoundError(internal_detail=f"report {report_id}")
            if report.status is not ReportStatus.PENDING:
                return report
            report.status = ReportStatus.GENERATING
            content = await self._build_content(uow, report, now)
            await uow.commit()
        try:
            data = await asyncio.to_thread(self._renderer.render, content, report.format)
            key = report_storage_key(org_id, report.id, report.format)
            stored = await self._storage.save_bytes(key, data)
        except Exception:
            # Possibly transient (storage full or unavailable): back to PENDING, so
            # the job's retry renders it again. The report fails only once the
            # retries are spent (``mark_failed``, with a dead letter).
            await self._release(org_id, report_id)
            raise
        return await self._finish(
            org_id, report_id, key=key, size=stored.size, sha256=stored.sha256
        )

    async def _release(self, org_id: UUID, report_id: UUID) -> None:
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            report = await uow.data.reports.get_for_update(org_id, report_id)
            if report is not None and report.status is ReportStatus.GENERATING:
                report.status = ReportStatus.PENDING
                await uow.commit()

    async def mark_failed(self, *, org_id: UUID, report_id: UUID) -> None:
        """Called when the job's retries are exhausted (dead-letter path)."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            report = await uow.data.reports.get_for_update(org_id, report_id)
            if report is not None and report.status in (
                ReportStatus.PENDING,
                ReportStatus.GENERATING,
            ):
                report.status = ReportStatus.FAILED
                report.error_code = "render_failed"
                report.completed_at = self._clock.now()
                await uow.commit()

    async def _finish(
        self, org_id: UUID, report_id: UUID, *, key: str, size: int, sha256: str
    ) -> Report:
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            report = await uow.data.reports.get_for_update(org_id, report_id)
            if report is None:
                raise NotFoundError()
            report.status = ReportStatus.READY
            report.storage_key, report.size_bytes, report.sha256 = key, size, sha256
            report.expires_at = now + self._ttl
            report.completed_at = now
            await uow.commit()
            return report

    async def expire(self, *, org_id: UUID) -> int:
        """Delete files of expired reports (retention)."""
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            expired = await uow.data.reports.expired(org_id, now, limit=200)
            for report in expired:
                if report.storage_key:
                    await self._storage.delete(report.storage_key)
                report.status = ReportStatus.EXPIRED
                report.storage_key = None
            await uow.commit()
            return len(expired)

    async def _build_content(self, uow: UnitOfWork, report: Report, now: datetime) -> ReportContent:
        org_id = report.org_id
        organization = await uow.organizations.get(org_id)
        project = await uow.data.projects.get(org_id, report.project_id)
        if report.dataset_id is not None:
            datasets = [await get_dataset(uow, org_id, report.dataset_id)]
        else:
            datasets = await project_datasets(uow, org_id, report.project_id)
        dataset_ids = [d.id for d in datasets]
        sensitive = {d.id: d.spec.sensitive_fields for d in datasets}
        start, end = report.period_start, report.period_end
        changes = uow.data.changes
        # Totals and the daily series count every change of the period; the
        # listings show its most significant ones.
        volume = (
            await changes.volume(org_id, dataset_ids=dataset_ids, start=start, end=end)
            if dataset_ids
            else []
        )
        top = (
            await changes.ranked_in_period(
                org_id, dataset_ids=dataset_ids, start=start, end=end, limit=_TOP_CHANGES
            )
            if dataset_ids
            else []
        )
        notable = (
            await changes.ranked_in_period(
                org_id,
                dataset_ids=dataset_ids,
                start=start,
                end=end,
                limit=_TOP_NOTABLE,
                significances=(Significance.HIGH, Significance.CRITICAL),
            )
            if dataset_ids
            else []
        )
        insights = (
            await uow.data.insights.in_period(org_id, dataset_ids=dataset_ids, start=start, end=end)
            if dataset_ids
            else []
        )
        # The report's own alerts: of its project's rules, and about its dataset.
        alerts = await uow.data.alerts.in_period(
            org_id,
            start=start,
            end=end,
            limit=100,
            project_id=report.project_id,
            dataset_id=report.dataset_id,
        )
        summary = summarize_volume(volume, start, end)
        scope = datasets[0].name if len(datasets) == 1 else (project.name if project else "project")
        executive = [headline(summary, scope)]
        if summary.totals["changes"]:
            executive.append(summary.trend_note)
        if insights and insights[-1].summary:
            executive.append(f"Latest analysis: {insights[-1].summary}")
        return ReportContent(
            title=report.title,
            organization=organization.name if organization else "",
            project=project.name if project else "",
            dataset=datasets[0].name if report.dataset_id and datasets else None,
            period_start=report.period_start,
            period_end=report.period_end,
            generated_at=now,
            executive_summary=" ".join(executive),
            totals=summary.totals,
            by_significance=summary.by_significance,
            daily_trend=summary.daily,
            volume_anomalies=summary.unusual_days,
            trend_note=summary.trend_note,
            changes=[_change_row(c, sensitive.get(c.dataset_id, frozenset())) for c in top],
            anomalies=[_change_row(c, sensitive.get(c.dataset_id, frozenset())) for c in notable],
            alerts=[
                {
                    "title": a.title,
                    "severity": a.severity.value,
                    "status": a.status.value,
                    "triggered_at": a.triggered_at.isoformat(),
                }
                for a in alerts
            ],
            insights=[
                {
                    "summary": i.summary or "",
                    "risk_level": i.risk_level.value if i.risk_level else None,
                    "created_at": i.created_at.isoformat(),
                    "findings": [f.get("title") for f in i.findings][:10],
                    "recommendations": list(i.recommendations)[:10],
                    "provider": i.provider,
                }
                for i in insights
            ],
            sources=await _source_refs(uow, org_id, dataset_ids),
        )


def _check_period(start: datetime, end: datetime) -> None:
    if end <= start or end - start > MAX_PERIOD:
        raise InvalidInputError(
            "The period must be positive and at most one year.", code="invalid_period"
        )


async def _datasets_in_scope(
    uow: UnitOfWork, org_id: UUID, project_id: UUID, dataset_id: UUID | None
) -> list[Dataset]:
    """The project's datasets, or the one asked for; 404 unless it is the project's."""
    if await uow.data.projects.get(org_id, project_id) is None:
        raise NotFoundError()
    if dataset_id is None:
        return await project_datasets(uow, org_id, project_id)
    dataset = await get_dataset(uow, org_id, dataset_id)
    if dataset.project_id != project_id:
        raise NotFoundError()
    return [dataset]


def _change_row(change: Change, sensitive: frozenset[str]) -> dict[str, Any]:
    return {
        "id": str(change.id),
        "record_key": change.record_key,
        "change_type": change.change_type.value,
        "significance": change.significance.value,
        "score": change.score,
        "detected_at": change.detected_at.isoformat(),
        "diff": mask_diff(change.diff, sensitive, reveal=False),
    }


async def _source_refs(
    uow: UnitOfWork, org_id: UUID, dataset_ids: list[UUID]
) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for dataset_id in dataset_ids[:50]:
        page = await uow.data.sources.list_page(
            org_id, PageRequest(limit=100), {"dataset_id": dataset_id}
        )
        for source in page.items:
            config = source.parsed_config
            location = ""
            if isinstance(config, (WebsiteConfig, RestApiConfig)):
                parts = urlsplit(config.url)
                location = (
                    f"{parts.scheme}://{parts.netloc}{parts.path}"  # never include query strings
                )
            refs.append({"name": source.name, "kind": source.kind.value, "location": location})
    return refs

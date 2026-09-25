"""Tenant automation workflows (definitions, kill switch, manual runs)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import ConflictError, InvalidInputError, NotFoundError
from nexusflow.core.ids import uuid7
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.core.text import clean_text, required_name, single_line
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.automation.model import (
    MAX_INTERVAL_MINUTES,
    MIN_INTERVAL_MINUTES,
    Workflow,
    WorkflowRun,
    WorkflowRunStatus,
    WorkflowStatus,
    WorkflowStep,
    WorkflowTrigger,
)
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.sources.model import RunStatus, RunTrigger, SourceKind
from nexusflow.domain.sources.service import queue_run

_PULL = frozenset({SourceKind.WEBSITE, SourceKind.REST_API})
MAX_SOURCES_PER_WORKFLOW = 50


class WorkflowService:
    def __init__(
        self, *, uow_factory: UnitOfWorkFactory, clock: Clock, audit: AuditRecorder
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit

    async def create(
        self,
        principal: Principal,
        *,
        project_id: UUID,
        name: str,
        description: str | None,
        trigger: WorkflowTrigger,
        interval_minutes: int | None,
        source_ids: list[UUID],
        analyze: bool,
        alert: bool,
        meta: RequestMeta,
    ) -> Workflow:
        principal.require(Permission.WORKFLOWS_WRITE)
        org_id = principal.require_org()
        now = self._clock.now()
        _check_schedule(trigger, interval_minutes)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            if await uow.data.projects.get(org_id, project_id) is None:
                raise NotFoundError()
            await _check_sources(uow, org_id, project_id, source_ids)
            workflow = Workflow(
                id=uuid7(),
                org_id=org_id,
                project_id=project_id,
                name=required_name(name),
                description=clean_text(description, max_length=1000, multiline=True)
                if description
                else None,
                trigger=trigger,
                schedule_interval_minutes=interval_minutes,
                source_ids=list(dict.fromkeys(source_ids)),
                analyze=analyze,
                alert=alert,
                created_by=principal.actor_user_id,
                created_at=now,
                updated_at=now,
            )
            workflow.next_run_at = now if trigger is WorkflowTrigger.SCHEDULE else None
            await uow.data.workflows.add(workflow)
            await self._audit.record(
                uow.audit,
                action=AuditAction.WORKFLOW_CREATED,
                principal=principal,
                meta=meta,
                resource_type="workflow",
                resource_id=workflow.id,
                metadata={"trigger": trigger, "sources": len(workflow.source_ids)},
            )
            await uow.commit()
        return workflow

    async def update(
        self,
        principal: Principal,
        workflow_id: UUID,
        *,
        name: str | None,
        description: str | None,
        interval_minutes: int | None,
        source_ids: list[UUID] | None,
        analyze: bool | None,
        alert: bool | None,
        expected_version: int | None,
        meta: RequestMeta,
    ) -> Workflow:
        principal.require(Permission.WORKFLOWS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            workflow = await _workflow(uow, org_id, workflow_id, lock=True)
            if expected_version is not None and expected_version != workflow.version:
                raise ConflictError(
                    "The workflow was modified concurrently.", code="version_conflict"
                )
            if interval_minutes is not None:
                _check_schedule(workflow.trigger, interval_minutes)
                workflow.schedule_interval_minutes = interval_minutes
            if source_ids is not None:
                await _check_sources(uow, org_id, workflow.project_id, source_ids)
                workflow.source_ids = list(dict.fromkeys(source_ids))
            if name is not None:
                workflow.name = required_name(name)
            if description is not None:
                workflow.description = clean_text(description, max_length=1000, multiline=True)
            if analyze is not None:
                workflow.analyze = analyze
            if alert is not None:
                workflow.alert = alert
            workflow.updated_at = self._clock.now()
            workflow.version += 1
            await self._audit.record(
                uow.audit,
                action=AuditAction.WORKFLOW_UPDATED,
                principal=principal,
                meta=meta,
                resource_type="workflow",
                resource_id=workflow.id,
                metadata={"version": workflow.version},
            )
            await uow.commit()
            return workflow

    async def set_status(
        self,
        principal: Principal,
        workflow_id: UUID,
        *,
        status: WorkflowStatus,
        reason: str | None,
        meta: RequestMeta,
    ) -> Workflow:
        """Pause/resume, or DISABLE - the per-workflow kill switch that also
        cancels queued work. Operators may disable; re-enabling needs write access."""
        org_id = principal.require_org()
        if status is WorkflowStatus.DISABLED:
            principal.require(Permission.WORKFLOWS_DISABLE)
        else:
            principal.require(Permission.WORKFLOWS_WRITE)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            workflow = await _workflow(uow, org_id, workflow_id, lock=True)
            if status is WorkflowStatus.DISABLED:
                workflow.disable(reason=reason or "disabled", by=principal.actor_user_id, now=now)
                cancelled = await _cancel_open_runs(uow, workflow, now)
                action, metadata = (
                    AuditAction.WORKFLOW_DISABLED,
                    {"reason": reason, "cancelled_runs": cancelled},
                )
            else:
                workflow.status = status
                workflow.disabled_reason = workflow.disabled_by = workflow.disabled_at = None
                if status is WorkflowStatus.ACTIVE:
                    workflow.schedule_next(now)
                else:
                    workflow.next_run_at = None
                workflow.updated_at = now
                workflow.version += 1
                action, metadata = AuditAction.WORKFLOW_ENABLED, {"status": status}
            await self._audit.record(
                uow.audit,
                action=action,
                principal=principal,
                meta=meta,
                resource_type="workflow",
                resource_id=workflow.id,
                metadata=metadata,
            )
            await uow.commit()
            return workflow

    async def delete(self, principal: Principal, workflow_id: UUID, meta: RequestMeta) -> None:
        principal.require(Permission.WORKFLOWS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            workflow = await _workflow(uow, org_id, workflow_id, lock=True)
            await uow.data.workflows.delete(workflow)
            await self._audit.record(
                uow.audit,
                action=AuditAction.WORKFLOW_DELETED,
                principal=principal,
                meta=meta,
                resource_type="workflow",
                resource_id=workflow_id,
            )
            await uow.commit()

    async def list(
        self, principal: Principal, page: PageRequest, *, project_id: UUID | None
    ) -> Page[Workflow]:
        principal.require(Permission.WORKFLOWS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.workflows.list_page(
                principal.require_org(), page, {"project_id": project_id}
            )

    async def get(self, principal: Principal, workflow_id: UUID) -> Workflow:
        principal.require(Permission.WORKFLOWS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await _workflow(uow, principal.require_org(), workflow_id, lock=False)

    async def run_now(
        self,
        principal: Principal,
        workflow_id: UUID,
        *,
        idempotency_key: str | None,
        meta: RequestMeta,
    ) -> tuple[WorkflowRun, bool]:
        principal.require(Permission.WORKFLOWS_EXECUTE)
        org_id = principal.require_org()
        now = self._clock.now()
        key = (
            f"manual:{single_line(idempotency_key, 100)}"
            if idempotency_key
            else f"manual:{uuid7()}"
        )
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            existing = await uow.data.workflow_runs.get_by_idempotency_key(org_id, key)
            if existing is not None:
                return existing, False
            workflow = await _workflow(uow, org_id, workflow_id, lock=True)
            if not workflow.is_runnable:
                raise ConflictError(
                    f"The workflow is {workflow.status}.", code="workflow_not_runnable"
                )
            organization = await uow.organizations.get(org_id)
            if organization is not None and organization.policy.automation_frozen:
                raise ConflictError(
                    "Automation is frozen for this organization.", code="automation_frozen"
                )
            run = await start_workflow_run(
                uow, workflow, trigger=WorkflowTrigger.MANUAL, key=key, now=now
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.WORKFLOW_EXECUTED,
                principal=principal,
                meta=meta,
                resource_type="workflow",
                resource_id=workflow.id,
                metadata={"run_id": str(run.id)},
            )
            await uow.commit()
        return run, True

    async def list_runs(
        self, principal: Principal, page: PageRequest, *, workflow_id: UUID | None
    ) -> Page[WorkflowRun]:
        principal.require(Permission.WORKFLOWS_READ)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            if workflow_id is not None:
                await _workflow(uow, org_id, workflow_id, lock=False)  # 404 if not this tenant's
            return await uow.data.workflow_runs.list_page(
                org_id, page, {"workflow_id": workflow_id}
            )


async def start_workflow_run(
    uow: UnitOfWork, workflow: Workflow, *, trigger: WorkflowTrigger, key: str, now: datetime
) -> WorkflowRun:
    run = WorkflowRun(
        id=uuid7(),
        org_id=workflow.org_id,
        workflow_id=workflow.id,
        trigger=trigger,
        idempotency_key=key[:128],
        created_at=now,
    )
    await uow.data.workflow_runs.add(run)
    sources = await uow.data.sources.list_by_ids(workflow.org_id, workflow.source_ids)
    queued = 0
    for source in sources:
        if source.is_runnable and source.kind in _PULL:
            await queue_run(
                uow,
                source,
                trigger=RunTrigger.SCHEDULE
                if trigger is WorkflowTrigger.SCHEDULE
                else RunTrigger.AUTOMATION,
                idempotency_key=f"{run.id}:{source.id}",
                now=now,
                workflow_run_id=run.id,
            )
            queued += 1
    run.record_step(WorkflowStep.COLLECT, {"queued": queued}, now)
    if queued == 0:
        run.finish(WorkflowRunStatus.SUCCEEDED, now)
    workflow.last_run_at = now
    workflow.schedule_next(now)
    return run


async def _cancel_open_runs(uow: UnitOfWork, workflow: Workflow, now: datetime) -> int:
    page = await uow.data.workflow_runs.list_page(
        workflow.org_id, PageRequest(limit=200), {"workflow_id": workflow.id}
    )
    cancelled = 0
    for run in page.items:
        if run.is_terminal:
            continue
        run.finish(WorkflowRunStatus.CANCELLED, now, error_code="workflow_disabled")
        for collection in await uow.data.runs.list_for_workflow_run(workflow.org_id, run.id):
            if collection.status is RunStatus.QUEUED:
                collection.status = RunStatus.CANCELLED
                collection.finished_at = now
        cancelled += 1
    return cancelled


async def _workflow(uow: UnitOfWork, org_id: UUID, workflow_id: UUID, *, lock: bool) -> Workflow:
    repo = uow.data.workflows
    workflow = await (
        repo.get_for_update(org_id, workflow_id) if lock else repo.get(org_id, workflow_id)
    )
    if workflow is None:
        raise NotFoundError()
    return workflow


async def _check_sources(
    uow: UnitOfWork, org_id: UUID, project_id: UUID, source_ids: list[UUID]
) -> None:
    if len(source_ids) > MAX_SOURCES_PER_WORKFLOW:
        raise InvalidInputError(f"At most {MAX_SOURCES_PER_WORKFLOW} sources per workflow.")
    sources = await uow.data.sources.list_by_ids(org_id, list(dict.fromkeys(source_ids)))
    if len(sources) != len(set(source_ids)) or any(s.project_id != project_id for s in sources):
        raise NotFoundError("One or more sources were not found in this project.")
    if any(s.kind not in _PULL for s in sources):
        raise InvalidInputError(
            "Workflows schedule pull sources (website, rest_api) only.", code="not_pull_source"
        )


def _check_schedule(trigger: WorkflowTrigger, interval: int | None) -> None:
    if trigger is WorkflowTrigger.SCHEDULE:
        if interval is None or not MIN_INTERVAL_MINUTES <= interval <= MAX_INTERVAL_MINUTES:
            raise InvalidInputError(
                f"Scheduled workflows need an interval between {MIN_INTERVAL_MINUTES} and "
                f"{MAX_INTERVAL_MINUTES} minutes.",
                code="invalid_interval",
            )
    elif interval is not None:
        raise InvalidInputError("Manual workflows have no schedule.", code="invalid_interval")

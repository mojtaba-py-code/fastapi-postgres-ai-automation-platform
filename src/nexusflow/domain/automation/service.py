"""Automation steps exposed to n8n through the internal API.

n8n orchestrates; Python executes. Each step is:

* authorized by a *per-workflow* service token with narrow scopes (revoking one
  token disables exactly one n8n workflow - the platform-level kill switch);
* idempotent (slot keys, unique constraints, state machines), because n8n
  retries failed nodes;
* bounded (batch limits) and returns identifiers/counters only - never tenant
  content - so a compromised automation layer cannot exfiltrate data through
  these endpoints.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import ConflictError, NotFoundError, ServiceUnavailableError
from nexusflow.core.resilience import backoff_delay
from nexusflow.core.text import single_line
from nexusflow.domain.alerts.service import AlertService
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal, ServiceScope
from nexusflow.domain.automation.dead_letters import DeadLetterService
from nexusflow.domain.automation.model import (
    WorkflowRunStatus,
    WorkflowStep,
    WorkflowTrigger,
)
from nexusflow.domain.automation.workflows import start_workflow_run
from nexusflow.domain.intelligence.service import IntelligenceService
from nexusflow.domain.records.service import ChangeDetectionService
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.ports import NonceStore
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.sources.model import RunStatus

MAX_STEP_RETRIES = 3
# Identical operator alerts within this window page once (a failure storm is
# one incident, not hundreds of pages).
OPERATOR_ALERT_DEDUP_SECONDS = 15 * 60
_ALERT_NAMESPACE = "operator-alert"


@dataclass(frozen=True, slots=True)
class DispatchedRun:
    org_id: UUID
    workflow_id: UUID
    workflow_run_id: UUID


@dataclass(frozen=True, slots=True)
class FailureDecision:
    retry: bool
    delay_seconds: float
    dead_letter_id: UUID | None


class AutomationGate(Protocol):
    """The global operator kill switch (a runtime flag outside the database)."""

    async def automation_disabled(self) -> bool: ...


class FailureLedger(Protocol):
    """Counts failures per n8n retry chain (an execution and its retries)."""

    async def record_failure(self, execution_id: str, retry_of: str | None) -> int:
        """Record one failure; return how many the chain has had, this one included."""
        ...


class AutomationService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        detection: ChangeDetectionService,
        intelligence: IntelligenceService,
        alerts: AlertService,
        dead_letters: DeadLetterService,
        gate: AutomationGate | None = None,
        nonces: NonceStore | None = None,
        ledger: FailureLedger | None = None,
        audit: AuditRecorder | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._detection = detection
        self._intelligence = intelligence
        self._alerts = alerts
        self._dead_letters = dead_letters
        self._gate = gate
        self._nonces = nonces
        self._ledger = ledger
        self._audit = audit

    async def dispatch_due(self, principal: Principal, *, limit: int) -> list[DispatchedRun]:
        """Workflow 1 entry point: start every due scheduled workflow once per slot."""
        principal.require_scope(ServiceScope.COLLECT)
        await self.ensure_allowed(None)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(None)) as uow:
            due = await uow.data.system.due_workflows(now, min(limit, 500))
        dispatched: list[DispatchedRun] = []
        for org_id, workflow_id in due:
            async with self._uow_factory(TenantScope.system(org_id)) as uow:
                workflow = await uow.data.workflows.get_for_update(org_id, workflow_id)
                if workflow is None or not workflow.is_runnable:
                    continue
                if workflow.next_run_at is None or workflow.next_run_at > now:
                    continue  # another dispatcher got here first
                key = workflow.slot_key(now)
                if await uow.data.workflow_runs.get_by_idempotency_key(org_id, key) is not None:
                    workflow.schedule_next(now)
                    await uow.commit()
                    continue
                run = await start_workflow_run(
                    uow, workflow, trigger=WorkflowTrigger.SCHEDULE, key=key, now=now
                )
                await self._audit_step(
                    uow,
                    principal,
                    org_id,
                    AuditAction.WORKFLOW_EXECUTED,
                    resource=("workflow", str(workflow.id)),
                    metadata={"run_id": str(run.id), "trigger": WorkflowTrigger.SCHEDULE.value},
                )
                await uow.commit()
                dispatched.append(DispatchedRun(org_id, workflow.id, run.id))
        return dispatched

    async def workflow_run_status(
        self, principal: Principal, *, org_id: UUID, workflow_run_id: UUID
    ) -> dict[str, Any]:
        """Poll target for n8n: aggregates collection-run states and advances the run."""
        principal.require_scope(ServiceScope.COLLECT)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            run = await uow.data.workflow_runs.get_for_update(org_id, workflow_run_id)
            if run is None:
                raise NotFoundError()
            collections = await uow.data.runs.list_for_workflow_run(org_id, run.id)
            counts: dict[str, int] = {}
            for collection in collections:
                counts[collection.status.value] = counts.get(collection.status.value, 0) + 1
            pending = counts.get(RunStatus.QUEUED.value, 0) + counts.get(RunStatus.RUNNING.value, 0)
            sources = sorted({str(c.source_id) for c in collections})
            completed_now = not run.is_terminal and pending == 0
            if completed_now:
                succeeded = counts.get(RunStatus.SUCCEEDED.value, 0)
                run.record_step(WorkflowStep.COLLECT, {"runs": counts}, now)
                if collections and succeeded == 0:
                    run.finish(WorkflowRunStatus.FAILED, now, error_code="all_collections_failed")
                else:
                    run.finish(WorkflowRunStatus.SUCCEEDED, now)
                await self._audit_step(
                    uow,
                    principal,
                    org_id,
                    AuditAction.AUTOMATION_STEP,
                    resource=("workflow_run", str(run.id)),
                    metadata={"step": "run_finished", "status": run.status.value, "runs": counts},
                )
            await uow.commit()
            return {
                "workflow_run_id": str(run.id),
                "status": run.status.value,
                "collections": counts,
                "pending": pending,
                "sources": sources,
                "completed_now": completed_now,  # for the caller's metrics; not part of the API
            }

    async def _audit_step(
        self,
        uow: UnitOfWork,
        principal: Principal,
        org_id: UUID,
        action: AuditAction,
        *,
        resource: tuple[str, str] | None,
        metadata: dict[str, Any],
    ) -> None:
        """Record an automation action in the tenant's chain, attributed to the
        service account (n8n workflow or the internal orchestrator) that ran it."""
        if self._audit is None:
            return
        await self._audit.record(
            uow.audit,
            action=action,
            principal=principal,
            meta=RequestMeta(request_id=None, ip=None, user_agent=principal.label[:200]),
            org_id=org_id,
            resource_type=resource[0] if resource else None,
            resource_id=resource[1] if resource else None,
            metadata=metadata,
        )

    async def _record_step(
        self,
        principal: Principal,
        org_id: UUID,
        step: str,
        resource: tuple[str, str] | None,
        metadata: dict[str, Any],
    ) -> None:
        if self._audit is None:
            return
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            await self._audit_step(
                uow,
                principal,
                org_id,
                AuditAction.AUTOMATION_STEP,
                resource=resource,
                metadata={"step": step, **metadata},
            )
            await uow.commit()

    async def ensure_allowed(self, org_id: UUID | None) -> None:
        """The global operator kill switch, then the tenant freeze.

        Enforced here - not only in the HTTP layer - so every orchestration
        path (n8n via the internal API, and the platform's own internal mode)
        honours both switches.
        """
        if self._gate is not None and await self._gate.automation_disabled():
            raise ServiceUnavailableError(
                "Automation is disabled by the operator kill switch.", code="automation_disabled"
            )
        if org_id is None:
            return
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            organization = await uow.organizations.get(org_id)
        if organization is None:
            raise NotFoundError()
        if not organization.is_active or organization.policy.automation_frozen:
            raise ConflictError(
                "Automation is disabled for this organization.", code="automation_frozen"
            )

    async def detect(
        self, principal: Principal, *, org_id: UUID, dataset_id: UUID
    ) -> dict[str, Any]:
        principal.require_scope(ServiceScope.DETECT)
        await self.ensure_allowed(org_id)
        outcome = await self._detection.detect(org_id=org_id, dataset_id=dataset_id)
        await self._record_step(
            principal,
            org_id,
            "detect",
            ("dataset", str(dataset_id)),
            {"changes_created": outcome.changes_created},
        )
        return {
            "dataset_id": str(dataset_id),
            "versions_processed": outcome.versions_processed,
            "changes_created": outcome.changes_created,
            "max_significance": outcome.max_significance.value
            if outcome.max_significance
            else None,
            "analyze": outcome.analyze,
        }

    async def sweep_detection(self, principal: Principal, *, limit: int) -> int:
        """Workflow 2 safety net: enqueue detection for datasets with pending versions."""
        principal.require_scope(ServiceScope.DETECT)
        await self.ensure_allowed(None)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(None)) as uow:
            pending = await uow.data.system.pending_detection(min(limit, 1000))
            for org_id, dataset_id in pending:
                await uow.outbox.add(
                    new_message(
                        TaskName.DETECT_CHANGES,
                        {"org_id": str(org_id), "dataset_id": str(dataset_id)},
                        org_id=org_id,
                        now=now,
                    )
                )
            await uow.commit()
        return len(pending)

    async def analyze(
        self, principal: Principal, *, org_id: UUID, dataset_id: UUID
    ) -> dict[str, Any]:
        principal.require_scope(ServiceScope.ANALYZE)
        await self.ensure_allowed(org_id)
        insight = await self._intelligence.request_automatic(org_id=org_id, dataset_id=dataset_id)
        await self._record_step(
            principal,
            org_id,
            "analyze",
            ("dataset", str(dataset_id)),
            {"insight_id": str(insight.id) if insight else None},
        )
        return {"insight_id": str(insight.id) if insight else None, "queued": insight is not None}

    async def insight_status(
        self, principal: Principal, *, org_id: UUID, insight_id: UUID
    ) -> dict[str, Any]:
        principal.require_scope(ServiceScope.ANALYZE)
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            insight = await uow.data.insights.get(org_id, insight_id)
            if insight is None:
                raise NotFoundError()
            return {
                "insight_id": str(insight.id),
                "status": insight.status.value,
                "risk_level": insight.risk_level.value if insight.risk_level else None,
                "error_code": insight.error_code,
            }

    async def evaluate_alerts(self, principal: Principal, *, org_id: UUID) -> dict[str, Any]:
        principal.require_scope(ServiceScope.ALERT)
        await self.ensure_allowed(org_id)
        created = await self._alerts.evaluate_changes(org_id=org_id)
        await self._record_step(
            principal, org_id, "evaluate_alerts", None, {"alerts_created": created}
        )
        return {"alerts_created": created}

    async def record_failure(
        self,
        principal: Principal,
        *,
        org_id: UUID | None,
        workflow: str,
        node: str,
        execution_id: str,
        retry_of: str | None,
        error_message: str,
        idempotent: bool,
    ) -> FailureDecision:
        """Workflow 5: decide retry (with exponential backoff) vs dead letter.

        Attempts are counted here, per retry chain, so a caller cannot retry
        forever. Nothing is retried while automation is stopped (kill switch or
        tenant freeze), nor when the attempt count cannot be established.
        """
        principal.require_scope(ServiceScope.RECOVER)
        attempt = await self._failure_attempt(execution_id, retry_of)
        if idempotent and attempt <= MAX_STEP_RETRIES and await self._may_retry(org_id):
            return FailureDecision(
                True, backoff_delay(attempt, base_seconds=30, cap_seconds=900), None
            )
        letter = await self._dead_letters.record(
            org_id=org_id,
            origin="n8n",
            task_name=f"n8n:{single_line(workflow, 40)}:{single_line(node, 40)}",
            payload={"execution_id": single_line(execution_id, 64)},
            error_code="n8n_step_failed",
            error_message=error_message,
            attempts=attempt,
            reference_type="n8n_execution",
            reference_id=single_line(execution_id, 64),
        )
        return FailureDecision(False, 0.0, letter.id)

    async def _failure_attempt(self, execution_id: str, retry_of: str | None) -> int:
        if self._ledger is None:
            # Without a ledger only a first failure is retried, and only once.
            return 1 if retry_of is None else MAX_STEP_RETRIES + 1
        try:
            return await self._ledger.record_failure(execution_id, retry_of)
        except ServiceUnavailableError:
            return MAX_STEP_RETRIES + 1  # unknown count: dead-letter, never loop

    async def _may_retry(self, org_id: UUID | None) -> bool:
        try:
            await self.ensure_allowed(org_id)
        except (ServiceUnavailableError, ConflictError, NotFoundError):
            return False  # stopped automation is never restarted by a retry
        return True

    async def operator_alert(self, principal: Principal, *, severity: str, summary: str) -> bool:
        """Queue a page for the operators. Returns ``False`` when the identical
        alert was already queued within ``OPERATOR_ALERT_DEDUP_SECONDS``, so a
        failure storm pages once instead of once per failed job."""
        principal.require_scope(ServiceScope.OPERATOR_ALERT)
        severity, summary = single_line(severity, 16), single_line(summary, 500)
        fingerprint = hashlib.sha256(f"{severity}\n{summary}".encode()).hexdigest()
        if not await self._first_alert(fingerprint):
            return False
        try:
            async with self._uow_factory(TenantScope.system(None)) as uow:
                await uow.outbox.add(
                    new_message(
                        TaskName.OPERATOR_ALERT,
                        {"severity": severity, "summary": summary},
                        org_id=None,
                        now=self._clock.now(),
                    )
                )
                await uow.commit()
        except BaseException:
            if self._nonces is not None:  # not queued: a retry must not be suppressed
                await self._nonces.release(_ALERT_NAMESPACE, fingerprint)
            raise
        return True

    async def _first_alert(self, fingerprint: str) -> bool:
        if self._nonces is None:
            return True
        try:
            return await self._nonces.first_use(
                _ALERT_NAMESPACE, fingerprint, ttl_seconds=OPERATOR_ALERT_DEDUP_SECONDS
            )
        except ServiceUnavailableError:
            return True  # fail open: a duplicate page beats a lost one

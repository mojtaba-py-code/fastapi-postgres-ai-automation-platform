"""Task handlers of the platform worker pools (``pipeline`` and ``integrations``).

Handlers are thin: validate the message (see :mod:`.messages`), call a domain
service, done. All of them are idempotent - the broker delivers at least once
and the reaper re-queues work of crashed workers.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from nexusflow.apps.workers.messages import (
    DatasetMessage,
    DeliveryMessage,
    Empty,
    EventMessage,
    FilesMessage,
    InsightMessage,
    InvitationMessage,
    Message,
    OperatorAlertMessage,
    OptionalOrgMessage,
    OrgMessage,
    PasswordResetMessage,
    ReportMessage,
    RunMessage,
    SecurityEmailMessage,
    SignupLinkMessage,
)
from nexusflow.bootstrap.container import Container
from nexusflow.bootstrap.messaging import build_relay
from nexusflow.core.errors import (
    ConflictError,
    NexusFlowError,
    ServiceUnavailableError,
    TransientError,
)
from nexusflow.domain.audit.model import ChainVerification
from nexusflow.domain.authorization.principal import Principal, PrincipalType, ServiceScope
from nexusflow.domain.automation.events import EventType
from nexusflow.domain.identity.login_risk import SignInDetails
from nexusflow.domain.integrations.model import SOURCE_AUTH_KINDS
from nexusflow.domain.pipeline.collection import CollectionAction, CollectionPlan
from nexusflow.domain.records.service import DetectionOutcome
from nexusflow.infrastructure.messaging.celery_app import (
    INTEGRATIONS,
    SANDBOX,
    SANDBOX_UPLOAD_TASK,
    SANDBOX_WEBSITE_TASK,
)
from nexusflow.infrastructure.messaging.outbox import CeleryDispatcher, OutboxRelay
from nexusflow.infrastructure.notifications.senders import SmtpEmailTransport
from nexusflow.infrastructure.observability import metrics
from nexusflow.infrastructure.observability.logging import get_logger

_log = get_logger("nexusflow.worker")

# The platform acting as its own orchestrator (orchestration mode "internal").
INTERNAL_SERVICE = Principal(
    type=PrincipalType.SERVICE,
    id=UUID(int=0),
    org_id=None,
    role=None,
    service_scopes=frozenset(ServiceScope),
    label="service:internal-orchestrator",
)
FORWARD_TASK = "nexusflow.events.forward"


@dataclass
class WorkerDeps:
    container: Container
    dispatcher: CeleryDispatcher
    _relay: OutboxRelay | None = field(default=None, repr=False)

    @property
    def relay(self) -> OutboxRelay:
        if self._relay is None:
            self._relay = build_relay(self.container, self.dispatcher)
        return self._relay

    async def send(self, name: str, *, kwargs: dict[str, Any], queue: str) -> None:
        await asyncio.to_thread(self.dispatcher.send_task, name, kwargs=kwargs, queue=queue)


type Handler[M: Message] = Callable[[WorkerDeps, M], Awaitable[None]]


def _uuid(value: Any) -> UUID | None:
    try:
        return UUID(str(value)) if value else None
    except ValueError:
        return None


def _internal_orchestration(c: Container) -> bool:
    return c.settings.n8n.orchestration == "internal" or c.n8n is None


# --------------------------------------------------------------- collection


def _sandbox_kwargs(plan: CollectionPlan) -> dict[str, Any]:
    return {
        "org_id": str(plan.org_id),
        "run_id": str(plan.run_id),
        "ticket": plan.ticket,
        "config": plan.config,
        "allowed_domains": plan.allowed_domains,
        "max_items": plan.max_items,
        "limits": plan.limits,
    }


async def collect_dispatch(deps: WorkerDeps, msg: RunMessage) -> None:
    c = deps.container
    plan = await c.collection.plan(org_id=msg.org_id, run_id=msg.run_id)
    match plan.action:
        case CollectionAction.INGEST_STAGED:
            outcome = await c.ingestion.ingest(org_id=msg.org_id, run_id=msg.run_id, items=None)
            metrics.record_ingestion(
                plan.source_kind or "unknown",
                outcome.status.value,
                outcome.stats,
                outcome.duration_seconds,
            )
        case CollectionAction.REST_API:
            await deps.send(
                "nexusflow.collect.rest_api",
                kwargs={"org_id": str(msg.org_id), "run_id": str(msg.run_id)},
                queue=INTEGRATIONS,
            )
        case CollectionAction.SANDBOX_WEBSITE | CollectionAction.SANDBOX_UPLOAD:
            task = (
                SANDBOX_WEBSITE_TASK
                if plan.action is CollectionAction.SANDBOX_WEBSITE
                else SANDBOX_UPLOAD_TASK
            )
            try:
                await deps.send(task, kwargs=_sandbox_kwargs(plan), queue=SANDBOX)
            except Exception as exc:
                await c.collection.release(org_id=msg.org_id, run_id=msg.run_id)
                raise TransientError(
                    code="broker_unavailable", internal_detail=type(exc).__name__
                ) from exc
        case CollectionAction.SKIP:
            return


async def collect_rest_api(deps: WorkerDeps, msg: RunMessage) -> None:
    c = deps.container
    job = await c.collection.begin_rest_api(org_id=msg.org_id, run_id=msg.run_id)
    if job is None:
        return
    try:
        credential = (
            await c.integrations.resolve(msg.org_id, job.integration_id, allowed=SOURCE_AUTH_KINDS)
            if job.integration_id is not None
            else None
        )
        result = await c.rest_collector.collect(
            job.config,
            policy=c.url_policy.with_allowed_domains(job.allowed_domains),
            credential=credential,
            integration_id=job.integration_id,
            max_items=job.max_items,
        )
    except TransientError:
        await c.collection.release(org_id=msg.org_id, run_id=msg.run_id)
        raise
    except NexusFlowError as exc:  # blocked URL, 4xx, invalid JSON, unusable credential
        await c.ingestion.fail_run(org_id=msg.org_id, run_id=msg.run_id, code=exc.code, detail=None)
        return
    except Exception:
        # Unexpected (a bug, a library error): hand the run back like a transient
        # failure, so the task's retry can start it again instead of finding it
        # RUNNING and returning; after the last retry it fails (fail_collection).
        await c.collection.release(org_id=msg.org_id, run_id=msg.run_id)
        raise
    outcome = await c.ingestion.ingest(
        org_id=msg.org_id,
        run_id=msg.run_id,
        items=result.items,
        truncated=result.truncated,
        source_detail=result.detail,
    )
    metrics.record_ingestion(
        "rest_api", outcome.status.value, outcome.stats, outcome.duration_seconds
    )


async def fail_collection(c: Container, msg: RunMessage, code: str) -> None:
    await c.ingestion.fail_run(org_id=msg.org_id, run_id=msg.run_id, code=code, detail=None)
    metrics.COLLECTION_RUNS.labels(source_kind="unknown", status="failed").inc()


# ------------------------------------------------ detection, AI, alerting


def _record_detection(outcome: DetectionOutcome) -> None:
    if outcome.changes_created:
        level = outcome.max_significance.value if outcome.max_significance else "unknown"
        metrics.CHANGES_DETECTED.labels(change_type="any", significance=level).inc(
            outcome.changes_created
        )


async def _paused(c: Container, org_id: UUID | None) -> str | None:
    """Why automation must not run right now (global kill switch or tenant
    freeze), or ``None`` when it may. Paused work is skipped, not failed: the
    detection sweep and the next events pick it up after the release."""
    try:
        await c.automation.ensure_allowed(org_id)
    except (ConflictError, ServiceUnavailableError) as exc:
        return exc.code
    return None


async def detect_changes(deps: WorkerDeps, msg: DatasetMessage) -> None:
    c = deps.container
    if (reason := await _paused(c, msg.org_id)) is not None:
        _log.info("detection_skipped", org_id=str(msg.org_id), reason=reason)
        return
    with metrics.observe_duration(metrics.WORKFLOW_STEP_DURATION, step="detect"):
        outcome = await c.detection.detect(org_id=msg.org_id, dataset_id=msg.dataset_id)
    _record_detection(outcome)


_KNOWN_TOOLS = frozenset({"get_record_history", "get_dataset_overview"})


async def analyze_changes(deps: WorkerDeps, msg: InsightMessage) -> None:
    c = deps.container
    if (reason := await _paused(c, msg.org_id)) is not None:
        # Never send data to an AI provider while automation is stopped.
        await c.intelligence.mark_failed(org_id=msg.org_id, insight_id=msg.insight_id, code=reason)
        return
    with metrics.observe_duration(metrics.WORKFLOW_STEP_DURATION, step="analyze"):
        insight = await c.intelligence.analyze(org_id=msg.org_id, insight_id=msg.insight_id)
    calls = insight.usage.get("tool_calls", [])
    for call in calls if isinstance(calls, list) else []:
        if not isinstance(call, dict):
            continue
        # Tool names come from the model: bucket unknown ones so a prompt
        # injection cannot explode the metric's label cardinality.
        tool = call.get("tool") if call.get("tool") in _KNOWN_TOOLS else "other"
        decision = str(call.get("decision", "unknown"))[:32]
        metrics.AI_TOOL_CALLS.labels(tool=tool, decision=decision).inc()


async def fail_analysis(c: Container, msg: InsightMessage, code: str) -> None:
    await c.intelligence.mark_failed(org_id=msg.org_id, insight_id=msg.insight_id, code=code)


async def evaluate_alerts(deps: WorkerDeps, msg: OrgMessage) -> None:
    c = deps.container
    if (reason := await _paused(c, msg.org_id)) is not None:
        _log.info("alert_evaluation_skipped", org_id=str(msg.org_id), reason=reason)
        return
    with metrics.observe_duration(metrics.WORKFLOW_STEP_DURATION, step="evaluate_alerts"):
        await c.alerts.evaluate_changes(org_id=msg.org_id)


async def sweep_alerts(deps: WorkerDeps, msg: Empty) -> None:
    """Safety net: evaluate the changes no evaluation reached - an event that was
    lost, or whose evaluation failed for good. Evaluation is idempotent, so it
    runs whatever the orchestration mode; paused tenants wait for their release."""
    c = deps.container
    if (reason := await _paused(c, None)) is not None:
        _log.info("alert_sweep_skipped", reason=reason)
        return

    async def evaluate(org_id: UUID) -> None:
        if await _paused(c, org_id) is None:
            await c.alerts.evaluate_changes(org_id=org_id)

    await _each_tenant(c, evaluate, "alert_sweep")


async def deliver_notification(deps: WorkerDeps, msg: DeliveryMessage) -> None:
    # The notification service schedules its own retries (with backoff and a
    # dead letter at the end); this task only has to run one attempt.
    await deps.container.notifications.deliver(org_id=msg.org_id, delivery_id=msg.delivery_id)


async def generate_report(deps: WorkerDeps, msg: ReportMessage) -> None:
    await deps.container.reports.generate(org_id=msg.org_id, report_id=msg.report_id)


async def fail_report(c: Container, msg: ReportMessage, code: str) -> None:
    # The dead letter keeps the job's error code; the report says what failed.
    await c.reports.mark_failed(org_id=msg.org_id, report_id=msg.report_id)


# ------------------------------------------------------------ security mail


def _mail_disabled(deps: WorkerDeps, kind: str) -> bool:
    """An empty SMTP host means "no e-mail" (reported at start-up): account mail
    is skipped and logged, not failed - failing would dead-letter every message
    and keep DeadLettersAccumulating firing for a deliberate setting."""
    if deps.container.settings.notifications.smtp_host:
        return False
    _log.warning("account_email_skipped", kind=kind, reason="smtp_not_configured")
    return True


async def send_security_email(deps: WorkerDeps, msg: SecurityEmailMessage) -> None:
    if _mail_disabled(deps, msg.template):
        return
    sign_in = (
        SignInDetails(
            at=msg.sign_in.at,
            ip=str(msg.sign_in.ip) if msg.sign_in.ip is not None else None,
            client=msg.sign_in.client,
        )
        if msg.sign_in is not None
        else None
    )
    await deps.container.security_emails.send_notification(
        user_id=msg.user_id,
        template=msg.template,
        sign_in=sign_in,
        member_id=msg.member_id,
        org_id=msg.org_id,
    )


async def send_invitation(deps: WorkerDeps, msg: InvitationMessage) -> None:
    if _mail_disabled(deps, "invitation"):
        return
    await deps.container.security_emails.send_invitation(
        org_id=msg.org_id, invitation_id=msg.invitation_id
    )


async def send_password_reset(deps: WorkerDeps, msg: PasswordResetMessage) -> None:
    if _mail_disabled(deps, "password_reset"):
        return
    await deps.container.security_emails.send_password_reset(reset_id=msg.reset_id)


async def send_signup_link(deps: WorkerDeps, msg: SignupLinkMessage) -> None:
    if _mail_disabled(deps, "signup_link"):
        return
    await deps.container.security_emails.send_signup_link(signup_id=msg.signup_id)


async def operator_alert(deps: WorkerDeps, msg: OperatorAlertMessage) -> None:
    level = {"info": "info", "warning": "warning", "critical": "error"}[msg.severity]
    getattr(_log, level)("operator_alert", severity=msg.severity, summary=msg.summary)
    mail = deps.container.settings.notifications
    if mail.smtp_host and mail.operator_emails:
        await SmtpEmailTransport(mail).send_email(
            [str(address) for address in mail.operator_emails],
            f"[NexusFlow {msg.severity.upper()}] operator alert",
            msg.summary,
        )


# ----------------------------------------------------------------- events


async def route_event(deps: WorkerDeps, msg: EventMessage) -> None:
    """Run the consequences of a domain event, then forward it to n8n.

    Alerts on failed runs and on AI insights are always evaluated here. The
    pipeline steps themselves (detect -> alert -> analyze) run here only in
    ``internal`` orchestration mode; in ``n8n`` mode the forwarded event lets
    the n8n workflows drive them through the internal automation API.
    """
    c = deps.container
    org_id = msg.org_id
    internal = _internal_orchestration(c)
    if org_id is not None:
        workflow_run_id = _uuid(msg.value("workflow_run_id"))
        if internal and msg.event is EventType.COLLECTION_COMPLETED and workflow_run_id:
            # Bookkeeping only (closes the workflow run) - allowed even when paused.
            advanced = await c.automation.workflow_run_status(
                INTERNAL_SERVICE, org_id=org_id, workflow_run_id=workflow_run_id
            )
            if advanced.get("completed_now"):
                metrics.WORKFLOW_RUNS.labels(status=advanced["status"]).inc()
        if (reason := await _paused(c, org_id)) is not None:
            _log.info(
                "event_skipped", domain_event=msg.event.value, org_id=str(org_id), reason=reason
            )
        else:
            await _event_consequences(c, msg, org_id, internal=internal)
    if c.n8n is not None:
        await deps.send(FORWARD_TASK, kwargs=msg.payload(), queue=INTEGRATIONS)


async def _event_consequences(
    c: Container, msg: EventMessage, org_id: UUID, *, internal: bool
) -> None:
    match msg.event:
        case EventType.COLLECTION_COMPLETED:
            run_id = _uuid(msg.value("run_id"))
            dataset_id = _uuid(msg.value("dataset_id"))
            status = msg.value("status")
            if status == "failed" and run_id is not None:
                await c.alerts.evaluate_failed_run(org_id=org_id, run_id=run_id)
            if internal and status == "succeeded" and dataset_id is not None:
                _record_detection(await c.detection.detect(org_id=org_id, dataset_id=dataset_id))
        case EventType.CHANGES_DETECTED if internal:
            await c.alerts.evaluate_changes(org_id=org_id)
            dataset_id = _uuid(msg.value("dataset_id"))
            if msg.value("analyze") is True and dataset_id is not None:
                await c.intelligence.request_automatic(org_id=org_id, dataset_id=dataset_id)
        case EventType.INSIGHT_CREATED:
            insight_id = _uuid(msg.value("insight_id"))
            if insight_id is not None:
                await c.alerts.evaluate_insight(org_id=org_id, insight_id=insight_id)
        case _:
            pass


async def forward_event(deps: WorkerDeps, msg: EventMessage) -> None:
    n8n = deps.container.n8n
    if n8n is not None:
        await n8n.emit(msg.event.value, msg.payload())


# ------------------------------------------------------------- scheduling


async def dispatch_due_workflows(deps: WorkerDeps, msg: Empty) -> None:
    c = deps.container
    if not _internal_orchestration(c):
        return
    if (reason := await _paused(c, None)) is not None:
        _log.info("dispatch_skipped", reason=reason)
        return
    await c.automation.dispatch_due(INTERNAL_SERVICE, limit=200)


async def sweep_detection(deps: WorkerDeps, msg: Empty) -> None:
    c = deps.container
    if not _internal_orchestration(c):
        return
    if (reason := await _paused(c, None)) is not None:
        _log.info("sweep_skipped", reason=reason)
        return
    await c.automation.sweep_detection(INTERNAL_SERVICE, limit=500)


# ------------------------------------------------------------ maintenance


async def relay_outbox(deps: WorkerDeps, msg: Empty) -> None:
    await deps.relay.run_once()


async def purge_organizations(deps: WorkerDeps, msg: OptionalOrgMessage) -> None:
    def failed(org_id: UUID, exc: Exception) -> None:  # retried by the next run
        _log.error("organization_purge_failed", org_id=str(org_id), error=type(exc).__name__)

    purged = await deps.container.maintenance.purge_due_organizations(on_error=failed)
    if purged:
        _log.info("organizations_purged", count=len(purged))


async def purge_dataset(deps: WorkerDeps, msg: DatasetMessage) -> None:
    await deps.container.maintenance.purge_dataset(msg.org_id, msg.dataset_id)


async def delete_files(deps: WorkerDeps, msg: FilesMessage) -> None:
    await deps.container.maintenance.delete_files(msg.org_id, msg.keys)


async def seal_dataset(deps: WorkerDeps, msg: DatasetMessage) -> None:
    remaining = await deps.container.maintenance.seal_sensitive(msg.org_id, msg.dataset_id)
    if remaining:
        # Rows in use were skipped: retried with backoff (then dead-lettered,
        # retryable from the API) until every stored value is sealed.
        raise TransientError(code="sealing_incomplete", internal_detail=f"{remaining} rows")


async def _each_tenant(c: Container, work: Callable[[UUID], Awaitable[Any]], task: str) -> None:
    """Per-tenant maintenance: one tenant's failure must not starve the others."""
    for org_id in await c.maintenance.tenants():
        try:
            await work(org_id)
        except Exception as exc:  # noqa: BLE001 - logged, retried on the next schedule
            _log.error(
                "maintenance_failed", task=task, org_id=str(org_id), error=type(exc).__name__
            )


async def apply_retention(deps: WorkerDeps, msg: Empty) -> None:
    await _each_tenant(deps.container, deps.container.maintenance.apply_retention, "retention")
    purged = await deps.container.maintenance.apply_platform_retention()
    scratch = await deps.container.maintenance.purge_scratch()
    identity = await deps.container.maintenance.apply_identity_retention()
    if purged or scratch or identity:
        _log.info("platform_retention", dead_letters=purged, scratch_files=scratch, **identity)


async def reap_stuck_work(deps: WorkerDeps, msg: Empty) -> None:
    await _each_tenant(deps.container, deps.container.maintenance.reap, "reap")


async def expire_reports(deps: WorkerDeps, msg: Empty) -> None:
    reports = deps.container.reports

    async def expire(org_id: UUID) -> None:
        await reports.expire(org_id=org_id)

    await _each_tenant(deps.container, expire, "expire_reports")


async def cleanup_outbox(deps: WorkerDeps, msg: Empty) -> None:
    await deps.container.maintenance.cleanup_outbox()


async def rewrap_keys(deps: WorkerDeps, msg: Empty) -> None:
    c = deps.container
    active = c.settings.security.encryption_active_key_id

    async def rewrap(org_id: UUID) -> None:
        count = await c.integrations.rewrap(org_id, active_key_id=active)
        count += await c.webhooks.rewrap(org_id, active_key_id=active)
        count += await c.sso.rewrap(org_id, active_key_id=active)
        count += await c.maintenance.rewrap_sealed(org_id, active_key_id=active)
        if count:
            _log.info("secrets_rewrapped", org_id=str(org_id), count=count, key_id=active)

    await _each_tenant(c, rewrap, "rewrap_keys")


async def verify_audit_chains(deps: WorkerDeps, msg: Empty) -> None:
    """Daily tamper check: recompute every tenant chain and the platform chain.

    Hash chains only protect the audit trail if something checks them; a break
    is logged, counted (``AuditChainBroken`` alert) and pages the operators.
    """
    c = deps.container
    broken: list[str] = []

    def record(chain: str, verification: ChainVerification) -> None:
        metrics.AUDIT_CHAIN_VERIFICATIONS.labels(result="ok" if verification.ok else "broken").inc()
        if not verification.ok:
            broken.append(chain)
            _log.error(
                "audit_chain_broken",
                chain=chain,
                first_invalid_seq=verification.first_invalid_seq,
                reason=verification.reason,
            )

    async def verify(org_id: UUID) -> None:
        verification = await c.audit_log.verify_integrity(Principal.system(org_id), complete=True)
        record(str(org_id), verification)

    await _each_tenant(c, verify, "audit_verify")
    record("platform", await c.audit_log.verify_platform_chain())
    if broken:
        await c.automation.page_operators(
            severity="critical",
            summary=(
                f"Audit hash chain verification failed for {len(broken)} chain(s): "
                f"{', '.join(broken[:5])}. Follow INCIDENT_RESPONSE.md (audit tampering)."
            ),
        )


async def anchor_audit_chains(deps: WorkerDeps, msg: Empty) -> None:
    c = deps.container

    async def anchor(org_id: UUID) -> None:
        point = await c.audit_log.anchor(org_id)
        if point is not None:
            _log.info("audit_anchor", chain=str(org_id), seq=point[0], hash=point[1])

    await _each_tenant(c, anchor, "audit_anchor")
    platform = await c.audit_log.anchor(None)
    if platform is not None:
        _log.info("audit_anchor", chain="platform", seq=platform[0], hash=platform[1])

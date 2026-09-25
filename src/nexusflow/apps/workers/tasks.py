"""Celery task registration: message validation, retries, dead letters, metrics.

Failure policy (per task):

* invalid message -> rejected (logged, counted); never retried;
* ``NotFoundError`` / ``ConflictError`` -> the work is moot (entity deleted,
  state moved on); acknowledged quietly;
* ``TransientError`` and unexpected exceptions -> retried with capped
  exponential backoff and jitter, then given up;
* other domain errors -> given up immediately.

Giving up runs the task's compensation (e.g. fail the collection run) and
records a dead letter - retryable from the API when the task maps to an
outbox job - unless the task is periodic (it simply runs again on schedule).
Dead-letter error text is the client-safe message only: exception strings can
contain SQL or tenant data and never leave the logs.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import structlog
from celery import Celery, Task
from pydantic import ValidationError

from nexusflow.apps.workers import handlers as h
from nexusflow.apps.workers import messages as m
from nexusflow.apps.workers.runtime import ProcessRuntime
from nexusflow.bootstrap.container import Container
from nexusflow.core.correlation import CORRELATION_KWARG, correlation, valid_correlation_id
from nexusflow.core.errors import ConflictError, NexusFlowError, NotFoundError, TransientError
from nexusflow.core.resilience import backoff_delay
from nexusflow.domain.shared.outbox import TaskName
from nexusflow.infrastructure.observability.logging import get_logger
from nexusflow.infrastructure.observability.metrics import DEAD_LETTERS, TASK_DURATION, TASKS

_log = get_logger("nexusflow.worker")


@dataclass(frozen=True, slots=True)
class TaskSpec[M: m.Message]:
    name: str
    model: type[M]
    handler: Callable[[h.WorkerDeps, M], Awaitable[None]]
    dead_letter_as: TaskName | None = None  # makes the dead letter retryable via the API
    retries: int = 5
    base_delay: float = 15.0
    max_delay: float = 900.0
    reference: tuple[str, str] | None = None  # (reference_type, message field)
    on_give_up: Callable[[Container, M, str], Awaitable[None]] | None = None
    periodic: bool = False
    emit_failure_event: bool = True


_RUN = ("collection_run", "run_id")

PLATFORM_TASKS: tuple[TaskSpec[Any], ...] = (
    TaskSpec(
        "nexusflow.collect.dispatch",
        m.RunMessage,
        h.collect_dispatch,
        TaskName.COLLECT_SOURCE,
        reference=_RUN,
        on_give_up=h.fail_collection,
    ),
    TaskSpec(
        "nexusflow.collect.rest_api",
        m.RunMessage,
        h.collect_rest_api,
        TaskName.COLLECT_SOURCE,
        reference=_RUN,
        on_give_up=h.fail_collection,
    ),
    TaskSpec(
        "nexusflow.detection.detect",
        m.DatasetMessage,
        h.detect_changes,
        TaskName.DETECT_CHANGES,
        reference=("dataset", "dataset_id"),
    ),
    TaskSpec(
        "nexusflow.intelligence.analyze",
        m.InsightMessage,
        h.analyze_changes,
        TaskName.ANALYZE_CHANGES,
        retries=3,
        reference=("insight", "insight_id"),
        on_give_up=h.fail_analysis,
    ),
    TaskSpec(
        "nexusflow.alerts.evaluate", m.OrgMessage, h.evaluate_alerts, TaskName.EVALUATE_ALERTS
    ),
    TaskSpec(
        "nexusflow.notifications.deliver",
        m.DeliveryMessage,
        h.deliver_notification,
        TaskName.DELIVER_NOTIFICATION,
        retries=3,
        reference=("notification_delivery", "delivery_id"),
    ),
    TaskSpec(
        "nexusflow.reports.generate",
        m.ReportMessage,
        h.generate_report,
        TaskName.GENERATE_REPORT,
        retries=2,
        reference=("report", "report_id"),
    ),
    TaskSpec("nexusflow.security.notify", m.SecurityEmailMessage, h.send_security_email),
    TaskSpec("nexusflow.security.invitation", m.InvitationMessage, h.send_invitation),
    TaskSpec(
        "nexusflow.security.password_reset",
        m.PasswordResetMessage,
        h.send_password_reset,
        retries=3,
    ),
    # The next three never emit job.failed when they give up: each one is (or
    # feeds) the path that *handles* job.failed events - operator paging, event
    # routing and forwarding to n8n - so a persistent failure (SMTP rejecting
    # mail, n8n unreachable) would otherwise re-trigger itself forever.
    TaskSpec(
        "nexusflow.operators.alert",
        m.OperatorAlertMessage,
        h.operator_alert,
        emit_failure_event=False,
    ),
    TaskSpec("nexusflow.events.route", m.EventMessage, h.route_event, emit_failure_event=False),
    TaskSpec(h.FORWARD_TASK, m.EventMessage, h.forward_event, emit_failure_event=False),
    TaskSpec(
        "nexusflow.maintenance.purge_organizations", m.OptionalOrgMessage, h.purge_organizations
    ),
    TaskSpec("nexusflow.maintenance.purge_dataset", m.DatasetMessage, h.purge_dataset),
    TaskSpec("nexusflow.maintenance.delete_files", m.FilesMessage, h.delete_files),
    TaskSpec(
        "nexusflow.maintenance.seal_dataset",
        m.DatasetMessage,
        h.seal_dataset,
        TaskName.SEAL_DATASET,
        reference=("dataset", "dataset_id"),
    ),
    TaskSpec(
        "nexusflow.automation.dispatch", m.Empty, h.dispatch_due_workflows, retries=0, periodic=True
    ),
    TaskSpec("nexusflow.automation.sweep", m.Empty, h.sweep_detection, retries=0, periodic=True),
    TaskSpec("nexusflow.outbox.relay", m.Empty, h.relay_outbox, retries=0, periodic=True),
    TaskSpec(
        "nexusflow.maintenance.retention", m.Empty, h.apply_retention, retries=0, periodic=True
    ),
    TaskSpec("nexusflow.maintenance.reap", m.Empty, h.reap_stuck_work, retries=0, periodic=True),
    TaskSpec(
        "nexusflow.maintenance.expire_reports", m.Empty, h.expire_reports, retries=0, periodic=True
    ),
    TaskSpec(
        "nexusflow.maintenance.outbox_cleanup", m.Empty, h.cleanup_outbox, retries=0, periodic=True
    ),
    TaskSpec("nexusflow.maintenance.rewrap_keys", m.Empty, h.rewrap_keys, retries=0, periodic=True),
    TaskSpec("nexusflow.audit.anchor", m.Empty, h.anchor_audit_chains, retries=0, periodic=True),
    TaskSpec("nexusflow.audit.verify", m.Empty, h.verify_audit_chains, retries=0, periodic=True),
)


def _code(exc: BaseException) -> str:
    return exc.code if isinstance(exc, NexusFlowError) else "unexpected_error"


def _safe_message(exc: BaseException) -> str:
    return exc.message if isinstance(exc, NexusFlowError) else type(exc).__name__


async def _give_up[M: m.Message](
    deps: h.WorkerDeps, spec: TaskSpec[M], message: M, exc: BaseException, attempts: int
) -> None:
    c = deps.container
    code = _code(exc)
    if spec.on_give_up is not None:
        try:
            await spec.on_give_up(c, message, code)
        except Exception as compensation_error:  # noqa: BLE001 - still record the dead letter
            _log.error(
                "compensation_failed", task=spec.name, error=type(compensation_error).__name__
            )
    if spec.periodic:
        return
    reference_type, field_name = spec.reference or (None, None)
    reference = getattr(message, field_name, None) if field_name else None
    await c.dead_letters.record(
        org_id=getattr(message, "org_id", None),
        origin="celery",
        task_name=(spec.dead_letter_as or spec.name),
        payload=message.model_dump(mode="json"),
        error_code=code,
        error_message=_safe_message(exc),
        attempts=attempts,
        reference_type=reference_type,
        reference_id=str(reference) if reference is not None else None,
        emit_event=spec.emit_failure_event,
    )
    DEAD_LETTERS.labels(task=spec.name).inc()


def _execute[M: m.Message](
    task: Task[Any, Any],
    runtime: ProcessRuntime[h.WorkerDeps],
    spec: TaskSpec[M],
    kwargs: dict[str, Any],
) -> None:
    kwargs = dict(kwargs)
    # The request that caused this job - or, for a scheduled job, the job itself.
    incoming = valid_correlation_id(kwargs.pop(CORRELATION_KWARG, None))
    org_id = kwargs.get("org_id")
    # Every log line of this task carries its name, id, tenant and correlation, and
    # every message it emits carries the correlation on.
    with (
        correlation(incoming or task.request.id) as correlation_id,
        structlog.contextvars.bound_contextvars(
            task=spec.name,
            task_id=task.request.id,
            org_id=str(org_id) if org_id else None,
            request_id=correlation_id,
        ),
    ):
        _execute_in_context(task, runtime, spec, kwargs)


def _execute_in_context[M: m.Message](
    task: Task[Any, Any],
    runtime: ProcessRuntime[h.WorkerDeps],
    spec: TaskSpec[M],
    kwargs: dict[str, Any],
) -> None:
    started = time.monotonic()
    result = "success"
    try:
        try:
            message = spec.model.model_validate(kwargs)
        except ValidationError as exc:
            result = "rejected"
            _log.error("task_message_rejected", errors=exc.error_count())
            return
        try:
            runtime.run(lambda deps: spec.handler(deps, message))
        except (NotFoundError, ConflictError) as exc:
            result = "moot"
            _log.info("task_moot", error_code=exc.code)
        except NexusFlowError as exc:
            if isinstance(exc, TransientError) and task.request.retries < spec.retries:
                result = "retry"
                raise task.retry(exc=exc, countdown=_delay(task, spec)) from exc
            result = "failed"
            _log.warning("task_failed", error_code=exc.code, detail=exc.internal_detail)
            _fail(runtime, spec, message, exc, task.request.retries + 1)
        except Exception as exc:  # unexpected: retry, then dead-letter
            if task.request.retries < spec.retries:
                result = "retry"
                _log.warning("task_error_retrying", error=type(exc).__name__)
                raise task.retry(exc=exc, countdown=_delay(task, spec)) from exc
            result = "failed"
            _log.error("task_error", error=type(exc).__name__, exc_info=exc)
            _fail(runtime, spec, message, exc, task.request.retries + 1)
    finally:
        elapsed = time.monotonic() - started
        TASKS.labels(task=spec.name, result=result).inc()
        TASK_DURATION.labels(task=spec.name).observe(elapsed)
        _log.info(
            "task_finished",
            status=result,
            duration_ms=round(elapsed * 1000, 1),
            attempt=task.request.retries + 1,
        )


def _fail[M: m.Message](
    runtime: ProcessRuntime[h.WorkerDeps],
    spec: TaskSpec[M],
    message: M,
    exc: BaseException,
    attempts: int,
) -> None:
    runtime.run(lambda deps: _give_up(deps, spec, message, exc, attempts))


def _delay(task: Task[Any, Any], spec: TaskSpec[Any]) -> float:
    return backoff_delay(
        task.request.retries + 1, base_seconds=spec.base_delay, cap_seconds=spec.max_delay
    )


def register_tasks(
    app: Celery, runtime: ProcessRuntime[h.WorkerDeps], specs: tuple[TaskSpec[Any], ...]
) -> None:
    for spec in specs:
        _register(app, runtime, spec)


def _register(app: Celery, runtime: ProcessRuntime[h.WorkerDeps], spec: TaskSpec[Any]) -> None:
    def run(self: Task[Any, Any], /, **kwargs: Any) -> None:
        _execute(self, runtime, spec, kwargs)

    run.__name__ = spec.name.rsplit(".", 1)[-1]
    app.task(name=spec.name, bind=True, max_retries=spec.retries, ignore_result=True)(run)

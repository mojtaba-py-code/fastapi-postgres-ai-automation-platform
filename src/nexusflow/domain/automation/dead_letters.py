"""Dead-letter store: failed jobs that exhausted their retries."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import ConflictError, InvalidInputError, NotFoundError
from nexusflow.core.ids import uuid7
from nexusflow.core.jsonutil import JSONObject
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.core.text import single_line
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder, sanitize_metadata
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.automation.events import EventType, event_message
from nexusflow.domain.automation.model import DeadLetter, DeadLetterStatus
from nexusflow.domain.intelligence.redaction import redact_text
from nexusflow.domain.reports.model import ReportStatus
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.sources.model import CollectionRun, RunStatus, RunTrigger
from nexusflow.domain.uploads.model import UploadStatus

# Jobs that may be re-driven from the dead-letter store. All of them are
# idempotent (state machines + unique constraints), so a retry cannot duplicate
# business effects - which is also why a retry first hands the job's entity back
# from the terminal state its failure left it in (see ``_reopen``).
RETRYABLE_TASKS = frozenset(
    {
        TaskName.COLLECT_SOURCE,
        TaskName.PROCESS_UPLOAD,
        TaskName.DETECT_CHANGES,
        TaskName.ANALYZE_CHANGES,
        TaskName.EVALUATE_ALERTS,
        TaskName.DELIVER_NOTIFICATION,
        TaskName.GENERATE_REPORT,
        TaskName.SEAL_DATASET,
    }
)

_URL_USERINFO = re.compile(r"(?i)\b(https?://)[^\s/@]+@")
_URL_QUERY = re.compile(r"(?i)\b(https?://[^\s?#]+)\?[^\s#]+")


def scrub_error_message(message: str | None) -> str | None:
    """Error text from workers and n8n is shown to tenant admins: strip
    credentials, URL userinfo/query strings and personal data first."""
    if not message:
        return None
    text = single_line(message, 500)
    text = _URL_USERINFO.sub(r"\1[REDACTED]@", text)
    text = _URL_QUERY.sub(r"\1?[REDACTED]", text)
    return redact_text(text)[0]


async def stage_dead_letter(
    uow: UnitOfWork, letter: DeadLetter, *, now: datetime, emit_event: bool = True
) -> None:
    """Add ``letter`` to the caller's transaction together with its ``job.failed``
    event, so every dead letter - whoever writes it - reaches the
    failure-recovery workflow. n8n reports its own failures, and event
    forwarding failures suppress the event (an unreachable n8n would loop)."""
    await uow.data.dead_letters.add(letter)
    if emit_event and letter.origin != "n8n":
        await uow.outbox.add(
            event_message(
                EventType.JOB_FAILED,
                org_id=letter.org_id,
                payload={
                    "dead_letter_id": str(letter.id),
                    "task": letter.task_name,
                    "error_code": letter.error_code,
                },
                now=now,
            )
        )


class DeadLetterService:
    def __init__(
        self, *, uow_factory: UnitOfWorkFactory, clock: Clock, audit: AuditRecorder
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit

    async def record(
        self,
        *,
        org_id: UUID | None,
        origin: str,
        task_name: str,
        payload: dict[str, Any],
        error_code: str,
        error_message: str | None,
        attempts: int,
        reference_type: str | None = None,
        reference_id: str | None = None,
        emit_event: bool = True,
    ) -> DeadLetter:
        """Persist a failed job; unless suppressed, a ``job.failed`` event lets
        the failure-recovery workflow react. Suppress it for failures of event
        forwarding itself - otherwise an unreachable n8n would loop forever."""
        now = self._clock.now()
        letter = DeadLetter(
            id=uuid7(),
            org_id=org_id,
            origin=origin,
            task_name=single_line(task_name, 100),
            reference_type=reference_type,
            reference_id=reference_id,
            payload=sanitize_metadata(payload),
            error_code=single_line(error_code, 64),
            error_message=scrub_error_message(error_message),
            attempts=attempts,
            first_failed_at=now,
            last_failed_at=now,
        )
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            await stage_dead_letter(uow, letter, now=now, emit_event=emit_event)
            await uow.commit()
        return letter

    async def list(
        self, principal: Principal, page: PageRequest, *, status: DeadLetterStatus | None
    ) -> Page[DeadLetter]:
        principal.require(Permission.DEAD_LETTERS_MANAGE)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.dead_letters.list_page(
                principal.require_org(), page, {"status": status}
            )

    async def retry(self, principal: Principal, letter_id: UUID, meta: RequestMeta) -> DeadLetter:
        principal.require(Permission.DEAD_LETTERS_MANAGE)
        return await self._resolve(principal, letter_id, retry=True, meta=meta)

    async def discard(self, principal: Principal, letter_id: UUID, meta: RequestMeta) -> DeadLetter:
        principal.require(Permission.DEAD_LETTERS_MANAGE)
        return await self._resolve(principal, letter_id, retry=False, meta=meta)

    async def _resolve(
        self, principal: Principal, letter_id: UUID, *, retry: bool, meta: RequestMeta
    ) -> DeadLetter:
        org_id = principal.require_org()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            letter = await uow.data.dead_letters.get_for_update(org_id, letter_id)
            if letter is None:
                raise NotFoundError()
            if letter.status is not DeadLetterStatus.OPEN:
                raise ConflictError(
                    "The dead letter was already handled.", code="dead_letter_closed"
                )
            if retry:
                if letter.task_name not in RETRYABLE_TASKS:
                    raise InvalidInputError(
                        "This job type cannot be retried.", code="not_retryable"
                    )
                await _reopen(uow, org_id, letter)
                payload: JSONObject = {
                    k: v for k, v in letter.payload.items() if isinstance(v, str)
                }
                payload["org_id"] = str(org_id)
                await uow.outbox.add(
                    new_message(TaskName(letter.task_name), payload, org_id=org_id, now=now)
                )
                letter.status = DeadLetterStatus.RETRIED
            else:
                letter.status = DeadLetterStatus.DISCARDED
            letter.resolved_at = now
            letter.resolved_by = principal.actor_user_id
            await self._audit.record(
                uow.audit,
                action=AuditAction.DEAD_LETTER_RETRIED
                if retry
                else AuditAction.DEAD_LETTER_DISCARDED,
                principal=principal,
                meta=meta,
                resource_type="dead_letter",
                resource_id=letter.id,
                metadata={"task": letter.task_name},
            )
            await uow.commit()
            return letter


def _entity_id(letter: DeadLetter, field_name: str) -> UUID | None:
    """The id the retried job will act on (from the job's own payload)."""
    try:
        return UUID(str(letter.payload[field_name]))
    except (KeyError, ValueError):
        return None


async def _reopen(uow: UnitOfWork, org_id: UUID, letter: DeadLetter) -> None:
    """Hand the job's entity back from the terminal state its failure left it in.

    Every handler skips finished work - that is what makes redeliveries safe - so
    re-enqueueing the job alone would do nothing for a failed run or analysis, a
    dead delivery or a failed report. Entities in any other state are left as
    they are (the job then does whatever is still to do, possibly nothing);
    detection and alert evaluation resume from pending data by themselves.
    """
    task = TaskName(letter.task_name)
    if task in (TaskName.COLLECT_SOURCE, TaskName.PROCESS_UPLOAD):
        run_id = _entity_id(letter, "run_id")
        run = await uow.data.runs.get_for_update(org_id, run_id) if run_id else None
        if run is not None and run.status is RunStatus.FAILED:
            await _reopen_upload(uow, run)
            run.reopen()
    elif task is TaskName.ANALYZE_CHANGES:
        insight_id = _entity_id(letter, "insight_id")
        insight = await uow.data.insights.get_for_update(org_id, insight_id) if insight_id else None
        if insight is not None:
            insight.reopen()
    elif task is TaskName.DELIVER_NOTIFICATION:
        delivery_id = _entity_id(letter, "delivery_id")
        delivery = (
            await uow.data.deliveries.get_for_update(org_id, delivery_id) if delivery_id else None
        )
        if delivery is not None:
            delivery.reopen()
    elif task is TaskName.GENERATE_REPORT:
        report_id = _entity_id(letter, "report_id")
        report = await uow.data.reports.get_for_update(org_id, report_id) if report_id else None
        if report is not None and report.status is ReportStatus.FAILED:
            report.status, report.error_code, report.completed_at = ReportStatus.PENDING, None, None


async def _reopen_upload(uow: UnitOfWork, run: CollectionRun) -> None:
    """An upload run needs its file back: the failure released the upload."""
    if run.trigger is not RunTrigger.UPLOAD:
        return
    upload = await uow.data.uploads.get_by_run(run.org_id, run.id)
    if upload is None or upload.status is not UploadStatus.FAILED:
        return
    live = await uow.data.uploads.find_by_hash(run.org_id, upload.source_id, upload.sha256)
    if live is not None:
        # The same file was uploaded again meanwhile: that upload is the one to process.
        raise ConflictError(
            "The file was uploaded again since; its newer upload is processed instead.",
            code="upload_superseded",
        )
    upload.reopen()

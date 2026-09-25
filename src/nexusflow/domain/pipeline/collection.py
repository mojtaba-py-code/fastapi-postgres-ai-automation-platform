"""Collection-run orchestration: where each run executes, and the sandbox trust boundary.

Untrusted content (web pages, uploaded files) is only fetched and parsed in the
*sandbox* worker pool, which has internet egress but no database, no storage
mount and no application secrets. For every run it processes, the sandbox
receives a *ticket*: ``HMAC(pepper, org_id:run_id:attempt)``. The ticket is the
only credential it holds; it is required to download the run's input file and
to submit the run's results through the internal gateway. Consequently:

* a compromised sandbox can only read or influence the runs it was handed -
  never other tenants' files or runs;
* a retried run (new ``attempt``) invalidates every earlier ticket, so late or
  replayed results are rejected;
* sandbox output is untrusted input: it is structurally bounded here and then
  validated against the dataset schema by the ingestion pipeline.

Every transition is idempotent (``QUEUED -> RUNNING`` has exactly one winner),
because brokers redeliver and the reaper re-queues runs of crashed workers.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import (
    AuthenticationError,
    ConflictError,
    InvalidInputError,
    PermanentError,
)
from nexusflow.core.jsonutil import JSONObject, JSONValue
from nexusflow.core.text import single_line
from nexusflow.domain.organizations.model import Organization
from nexusflow.domain.pipeline.ingestion import IngestionService
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.security import TokenHasher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.sources.model import (
    CollectionRun,
    FileUploadConfig,
    RestApiConfig,
    RunStatus,
    Source,
    SourceKind,
    WebsiteConfig,
)
from nexusflow.domain.uploads.model import UploadStatus

MAX_ITEM_FIELDS = 200
MAX_VALUE_CHARS = 10_000
_DETAIL_KEYS: dict[str, type | tuple[type, ...]] = {
    "http_status": int,
    "bytes": int,
    "host": str,
    "pages": int,
    "rows": int,
}


class CollectionAction(StrEnum):
    SKIP = "skip"
    INGEST_STAGED = "ingest_staged"
    SANDBOX_WEBSITE = "sandbox_website"
    SANDBOX_UPLOAD = "sandbox_upload"
    REST_API = "rest_api"


@dataclass(frozen=True, slots=True)
class CollectionPlan:
    action: CollectionAction
    org_id: UUID
    run_id: UUID
    ticket: str | None = None
    config: JSONObject | None = None
    allowed_domains: list[str] | None = None
    max_items: int = 0
    limits: dict[str, int] = field(default_factory=dict)
    source_kind: str | None = None


@dataclass(frozen=True, slots=True)
class RestApiJob:
    config: RestApiConfig
    integration_id: UUID | None
    allowed_domains: list[str] | None
    max_items: int


@dataclass(frozen=True, slots=True)
class SandboxInput:
    storage_key: str
    format: Literal["csv", "xlsx"]
    size_bytes: int


def _frozen(organization: Organization) -> bool:
    return not organization.is_active or organization.policy.automation_frozen


def _bounded_items(raw: Any, *, max_items: int) -> list[JSONValue]:
    if not isinstance(raw, list):
        raise InvalidInputError("items must be a list.", code="invalid_result")
    if len(raw) > max_items:
        raise InvalidInputError("Too many items.", code="invalid_result")
    items: list[JSONValue] = []
    for item in raw:
        if not isinstance(item, dict) or len(item) > MAX_ITEM_FIELDS:
            raise InvalidInputError("Items must be flat objects.", code="invalid_result")
        clean: dict[str, JSONValue] = {}
        for key, value in item.items():
            if not isinstance(key, str) or len(key) > 64:
                raise InvalidInputError("Invalid item field name.", code="invalid_result")
            if value is not None and not isinstance(value, (str, bool, int, float)):
                raise InvalidInputError("Item values must be scalars.", code="invalid_result")
            clean[key] = value[:MAX_VALUE_CHARS] if isinstance(value, str) else value
        items.append(clean)
    return items


def _bounded_detail(raw: dict[str, Any] | None) -> dict[str, Any]:
    detail: dict[str, Any] = {}
    for key, expected in _DETAIL_KEYS.items():
        value = (raw or {}).get(key)
        if isinstance(value, expected) and not isinstance(value, bool):
            detail[key] = single_line(value, 253) if isinstance(value, str) else value
    return detail


class CollectionService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        ingestion: IngestionService,
        ticket_hasher: TokenHasher,
        max_items_per_run: int,
        max_upload_rows: int,
        max_upload_columns: int,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._ingestion = ingestion
        self._hasher = ticket_hasher
        self._max_items = max_items_per_run
        self._max_rows = max_upload_rows
        self._max_columns = max_upload_columns

    # ---------------------------------------------------------------- tickets

    def ticket_for(self, run: CollectionRun) -> str:
        return self._hasher.hash(f"sandbox-ticket:v1:{run.org_id}:{run.id}:{run.attempt}")

    def _check_ticket(self, run: CollectionRun | None, ticket: str) -> CollectionRun:
        if run is None or not hmac.compare_digest(self.ticket_for(run), ticket):
            raise AuthenticationError("Invalid sandbox ticket.", code="invalid_ticket")
        if run.status is not RunStatus.RUNNING:
            raise ConflictError("The run is no longer accepting results.", code="run_closed")
        return run

    # --------------------------------------------------------------- dispatch

    async def plan(self, *, org_id: UUID, run_id: UUID) -> CollectionPlan:
        """Decide how a queued run executes (pipeline worker)."""
        now = self._clock.now()
        skip = CollectionPlan(CollectionAction.SKIP, org_id, run_id)
        cancel_code: str | None = None
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            run = await uow.data.runs.get_for_update(org_id, run_id)
            if run is None or run.is_terminal:
                return skip
            source = await uow.data.sources.get(org_id, run.source_id)
            organization = await uow.organizations.get(org_id)
            if source is None:
                cancel_code = "source_deleted"
            elif organization is None or _frozen(organization):
                cancel_code = "automation_frozen"
            elif not source.is_runnable:
                cancel_code = f"source_{source.status.value}"
            elif (
                await uow.data.payloads.exists(org_id, run.id) or source.kind is SourceKind.WEBHOOK
            ):
                return CollectionPlan(
                    CollectionAction.INGEST_STAGED, org_id, run_id, source_kind=source.kind.value
                )
            elif source.kind is SourceKind.REST_API:
                return CollectionPlan(CollectionAction.REST_API, org_id, run_id)
            else:
                return await self._plan_sandbox(uow, run, source, organization, now)
        await self._ingestion.cancel_run(org_id=org_id, run_id=run_id, code=cancel_code)
        return skip

    async def _plan_sandbox(
        self,
        uow: UnitOfWork,
        run: CollectionRun,
        source: Source,
        organization: Organization,
        now: datetime,
    ) -> CollectionPlan:
        if not run.start(now):
            # Already RUNNING: a duplicate delivery. The owner (or the reaper) finishes it.
            return CollectionPlan(CollectionAction.SKIP, run.org_id, run.id)
        config = source.parsed_config
        if isinstance(config, FileUploadConfig):
            upload = await uow.data.uploads.get_by_run(run.org_id, run.id)
            if upload is not None and upload.status is UploadStatus.PROCESSING:
                # A new attempt (new ticket) gets a new single-use download.
                upload.status = UploadStatus.ACCEPTED
        await uow.commit()
        if isinstance(config, WebsiteConfig):
            return CollectionPlan(
                CollectionAction.SANDBOX_WEBSITE,
                run.org_id,
                run.id,
                ticket=self.ticket_for(run),
                config=config.model_dump(mode="json"),
                allowed_domains=organization.policy.allowed_source_domains,
                max_items=min(config.max_items, self._max_items),
            )
        if isinstance(config, FileUploadConfig):
            return CollectionPlan(
                CollectionAction.SANDBOX_UPLOAD,
                run.org_id,
                run.id,
                ticket=self.ticket_for(run),
                config=config.model_dump(mode="json"),
                max_items=self._max_rows,
                limits={"max_rows": self._max_rows, "max_columns": self._max_columns},
            )
        raise PermanentError(code="unsupported_source", internal_detail=source.kind.value)

    async def release(self, *, org_id: UUID, run_id: UUID) -> None:
        """Hand a started run back to the queue after a transient hand-off
        failure; the retry starts a new attempt (and invalidates old tickets)."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            run = await uow.data.runs.get_for_update(org_id, run_id)
            if run is not None and run.status is RunStatus.RUNNING:
                run.requeue()
                await uow.commit()

    # ---------------------------------------------------- integrations worker

    async def begin_rest_api(self, *, org_id: UUID, run_id: UUID) -> RestApiJob | None:
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            run = await uow.data.runs.get_for_update(org_id, run_id)
            if run is None or run.is_terminal:
                return None
            source = await uow.data.sources.get(org_id, run.source_id)
            organization = await uow.organizations.get(org_id)
            if source is None:
                code = "source_deleted"
            elif organization is None or _frozen(organization):
                code = "automation_frozen"
            elif not source.is_runnable:
                code = f"source_{source.status.value}"
            else:
                config = source.parsed_config
                if not isinstance(config, RestApiConfig):
                    raise PermanentError(code="unsupported_source")
                if not run.start(now):
                    return None  # duplicate delivery: another worker owns the run
                await uow.commit()
                return RestApiJob(
                    config=config,
                    integration_id=source.integration_id,
                    allowed_domains=organization.policy.allowed_source_domains,
                    max_items=min(config.max_items, self._max_items),
                )
        await self._ingestion.cancel_run(org_id=org_id, run_id=run_id, code=code)
        return None

    # --------------------------------------------------------- sandbox gateway

    async def authorize_result(
        self, *, org_id: UUID, run_id: UUID, ticket: str
    ) -> tuple[int, int | None]:
        """Check a result submission *before* its body is read.

        Returns ``(max_items, input_bytes)``: the item cap of this run and, for
        upload runs, the size of the uploaded file - so the gateway can bound
        the body (and the memory to parse it) by what the input can produce.
        """
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            run = self._check_ticket(await uow.data.runs.get(org_id, run_id), ticket)
            upload = await uow.data.uploads.get_by_run(org_id, run.id)
        if upload is not None:
            return self._max_rows, upload.size_bytes
        return self._max_items, None

    async def sandbox_input(self, *, org_id: UUID, run_id: UUID, ticket: str) -> SandboxInput:
        """The uploaded file behind an upload run - for the ticket holder, once.

        The download moves the upload to ``PROCESSING`` under the run's row
        lock, so a copied ticket is worthless once the worker that owns the job
        has fetched its input (a retry issues a new ticket and resets it).
        """
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            run = self._check_ticket(await uow.data.runs.get_for_update(org_id, run_id), ticket)
            upload = await uow.data.uploads.get_by_run(org_id, run.id)
            if upload is None or upload.status is not UploadStatus.ACCEPTED:
                raise ConflictError("No pending upload for this run.", code="no_input")
            upload.status = UploadStatus.PROCESSING
            await uow.commit()
            fmt: Literal["csv", "xlsx"] = "xlsx" if upload.storage_key.endswith(".xlsx") else "csv"
            return SandboxInput(
                storage_key=upload.storage_key, format=fmt, size_bytes=upload.size_bytes
            )

    async def accept_sandbox_result(
        self,
        *,
        org_id: UUID,
        run_id: UUID,
        ticket: str,
        items: Any,
        truncated: bool,
        detail: dict[str, Any] | None,
        error_code: str | None,
    ) -> None:
        """Stage verified sandbox output and queue ingestion (idempotent)."""
        now = self._clock.now()
        if error_code is not None:
            async with self._uow_factory(TenantScope.system(org_id)) as uow:
                self._check_ticket(await uow.data.runs.get(org_id, run_id), ticket)
            # Failing the run also fails its upload (see ``release_upload``).
            await self._ingestion.fail_run(
                org_id=org_id, run_id=run_id, code=single_line(error_code, 64), detail=None
            )
            return
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            run = self._check_ticket(await uow.data.runs.get_for_update(org_id, run_id), ticket)
            if await uow.data.payloads.exists(org_id, run.id):
                return  # the sandbox retried a submission that already succeeded
            upload = await uow.data.uploads.get_by_run(org_id, run.id)
            limit = self._max_rows if upload is not None else self._max_items
            staged = _bounded_items(items, max_items=limit)
            await uow.data.payloads.put(org_id, run.id, staged, now)
            run.stats = {**_bounded_detail(detail), "source_truncated": bool(truncated)}
            if upload is not None:
                upload.status = UploadStatus.PROCESSED
                upload.row_count = len(staged)
                upload.processed_at = now
            await uow.outbox.add(
                new_message(
                    TaskName.COLLECT_SOURCE,
                    {"org_id": str(org_id), "run_id": str(run.id)},
                    org_id=org_id,
                    now=now,
                )
            )
            await uow.commit()

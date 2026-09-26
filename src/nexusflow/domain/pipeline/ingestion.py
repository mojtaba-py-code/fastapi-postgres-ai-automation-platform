"""Store pipeline output: versioned upserts, snapshot deletions, run bookkeeping.

Idempotency and integrity:

* a run is processed at most once (state machine ``QUEUED -> RUNNING -> terminal``;
  duplicate task deliveries see a terminal run and return early);
* ingestion is serialized per source with a transaction-scoped advisory lock;
* records are upserted with ``SELECT ... FOR UPDATE`` + a unique
  ``(dataset_id, record_key)`` constraint;
* deletions are inferred from *full* snapshots only, and only when every item
  was valid and the snapshot was not truncated - otherwise a partial scrape
  would wrongly "delete" records;
* a snapshot that would delete more than the source's ``max_deletion_ratio``
  of the live records deletes nothing and reports ``deletions_withheld``;
* runs of one source may finish in any order: a full snapshot collected
  before the newest one already applied is not stored (``superseded``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import NotFoundError
from nexusflow.core.ids import uuid7
from nexusflow.domain.automation.events import EventType, event_message
from nexusflow.domain.catalog.model import Dataset
from nexusflow.domain.catalog.service import get_dataset
from nexusflow.domain.pipeline.stages import CleanRecord, PipelineResult, run_pipeline
from nexusflow.domain.records.model import Record, RecordVersion
from nexusflow.domain.records.sealing import seal_data
from nexusflow.domain.shared.security import SecretCipher, TokenHasher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.sources.model import (
    DEFAULT_MAX_DELETION_RATIO,
    CollectionRun,
    RunStatus,
    RunTrigger,
    Source,
)

_CHUNK = 500
_MAX_DELETIONS_PER_RUN = 10_000
_GUARD_MIN_DELETIONS = 10  # smaller deletions can never wipe a dataset


async def release_upload(
    uow: UnitOfWork, run: CollectionRun, now: datetime, *, reason: str
) -> None:
    """A run that ends without storing its uploaded file marks the upload failed,
    which frees that file for a new upload (otherwise it stays deduplicated
    against an upload that will never finish)."""
    if run.trigger is not RunTrigger.UPLOAD:
        return
    upload = await uow.data.uploads.get_by_run(run.org_id, run.id)
    if upload is not None:
        upload.fail(now, reason=reason)


@dataclass(frozen=True, slots=True)
class IngestionOutcome:
    run_id: UUID
    status: RunStatus
    stats: dict[str, Any]
    duration_seconds: float | None = None  # collection start -> run finished


def _duration(run: CollectionRun) -> float | None:
    if run.started_at is None or run.finished_at is None:
        return None
    return max(0.0, (run.finished_at - run.started_at).total_seconds())


def _collected_at(run: CollectionRun) -> datetime:
    """When the run's data was collected, as far as the platform can tell.

    Pushed data (webhook deliveries, uploaded files) is what it was on
    receipt. Pulled data is fetched once the run has started (the latest
    attempt); for a run no collector ever started, its request time is the
    best estimate.
    """
    if run.trigger in (RunTrigger.WEBHOOK, RunTrigger.UPLOAD) or run.started_at is None:
        return run.created_at
    return run.started_at


@dataclass(slots=True)
class _Counts:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    deleted: int = 0


class IngestionService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        cipher: SecretCipher,
        hasher: TokenHasher,
        max_items_per_run: int,
        max_invalid_ratio: float = 0.5,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._cipher = cipher
        self._hasher = hasher
        self._max_items = max_items_per_run
        self._max_invalid_ratio = max_invalid_ratio

    def _seal(self, dataset: Dataset, record_id: UUID, data: dict[str, Any]) -> dict[str, Any]:
        """Sensitive values are encrypted before they are stored (records.sealing)."""
        return seal_data(
            self._cipher,
            data,
            dataset.spec.sensitive_fields,
            org_id=dataset.org_id,
            dataset_id=dataset.id,
            record_id=record_id,
        )

    def _fingerprint(self, content_hash: str) -> str:
        """The stored content hash is keyed: a plain hash over all fields would let
        anyone holding a database copy confirm guesses of a sensitive value."""
        return self._hasher.hash(f"record-content:v1:{content_hash}")

    async def ingest(
        self,
        *,
        org_id: UUID,
        run_id: UUID,
        items: Sequence[Mapping[str, Any]] | None,
        truncated: bool = False,
        source_detail: dict[str, Any] | None = None,
    ) -> IngestionOutcome:
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            run = await uow.data.runs.get_for_update(org_id, run_id)
            if run is None:
                raise NotFoundError(internal_detail=f"run {run_id}")
            if run.is_terminal:
                return IngestionOutcome(run.id, run.status, run.stats)
            source = await uow.data.sources.get_for_update(org_id, run.source_id)
            if source is None:
                raise NotFoundError(internal_detail=f"source {run.source_id}")
            dataset = await get_dataset(uow, org_id, source.dataset_id)
            collected_at = _collected_at(run)  # before start() re-stamps the run
            if run.status is RunStatus.QUEUED:
                run.start(now)
            await uow.data.sources.lock(source.id)
            carried: dict[str, Any] = {}
            if items is None:
                # Staged input (webhook body or sandbox output); the stager may
                # have recorded collection details on the run.
                carried = dict(run.stats)
                staged = await uow.data.payloads.take(org_id, run.id) or []
                items = [item for item in staged if isinstance(item, dict)]
            if await self._superseded(uow, source, collected_at):
                # Runs finish in any order; a newer snapshot of this source is
                # applied already, and this one would revert its values and
                # delete what it added. Nothing of it is stored.
                carried.pop("source_truncated", None)
                return await self._skip_superseded(
                    uow,
                    run,
                    source,
                    {**carried, **(source_detail or {}), "received": len(items)},
                    collected_at,
                    now,
                )
            max_items = int(source.config.get("max_items", self._max_items))
            result = run_pipeline(dataset.spec, items, max_items=min(max_items, self._max_items))
            result.truncated = (
                result.truncated or truncated or bool(carried.pop("source_truncated", False))
            )
            stats: dict[str, Any] = {**result.stats(), **carried, **(source_detail or {})}
            if result.received and result.invalid_ratio > self._max_invalid_ratio:
                run.fail(
                    now,
                    code="validation_threshold_exceeded",
                    detail=f"{result.invalid} invalid items",
                )
                run.stats = stats
                await release_upload(uow, run, now, reason="validation_threshold_exceeded")
                source.record_failure(now)
                await self._emit(uow, run, source, now)
                await uow.commit()
                return IngestionOutcome(run.id, run.status, stats, _duration(run))
            counts = await self._store(uow, dataset, source, run, result.records, now)
            if self._can_infer_deletions(source, result):
                counts.deleted, withheld = await self._mark_deleted(
                    uow, dataset, source, run, counts, now
                )
                if withheld:
                    stats["deletions_withheld"] = withheld
            stats.update(
                created=counts.created,
                updated=counts.updated,
                unchanged=counts.unchanged,
                deleted=counts.deleted,
                collected_at=collected_at.isoformat(),
            )
            run.succeed(now, stats)
            source.record_success(now)
            await self._emit(uow, run, source, now)
            await uow.commit()
        return IngestionOutcome(run.id, run.status, stats, _duration(run))

    async def fail_run(self, *, org_id: UUID, run_id: UUID, code: str, detail: str | None) -> None:
        """Record a collection failure (fetch/parse errors raised before ingestion)."""
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            run = await uow.data.runs.get_for_update(org_id, run_id)
            if run is None or run.is_terminal:
                return
            source = await uow.data.sources.get_for_update(org_id, run.source_id)
            run.fail(now, code=code, detail=detail)
            await release_upload(uow, run, now, reason=code)
            if source is not None:
                source.record_failure(now)
                await self._emit(uow, run, source, now)
            await uow.commit()

    async def cancel_run(self, *, org_id: UUID, run_id: UUID, code: str) -> None:
        """Cancel without counting a source failure (freeze, deleted source...)."""
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            run = await uow.data.runs.get_for_update(org_id, run_id)
            if run is None or run.is_terminal:
                return
            run.cancel(now, code=code)
            await release_upload(uow, run, now, reason=code)
            await uow.data.payloads.take(org_id, run.id)  # drop staged data, if any
            source = await uow.data.sources.get(org_id, run.source_id)
            if source is not None:
                await self._emit(uow, run, source, now)
            await uow.commit()

    # ----------------------------------------------------------------- store

    async def _store(
        self,
        uow: UnitOfWork,
        dataset: Dataset,
        source: Source,
        run: CollectionRun,
        records: list[CleanRecord],
        now: datetime,
    ) -> _Counts:
        counts = _Counts()
        for start in range(0, len(records), _CHUNK):
            chunk = records[start : start + _CHUNK]
            existing = await uow.data.records.fetch_for_update(
                dataset.org_id, dataset.id, [r.key for r in chunk]
            )
            new_records: list[Record] = []
            versions: list[RecordVersion] = []
            unchanged: list[UUID] = []
            for clean in chunk:
                current = existing.get(clean.key)
                fingerprint = self._fingerprint(clean.content_hash)
                if current is None:
                    record_id = uuid7()
                    record = Record(
                        id=record_id,
                        org_id=dataset.org_id,
                        dataset_id=dataset.id,
                        record_key=clean.key,
                        data=self._seal(dataset, record_id, clean.data),
                        content_hash=fingerprint,
                        version=1,
                        source_id=source.id,
                        first_seen_at=now,
                        last_seen_at=now,
                        last_run_id=run.id,
                    )
                    new_records.append(record)
                    versions.append(_version(record, run.id, now, data=record.data))
                    counts.created += 1
                elif current.content_hash != fingerprint or current.deleted_at is not None:
                    current.version += 1
                    current.data = self._seal(dataset, current.id, clean.data)
                    current.content_hash = fingerprint
                    current.deleted_at = None
                    current.last_seen_at = now
                    current.last_run_id = run.id
                    current.source_id = source.id
                    versions.append(_version(current, run.id, now, data=current.data))
                    counts.updated += 1
                else:
                    unchanged.append(current.id)
                    counts.unchanged += 1
            await uow.data.records.add_many(new_records)
            await uow.data.records.add_versions(versions)
            # The source that last saw a record owns it, changed or not: a record
            # that moved to another source (or whose source was replaced) is
            # deleted by the snapshots of the source that has it now.
            await uow.data.records.touch(
                dataset.org_id, unchanged, run_id=run.id, source_id=source.id, now=now
            )
        return counts

    @staticmethod
    async def _superseded(uow: UnitOfWork, source: Source, collected_at: datetime) -> bool:
        """Whether a full snapshot is older than the newest one applied from its
        source (checked under the source lock, so concurrent runs see each other).

        Only full snapshots: one stands for the whole source, while an
        incremental one holds some records only - skipping it would lose them.
        """
        if source.config.get("snapshot_mode") != "full":
            return False
        latest = await uow.data.runs.latest_collected_at(source.org_id, source.id)
        return latest is not None and collected_at < latest

    async def _skip_superseded(
        self,
        uow: UnitOfWork,
        run: CollectionRun,
        source: Source,
        stats: dict[str, Any],
        collected_at: datetime,
        now: datetime,
    ) -> IngestionOutcome:
        """The run succeeds - its collection worked - and stores nothing."""
        stats.update(
            superseded=True,
            collected_at=collected_at.isoformat(),
            created=0,
            updated=0,
            unchanged=0,
            deleted=0,
        )
        run.succeed(now, stats)
        await self._emit(uow, run, source, now)
        await uow.commit()
        return IngestionOutcome(run.id, run.status, stats, _duration(run))

    @staticmethod
    def _can_infer_deletions(source: Source, result: PipelineResult) -> bool:
        return (
            source.config.get("snapshot_mode") == "full"
            and not result.truncated
            and result.invalid == 0
            and result.valid > 0
        )

    async def _mark_deleted(
        self,
        uow: UnitOfWork,
        dataset: Dataset,
        source: Source,
        run: CollectionRun,
        counts: _Counts,
        now: datetime,
    ) -> tuple[int, int]:
        """Soft-delete records the full snapshot no longer contains.

        Returns ``(deleted, withheld)``: when the snapshot would delete more
        than the source's ``max_deletion_ratio`` of the previously live records
        (and at least ``_GUARD_MIN_DELETIONS``), nothing is deleted and the
        count is reported on the run instead - a mass disappearance is far more
        likely a broken or hostile source than a real catalogue change.
        """
        missing_total = await uow.data.records.count_missing_from_run(
            dataset.org_id, dataset.id, source.id, run.id
        )
        if missing_total == 0:
            return 0, 0
        previously_live = counts.updated + counts.unchanged + missing_total
        ratio = float(source.config.get("max_deletion_ratio", DEFAULT_MAX_DELETION_RATIO))
        if missing_total >= _GUARD_MIN_DELETIONS and missing_total > ratio * previously_live:
            return 0, missing_total
        missing = await uow.data.records.missing_from_run(
            dataset.org_id, dataset.id, source.id, run.id, limit=_MAX_DELETIONS_PER_RUN
        )
        versions = []
        for record in missing:
            record.version += 1
            record.deleted_at = now
            record.last_run_id = run.id
            # Loaded rows hold opened values: the deletion version is sealed again.
            sealed = self._seal(dataset, record.id, record.data)
            versions.append(_version(record, run.id, now, data=sealed, is_deletion=True))
        await uow.data.records.add_versions(versions)
        return len(missing), 0

    async def _emit(
        self, uow: UnitOfWork, run: CollectionRun, source: Source, now: datetime
    ) -> None:
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


def _version(
    record: Record,
    run_id: UUID,
    now: datetime,
    *,
    data: dict[str, Any],
    is_deletion: bool = False,
) -> RecordVersion:
    """A version of ``record`` holding ``data`` - already sealed by the caller."""
    return RecordVersion(
        id=uuid7(),
        org_id=record.org_id,
        dataset_id=record.dataset_id,
        record_id=record.id,
        version=record.version,
        data=dict(data),
        content_hash=record.content_hash,
        run_id=run_id,
        captured_at=now,
        is_deletion=is_deletion,
    )

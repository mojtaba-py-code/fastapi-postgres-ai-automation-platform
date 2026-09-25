"""SQL repositories for the business-data contexts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    DateTime,
    LargeBinary,
    Select,
    String,
    and_,
    cast,
    delete,
    false,
    func,
    literal,
    literal_column,
    null,
    or_,
    select,
    text,
    tuple_,
    union,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from nexusflow.core.jsonutil import JSONValue
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.domain.alerts.model import Alert, AlertRule
from nexusflow.domain.automation.model import DeadLetter, Workflow, WorkflowRun
from nexusflow.domain.catalog.model import Dataset, Project
from nexusflow.domain.integrations.model import Integration
from nexusflow.domain.intelligence.model import Insight, InsightStatus
from nexusflow.domain.notifications.model import NotificationChannel, NotificationDelivery
from nexusflow.domain.records.model import (
    Change,
    ChangeType,
    ChangeVolume,
    Record,
    RecordVersion,
    Significance,
)
from nexusflow.domain.records.sealing import (
    SealedValueError,
    field_context,
    is_sealed,
    open_value,
    rewrap_value,
    seal_data,
    seal_diff,
    seal_value,
)
from nexusflow.domain.reports.model import Report
from nexusflow.domain.shared.idempotency import CLIENT_KEY_PREFIX
from nexusflow.domain.shared.security import SecretCipher
from nexusflow.domain.sources.model import CollectionRun, RunStatus, Source
from nexusflow.domain.uploads.model import Upload, UploadStatus
from nexusflow.domain.webhooks.model import InboundWebhookEvent, WebhookEndpoint
from nexusflow.infrastructure.database.pagination import paginate
from nexusflow.infrastructure.database.repositories.base import TenantRepository
from nexusflow.infrastructure.database.sealing import CIPHER_KEY
from nexusflow.infrastructure.database.tables import data as d
from nexusflow.infrastructure.database.tables import identity as t


class SqlProjectRepository(TenantRepository[Project]):
    entity = Project
    table = d.projects
    sortable = ("created_at", "name")


class SqlDatasetRepository(TenantRepository[Dataset]):
    entity = Dataset
    table = d.datasets
    sortable = ("created_at", "name")

    async def get_for_share(self, org_id: UUID, dataset_id: UUID) -> Dataset | None:
        statement = (
            select(Dataset)
            .where(d.datasets.c.org_id == org_id, d.datasets.c.id == dataset_id)
            .with_for_update(read=True)
            .execution_options(populate_existing=True)
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def list_page(
        self,
        org_id: UUID,
        page: PageRequest,
        filters: Mapping[str, Any] | None = None,
        extra: Iterable[Any] = (),
    ) -> Page[Dataset]:
        # Soft-deleted datasets are never listed.
        return await super().list_page(
            org_id, page, filters, [*extra, d.datasets.c.deleted_at.is_(None)]
        )


class SqlIntegrationRepository(TenantRepository[Integration]):
    entity = Integration
    table = d.integrations
    sortable = ("created_at", "name")

    async def references(self, org_id: UUID, integration_id: UUID) -> int:
        sources = (
            select(func.count())
            .select_from(d.sources)
            .where(d.sources.c.org_id == org_id, d.sources.c.integration_id == integration_id)
        )
        channels = (
            select(func.count())
            .select_from(d.notification_channels)
            .where(
                d.notification_channels.c.org_id == org_id,
                d.notification_channels.c.integration_id == integration_id,
            )
        )
        return int((await self._s.execute(sources)).scalar_one()) + int(
            (await self._s.execute(channels)).scalar_one()
        )

    async def needing_rewrap(
        self, org_id: UUID, active_key_id: str, limit: int
    ) -> list[Integration]:
        statement = (
            select(Integration)
            .where(
                d.integrations.c.org_id == org_id, d.integrations.c.secret_key_id != active_key_id
            )
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def count_needing_rewrap(self, org_id: UUID, active_key_id: str) -> int:
        i = d.integrations
        statement = (
            select(func.count())
            .select_from(i)
            .where(i.c.org_id == org_id, i.c.secret_key_id != active_key_id)
        )
        return int((await self._s.execute(statement)).scalar_one())


class SqlSourceRepository(TenantRepository[Source]):
    entity = Source
    table = d.sources
    sortable = ("created_at", "name")

    async def lock(self, source_id: UUID) -> None:
        """Serialize ingestion per source (transaction-scoped advisory lock)."""
        await self._s.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": f"source:{source_id}"},
        )

    async def list_by_ids(self, org_id: UUID, ids: Sequence[UUID]) -> list[Source]:
        if not ids:
            return []
        statement = select(Source).where(d.sources.c.org_id == org_id, d.sources.c.id.in_(ids))
        return list((await self._s.execute(statement)).scalars().all())

    async def wait_for_ingestions(self, org_id: UUID, dataset_id: UUID) -> None:
        """Lock the dataset's sources: an ingestion holds its source's row from
        before it reads the dataset until it commits, so this waits for every
        ingestion that may still work with an older schema."""
        statement = (
            select(d.sources.c.id)
            .where(d.sources.c.org_id == org_id, d.sources.c.dataset_id == dataset_id)
            .with_for_update()
        )
        await self._s.execute(statement)


class SqlCollectionRunRepository(TenantRepository[CollectionRun]):
    entity = CollectionRun
    table = d.collection_runs

    async def get_by_idempotency_key(self, org_id: UUID, key: str) -> CollectionRun | None:
        statement = select(CollectionRun).where(
            d.collection_runs.c.org_id == org_id, d.collection_runs.c.idempotency_key == key
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def list_stale(
        self, org_id: UUID, *, started_before: datetime, limit: int
    ) -> list[CollectionRun]:
        runs = d.collection_runs
        statement = (
            select(CollectionRun)
            .where(
                runs.c.org_id == org_id,
                runs.c.status == RunStatus.RUNNING.value,
                runs.c.started_at < started_before,
            )
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def list_for_workflow_run(
        self, org_id: UUID, workflow_run_id: UUID
    ) -> list[CollectionRun]:
        statement = select(CollectionRun).where(
            d.collection_runs.c.org_id == org_id,
            d.collection_runs.c.workflow_run_id == workflow_run_id,
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def latest_collected_at(self, org_id: UUID, source_id: UUID) -> datetime | None:
        runs = d.collection_runs
        collected = runs.c.stats["collected_at"].astext.cast(DateTime(timezone=True))
        statement = select(func.max(collected)).where(
            runs.c.org_id == org_id,
            runs.c.source_id == source_id,
            runs.c.status == RunStatus.SUCCEEDED.value,
        )
        latest: datetime | None = (await self._s.execute(statement)).scalar_one_or_none()
        return latest


class SqlRunPayloadRepository:
    """Collected items staged between receipt and ingestion - sealed as a whole:
    they are raw source data, sensitive fields included, before any schema."""

    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    def _cipher(self) -> SecretCipher:
        return _session_cipher(self._s)

    async def put(self, org_id: UUID, run_id: UUID, items: list[JSONValue], now: datetime) -> None:
        sealed = seal_value(self._cipher(), items, _payload_context(org_id, run_id))
        await self._s.execute(
            d.run_payloads.insert().values(
                run_id=run_id, org_id=org_id, items=sealed, created_at=now
            )
        )

    async def take(self, org_id: UUID, run_id: UUID) -> list[JSONValue] | None:
        statement = (
            delete(d.run_payloads)
            .where(d.run_payloads.c.org_id == org_id, d.run_payloads.c.run_id == run_id)
            .returning(d.run_payloads.c["items"])
        )
        items = (await self._s.execute(statement)).scalar_one_or_none()
        if items is None:
            return None
        if is_sealed(items):
            items = open_value(self._cipher(), items, _payload_context(org_id, run_id))
        return list(items)

    async def exists(self, org_id: UUID, run_id: UUID) -> bool:
        statement = select(d.run_payloads.c.run_id).where(
            d.run_payloads.c.org_id == org_id, d.run_payloads.c.run_id == run_id
        )
        return (await self._s.execute(statement)).first() is not None


def _payload_context(org_id: UUID, run_id: UUID) -> str:
    return f"payload:v1:{org_id}:{run_id}"


def _session_cipher(session: AsyncSession) -> SecretCipher:
    cipher = session.info.get(CIPHER_KEY)
    if cipher is None:
        raise SealedValueError(internal_detail="sealed data needs a field cipher")
    return cipher  # type: ignore[no-any-return]


# JSONPath over a data mapping (field -> value) or a diff (field -> {old, new, pct}):
# a sealed marker whose key id is not the active one. Constant text, never input.
_STALE_IN_DATA: ColumnElement[Any] = literal_column("'$.* ? (@.kid != $kid)'::jsonpath")
_STALE_IN_DIFF: ColumnElement[Any] = literal_column("'$.*.* ? (@.kid != $kid)'::jsonpath")


async def _rewrap_rows(
    session: AsyncSession,
    table: Any,
    column: str,
    record_column: str,
    org_id: UUID,
    active_key_id: str,
    limit: int,
) -> int:
    """Re-encrypt the stale sealed values of up to ``limit`` rows of ``table``."""
    cipher = _session_cipher(session)
    stale = _STALE_IN_DIFF if column == "diff" else _STALE_IN_DATA
    statement = (
        select(
            table.c.id,
            table.c.dataset_id,
            table.c[record_column].label("record_id"),  # records: the id itself
            table.c[column],
        )
        .where(
            table.c.org_id == org_id,
            func.jsonb_path_exists(
                table.c[column], stale, func.jsonb_build_object("kid", active_key_id)
            ),
        )
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    rows = (await session.execute(statement)).all()
    for row_id, dataset_id, record_id, value in rows:
        rewrapped: dict[str, Any] = {}
        for name, entry in value.items():
            context = field_context(org_id, dataset_id, record_id, name)
            if column == "diff" and isinstance(entry, dict) and not is_sealed(entry):
                rewrapped[name] = {k: rewrap_value(cipher, v, context) for k, v in entry.items()}
            else:
                rewrapped[name] = rewrap_value(cipher, entry, context)
        await session.execute(update(table).where(table.c.id == row_id).values({column: rewrapped}))
    return len(rows)


def _plaintext(table: Any, column: str, fields: Iterable[str]) -> ColumnElement[bool]:
    """A value of one of ``fields`` stored in clear (a scalar where a sealed
    marker - an object - belongs). Field names travel as bound parameters."""
    value = table.c[column]
    parts = ("old", "new", "pct") if column == "diff" else (None,)
    return or_(
        *(
            func.jsonb_typeof(value[name] if part is None else value[name][part]).not_in(
                ("object", "null")
            )
            for name in fields
            for part in parts
        )
    )


async def _seal_rows(
    session: AsyncSession,
    table: Any,
    column: str,
    record_column: str,
    org_id: UUID,
    dataset_id: UUID,
    fields: frozenset[str],
    limit: int,
) -> int:
    """Seal the plaintext values of ``fields`` in up to ``limit`` rows of
    ``table`` (rows other transactions hold are skipped)."""
    cipher = _session_cipher(session)
    statement = (
        select(table.c.id, table.c[record_column].label("record_id"), table.c[column])
        .where(
            table.c.org_id == org_id,
            table.c.dataset_id == dataset_id,
            _plaintext(table, column, fields),
        )
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    rows = (await session.execute(statement)).all()
    seal = seal_diff if column == "diff" else seal_data
    for row_id, record_id, value in rows:
        sealed = seal(
            cipher, value, fields, org_id=org_id, dataset_id=dataset_id, record_id=record_id
        )
        await session.execute(update(table).where(table.c.id == row_id).values({column: sealed}))
    return len(rows)


async def _count_plaintext(
    session: AsyncSession,
    table: Any,
    column: str,
    org_id: UUID,
    dataset_id: UUID,
    fields: frozenset[str],
) -> int:
    statement = (
        select(func.count())
        .select_from(table)
        .where(
            table.c.org_id == org_id,
            table.c.dataset_id == dataset_id,
            _plaintext(table, column, fields),
        )
    )
    return int((await session.execute(statement)).scalar_one())


async def _count_stale(
    session: AsyncSession, table: Any, column: str, org_id: UUID, active_key_id: str
) -> int:
    """Rows of ``table`` holding a value sealed under an older key - counted
    without locks, so rows other transactions hold are counted too."""
    stale = _STALE_IN_DIFF if column == "diff" else _STALE_IN_DATA
    statement = (
        select(func.count())
        .select_from(table)
        .where(
            table.c.org_id == org_id,
            func.jsonb_path_exists(
                table.c[column], stale, func.jsonb_build_object("kid", active_key_id)
            ),
        )
    )
    return int((await session.execute(statement)).scalar_one())


async def _delete_ids(session: AsyncSession, table: Any, ids: Select[Any]) -> int:
    """Delete the rows ``ids`` selects - a bounded batch, so one short statement."""
    statement = (
        delete(table).where(table.c.id.in_(ids)).execution_options(synchronize_session=False)
    )
    result = await session.execute(statement)
    return int(getattr(result, "rowcount", 0) or 0)


class SqlRecordRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def rewrap_sealed(self, org_id: UUID, active_key_id: str, *, limit: int) -> int:
        count = await _rewrap_rows(self._s, d.records, "data", "id", org_id, active_key_id, limit)
        return count + await _rewrap_rows(
            self._s, d.record_versions, "data", "record_id", org_id, active_key_id, limit
        )

    async def count_stale_sealed(self, org_id: UUID, active_key_id: str) -> tuple[int, int]:
        return (
            await _count_stale(self._s, d.records, "data", org_id, active_key_id),
            await _count_stale(self._s, d.record_versions, "data", org_id, active_key_id),
        )

    async def seal_plaintext(
        self, org_id: UUID, dataset_id: UUID, fields: frozenset[str], *, limit: int
    ) -> int:
        count = await _seal_rows(
            self._s, d.records, "data", "id", org_id, dataset_id, fields, limit
        )
        return count + await _seal_rows(
            self._s, d.record_versions, "data", "record_id", org_id, dataset_id, fields, limit
        )

    async def count_plaintext(self, org_id: UUID, dataset_id: UUID, fields: frozenset[str]) -> int:
        count = await _count_plaintext(self._s, d.records, "data", org_id, dataset_id, fields)
        return count + await _count_plaintext(
            self._s, d.record_versions, "data", org_id, dataset_id, fields
        )

    async def fetch_for_update(self, dataset_id: UUID, keys: Sequence[str]) -> dict[str, Record]:
        if not keys:
            return {}
        statement = (
            select(Record)
            .where(d.records.c.dataset_id == dataset_id, d.records.c.record_key.in_(list(keys)))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return {r.record_key: r for r in (await self._s.execute(statement)).scalars().all()}

    async def add_many(self, records: Sequence[Record]) -> None:
        self._s.add_all(records)
        await self._s.flush()

    async def add_versions(self, versions: Sequence[RecordVersion]) -> None:
        self._s.add_all(versions)
        await self._s.flush()

    async def touch(
        self, record_ids: Sequence[UUID], *, run_id: UUID, source_id: UUID, now: datetime
    ) -> None:
        if not record_ids:
            return
        await self._s.execute(
            update(d.records)
            .where(d.records.c.id.in_(list(record_ids)))
            .values(last_seen_at=now, last_run_id=run_id, source_id=source_id)
            .execution_options(synchronize_session=False)
        )

    @staticmethod
    def _missing(dataset_id: UUID, source_id: UUID, run_id: UUID) -> tuple[Any, ...]:
        r = d.records
        return (
            r.c.dataset_id == dataset_id,
            r.c.source_id == source_id,
            r.c.deleted_at.is_(None),
            or_(r.c.last_run_id.is_(None), r.c.last_run_id != run_id),
        )

    async def missing_from_run(
        self, dataset_id: UUID, source_id: UUID, run_id: UUID, *, limit: int
    ) -> list[Record]:
        statement = (
            select(Record)
            .where(*self._missing(dataset_id, source_id, run_id))
            .limit(limit)
            .with_for_update()
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def count_missing_from_run(self, dataset_id: UUID, source_id: UUID, run_id: UUID) -> int:
        statement = (
            select(func.count())
            .select_from(d.records)
            .where(*self._missing(dataset_id, source_id, run_id))
        )
        return int((await self._s.execute(statement)).scalar_one())

    async def get(self, org_id: UUID, record_id: UUID) -> Record | None:
        statement = select(Record).where(d.records.c.org_id == org_id, d.records.c.id == record_id)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def get_by_key(self, org_id: UUID, dataset_id: UUID, record_key: str) -> Record | None:
        statement = select(Record).where(
            d.records.c.org_id == org_id,
            d.records.c.dataset_id == dataset_id,
            d.records.c.record_key == record_key,
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def list_page(
        self, org_id: UUID, dataset_id: UUID, page: PageRequest, *, include_deleted: bool
    ) -> Page[Record]:
        r = d.records
        statement = select(Record).where(r.c.org_id == org_id, r.c.dataset_id == dataset_id)
        if not include_deleted:
            statement = statement.where(r.c.deleted_at.is_(None))
        return await paginate(
            self._s,
            statement,
            page=page,
            sort_columns={"created_at": r.c.first_seen_at, "last_seen_at": r.c.last_seen_at},
            id_column=r.c.id,
            key=lambda rec: (
                rec.first_seen_at if page.sort.field == "created_at" else rec.last_seen_at,
                rec.id,
            ),
        )

    async def history(self, org_id: UUID, record_id: UUID, *, limit: int) -> list[RecordVersion]:
        v = d.record_versions
        statement = (
            select(RecordVersion)
            .where(v.c.org_id == org_id, v.c.record_id == record_id)
            .order_by(v.c.version.desc())
            .limit(limit)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def pending_versions(self, dataset_id: UUID, *, limit: int) -> list[RecordVersion]:
        v = d.record_versions
        statement = (
            select(RecordVersion)
            .where(v.c.dataset_id == dataset_id, v.c.diffed.is_(False))
            .order_by(v.c.record_id, v.c.version)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def previous_versions(
        self, pairs: Iterable[tuple[UUID, int]]
    ) -> dict[tuple[UUID, int], RecordVersion]:
        wanted = [(record_id, version) for record_id, version in pairs if version >= 1]
        if not wanted:
            return {}
        v = d.record_versions
        statement = select(RecordVersion).where(tuple_(v.c.record_id, v.c.version).in_(wanted))
        rows = (await self._s.execute(statement)).scalars().all()
        return {(row.record_id, row.version): row for row in rows}

    async def mark_diffed(self, version_ids: Sequence[UUID]) -> None:
        if not version_ids:
            return
        await self._s.execute(
            update(d.record_versions)
            .where(d.record_versions.c.id.in_(list(version_ids)))
            .values(diffed=True)
            .execution_options(synchronize_session=False)
        )

    async def keys_for(self, record_ids: Sequence[UUID]) -> dict[UUID, str]:
        if not record_ids:
            return {}
        statement = select(d.records.c.id, d.records.c.record_key).where(
            d.records.c.id.in_(list(record_ids))
        )
        return {row.id: row.record_key for row in (await self._s.execute(statement)).all()}

    async def batch_after(
        self, org_id: UUID, dataset_id: UUID, *, after: UUID | None, limit: int
    ) -> list[Record]:
        r = d.records
        statement = (
            select(Record)
            .where(r.c.org_id == org_id, r.c.dataset_id == dataset_id, r.c.deleted_at.is_(None))
            .order_by(r.c.id)
            .limit(limit)
        )
        if after is not None:
            statement = statement.where(r.c.id > after)
        return list((await self._s.execute(statement)).scalars().all())

    async def purge_versions_before(
        self, org_id: UUID, dataset_id: UUID, before: datetime, *, limit: int
    ) -> int:
        v = d.record_versions
        successor = d.record_versions.alias("successor")
        # Change detection diffs version n against version n - 1: a version may go
        # only once its successor has been diffed. That keeps the newest version of
        # every record, and every version a pending (undiffed) one still needs.
        doomed = (
            select(v.c.id)
            .where(
                v.c.org_id == org_id,
                v.c.dataset_id == dataset_id,
                v.c.captured_at < before,
                v.c.diffed.is_(True),
                select(successor.c.id)
                .where(
                    successor.c.record_id == v.c.record_id,
                    successor.c.version == v.c.version + 1,
                    successor.c.diffed.is_(True),
                )
                .exists(),
            )
            .limit(limit)
        )
        return await _delete_ids(self._s, v, doomed)


_SIGNIFICANCE_ORDER = [s.value for s in Significance]


class SqlChangeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add_new(self, changes: Sequence[Change]) -> list[Change]:
        """Insert changes; duplicates (same record/version) are skipped - idempotent."""
        inserted: list[Change] = []
        for change in changes:
            statement = (
                pg_insert(d.changes)
                .values(
                    id=change.id,
                    org_id=change.org_id,
                    dataset_id=change.dataset_id,
                    record_id=change.record_id,
                    record_key=change.record_key,
                    run_id=change.run_id,
                    change_type=change.change_type.value,
                    from_version=change.from_version,
                    to_version=change.to_version,
                    diff=change.diff,
                    significance=change.significance.value,
                    score=change.score,
                    detected_at=change.detected_at,
                    insight_id=None,
                    alerts_evaluated=False,
                )
                .on_conflict_do_nothing(index_elements=["record_id", "to_version"])
                .returning(d.changes.c.id)
            )
            if (await self._s.execute(statement)).scalar_one_or_none() is not None:
                inserted.append(change)
        return inserted

    async def get(self, org_id: UUID, change_id: UUID) -> Change | None:
        statement = select(Change).where(d.changes.c.org_id == org_id, d.changes.c.id == change_id)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def list_page(
        self, org_id: UUID, page: PageRequest, filters: Mapping[str, Any]
    ) -> Page[Change]:
        c = d.changes
        statement = select(Change).where(c.c.org_id == org_id)
        if filters.get("dataset_id"):
            statement = statement.where(c.c.dataset_id == filters["dataset_id"])
        if filters.get("change_type"):
            statement = statement.where(c.c.change_type == filters["change_type"])
        if filters.get("min_significance"):
            index = _SIGNIFICANCE_ORDER.index(filters["min_significance"])
            statement = statement.where(c.c.significance.in_(_SIGNIFICANCE_ORDER[index:]))
        if filters.get("record_id"):
            statement = statement.where(c.c.record_id == filters["record_id"])
        if filters.get("since"):
            statement = statement.where(c.c.detected_at >= filters["since"])
        return await paginate(
            self._s,
            statement,
            page=page,
            sort_columns={
                "created_at": c.c.detected_at,
                "detected_at": c.c.detected_at,
                "score": c.c.score,
            },
            id_column=c.c.id,
            key=lambda ch: (ch.score if page.sort.field == "score" else ch.detected_at, ch.id),
        )

    async def unanalyzed(self, org_id: UUID, dataset_id: UUID, *, limit: int) -> list[Change]:
        c = d.changes
        statement = (
            select(Change)
            .where(c.c.org_id == org_id, c.c.dataset_id == dataset_id, c.c.insight_id.is_(None))
            .order_by(c.c.score.desc(), c.c.detected_at)
            .limit(limit)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def assign_insight(self, change_ids: Sequence[UUID], insight_id: UUID) -> None:
        if change_ids:
            await self._s.execute(
                update(d.changes)
                .where(d.changes.c.id.in_(list(change_ids)))
                .values(insight_id=insight_id)
                .execution_options(synchronize_session=False)
            )

    async def pending_alerts(self, org_id: UUID, *, limit: int) -> list[Change]:
        c = d.changes
        statement = (
            select(Change)
            .where(c.c.org_id == org_id, c.c.alerts_evaluated.is_(False))
            .order_by(c.c.detected_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def rewrap_sealed(self, org_id: UUID, active_key_id: str, *, limit: int) -> int:
        return await _rewrap_rows(
            self._s, d.changes, "diff", "record_id", org_id, active_key_id, limit
        )

    async def count_stale_sealed(self, org_id: UUID, active_key_id: str) -> int:
        return await _count_stale(self._s, d.changes, "diff", org_id, active_key_id)

    async def seal_plaintext(
        self, org_id: UUID, dataset_id: UUID, fields: frozenset[str], *, limit: int
    ) -> int:
        return await _seal_rows(
            self._s, d.changes, "diff", "record_id", org_id, dataset_id, fields, limit
        )

    async def count_plaintext(self, org_id: UUID, dataset_id: UUID, fields: frozenset[str]) -> int:
        return await _count_plaintext(self._s, d.changes, "diff", org_id, dataset_id, fields)

    async def purge_before(
        self, org_id: UUID, dataset_id: UUID, before: datetime, *, limit: int
    ) -> int:
        c = d.changes
        # Nothing references a change by foreign key (alerts keep their own text
        # and subject id; insights their own summary): once its alerts have been
        # evaluated, an old change can go like the versions it compared.
        doomed = (
            select(c.c.id)
            .where(
                c.c.org_id == org_id,
                c.c.dataset_id == dataset_id,
                c.c.detected_at < before,
                c.c.alerts_evaluated.is_(True),
            )
            .limit(limit)
        )
        return await _delete_ids(self._s, c, doomed)

    async def mark_alerts_evaluated(self, change_ids: Sequence[UUID]) -> None:
        if change_ids:
            await self._s.execute(
                update(d.changes)
                .where(d.changes.c.id.in_(list(change_ids)))
                .values(alerts_evaluated=True)
                .execution_options(synchronize_session=False)
            )

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
        c = d.changes
        statement = (
            select(Change)
            .where(*_in_period(org_id, dataset_ids, start, end))
            .order_by(c.c.score.desc(), c.c.detected_at.desc(), c.c.id)
            .limit(limit)
        )
        if significances is not None:
            statement = statement.where(c.c.significance.in_([s.value for s in significances]))
        return list((await self._s.execute(statement)).scalars().all())

    async def volume(
        self, org_id: UUID, *, dataset_ids: Sequence[UUID], start: datetime, end: datetime
    ) -> list[ChangeVolume]:
        c = d.changes
        # The UTC calendar day; the zone is inlined so that the grouped expression
        # and the selected one are the same (two bound parameters would differ).
        day = func.date(func.timezone(literal_column("'UTC'"), c.c.detected_at))
        statement = (
            select(day.label("day"), c.c.change_type, c.c.significance, func.count())
            .where(*_in_period(org_id, dataset_ids, start, end))
            .group_by(day, c.c.change_type, c.c.significance)
        )
        return [
            ChangeVolume(
                day=row[0],
                change_type=ChangeType(row[1]),
                significance=Significance(row[2]),
                count=int(row[3]),
            )
            for row in (await self._s.execute(statement)).all()
        ]


def _in_period(
    org_id: UUID, dataset_ids: Sequence[UUID], start: datetime, end: datetime
) -> list[Any]:
    c = d.changes
    return [
        c.c.org_id == org_id,
        c.c.dataset_id.in_(list(dataset_ids)),
        c.c.detected_at >= start,
        c.c.detected_at < end,  # the end is exclusive
    ]


class SqlInsightRepository(TenantRepository[Insight]):
    entity = Insight
    table = d.insights

    async def get_by_idempotency_key(self, org_id: UUID, key: str) -> Insight | None:
        statement = select(Insight).where(
            d.insights.c.org_id == org_id, d.insights.c.idempotency_key == key
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def in_period(
        self, org_id: UUID, *, dataset_ids: Sequence[UUID], start: datetime, end: datetime
    ) -> list[Insight]:
        i = d.insights
        statement = (
            select(Insight)
            .where(
                i.c.org_id == org_id,
                i.c.dataset_id.in_(list(dataset_ids)),
                i.c.created_at >= start,
                i.c.created_at < end,
                i.c.status == "completed",
            )
            .order_by(i.c.created_at)
            .limit(50)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def stuck(self, org_id: UUID, *, started_before: datetime, limit: int) -> list[Insight]:
        i = d.insights
        statement = (
            select(Insight)
            .where(
                i.c.org_id == org_id,
                i.c.status == InsightStatus.RUNNING.value,
                i.c.started_at < started_before,
            )
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return list((await self._s.execute(statement)).scalars().all())


class SqlAlertRuleRepository(TenantRepository[AlertRule]):
    entity = AlertRule
    table = d.alert_rules
    sortable = ("created_at", "name")

    async def enabled_for(
        self, org_id: UUID, *, dataset_id: UUID | None, project_id: UUID | None
    ) -> list[AlertRule]:
        r = d.alert_rules
        statement = select(AlertRule).where(r.c.org_id == org_id, r.c.enabled.is_(True))
        scope = []
        if dataset_id is not None:
            scope.append(r.c.dataset_id == dataset_id)
        if project_id is not None:
            scope.append(and_(r.c.project_id == project_id, r.c.dataset_id.is_(None)))
        if scope:
            statement = statement.where(or_(*scope))
        return list((await self._s.execute(statement)).scalars().all())


class SqlAlertRepository(TenantRepository[Alert]):
    entity = Alert
    table = d.alerts
    sortable = ("triggered_at",)

    async def add_if_new(self, alert: Alert) -> bool:
        statement = (
            pg_insert(d.alerts)
            .values(
                id=alert.id,
                org_id=alert.org_id,
                rule_id=alert.rule_id,
                severity=alert.severity.value,
                title=alert.title,
                body=alert.body,
                dedup_key=alert.dedup_key,
                subject_type=alert.subject_type,
                subject_id=alert.subject_id,
                status=alert.status.value,
                triggered_at=alert.triggered_at,
            )
            .on_conflict_do_nothing(index_elements=["org_id", "dedup_key"])
            .returning(d.alerts.c.id)
        )
        return (await self._s.execute(statement)).scalar_one_or_none() is not None

    async def in_period(
        self, org_id: UUID, *, start: datetime, end: datetime, limit: int
    ) -> list[Alert]:
        a = d.alerts
        statement = (
            select(Alert)
            .where(a.c.org_id == org_id, a.c.triggered_at >= start, a.c.triggered_at < end)
            .order_by(a.c.triggered_at.desc())
            .limit(limit)
        )
        return list((await self._s.execute(statement)).scalars().all())

    def _sort_key(self, page: PageRequest) -> Any:
        return lambda alert: (alert.triggered_at, alert.id)


class SqlChannelRepository(TenantRepository[NotificationChannel]):
    entity = NotificationChannel
    table = d.notification_channels
    sortable = ("created_at", "name")

    async def list_by_ids(self, org_id: UUID, ids: Sequence[UUID]) -> list[NotificationChannel]:
        if not ids:
            return []
        statement = select(NotificationChannel).where(
            d.notification_channels.c.org_id == org_id, d.notification_channels.c.id.in_(ids)
        )
        return list((await self._s.execute(statement)).scalars().all())


class SqlDeliveryRepository(TenantRepository[NotificationDelivery]):
    entity = NotificationDelivery
    table = d.notification_deliveries

    async def add_if_new(self, delivery: NotificationDelivery) -> bool:
        statement = (
            pg_insert(d.notification_deliveries)
            .values(
                id=delivery.id,
                org_id=delivery.org_id,
                alert_id=delivery.alert_id,
                channel_id=delivery.channel_id,
                status=delivery.status.value,
                attempts=delivery.attempts,
                next_attempt_at=delivery.next_attempt_at,
                last_error_code=None,
                delivered_at=None,
                claimed_at=None,
                created_at=delivery.created_at,
            )
            .on_conflict_do_nothing(index_elements=["alert_id", "channel_id"])
            .returning(d.notification_deliveries.c.id)
        )
        return (await self._s.execute(statement)).scalar_one_or_none() is not None

    async def for_alert(self, org_id: UUID, alert_id: UUID) -> list[NotificationDelivery]:
        statement = select(NotificationDelivery).where(
            d.notification_deliveries.c.org_id == org_id,
            d.notification_deliveries.c.alert_id == alert_id,
        )
        return list((await self._s.execute(statement)).scalars().all())


class SqlReportRepository(TenantRepository[Report]):
    entity = Report
    table = d.reports

    async def get_by_idempotency_key(self, org_id: UUID, key: str) -> Report | None:
        statement = select(Report).where(
            d.reports.c.org_id == org_id, d.reports.c.idempotency_key == key
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def expired(self, org_id: UUID, now: datetime, *, limit: int) -> list[Report]:
        r = d.reports
        statement = (
            select(Report)
            .where(r.c.org_id == org_id, r.c.expires_at < now, r.c.status == "ready")
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def stuck(self, org_id: UUID, *, created_before: datetime, limit: int) -> list[Report]:
        r = d.reports
        statement = (
            select(Report)
            .where(
                r.c.org_id == org_id, r.c.status == "generating", r.c.created_at < created_before
            )
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return list((await self._s.execute(statement)).scalars().all())


class SqlUploadRepository(TenantRepository[Upload]):
    entity = Upload
    table = d.uploads

    async def find_by_hash(self, org_id: UUID, source_id: UUID, sha256: str) -> Upload | None:
        """The live upload of this file, if any (matches ``uq_uploads_live_sha256``)."""
        u = d.uploads
        statement = select(Upload).where(
            u.c.org_id == org_id,
            u.c.source_id == source_id,
            u.c.sha256 == sha256,
            u.c.status.not_in((UploadStatus.FAILED.value, UploadStatus.REJECTED.value)),
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def get_by_run(self, org_id: UUID, run_id: UUID) -> Upload | None:
        statement = select(Upload).where(d.uploads.c.org_id == org_id, d.uploads.c.run_id == run_id)
        return (await self._s.execute(statement)).scalar_one_or_none()


def _sealed_under_other_key(blob: Any, active_key_id: str) -> ColumnElement[bool]:
    """A secret blob wrapped under a key other than ``active_key_id``: its key id
    is stored in clear in the blob header (``NF | version | length | key id``)."""
    key_id = func.substring(blob, 5, func.get_byte(blob, 3))
    condition: ColumnElement[bool] = and_(
        blob.is_not(None),
        func.octet_length(blob) > 4,
        key_id != literal(active_key_id.encode("ascii"), LargeBinary),
    )
    return condition


def _stale_endpoint(active_key_id: str) -> ColumnElement[bool]:
    w = d.webhook_endpoints
    return or_(
        _sealed_under_other_key(w.c.secret_ciphertext, active_key_id),
        _sealed_under_other_key(w.c.previous_secret_ciphertext, active_key_id),
    )


class SqlWebhookEndpointRepository(TenantRepository[WebhookEndpoint]):
    entity = WebhookEndpoint
    table = d.webhook_endpoints

    async def stale_for_update(
        self, org_id: UUID, active_key_id: str, *, after: UUID | None, limit: int
    ) -> list[WebhookEndpoint]:
        w = d.webhook_endpoints
        statement = (
            select(WebhookEndpoint)
            .where(w.c.org_id == org_id, _stale_endpoint(active_key_id))
            .order_by(w.c.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        if after is not None:
            statement = statement.where(w.c.id > after)
        return list((await self._s.execute(statement)).scalars().all())

    async def count_stale(self, org_id: UUID, active_key_id: str) -> int:
        w = d.webhook_endpoints
        statement = (
            select(func.count())
            .select_from(w)
            .where(w.c.org_id == org_id, _stale_endpoint(active_key_id))
        )
        return int((await self._s.execute(statement)).scalar_one())


class SqlWebhookEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, event: InboundWebhookEvent) -> bool:
        """Insert unless this delivery id was seen before (durable replay guard)."""
        statement = (
            pg_insert(d.inbound_webhook_events)
            .values(
                id=event.id,
                org_id=event.org_id,
                endpoint_id=event.endpoint_id,
                delivery_id=event.delivery_id,
                received_at=event.received_at,
                payload_sha256=event.payload_sha256,
                payload_size=event.payload_size,
                item_count=event.item_count,
                status=event.status.value,
                run_id=event.run_id,
            )
            .on_conflict_do_nothing(index_elements=["endpoint_id", "delivery_id"])
            .returning(d.inbound_webhook_events.c.id)
        )
        return (await self._s.execute(statement)).scalar_one_or_none() is not None

    async def exists(self, endpoint_id: UUID, delivery_id: str) -> bool:
        events = d.inbound_webhook_events
        statement = select(events.c.id).where(
            events.c.endpoint_id == endpoint_id, events.c.delivery_id == delivery_id
        )
        return (await self._s.execute(statement)).first() is not None

    async def get(self, org_id: UUID, event_id: UUID) -> InboundWebhookEvent | None:
        statement = select(InboundWebhookEvent).where(
            d.inbound_webhook_events.c.org_id == org_id, d.inbound_webhook_events.c.id == event_id
        )
        return (await self._s.execute(statement)).scalar_one_or_none()


class SqlWorkflowRepository(TenantRepository[Workflow]):
    entity = Workflow
    table = d.workflows
    sortable = ("created_at", "name")


class SqlWorkflowRunRepository(TenantRepository[WorkflowRun]):
    entity = WorkflowRun
    table = d.workflow_runs

    async def get_by_idempotency_key(self, org_id: UUID, key: str) -> WorkflowRun | None:
        statement = select(WorkflowRun).where(
            d.workflow_runs.c.org_id == org_id, d.workflow_runs.c.idempotency_key == key
        )
        return (await self._s.execute(statement)).scalar_one_or_none()


class SqlDeadLetterRepository(TenantRepository[DeadLetter]):
    entity = DeadLetter
    table = d.dead_letters
    sortable = ("first_failed_at",)


_PURGE_TARGETS = {
    "collection_runs": (d.collection_runs, d.collection_runs.c.created_at),
    "inbound_webhook_events": (d.inbound_webhook_events, d.inbound_webhook_events.c.received_at),
    "notification_deliveries": (d.notification_deliveries, d.notification_deliveries.c.created_at),
}
# The runtime role has no DELETE right on dead letters; this function deletes
# only old ones of the current tenant context (or platform-level ones outside
# any tenant) - migration 0005.
_PURGE_DEAD_LETTERS = text("SELECT nf_purge_dead_letters(:before)")


# Children removed bottom-up, in batches, before a dataset or an organization
# row goes: one cascading DELETE of a large dataset outlasts the statement
# timeout. Each entry scopes its table to a dataset (tables reached through
# sources or alert rules by subquery); workflow runs belong to projects.
_BATCHED_PURGE = {
    "record_versions": d.record_versions,
    "changes": d.changes,
    "records": d.records,
    "insights": d.insights,
    "inbound_webhook_events": d.inbound_webhook_events,
    "collection_runs": d.collection_runs,
    "notification_deliveries": d.notification_deliveries,
    "alerts": d.alerts,
    "workflow_runs": d.workflow_runs,
}


def _dataset_scope(target: str, dataset_id: UUID) -> ColumnElement[bool]:
    sources = select(d.sources.c.id).where(d.sources.c.dataset_id == dataset_id)
    rules = select(d.alert_rules.c.id).where(d.alert_rules.c.dataset_id == dataset_id)
    match target:
        case "record_versions" | "changes" | "records" | "insights":
            column: ColumnElement[bool] = _BATCHED_PURGE[target].c.dataset_id == dataset_id
            return column
        case "collection_runs":
            return d.collection_runs.c.source_id.in_(sources)
        case "inbound_webhook_events":
            endpoints = select(d.webhook_endpoints.c.id).where(
                d.webhook_endpoints.c.source_id.in_(sources)
            )
            return d.inbound_webhook_events.c.endpoint_id.in_(endpoints)
        case "alerts":
            return d.alerts.c.rule_id.in_(rules)
        case "notification_deliveries":
            alerts = select(d.alerts.c.id).where(d.alerts.c.rule_id.in_(rules))
            return d.notification_deliveries.c.alert_id.in_(alerts)
    raise ValueError(f"{target} rows are not purged per dataset")


# Tables that keep client idempotency keys. A released key of a NOT NULL column
# becomes a tombstone unique to its row (``expired:<id>``).
_KEYED = {
    "collection_runs": d.collection_runs,
    "workflow_runs": d.workflow_runs,
    "insights": d.insights,
    "reports": d.reports,
}


def _client_keys(target: str) -> ColumnElement[bool]:
    key = _KEYED[target].c.idempotency_key
    if target == "reports":
        return key.is_not(None)  # every report key came from a client
    if target == "workflow_runs":  # "manual:<key>": the form before digests
        return or_(key.like(f"{CLIENT_KEY_PREFIX}%"), key.like("manual:%"))
    return key.like(f"{CLIENT_KEY_PREFIX}%")  # internal keys (webhooks, slots) stay


class SqlMaintenanceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def expire_idempotency_keys(
        self, org_id: UUID, target: str, before: datetime, *, limit: int
    ) -> int:
        table = _KEYED[target]
        keyed = (
            select(table.c.id)
            .where(table.c.org_id == org_id, table.c.created_at < before, _client_keys(target))
            .limit(limit)
        )
        released: Any = (
            null()
            if table.c.idempotency_key.nullable
            else literal("expired:") + cast(table.c.id, String)
        )
        statement = (
            update(table)
            .where(table.c.id.in_(keyed))
            .values(idempotency_key=released)
            .execution_options(synchronize_session=False)
        )
        result = await self._s.execute(statement)
        return int(getattr(result, "rowcount", 0) or 0)

    async def purge(
        self, org_id: UUID | None, target: str, before: datetime, *, limit: int | None = None
    ) -> int:
        """Retention delete for an allowlisted table (never built from input): up
        to ``limit`` rows, so the caller can purge in short batches.

        Dead letters are purged in the unit of work's tenant context - or,
        with ``org_id=None``, the platform-level ones - all at once (their
        purge function takes no limit); every other target belongs to a tenant.
        """
        if target == "dead_letters":
            return int(
                (await self._s.execute(_PURGE_DEAD_LETTERS, {"before": before})).scalar_one()
            )
        if org_id is None:
            raise ValueError(f"{target} rows always belong to a tenant")
        table, column = _PURGE_TARGETS[target]
        doomed = select(table.c.id).where(table.c.org_id == org_id, column < before)
        if target == "collection_runs":
            doomed = doomed.where(
                table.c.status.in_(
                    [s.value for s in RunStatus if s not in (RunStatus.QUEUED, RunStatus.RUNNING)]
                )
            )
        return await _delete_ids(self._s, table, doomed.limit(limit))

    async def delete_batch(
        self, org_id: UUID, target: str, *, dataset_id: UUID | None, limit: int
    ) -> int:
        table = _BATCHED_PURGE[target]
        doomed = select(table.c.id).where(table.c.org_id == org_id)
        if dataset_id is not None:
            doomed = doomed.where(_dataset_scope(target, dataset_id))
        return await _delete_ids(self._s, table, doomed.limit(limit))

    async def file_keys(
        self,
        org_id: UUID,
        *,
        project_id: UUID | None = None,
        dataset_id: UUID | None = None,
        source_id: UUID | None = None,
    ) -> list[str]:
        """Storage keys of the uploads and reports a project, dataset or source holds."""
        u, s, r = d.uploads, d.sources, d.reports
        sources = select(s.c.id).where(s.c.org_id == org_id)
        reports = select(r.c.storage_key).where(r.c.org_id == org_id, r.c.storage_key.is_not(None))
        if source_id is not None:
            sources = sources.where(s.c.id == source_id)
            reports = reports.where(false())  # a source holds no reports
        if dataset_id is not None:
            sources = sources.where(s.c.dataset_id == dataset_id)
            reports = reports.where(r.c.dataset_id == dataset_id)
        if project_id is not None:
            sources = sources.where(s.c.project_id == project_id)
            reports = reports.where(r.c.project_id == project_id)
        uploads = select(u.c.storage_key).where(u.c.org_id == org_id, u.c.source_id.in_(sources))
        keys = (await self._s.execute(union(uploads, reports))).scalars().all()
        return sorted(str(key) for key in keys)

    async def referenced_keys(self, org_id: UUID, keys: Sequence[str]) -> set[str]:
        """Which of ``keys`` an upload or a report still points to."""
        if not keys:
            return set()
        uploads = select(d.uploads.c.storage_key).where(
            d.uploads.c.org_id == org_id, d.uploads.c.storage_key.in_(list(keys))
        )
        reports = select(d.reports.c.storage_key).where(
            d.reports.c.org_id == org_id, d.reports.c.storage_key.in_(list(keys))
        )
        return {str(key) for key in (await self._s.execute(union(uploads, reports))).scalars()}

    async def stuck_deliveries(
        self, org_id: UUID, *, before: datetime, limit: int
    ) -> list[NotificationDelivery]:
        n = d.notification_deliveries
        statement = (
            select(NotificationDelivery)
            .where(n.c.org_id == org_id, n.c.status == "sending", n.c.claimed_at < before)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def delete_organization(self, org_id: UUID) -> None:
        await self._s.execute(delete(t.organizations).where(t.organizations.c.id == org_id))

    async def purge_outbox(self, before: datetime, *, limit: int) -> int:
        o = t.outbox_messages
        doomed = (
            select(o.c.id).where(o.c.dispatched_at.is_not(None), o.c.dispatched_at < before)
        ).limit(limit)
        return await _delete_ids(self._s, o, doomed)


class SqlSystemQueries:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def due_workflows(self, now: datetime, limit: int) -> list[tuple[UUID, UUID]]:
        rows = await self._s.execute(
            text("SELECT org_id, workflow_id FROM nf_due_workflows(:now, :limit)"),
            {"now": now, "limit": limit},
        )
        return [(row.org_id, row.workflow_id) for row in rows]

    async def pending_detection(self, limit: int) -> list[tuple[UUID, UUID]]:
        rows = await self._s.execute(
            text("SELECT org_id, dataset_id FROM nf_pending_detection(:limit)"), {"limit": limit}
        )
        return [(row.org_id, row.dataset_id) for row in rows]

    async def tenant_ids(self, statuses: Sequence[str]) -> list[UUID]:
        rows = await self._s.execute(
            text("SELECT nf_tenant_ids AS id FROM nf_tenant_ids(:statuses)"),
            {"statuses": list(statuses)},
        )
        return [row.id for row in rows]

    async def orgs_due_for_purge(self, before: datetime) -> list[UUID]:
        rows = await self._s.execute(
            text("SELECT nf_orgs_due_for_purge AS id FROM nf_orgs_due_for_purge(:before)"),
            {"before": before},
        )
        return [row.id for row in rows]

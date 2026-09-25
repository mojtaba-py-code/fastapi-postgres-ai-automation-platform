"""Projects, datasets, records and changes (read side) and dataset export."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import AsyncIterator, Mapping
from typing import Any, Literal
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import ConflictError, InvalidInputError, NotFoundError
from nexusflow.core.ids import uuid7
from nexusflow.core.jsonutil import JSONValue
from nexusflow.core.pagination import (
    MAX_PAGE_SIZE,
    Cursor,
    Page,
    PageRequest,
    decode_cursor,
)
from nexusflow.core.text import clean_text, required_name, spreadsheet_safe
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.catalog.model import (
    DataClassification,
    Dataset,
    DatasetSchema,
    Project,
    ProjectStatus,
)
from nexusflow.domain.records.model import Change, Record, RecordVersion
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.files import file_deletions
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory

MASKED = "[masked]"
_EXPORT_BATCH = 500

type ExportFormat = Literal["csv", "jsonl"]


def mask_data(
    data: Mapping[str, Any], sensitive: frozenset[str], *, reveal: bool
) -> dict[str, Any]:
    if reveal or not sensitive:
        return dict(data)
    return {key: (MASKED if key in sensitive else value) for key, value in data.items()}


def mask_diff(
    diff: Mapping[str, Any], sensitive: frozenset[str], *, reveal: bool
) -> dict[str, Any]:
    if reveal or not sensitive:
        return dict(diff)
    return {
        key: ({"old": MASKED, "new": MASKED} if key in sensitive else value)
        for key, value in diff.items()
    }


def describe_field_change(name: str, entry: Any) -> str | None:
    """``price: 9.90 -> 12.50 (+26.3%)`` - one wording for alerts and reports.

    ``None`` when ``entry`` is not an old/new pair. Values are cleaned and
    bounded; a masked value stays masked.
    """
    if not isinstance(entry, dict):
        return None
    pct = entry.get("pct")
    moved = f" ({pct:+.1f}%)" if isinstance(pct, (int, float)) and not isinstance(pct, bool) else ""
    return f"{name}: {_shown(entry.get('old'))} -> {_shown(entry.get('new'))}{moved}"


def _shown(value: Any) -> str:
    if value is None:
        return "-"
    if value == MASKED:
        return MASKED
    return clean_text(str(value), max_length=120)


def ensure_schema_compatible(old: DatasetSchema, new: DatasetSchema) -> None:
    """Additive evolution only: existing fields keep their type, new ones are optional."""
    if old.key_field != new.key_field:
        raise InvalidInputError("The key field cannot be changed.", code="schema_incompatible")
    new_fields = {f.name: f for f in new.fields}
    for existing in old.fields:
        replacement = new_fields.get(existing.name)
        if replacement is None or replacement.type is not existing.type:
            raise InvalidInputError(
                f"Field {existing.name!r} cannot be removed or change type.",
                code="schema_incompatible",
            )
    old_names = {f.name for f in old.fields}
    for name, spec in new_fields.items():
        if name not in old_names and spec.required:
            raise InvalidInputError(
                f"New field {name!r} must be optional.", code="schema_incompatible"
            )


class CatalogService:
    def __init__(
        self, *, uow_factory: UnitOfWorkFactory, clock: Clock, audit: AuditRecorder
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit

    # ------------------------------------------------------------ projects

    async def create_project(
        self, principal: Principal, *, name: str, description: str | None, meta: RequestMeta
    ) -> Project:
        principal.require(Permission.PROJECTS_WRITE)
        org_id = principal.require_org()
        now = self._clock.now()
        project = Project(
            id=uuid7(),
            org_id=org_id,
            name=required_name(name),
            description=clean_text(description, max_length=1000, multiline=True)
            if description
            else None,
            created_by=principal.actor_user_id,
            created_at=now,
            updated_at=now,
        )
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            await uow.data.projects.add(project)
            await self._audit.record(
                uow.audit,
                action=AuditAction.PROJECT_CREATED,
                principal=principal,
                meta=meta,
                resource_type="project",
                resource_id=project.id,
                metadata={"name": project.name},
            )
            await uow.commit()
        return project

    async def list_projects(self, principal: Principal, page: PageRequest) -> Page[Project]:
        principal.require(Permission.PROJECTS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.projects.list_page(principal.require_org(), page)

    async def get_project(self, principal: Principal, project_id: UUID) -> Project:
        principal.require(Permission.PROJECTS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await _project(uow, principal, project_id)

    async def update_project(
        self,
        principal: Principal,
        project_id: UUID,
        *,
        name: str | None,
        description: str | None,
        status: ProjectStatus | None,
        meta: RequestMeta,
    ) -> Project:
        principal.require(Permission.PROJECTS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            project = await uow.data.projects.get_for_update(org_id, project_id)
            if project is None:
                raise NotFoundError()
            if name is not None:
                project.name = required_name(name)
            if description is not None:
                project.description = clean_text(description, max_length=1000, multiline=True)
            if status is not None:
                project.status = status
            project.updated_at = self._clock.now()
            await self._audit.record(
                uow.audit,
                action=AuditAction.PROJECT_UPDATED,
                principal=principal,
                meta=meta,
                resource_type="project",
                resource_id=project.id,
                metadata={"status": project.status},
            )
            await uow.commit()
            return project

    async def delete_project(
        self, principal: Principal, project_id: UUID, meta: RequestMeta
    ) -> None:
        """Delete an empty project (its configuration goes with it).

        Refused while it still holds a live dataset: data is deleted explicitly,
        dataset by dataset, never as the side effect of removing a container.
        """
        principal.require(Permission.PROJECTS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            project = await uow.data.projects.get_for_update(org_id, project_id)
            if project is None:
                raise NotFoundError()
            live = await uow.data.datasets.list_page(
                org_id, PageRequest(limit=1), {"project_id": project_id}
            )
            if live.items:
                raise ConflictError(
                    "Delete the project's datasets first.", code="project_not_empty"
                )
            # The cascade removes the project's uploads and reports (those of
            # deleted datasets not purged yet included); their files follow the commit.
            keys = await uow.data.maintenance.file_keys(org_id, project_id=project_id)
            await uow.data.projects.delete(project)
            for message in file_deletions(org_id, keys, now=self._clock.now()):
                await uow.outbox.add(message)
            await self._audit.record(
                uow.audit,
                action=AuditAction.PROJECT_DELETED,
                principal=principal,
                meta=meta,
                resource_type="project",
                resource_id=project_id,
                metadata={"name": project.name},
            )
            await uow.commit()

    # ------------------------------------------------------------ datasets

    async def create_dataset(
        self,
        principal: Principal,
        *,
        project_id: UUID,
        name: str,
        description: str | None,
        schema: DatasetSchema,
        classification: DataClassification,
        retention_days: int,
        meta: RequestMeta,
    ) -> Dataset:
        principal.require(Permission.DATASETS_WRITE)
        org_id = principal.require_org()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            project = await _project(uow, principal, project_id)
            if project.status is not ProjectStatus.ACTIVE:
                raise ConflictError("The project is archived.", code="project_archived")
            dataset = Dataset(
                id=uuid7(),
                org_id=org_id,
                project_id=project.id,
                name=required_name(name),
                description=clean_text(description, max_length=1000, multiline=True)
                if description
                else None,
                schema=schema.model_dump(mode="json"),
                classification=classification,
                retention_days=retention_days,
                created_by=principal.actor_user_id,
                created_at=now,
                updated_at=now,
            )
            await uow.data.datasets.add(dataset)
            await self._audit.record(
                uow.audit,
                action=AuditAction.DATASET_CREATED,
                principal=principal,
                meta=meta,
                resource_type="dataset",
                resource_id=dataset.id,
                metadata={"classification": classification, "fields": len(schema.fields)},
            )
            await uow.commit()
        return dataset

    async def list_datasets(
        self, principal: Principal, page: PageRequest, *, project_id: UUID | None
    ) -> Page[Dataset]:
        principal.require(Permission.DATASETS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.datasets.list_page(
                principal.require_org(), page, {"project_id": project_id}
            )

    async def get_dataset(self, principal: Principal, dataset_id: UUID) -> Dataset:
        principal.require(Permission.DATASETS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await get_dataset(uow, principal.require_org(), dataset_id)

    async def update_dataset(
        self,
        principal: Principal,
        dataset_id: UUID,
        *,
        description: str | None,
        classification: DataClassification | None,
        retention_days: int | None,
        schema: DatasetSchema | None,
        meta: RequestMeta,
    ) -> Dataset:
        principal.require(Permission.DATASETS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            dataset = await uow.data.datasets.get_for_update(org_id, dataset_id)
            if dataset is None or dataset.is_deleted:
                raise NotFoundError()
            changes: dict[str, Any] = {}
            now = self._clock.now()
            if schema is not None:
                ensure_schema_compatible(dataset.spec, schema)
                newly_sensitive = schema.sensitive_fields - dataset.spec.sensitive_fields
                dataset.schema = schema.model_dump(mode="json")
                changes["schema_fields"] = len(schema.fields)
                if newly_sensitive:
                    # From now on these values are sealed as they are written; a job
                    # seals the values stored before (records, versions, diffs).
                    changes["sealing"] = sorted(newly_sensitive)
                    await uow.outbox.add(
                        new_message(
                            TaskName.SEAL_DATASET,
                            {"org_id": str(org_id), "dataset_id": str(dataset.id)},
                            org_id=org_id,
                            now=now,
                        )
                    )
            if description is not None:
                dataset.description = clean_text(description, max_length=1000, multiline=True)
            if classification is not None:
                changes["classification"] = classification
                dataset.classification = classification
            if retention_days is not None:
                changes["retention_days"] = retention_days
                dataset.retention_days = retention_days
            dataset.updated_at = now
            await self._audit.record(
                uow.audit,
                action=AuditAction.DATASET_UPDATED,
                principal=principal,
                meta=meta,
                resource_type="dataset",
                resource_id=dataset.id,
                metadata=changes,
            )
            await uow.commit()
            return dataset

    async def delete_dataset(
        self, principal: Principal, dataset_id: UUID, meta: RequestMeta
    ) -> None:
        """Soft-delete immediately; a background job purges records and history."""
        principal.require(Permission.DATASETS_WRITE)
        org_id = principal.require_org()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            dataset = await uow.data.datasets.get_for_update(org_id, dataset_id)
            if dataset is None or dataset.is_deleted:
                raise NotFoundError()
            dataset.deleted_at = now
            dataset.updated_at = now
            await uow.outbox.add(
                new_message(
                    TaskName.PURGE_DATASET,
                    {"org_id": str(org_id), "dataset_id": str(dataset.id)},
                    org_id=org_id,
                    now=now,
                )
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.DATASET_DELETED,
                principal=principal,
                meta=meta,
                resource_type="dataset",
                resource_id=dataset.id,
            )
            await uow.commit()

    # ------------------------------------------------------ records/changes

    async def list_records(
        self, principal: Principal, dataset_id: UUID, page: PageRequest, *, include_deleted: bool
    ) -> tuple[Dataset, Page[Record]]:
        principal.require(Permission.RECORDS_READ)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            dataset = await get_dataset(uow, org_id, dataset_id)
            records = await uow.data.records.list_page(
                org_id, dataset_id, page, include_deleted=include_deleted
            )
        reveal = principal.has(Permission.RECORDS_READ_SENSITIVE)
        sensitive = dataset.spec.sensitive_fields
        for record in records.items:
            record.data = mask_data(record.data, sensitive, reveal=reveal)
        return dataset, records

    async def record_history(
        self, principal: Principal, record_id: UUID, *, limit: int = 50
    ) -> tuple[Record, list[RecordVersion]]:
        principal.require(Permission.RECORDS_READ)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            record = await uow.data.records.get(org_id, record_id)
            if record is None:
                raise NotFoundError()
            dataset = await get_dataset(uow, org_id, record.dataset_id)
            versions = await uow.data.records.history(org_id, record_id, limit=min(limit, 200))
        reveal = principal.has(Permission.RECORDS_READ_SENSITIVE)
        sensitive = dataset.spec.sensitive_fields
        record.data = mask_data(record.data, sensitive, reveal=reveal)
        for version in versions:
            version.data = mask_data(version.data, sensitive, reveal=reveal)
        return record, versions

    async def list_changes(
        self, principal: Principal, page: PageRequest, filters: Mapping[str, Any]
    ) -> Page[Change]:
        principal.require(Permission.CHANGES_READ)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            result = await uow.data.changes.list_page(org_id, page, filters)
            schemas = await _sensitive_by_dataset(uow, org_id, {c.dataset_id for c in result.items})
        reveal = principal.has(Permission.RECORDS_READ_SENSITIVE)
        for change in result.items:
            change.diff = mask_diff(
                change.diff, schemas.get(change.dataset_id, frozenset()), reveal=reveal
            )
        return result

    # ---------------------------------------------------------------- export

    async def export_dataset(
        self, principal: Principal, dataset_id: UUID, *, fmt: ExportFormat, meta: RequestMeta
    ) -> tuple[Dataset, AsyncIterator[bytes]]:
        """Audited, streaming export. Each batch uses its own short transaction."""
        principal.require(Permission.DATASETS_EXPORT)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            dataset = await get_dataset(uow, org_id, dataset_id)
            await self._audit.record(
                uow.audit,
                action=AuditAction.DATASET_EXPORTED,
                principal=principal,
                meta=meta,
                resource_type="dataset",
                resource_id=dataset.id,
                metadata={"format": fmt},
            )
            await uow.commit()
        reveal = principal.has(Permission.RECORDS_READ_SENSITIVE)
        spec = dataset.spec
        columns = ["record_key", *[f.name for f in spec.fields], "first_seen_at", "last_seen_at"]

        async def stream() -> AsyncIterator[bytes]:
            if fmt == "csv":
                yield _csv_line(columns)
            async for batch in self._batches(principal, dataset_id):
                for record in batch:
                    data = mask_data(record.data, spec.sensitive_fields, reveal=reveal)
                    row: dict[str, Any] = {
                        "record_key": record.record_key,
                        **data,
                        "first_seen_at": record.first_seen_at.isoformat(),
                        "last_seen_at": record.last_seen_at.isoformat(),
                    }
                    if fmt == "csv":
                        yield _csv_line([row.get(c) for c in columns])
                    else:
                        yield (json.dumps(row, ensure_ascii=False, default=str) + "\n").encode()

        return dataset, stream()

    async def _batches(self, principal: Principal, dataset_id: UUID) -> AsyncIterator[list[Record]]:
        org_id = principal.require_org()
        last_seen: UUID | None = None
        while True:
            async with self._uow_factory(TenantScope.of(principal)) as uow:
                batch = await uow.data.records.batch_after(
                    org_id, dataset_id, after=last_seen, limit=_EXPORT_BATCH
                )
            if not batch:
                return
            yield batch
            last_seen = batch[-1].id


def _csv_line(values: list[Any]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow([_cell(v) for v in values])
    return buffer.getvalue().encode("utf-8")


def _cell(value: JSONValue | Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return spreadsheet_safe(str(value))


async def _project(uow: UnitOfWork, principal: Principal, project_id: UUID) -> Project:
    project = await uow.data.projects.get(principal.require_org(), project_id)
    if project is None:
        raise NotFoundError()
    return project


async def get_dataset(uow: UnitOfWork, org_id: UUID, dataset_id: UUID) -> Dataset:
    dataset = await uow.data.datasets.get(org_id, dataset_id)
    if dataset is None or dataset.is_deleted:
        raise NotFoundError()
    return dataset


async def project_datasets(uow: UnitOfWork, org_id: UUID, project_id: UUID) -> list[Dataset]:
    """Every live dataset of a project, however many pages they take."""
    return await _live_datasets(uow, org_id, {"project_id": project_id})


async def tenant_datasets(uow: UnitOfWork, org_id: UUID) -> list[Dataset]:
    """Every live dataset of an organization, however many pages they take."""
    return await _live_datasets(uow, org_id, {})


async def _live_datasets(
    uow: UnitOfWork, org_id: UUID, filters: Mapping[str, Any]
) -> list[Dataset]:
    datasets: list[Dataset] = []
    cursor: Cursor | None = None
    while True:
        page = await uow.data.datasets.list_page(
            org_id, PageRequest(limit=MAX_PAGE_SIZE, cursor=cursor), filters
        )
        datasets.extend(page.items)
        if page.next_cursor is None:
            return datasets
        cursor = decode_cursor(page.next_cursor)


async def _sensitive_by_dataset(
    uow: UnitOfWork, org_id: UUID, dataset_ids: set[UUID]
) -> dict[UUID, frozenset[str]]:
    result: dict[UUID, frozenset[str]] = {}
    for dataset_id in dataset_ids:
        dataset = await uow.data.datasets.get(org_id, dataset_id)
        if dataset is not None:
            result[dataset_id] = dataset.spec.sensitive_fields
    return result

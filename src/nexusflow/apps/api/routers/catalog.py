"""/api/v1/projects, /datasets, /records and /changes."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from fastapi.responses import StreamingResponse
from pydantic import AwareDatetime

from nexusflow.apps.api.dependencies import (
    ContainerDep,
    CurrentPrincipal,
    Meta,
    StateDep,
    budget_identity,
    page_params,
    require,
)
from nexusflow.apps.api.schemas.business import (
    ChangeOut,
    DatasetCreate,
    DatasetOut,
    DatasetUpdate,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    RecordHistoryOut,
    RecordOut,
    RecordVersionOut,
)
from nexusflow.apps.api.schemas.common import ERROR_RESPONSES, PageResponse
from nexusflow.core.pagination import PageRequest, SortSpec
from nexusflow.core.text import content_disposition, slugify
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.records.model import ChangeType, Significance

projects = APIRouter(prefix="/projects", tags=["projects"], responses=ERROR_RESPONSES)
datasets = APIRouter(prefix="/datasets", tags=["datasets"], responses=ERROR_RESPONSES)
records = APIRouter(prefix="/records", tags=["datasets"], responses=ERROR_RESPONSES)
changes = APIRouter(prefix="/changes", tags=["changes"], responses=ERROR_RESPONSES)

NamedPage = Annotated[PageRequest, Depends(page_params(frozenset({"created_at", "name"})))]
RecordPage = Annotated[
    PageRequest,
    Depends(page_params(frozenset({"created_at", "last_seen_at"}), SortSpec("last_seen_at"))),
]
ChangePage = Annotated[
    PageRequest,
    Depends(page_params(frozenset({"detected_at", "score"}), SortSpec("detected_at"))),
]

_EXPORT_MEDIA_TYPES = {"csv": "text/csv; charset=utf-8", "jsonl": "application/x-ndjson"}


# ----------------------------------------------------------------- projects


@projects.post(
    "",
    response_model=ProjectOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.PROJECTS_WRITE))],
)
async def create_project(
    body: ProjectCreate, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> ProjectOut:
    project = await container.catalog.create_project(
        principal, name=body.name, description=body.description, meta=meta
    )
    return ProjectOut.model_validate(project)


@projects.get(
    "",
    response_model=PageResponse[ProjectOut],
    dependencies=[Depends(require(Permission.PROJECTS_READ))],
)
async def list_projects(
    principal: CurrentPrincipal, container: ContainerDep, page: NamedPage
) -> PageResponse[ProjectOut]:
    result = await container.catalog.list_projects(principal, page)
    return PageResponse[ProjectOut](
        items=[ProjectOut.model_validate(p) for p in result.items], next_cursor=result.next_cursor
    )


@projects.get(
    "/{project_id}",
    response_model=ProjectOut,
    dependencies=[Depends(require(Permission.PROJECTS_READ))],
)
async def get_project(
    project_id: UUID, principal: CurrentPrincipal, container: ContainerDep
) -> ProjectOut:
    return ProjectOut.model_validate(await container.catalog.get_project(principal, project_id))


@projects.patch(
    "/{project_id}",
    response_model=ProjectOut,
    dependencies=[Depends(require(Permission.PROJECTS_WRITE))],
)
async def update_project(
    project_id: UUID,
    body: ProjectUpdate,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> ProjectOut:
    project = await container.catalog.update_project(
        principal,
        project_id,
        name=body.name,
        description=body.description,
        status=body.status,
        meta=meta,
    )
    return ProjectOut.model_validate(project)


@projects.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.PROJECTS_WRITE))],
    summary="Delete an empty project (409 project_not_empty while it holds datasets)",
)
async def delete_project(
    project_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.catalog.delete_project(principal, project_id, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ----------------------------------------------------------------- datasets


@datasets.post(
    "",
    response_model=DatasetOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.DATASETS_WRITE))],
)
async def create_dataset(
    body: DatasetCreate, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> DatasetOut:
    dataset = await container.catalog.create_dataset(
        principal,
        project_id=body.project_id,
        name=body.name,
        description=body.description,
        schema=body.schema_,
        classification=body.classification,
        retention_days=body.retention_days,
        meta=meta,
    )
    return DatasetOut.model_validate(dataset)


@datasets.get(
    "",
    response_model=PageResponse[DatasetOut],
    dependencies=[Depends(require(Permission.DATASETS_READ))],
)
async def list_datasets(
    principal: CurrentPrincipal,
    container: ContainerDep,
    page: NamedPage,
    project_id: UUID | None = None,
) -> PageResponse[DatasetOut]:
    result = await container.catalog.list_datasets(principal, page, project_id=project_id)
    return PageResponse[DatasetOut](
        items=[DatasetOut.model_validate(d) for d in result.items], next_cursor=result.next_cursor
    )


@datasets.get(
    "/{dataset_id}",
    response_model=DatasetOut,
    dependencies=[Depends(require(Permission.DATASETS_READ))],
)
async def get_dataset(
    dataset_id: UUID, principal: CurrentPrincipal, container: ContainerDep
) -> DatasetOut:
    return DatasetOut.model_validate(await container.catalog.get_dataset(principal, dataset_id))


@datasets.patch(
    "/{dataset_id}",
    response_model=DatasetOut,
    dependencies=[Depends(require(Permission.DATASETS_WRITE))],
)
async def update_dataset(
    dataset_id: UUID,
    body: DatasetUpdate,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> DatasetOut:
    dataset = await container.catalog.update_dataset(
        principal,
        dataset_id,
        description=body.description,
        classification=body.classification,
        retention_days=body.retention_days,
        schema=body.schema_,
        meta=meta,
    )
    return DatasetOut.model_validate(dataset)


@datasets.delete(
    "/{dataset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.DATASETS_WRITE))],
    summary="Delete a dataset (records are purged asynchronously)",
)
async def delete_dataset(
    dataset_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.catalog.delete_dataset(principal, dataset_id, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@datasets.get(
    "/{dataset_id}/records",
    response_model=PageResponse[RecordOut],
    dependencies=[Depends(require(Permission.RECORDS_READ))],
    summary="Current records (sensitive fields masked without records:read_sensitive)",
)
async def list_records(
    dataset_id: UUID,
    principal: CurrentPrincipal,
    container: ContainerDep,
    page: RecordPage,
    include_deleted: bool = False,
) -> PageResponse[RecordOut]:
    _, result = await container.catalog.list_records(
        principal, dataset_id, page, include_deleted=include_deleted
    )
    return PageResponse[RecordOut](
        items=[RecordOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@datasets.get(
    "/{dataset_id}/export",
    dependencies=[Depends(require(Permission.DATASETS_EXPORT))],
    response_class=StreamingResponse,
    responses={200: {"content": {"text/csv": {}, "application/x-ndjson": {}}}},
    summary="Stream a full export (audited; CSV cells are formula-escaped)",
)
async def export_dataset(
    dataset_id: UUID,
    principal: CurrentPrincipal,
    container: ContainerDep,
    state: StateDep,
    meta: Meta,
    fmt: Annotated[Literal["csv", "jsonl"], Query(alias="format")] = "csv",
) -> StreamingResponse:
    rule = container.settings.rate_limits.rules["api.export"]
    await state.limiter.enforce("api.export", budget_identity(principal), rule)
    dataset, stream = await container.catalog.export_dataset(
        principal, dataset_id, fmt=fmt, meta=meta
    )
    filename = f"{slugify(dataset.name) or 'dataset'}.{fmt}"
    return StreamingResponse(
        stream,
        media_type=_EXPORT_MEDIA_TYPES[fmt],
        headers={"Content-Disposition": content_disposition(filename), "Cache-Control": "no-store"},
    )


@records.get(
    "/{record_id}/history",
    response_model=RecordHistoryOut,
    dependencies=[Depends(require(Permission.RECORDS_READ))],
)
async def record_history(
    record_id: UUID,
    principal: CurrentPrincipal,
    container: ContainerDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> RecordHistoryOut:
    record, versions = await container.catalog.record_history(principal, record_id, limit=limit)
    return RecordHistoryOut(
        record=RecordOut.model_validate(record),
        versions=[RecordVersionOut.model_validate(v) for v in versions],
    )


# ------------------------------------------------------------------ changes


@changes.get(
    "",
    response_model=PageResponse[ChangeOut],
    dependencies=[Depends(require(Permission.CHANGES_READ))],
)
async def list_changes(
    principal: CurrentPrincipal,
    container: ContainerDep,
    page: ChangePage,
    dataset_id: UUID | None = None,
    record_id: UUID | None = None,
    change_type: ChangeType | None = None,
    min_significance: Significance | None = None,
    since: AwareDatetime | None = None,
) -> PageResponse[ChangeOut]:
    filters = {
        "dataset_id": dataset_id,
        "record_id": record_id,
        "change_type": change_type.value if change_type else None,
        "min_significance": min_significance.value if min_significance else None,
        "since": since,
    }
    result = await container.catalog.list_changes(principal, page, filters)
    return PageResponse[ChangeOut](
        items=[ChangeOut.model_validate(c) for c in result.items], next_cursor=result.next_cursor
    )

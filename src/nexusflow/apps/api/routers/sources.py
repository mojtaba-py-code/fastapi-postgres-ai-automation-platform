"""/api/v1/sources (+ runs and uploads), /integrations and /webhook-endpoints."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from starlette.datastructures import UploadFile

from nexusflow.apps.api.dependencies import (
    ContainerDep,
    CurrentPrincipal,
    DefaultPage,
    IdempotencyKey,
    Meta,
    page_params,
    require,
)
from nexusflow.apps.api.schemas.business import (
    IntegrationCreate,
    IntegrationCreatedOut,
    IntegrationOut,
    IntegrationRotate,
    IntegrationStatusChange,
    RunOut,
    SourceCreate,
    SourceOut,
    SourceUpdate,
    UploadOut,
    WebhookEndpointCreate,
    WebhookEndpointCreatedOut,
    WebhookEndpointOut,
    WebhookStatusChange,
)
from nexusflow.apps.api.schemas.common import ERROR_RESPONSES, PageResponse
from nexusflow.core.errors import InvalidInputError, UnsupportedMediaTypeError
from nexusflow.core.pagination import PageRequest
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.sources.model import SourceKind, SourceStatus
from nexusflow.domain.webhooks.service import CreatedEndpoint

sources = APIRouter(prefix="/sources", tags=["sources"], responses=ERROR_RESPONSES)
runs = APIRouter(prefix="/runs", tags=["sources"], responses=ERROR_RESPONSES)
integrations = APIRouter(prefix="/integrations", tags=["integrations"], responses=ERROR_RESPONSES)
webhook_endpoints = APIRouter(
    prefix="/webhook-endpoints", tags=["webhooks"], responses=ERROR_RESPONSES
)

NamedPage = Annotated[PageRequest, Depends(page_params(frozenset({"created_at", "name"})))]

_UPLOAD_CHUNK = 64 * 1024


# ------------------------------------------------------------------ sources


@sources.post(
    "",
    response_model=SourceOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.SOURCES_WRITE))],
    summary="Create a source (URLs are SSRF-validated; CSS selectors are compiled and bounded)",
)
async def create_source(
    body: SourceCreate, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> SourceOut:
    source = await container.sources.create(
        principal,
        project_id=body.project_id,
        dataset_id=body.dataset_id,
        name=body.name,
        config=body.config,
        integration_id=body.integration_id,
        meta=meta,
    )
    return SourceOut.model_validate(source)


@sources.get(
    "",
    response_model=PageResponse[SourceOut],
    dependencies=[Depends(require(Permission.SOURCES_READ))],
)
async def list_sources(
    principal: CurrentPrincipal,
    container: ContainerDep,
    page: NamedPage,
    project_id: UUID | None = None,
    dataset_id: UUID | None = None,
    kind: SourceKind | None = None,
    source_status: Annotated[SourceStatus | None, Query(alias="status")] = None,
) -> PageResponse[SourceOut]:
    filters = {
        "project_id": project_id,
        "dataset_id": dataset_id,
        "kind": kind.value if kind else None,
        "status": source_status.value if source_status else None,
    }
    result = await container.sources.list(principal, page, filters)
    return PageResponse[SourceOut](
        items=[SourceOut.model_validate(s) for s in result.items], next_cursor=result.next_cursor
    )


@sources.get(
    "/{source_id}",
    response_model=SourceOut,
    dependencies=[Depends(require(Permission.SOURCES_READ))],
)
async def get_source(
    source_id: UUID, principal: CurrentPrincipal, container: ContainerDep
) -> SourceOut:
    return SourceOut.model_validate(await container.sources.get(principal, source_id))


@sources.patch(
    "/{source_id}",
    response_model=SourceOut,
    dependencies=[Depends(require(Permission.SOURCES_WRITE))],
)
async def update_source(
    source_id: UUID,
    body: SourceUpdate,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> SourceOut:
    source = await container.sources.update(
        principal,
        source_id,
        name=body.name,
        config=body.config,
        integration_id=body.integration_id,
        clear_integration=body.clear_integration,
        status=SourceStatus(body.status) if body.status else None,
        meta=meta,
    )
    return SourceOut.model_validate(source)


@sources.delete(
    "/{source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.SOURCES_WRITE))],
)
async def delete_source(
    source_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.sources.delete(principal, source_id, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@sources.post(
    "/{source_id}/runs",
    response_model=RunOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require(Permission.SOURCES_RUN))],
    summary="Queue a collection run now (idempotent with an Idempotency-Key header)",
)
async def run_source(
    source_id: UUID,
    response: Response,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
    idempotency_key: IdempotencyKey = None,
) -> RunOut:
    run, created = await container.sources.request_run(
        principal, source_id, idempotency_key=idempotency_key, meta=meta
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return RunOut.model_validate(run)


@sources.get(
    "/{source_id}/runs",
    response_model=PageResponse[RunOut],
    dependencies=[Depends(require(Permission.SOURCES_READ))],
)
async def list_source_runs(
    source_id: UUID, principal: CurrentPrincipal, container: ContainerDep, page: DefaultPage
) -> PageResponse[RunOut]:
    result = await container.sources.list_runs(principal, page, source_id=source_id)
    return PageResponse[RunOut](
        items=[RunOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


async def _chunks(upload: UploadFile) -> AsyncIterator[bytes]:
    while chunk := await upload.read(_UPLOAD_CHUNK):
        yield chunk


@sources.post(
    "/{source_id}/uploads",
    response_model=UploadOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.UPLOADS_WRITE))],
    summary="Upload a CSV/XLSX file (multipart 'file'; sniffed, scanned, parsed in a sandbox)",
)
async def upload_file(
    source_id: UUID,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> UploadOut:
    content_type = request.headers.get("content-type", "")
    if not content_type.lower().startswith("multipart/form-data"):
        raise UnsupportedMediaTypeError("Expected a multipart/form-data body.")
    # One file part, no other fields: parser resource use is bounded up front.
    async with request.form(max_files=1, max_fields=1, max_part_size=1024) as form:
        file = form.get("file")
        if not isinstance(file, UploadFile):
            raise InvalidInputError(
                "A multipart part named 'file' is required.", code="file_required"
            )
        upload, created = await container.uploads.accept(
            principal, source_id=source_id, filename=file.filename, content=_chunks(file), meta=meta
        )
    if not created:
        response.status_code = status.HTTP_200_OK
    return UploadOut.model_validate(upload)


@sources.get(
    "/{source_id}/uploads",
    response_model=PageResponse[UploadOut],
    dependencies=[Depends(require(Permission.SOURCES_READ))],
)
async def list_uploads(
    source_id: UUID, principal: CurrentPrincipal, container: ContainerDep, page: DefaultPage
) -> PageResponse[UploadOut]:
    result = await container.uploads.list(principal, page, source_id=source_id)
    return PageResponse[UploadOut](
        items=[UploadOut.model_validate(u) for u in result.items], next_cursor=result.next_cursor
    )


@runs.get(
    "/{run_id}", response_model=RunOut, dependencies=[Depends(require(Permission.SOURCES_READ))]
)
async def get_run(run_id: UUID, principal: CurrentPrincipal, container: ContainerDep) -> RunOut:
    return RunOut.model_validate(await container.sources.get_run(principal, run_id))


# ------------------------------------------------------------- integrations


@integrations.post(
    "",
    response_model=IntegrationCreatedOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.INTEGRATIONS_WRITE))],
    summary="Store a credential (encrypted at rest; never returned by the API)",
)
async def create_integration(
    body: IntegrationCreate, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> IntegrationCreatedOut:
    created = await container.integrations.create(
        principal,
        name=body.name,
        kind=body.kind,
        secret=body.secret,
        metadata=dict(body.metadata),
        meta=meta,
    )
    base = IntegrationOut.model_validate(created.integration)
    return IntegrationCreatedOut(**base.model_dump(), generated_secret=created.generated_secret)


@integrations.get(
    "",
    response_model=PageResponse[IntegrationOut],
    dependencies=[Depends(require(Permission.INTEGRATIONS_READ))],
)
async def list_integrations(
    principal: CurrentPrincipal, container: ContainerDep, page: NamedPage
) -> PageResponse[IntegrationOut]:
    result = await container.integrations.list(principal, page)
    return PageResponse[IntegrationOut](
        items=[IntegrationOut.model_validate(i) for i in result.items],
        next_cursor=result.next_cursor,
    )


@integrations.get(
    "/{integration_id}",
    response_model=IntegrationOut,
    dependencies=[Depends(require(Permission.INTEGRATIONS_READ))],
)
async def get_integration(
    integration_id: UUID, principal: CurrentPrincipal, container: ContainerDep
) -> IntegrationOut:
    return IntegrationOut.model_validate(
        await container.integrations.get(principal, integration_id)
    )


@integrations.post(
    "/{integration_id}/rotate",
    response_model=IntegrationOut,
    dependencies=[Depends(require(Permission.INTEGRATIONS_WRITE))],
)
async def rotate_integration(
    integration_id: UUID,
    body: IntegrationRotate,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> IntegrationOut:
    integration = await container.integrations.rotate(
        principal,
        integration_id,
        secret=body.secret,
        metadata=dict(body.metadata) if body.metadata is not None else None,
        meta=meta,
    )
    return IntegrationOut.model_validate(integration)


@integrations.post(
    "/{integration_id}/status",
    response_model=IntegrationOut,
    dependencies=[Depends(require(Permission.INTEGRATIONS_WRITE))],
    summary="Revoke or quarantine a credential (e.g. suspected leak)",
)
async def set_integration_status(
    integration_id: UUID,
    body: IntegrationStatusChange,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> IntegrationOut:
    integration = await container.integrations.set_status(
        principal, integration_id, status=body.status, reason=body.reason, meta=meta
    )
    return IntegrationOut.model_validate(integration)


@integrations.delete(
    "/{integration_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.INTEGRATIONS_WRITE))],
)
async def delete_integration(
    integration_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.integrations.delete(principal, integration_id, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# -------------------------------------------------------- webhook endpoints


def _created_endpoint(created: CreatedEndpoint) -> WebhookEndpointCreatedOut:
    base = WebhookEndpointOut.model_validate(created.endpoint)
    return WebhookEndpointCreatedOut(**base.model_dump(), url=created.url, secret=created.secret)


@webhook_endpoints.post(
    "",
    response_model=WebhookEndpointCreatedOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.WEBHOOKS_WRITE))],
    summary="Create an inbound endpoint (the signing secret is shown once)",
)
async def create_webhook_endpoint(
    body: WebhookEndpointCreate, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> WebhookEndpointCreatedOut:
    created = await container.webhooks.create_endpoint(
        principal, source_id=body.source_id, name=body.name, meta=meta
    )
    return _created_endpoint(created)


@webhook_endpoints.get(
    "",
    response_model=PageResponse[WebhookEndpointOut],
    dependencies=[Depends(require(Permission.WEBHOOKS_READ))],
)
async def list_webhook_endpoints(
    principal: CurrentPrincipal, container: ContainerDep, page: DefaultPage
) -> PageResponse[WebhookEndpointOut]:
    result = await container.webhooks.list_endpoints(principal, page)
    return PageResponse[WebhookEndpointOut](
        items=[WebhookEndpointOut.model_validate(e) for e in result.items],
        next_cursor=result.next_cursor,
    )


@webhook_endpoints.post(
    "/{endpoint_id}/rotate-secret",
    response_model=WebhookEndpointCreatedOut,
    dependencies=[Depends(require(Permission.WEBHOOKS_WRITE))],
    summary="Rotate the signing secret (the previous one stays valid for a grace period)",
)
async def rotate_webhook_secret(
    endpoint_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> WebhookEndpointCreatedOut:
    return _created_endpoint(await container.webhooks.rotate_secret(principal, endpoint_id, meta))


@webhook_endpoints.post(
    "/{endpoint_id}/status",
    response_model=WebhookEndpointOut,
    dependencies=[Depends(require(Permission.WEBHOOKS_WRITE))],
)
async def set_webhook_status(
    endpoint_id: UUID,
    body: WebhookStatusChange,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> WebhookEndpointOut:
    endpoint = await container.webhooks.set_status(
        principal, endpoint_id, status=body.status, meta=meta
    )
    return WebhookEndpointOut.model_validate(endpoint)

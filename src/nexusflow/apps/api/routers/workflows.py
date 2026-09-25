"""/api/v1/workflows (+ runs) and /dead-letters."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from nexusflow.apps.api.dependencies import (
    ContainerDep,
    CurrentPrincipal,
    DefaultPage,
    IdempotencyKey,
    Meta,
    page_params,
    require,
    require_any,
)
from nexusflow.apps.api.schemas.business import (
    DeadLetterOut,
    WorkflowCreate,
    WorkflowOut,
    WorkflowRunOut,
    WorkflowStatusChange,
    WorkflowUpdate,
)
from nexusflow.apps.api.schemas.common import ERROR_RESPONSES, PageResponse
from nexusflow.core.pagination import PageRequest, SortSpec
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.automation.model import DeadLetterStatus

workflows = APIRouter(prefix="/workflows", tags=["workflows"], responses=ERROR_RESPONSES)
dead_letters = APIRouter(prefix="/dead-letters", tags=["workflows"], responses=ERROR_RESPONSES)

NamedPage = Annotated[PageRequest, Depends(page_params(frozenset({"created_at", "name"})))]
FailurePage = Annotated[
    PageRequest,
    Depends(page_params(frozenset({"first_failed_at"}), SortSpec("first_failed_at"))),
]


@workflows.post(
    "",
    response_model=WorkflowOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.WORKFLOWS_WRITE))],
)
async def create_workflow(
    body: WorkflowCreate, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> WorkflowOut:
    workflow = await container.workflows.create(
        principal,
        project_id=body.project_id,
        name=body.name,
        description=body.description,
        trigger=body.trigger,
        interval_minutes=body.schedule_interval_minutes,
        source_ids=list(body.source_ids),
        analyze=body.analyze,
        alert=body.alert,
        meta=meta,
    )
    return WorkflowOut.model_validate(workflow)


@workflows.get(
    "",
    response_model=PageResponse[WorkflowOut],
    dependencies=[Depends(require(Permission.WORKFLOWS_READ))],
)
async def list_workflows(
    principal: CurrentPrincipal,
    container: ContainerDep,
    page: NamedPage,
    project_id: UUID | None = None,
) -> PageResponse[WorkflowOut]:
    result = await container.workflows.list(principal, page, project_id=project_id)
    return PageResponse[WorkflowOut](
        items=[WorkflowOut.model_validate(w) for w in result.items], next_cursor=result.next_cursor
    )


@workflows.get(
    "/{workflow_id}",
    response_model=WorkflowOut,
    dependencies=[Depends(require(Permission.WORKFLOWS_READ))],
)
async def get_workflow(
    workflow_id: UUID, principal: CurrentPrincipal, container: ContainerDep
) -> WorkflowOut:
    return WorkflowOut.model_validate(await container.workflows.get(principal, workflow_id))


@workflows.patch(
    "/{workflow_id}",
    response_model=WorkflowOut,
    dependencies=[Depends(require(Permission.WORKFLOWS_WRITE))],
    summary="Update a workflow (pass expected_version for optimistic concurrency)",
)
async def update_workflow(
    workflow_id: UUID,
    body: WorkflowUpdate,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> WorkflowOut:
    workflow = await container.workflows.update(
        principal,
        workflow_id,
        name=body.name,
        description=body.description,
        interval_minutes=body.schedule_interval_minutes,
        source_ids=list(body.source_ids) if body.source_ids is not None else None,
        analyze=body.analyze,
        alert=body.alert,
        expected_version=body.expected_version,
        meta=meta,
    )
    return WorkflowOut.model_validate(workflow)


@workflows.post(
    "/{workflow_id}/status",
    response_model=WorkflowOut,
    dependencies=[Depends(require_any(Permission.WORKFLOWS_WRITE, Permission.WORKFLOWS_DISABLE))],
    summary="Activate, pause or disable (emergency stop) a workflow",
)
async def set_workflow_status(
    workflow_id: UUID,
    body: WorkflowStatusChange,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> WorkflowOut:
    workflow = await container.workflows.set_status(
        principal, workflow_id, status=body.status, reason=body.reason, meta=meta
    )
    return WorkflowOut.model_validate(workflow)


@workflows.delete(
    "/{workflow_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.WORKFLOWS_WRITE))],
)
async def delete_workflow(
    workflow_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.workflows.delete(principal, workflow_id, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@workflows.post(
    "/{workflow_id}/runs",
    response_model=WorkflowRunOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require(Permission.WORKFLOWS_EXECUTE))],
    summary="Run a workflow now (idempotent with an Idempotency-Key header)",
)
async def run_workflow(
    workflow_id: UUID,
    response: Response,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
    idempotency_key: IdempotencyKey = None,
) -> WorkflowRunOut:
    run, created = await container.workflows.run_now(
        principal, workflow_id, idempotency_key=idempotency_key, meta=meta
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return WorkflowRunOut.model_validate(run)


@workflows.get(
    "/{workflow_id}/runs",
    response_model=PageResponse[WorkflowRunOut],
    dependencies=[Depends(require(Permission.WORKFLOWS_READ))],
)
async def list_workflow_runs(
    workflow_id: UUID, principal: CurrentPrincipal, container: ContainerDep, page: DefaultPage
) -> PageResponse[WorkflowRunOut]:
    result = await container.workflows.list_runs(principal, page, workflow_id=workflow_id)
    return PageResponse[WorkflowRunOut](
        items=[WorkflowRunOut.model_validate(r) for r in result.items],
        next_cursor=result.next_cursor,
    )


# ------------------------------------------------------------- dead letters


@dead_letters.get(
    "",
    response_model=PageResponse[DeadLetterOut],
    dependencies=[Depends(require(Permission.DEAD_LETTERS_MANAGE))],
)
async def list_dead_letters(
    principal: CurrentPrincipal,
    container: ContainerDep,
    page: FailurePage,
    letter_status: Annotated[DeadLetterStatus | None, Query(alias="status")] = None,
) -> PageResponse[DeadLetterOut]:
    result = await container.dead_letters.list(principal, page, status=letter_status)
    return PageResponse[DeadLetterOut](
        items=[DeadLetterOut.model_validate(d) for d in result.items],
        next_cursor=result.next_cursor,
    )


@dead_letters.post(
    "/{letter_id}/retry",
    response_model=DeadLetterOut,
    dependencies=[Depends(require(Permission.DEAD_LETTERS_MANAGE))],
    summary="Re-enqueue a failed job (only idempotent task types are retryable)",
)
async def retry_dead_letter(
    letter_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> DeadLetterOut:
    return DeadLetterOut.model_validate(
        await container.dead_letters.retry(principal, letter_id, meta)
    )


@dead_letters.post(
    "/{letter_id}/discard",
    response_model=DeadLetterOut,
    dependencies=[Depends(require(Permission.DEAD_LETTERS_MANAGE))],
)
async def discard_dead_letter(
    letter_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> DeadLetterOut:
    return DeadLetterOut.model_validate(
        await container.dead_letters.discard(principal, letter_id, meta)
    )

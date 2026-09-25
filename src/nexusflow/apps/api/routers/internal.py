"""Internal automation API for n8n (private network only, never proxied publicly).

Every request passes, in order:

1. authentication - a per-workflow *service token* (``nxs_...``); user tokens
   and tenant API keys are rejected here, service tokens are rejected on the
   public API;
2. a per-token rate limit (``automation.service``);
3. the global operator kill switch (steps that start work are refused while it
   is engaged; failure reporting and status polling keep working);
4. the service scope of the step (checked again inside the domain service);
5. the tenant kill switch (``automation_frozen``) inside the domain service.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status

from nexusflow.apps.api.dependencies import ContainerDep, StateDep, get_principal
from nexusflow.apps.api.schemas.automation import (
    AlertEvaluationOut,
    AnalysisQueuedOut,
    DatasetStep,
    DetectionOut,
    DispatchedRunOut,
    DispatchRequest,
    DispatchResponse,
    FailureDecisionOut,
    FailureReport,
    InsightStatusOut,
    OperatorAlertIn,
    OrganizationStep,
    SweepOut,
    SweepRequest,
    WorkflowRunStatusOut,
)
from nexusflow.apps.api.schemas.common import ERROR_RESPONSES
from nexusflow.core.errors import AuthenticationError, ServiceUnavailableError
from nexusflow.domain.authorization.principal import Principal, PrincipalType, ServiceScope
from nexusflow.infrastructure.observability import metrics
from nexusflow.infrastructure.observability.logging import get_logger
from nexusflow.infrastructure.redis.client import FeatureFlags

_log = get_logger("nexusflow.api.internal")


async def get_service_principal(
    principal: Annotated[Principal, Depends(get_principal)], state: StateDep
) -> Principal:
    if principal.type is not PrincipalType.SERVICE:
        raise AuthenticationError("A service token is required.", code="invalid_token")
    rule = state.container.settings.rate_limits.rules["automation.service"]
    await state.limiter.enforce("automation.service", str(principal.id), rule)
    return principal


ServicePrincipal = Annotated[Principal, Depends(get_service_principal)]


def scoped(scope: ServiceScope) -> Any:
    async def dependency(principal: ServicePrincipal) -> None:
        principal.require_scope(scope)

    return Depends(dependency)


async def automation_enabled(state: StateDep) -> None:
    if await state.flags.is_enabled(FeatureFlags.AUTOMATION_KILL_SWITCH):
        raise ServiceUnavailableError(
            "Automation is disabled by the operator kill switch.", code="automation_disabled"
        )


_ENABLED = Depends(automation_enabled)

router = APIRouter(
    prefix="/internal/v1/automation",
    tags=["internal-automation"],
    responses=ERROR_RESPONSES,
    dependencies=[Depends(get_service_principal)],
)


@router.post(
    "/dispatch",
    response_model=DispatchResponse,
    dependencies=[scoped(ServiceScope.COLLECT), _ENABLED],
    summary="Workflow 1: start every due scheduled workflow (once per schedule slot)",
)
async def dispatch_due(
    body: DispatchRequest, principal: ServicePrincipal, container: ContainerDep
) -> DispatchResponse:
    runs = await container.automation.dispatch_due(principal, limit=body.limit)
    return DispatchResponse(
        dispatched=[
            DispatchedRunOut(
                org_id=r.org_id, workflow_id=r.workflow_id, workflow_run_id=r.workflow_run_id
            )
            for r in runs
        ]
    )


@router.post(
    "/organizations/{org_id}/workflow-runs/{workflow_run_id}/advance",
    response_model=WorkflowRunStatusOut,
    dependencies=[scoped(ServiceScope.COLLECT)],
    summary="Workflow 2: close the workflow run once all its collections finished (idempotent)",
)
async def workflow_run_status(
    org_id: UUID, workflow_run_id: UUID, principal: ServicePrincipal, container: ContainerDep
) -> WorkflowRunStatusOut:
    result = await container.automation.workflow_run_status(
        principal, org_id=org_id, workflow_run_id=workflow_run_id
    )
    if result.get("completed_now"):
        metrics.WORKFLOW_RUNS.labels(status=result["status"]).inc()
    return WorkflowRunStatusOut.model_validate(result)


@router.post(
    "/detect",
    response_model=DetectionOut,
    dependencies=[scoped(ServiceScope.DETECT), _ENABLED],
    summary="Workflow 2: diff new record versions into changes",
)
async def detect(
    body: DatasetStep, principal: ServicePrincipal, container: ContainerDep
) -> DetectionOut:
    with metrics.observe_duration(metrics.WORKFLOW_STEP_DURATION, step="detect"):
        result = await container.automation.detect(
            principal, org_id=body.org_id, dataset_id=body.dataset_id
        )
    return DetectionOut.model_validate(result)


@router.post(
    "/detect/sweep",
    response_model=SweepOut,
    dependencies=[scoped(ServiceScope.DETECT), _ENABLED],
    summary="Workflow 2 safety net: queue detection for datasets with pending versions",
)
async def sweep_detection(
    body: SweepRequest, principal: ServicePrincipal, container: ContainerDep
) -> SweepOut:
    return SweepOut(
        enqueued=await container.automation.sweep_detection(principal, limit=body.limit)
    )


@router.post(
    "/analyze",
    response_model=AnalysisQueuedOut,
    dependencies=[scoped(ServiceScope.ANALYZE), _ENABLED],
    summary="Workflow 3: queue an AI analysis when there are unanalysed changes",
)
async def analyze(
    body: DatasetStep, principal: ServicePrincipal, container: ContainerDep
) -> AnalysisQueuedOut:
    with metrics.observe_duration(metrics.WORKFLOW_STEP_DURATION, step="analyze"):
        result = await container.automation.analyze(
            principal, org_id=body.org_id, dataset_id=body.dataset_id
        )
    return AnalysisQueuedOut.model_validate(result)


@router.get(
    "/organizations/{org_id}/insights/{insight_id}",
    response_model=InsightStatusOut,
    dependencies=[scoped(ServiceScope.ANALYZE)],
)
async def insight_status(
    org_id: UUID, insight_id: UUID, principal: ServicePrincipal, container: ContainerDep
) -> InsightStatusOut:
    result = await container.automation.insight_status(
        principal, org_id=org_id, insight_id=insight_id
    )
    return InsightStatusOut.model_validate(result)


@router.post(
    "/alerts/evaluate",
    response_model=AlertEvaluationOut,
    dependencies=[scoped(ServiceScope.ALERT), _ENABLED],
    summary="Workflow 4: evaluate alert rules against new changes",
)
async def evaluate_alerts(
    body: OrganizationStep, principal: ServicePrincipal, container: ContainerDep
) -> AlertEvaluationOut:
    with metrics.observe_duration(metrics.WORKFLOW_STEP_DURATION, step="evaluate_alerts"):
        result = await container.automation.evaluate_alerts(principal, org_id=body.org_id)
    return AlertEvaluationOut.model_validate(result)


@router.post(
    "/failures",
    response_model=FailureDecisionOut,
    dependencies=[scoped(ServiceScope.RECOVER)],
    summary="Workflow 5: retry-or-dead-letter decision for a failed n8n node",
)
async def record_failure(
    body: FailureReport, principal: ServicePrincipal, container: ContainerDep
) -> FailureDecisionOut:
    decision = await container.automation.record_failure(
        principal,
        org_id=body.org_id,
        workflow=body.workflow,
        node=body.node,
        execution_id=body.execution_id,
        retry_of=body.retry_of,
        error_message=body.error_message,
        idempotent=body.idempotent,
    )
    return FailureDecisionOut(
        retry=decision.retry,
        delay_seconds=decision.delay_seconds,
        dead_letter_id=decision.dead_letter_id,
    )


@router.post(
    "/operator-alerts",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[scoped(ServiceScope.OPERATOR_ALERT)],
    summary="Page the platform operators (e.g. repeated workflow failures)",
)
async def operator_alert(
    body: OperatorAlertIn, principal: ServicePrincipal, container: ContainerDep
) -> Response:
    queued = await container.automation.operator_alert(
        principal, severity=body.severity, summary=body.summary
    )
    if not queued:
        _log.info("operator_alert_suppressed", severity=body.severity)
    return Response(status_code=status.HTTP_202_ACCEPTED)

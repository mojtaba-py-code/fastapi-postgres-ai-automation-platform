"""/api/v1/intelligence, /alert-rules, /alerts, /channels, /reports and /analytics."""

from __future__ import annotations

import base64
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from fastapi.responses import StreamingResponse
from pydantic import AwareDatetime

from nexusflow.apps.api.dependencies import (
    ContainerDep,
    CurrentPrincipal,
    DefaultPage,
    IdempotencyKey,
    Meta,
    StateDep,
    budget_identity,
    page_params,
    require,
)
from nexusflow.apps.api.schemas.business import (
    AlertAcknowledge,
    AlertOut,
    AlertRuleCreate,
    AlertRuleOut,
    AlertRuleUpdate,
    AnalysisCreate,
    ChangeAnalyticsOut,
    ChannelCreate,
    ChannelOut,
    ChannelUpdate,
    DailyVolumeOut,
    InsightOut,
    ReportCreate,
    ReportOut,
    UnusualDayOut,
)
from nexusflow.apps.api.schemas.common import ERROR_RESPONSES, PageResponse
from nexusflow.core.pagination import PageRequest, SortSpec
from nexusflow.core.text import content_disposition, slugify
from nexusflow.domain.alerts.model import AlertStatus
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.reports.model import ReportFormat

intelligence = APIRouter(prefix="/intelligence", tags=["intelligence"], responses=ERROR_RESPONSES)
alert_rules = APIRouter(prefix="/alert-rules", tags=["alerts"], responses=ERROR_RESPONSES)
alerts = APIRouter(prefix="/alerts", tags=["alerts"], responses=ERROR_RESPONSES)
channels = APIRouter(prefix="/channels", tags=["alerts"], responses=ERROR_RESPONSES)
reports = APIRouter(prefix="/reports", tags=["reports"], responses=ERROR_RESPONSES)
analytics = APIRouter(prefix="/analytics", tags=["reports"], responses=ERROR_RESPONSES)

NamedPage = Annotated[PageRequest, Depends(page_params(frozenset({"created_at", "name"})))]
AlertPage = Annotated[
    PageRequest, Depends(page_params(frozenset({"triggered_at"}), SortSpec("triggered_at")))
]

_REPORT_MEDIA_TYPES = {
    ReportFormat.JSON: "application/json",
    ReportFormat.CSV: "text/csv; charset=utf-8",
    ReportFormat.XLSX: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ReportFormat.PDF: "application/pdf",
}


async def _limit(state: StateDep, principal: Principal, scope: str) -> None:
    rule = state.container.settings.rate_limits.rules[scope]
    await state.limiter.enforce(scope, budget_identity(principal), rule)


# ------------------------------------------------------------- intelligence


@intelligence.post(
    "/analyses",
    response_model=InsightOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require(Permission.INSIGHTS_GENERATE))],
    summary="Queue an AI analysis of a dataset's unanalysed changes",
)
async def request_analysis(
    body: AnalysisCreate,
    response: Response,
    principal: CurrentPrincipal,
    container: ContainerDep,
    state: StateDep,
    meta: Meta,
    idempotency_key: IdempotencyKey = None,
) -> InsightOut:
    await _limit(state, principal, "api.ai")
    insight, created = await container.intelligence.request_analysis(
        principal, dataset_id=body.dataset_id, idempotency_key=idempotency_key, meta=meta
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return InsightOut.model_validate(insight)


@intelligence.get(
    "/insights",
    response_model=PageResponse[InsightOut],
    dependencies=[Depends(require(Permission.INSIGHTS_READ))],
)
async def list_insights(
    principal: CurrentPrincipal,
    container: ContainerDep,
    page: DefaultPage,
    dataset_id: UUID | None = None,
) -> PageResponse[InsightOut]:
    result = await container.intelligence.list(principal, page, dataset_id=dataset_id)
    return PageResponse[InsightOut](
        items=[InsightOut.model_validate(i) for i in result.items], next_cursor=result.next_cursor
    )


@intelligence.get(
    "/insights/{insight_id}",
    response_model=InsightOut,
    dependencies=[Depends(require(Permission.INSIGHTS_READ))],
)
async def get_insight(
    insight_id: UUID, principal: CurrentPrincipal, container: ContainerDep
) -> InsightOut:
    return InsightOut.model_validate(await container.intelligence.get(principal, insight_id))


# ------------------------------------------------------------------- alerts


@alert_rules.post(
    "",
    response_model=AlertRuleOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.ALERTS_WRITE))],
)
async def create_alert_rule(
    body: AlertRuleCreate, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> AlertRuleOut:
    rule = await container.alerts.create_rule(
        principal,
        project_id=body.project_id,
        dataset_id=body.dataset_id,
        name=body.name,
        condition=body.condition,
        severity=body.severity,
        channel_ids=list(body.channel_ids),
        cooldown_minutes=body.cooldown_minutes,
        meta=meta,
    )
    return AlertRuleOut.model_validate(rule)


@alert_rules.get(
    "",
    response_model=PageResponse[AlertRuleOut],
    dependencies=[Depends(require(Permission.ALERTS_READ))],
)
async def list_alert_rules(
    principal: CurrentPrincipal, container: ContainerDep, page: NamedPage
) -> PageResponse[AlertRuleOut]:
    result = await container.alerts.list_rules(principal, page)
    return PageResponse[AlertRuleOut](
        items=[AlertRuleOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@alert_rules.patch(
    "/{rule_id}",
    response_model=AlertRuleOut,
    dependencies=[Depends(require(Permission.ALERTS_WRITE))],
)
async def update_alert_rule(
    rule_id: UUID,
    body: AlertRuleUpdate,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> AlertRuleOut:
    rule = await container.alerts.update_rule(
        principal,
        rule_id,
        enabled=body.enabled,
        severity=body.severity,
        channel_ids=list(body.channel_ids) if body.channel_ids is not None else None,
        cooldown_minutes=body.cooldown_minutes,
        meta=meta,
    )
    return AlertRuleOut.model_validate(rule)


@alert_rules.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.ALERTS_WRITE))],
)
async def delete_alert_rule(
    rule_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.alerts.delete_rule(principal, rule_id, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@alerts.get(
    "",
    response_model=PageResponse[AlertOut],
    dependencies=[Depends(require(Permission.ALERTS_READ))],
)
async def list_alerts(
    principal: CurrentPrincipal,
    container: ContainerDep,
    page: AlertPage,
    alert_status: Annotated[AlertStatus | None, Query(alias="status")] = None,
) -> PageResponse[AlertOut]:
    result = await container.alerts.list_alerts(principal, page, status=alert_status)
    return PageResponse[AlertOut](
        items=[AlertOut.model_validate(a) for a in result.items], next_cursor=result.next_cursor
    )


@alerts.post(
    "/{alert_id}/acknowledge",
    response_model=AlertOut,
    dependencies=[Depends(require(Permission.ALERTS_ACK))],
)
async def acknowledge_alert(
    alert_id: UUID,
    body: AlertAcknowledge,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> AlertOut:
    alert = await container.alerts.acknowledge(principal, alert_id, resolve=body.resolve, meta=meta)
    return AlertOut.model_validate(alert)


# ----------------------------------------------------------------- channels


@channels.post(
    "",
    response_model=ChannelOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.CHANNELS_WRITE))],
    summary="Create a notification channel (secrets live in integrations, never in the config)",
)
async def create_channel(
    body: ChannelCreate, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> ChannelOut:
    channel = await container.notifications.create_channel(
        principal, name=body.name, config=body.config, integration_id=body.integration_id, meta=meta
    )
    return ChannelOut.model_validate(channel)


@channels.get(
    "",
    response_model=PageResponse[ChannelOut],
    dependencies=[Depends(require(Permission.CHANNELS_READ))],
)
async def list_channels(
    principal: CurrentPrincipal, container: ContainerDep, page: NamedPage
) -> PageResponse[ChannelOut]:
    result = await container.notifications.list_channels(principal, page)
    return PageResponse[ChannelOut](
        items=[ChannelOut.model_validate(c) for c in result.items], next_cursor=result.next_cursor
    )


@channels.patch(
    "/{channel_id}",
    response_model=ChannelOut,
    dependencies=[Depends(require(Permission.CHANNELS_WRITE))],
)
async def update_channel(
    channel_id: UUID,
    body: ChannelUpdate,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
) -> ChannelOut:
    channel = await container.notifications.set_enabled(
        principal, channel_id, enabled=body.enabled, meta=meta
    )
    return ChannelOut.model_validate(channel)


@channels.delete(
    "/{channel_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.CHANNELS_WRITE))],
)
async def delete_channel(
    channel_id: UUID, principal: CurrentPrincipal, container: ContainerDep, meta: Meta
) -> Response:
    await container.notifications.delete_channel(principal, channel_id, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------ reports


@reports.post(
    "",
    response_model=ReportOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require(Permission.REPORTS_GENERATE))],
    summary="Queue report generation (JSON, CSV, XLSX or PDF)",
)
async def request_report(
    body: ReportCreate,
    response: Response,
    principal: CurrentPrincipal,
    container: ContainerDep,
    meta: Meta,
    idempotency_key: IdempotencyKey = None,
) -> ReportOut:
    report, created = await container.reports.request(
        principal,
        project_id=body.project_id,
        dataset_id=body.dataset_id,
        period_start=body.period_start,
        period_end=body.period_end,
        fmt=body.format,
        title=body.title,
        idempotency_key=idempotency_key,
        meta=meta,
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return ReportOut.model_validate(report)


@reports.get(
    "",
    response_model=PageResponse[ReportOut],
    dependencies=[Depends(require(Permission.REPORTS_READ))],
)
async def list_reports(
    principal: CurrentPrincipal, container: ContainerDep, page: DefaultPage
) -> PageResponse[ReportOut]:
    result = await container.reports.list(principal, page)
    return PageResponse[ReportOut](
        items=[ReportOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@reports.get(
    "/{report_id}",
    response_model=ReportOut,
    dependencies=[Depends(require(Permission.REPORTS_READ))],
)
async def get_report(
    report_id: UUID, principal: CurrentPrincipal, container: ContainerDep
) -> ReportOut:
    return ReportOut.model_validate(await container.reports.get(principal, report_id))


@reports.get(
    "/{report_id}/download",
    dependencies=[Depends(require(Permission.REPORTS_DOWNLOAD))],
    response_class=StreamingResponse,
    responses={200: {"content": {media: {} for media in _REPORT_MEDIA_TYPES.values()}}},
    summary="Download a ready report (always as an attachment; audited)",
)
async def download_report(
    report_id: UUID,
    principal: CurrentPrincipal,
    container: ContainerDep,
    state: StateDep,
    meta: Meta,
) -> StreamingResponse:
    await _limit(state, principal, "api.export")
    report, stream = await container.reports.download(principal, report_id, meta)
    headers = {
        "Content-Disposition": content_disposition(
            f"{slugify(report.title) or 'report'}.{report.format.value}"
        ),
        "Cache-Control": "no-store",
    }
    if report.sha256:
        digest = base64.b64encode(bytes.fromhex(report.sha256)).decode("ascii")
        headers["Repr-Digest"] = f"sha-256=:{digest}:"  # RFC 9530 integrity check for clients
    return StreamingResponse(stream, media_type=_REPORT_MEDIA_TYPES[report.format], headers=headers)


# ---------------------------------------------------------------- analytics


@analytics.get(
    "/changes",
    response_model=ChangeAnalyticsOut,
    dependencies=[Depends(require(Permission.CHANGES_READ))],
    summary="Change volume of a project or dataset: totals, daily trend and unusual days",
)
async def change_analytics(
    principal: CurrentPrincipal,
    container: ContainerDep,
    project_id: UUID,
    dataset_id: UUID | None = None,
    period_start: Annotated[
        AwareDatetime | None, Query(description="Inclusive; defaults to 30 days before the end.")
    ] = None,
    period_end: Annotated[
        AwareDatetime | None, Query(description="Exclusive; defaults to now.")
    ] = None,
) -> ChangeAnalyticsOut:
    result = await container.reports.analytics(
        principal,
        project_id=project_id,
        dataset_id=dataset_id,
        period_start=period_start,
        period_end=period_end,
    )
    volume = result.volume
    return ChangeAnalyticsOut(
        project_id=result.project_id,
        dataset_id=result.dataset_id,
        period_start=result.period_start,
        period_end=result.period_end,
        totals=volume.totals,
        by_significance=volume.by_significance,
        daily=[DailyVolumeOut(date=day, changes=count) for day, count in volume.daily],
        unusual_days=[UnusualDayOut.model_validate(day) for day in volume.unusual_days],
        trend_note=volume.trend_note,
    )

"""Alert rules management and rule evaluation (idempotent, de-duplicated)."""

from __future__ import annotations

from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import ConflictError, InvalidInputError, NotFoundError
from nexusflow.core.ids import uuid7
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.core.text import clean_text, required_name, truncate
from nexusflow.domain.alerts.model import (
    Alert,
    AlertCondition,
    AlertRule,
    AlertSeverity,
    AlertStatus,
    AlertSubject,
    dedup_key,
    matches,
)
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.automation.events import EventType, event_message
from nexusflow.domain.catalog.service import describe_field_change, get_dataset, mask_diff
from nexusflow.domain.intelligence.model import Insight, InsightStatus
from nexusflow.domain.notifications.model import NotificationDelivery
from nexusflow.domain.records.model import Change
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.sources.model import RunStatus

_EVALUATION_BATCH = 500
# Batches one evaluation works through before it hands the rest of a backlog on
# to a follow-up job (one detection batch alone can create 1,000 changes).
_BATCHES_PER_EVALUATION = 4


class AlertService:
    def __init__(
        self, *, uow_factory: UnitOfWorkFactory, clock: Clock, audit: AuditRecorder
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit

    # ----------------------------------------------------------------- rules

    async def create_rule(
        self,
        principal: Principal,
        *,
        project_id: UUID,
        dataset_id: UUID | None,
        name: str,
        condition: AlertCondition,
        severity: AlertSeverity,
        channel_ids: list[UUID],
        cooldown_minutes: int,
        meta: RequestMeta,
    ) -> AlertRule:
        principal.require(Permission.ALERTS_WRITE)
        org_id = principal.require_org()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            await self._validate(uow, org_id, project_id, dataset_id, condition, channel_ids)
            rule = AlertRule(
                id=uuid7(),
                org_id=org_id,
                project_id=project_id,
                dataset_id=dataset_id,
                name=required_name(name),
                condition=condition.model_dump(mode="json"),
                severity=severity,
                channel_ids=list(dict.fromkeys(channel_ids)),
                cooldown_minutes=cooldown_minutes,
                created_by=principal.actor_user_id,
                created_at=now,
                updated_at=now,
            )
            await uow.data.alert_rules.add(rule)
            await self._audit.record(
                uow.audit,
                action=AuditAction.ALERT_RULE_CREATED,
                principal=principal,
                meta=meta,
                resource_type="alert_rule",
                resource_id=rule.id,
                metadata={"condition": condition.type},
            )
            await uow.commit()
        return rule

    async def update_rule(
        self,
        principal: Principal,
        rule_id: UUID,
        *,
        enabled: bool | None,
        severity: AlertSeverity | None,
        channel_ids: list[UUID] | None,
        cooldown_minutes: int | None,
        meta: RequestMeta,
    ) -> AlertRule:
        principal.require(Permission.ALERTS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            rule = await uow.data.alert_rules.get_for_update(org_id, rule_id)
            if rule is None:
                raise NotFoundError()
            if channel_ids is not None:
                await self._validate(
                    uow,
                    org_id,
                    rule.project_id,
                    rule.dataset_id,
                    rule.parsed_condition,
                    channel_ids,
                )
                rule.channel_ids = list(dict.fromkeys(channel_ids))
            if enabled is not None:
                rule.enabled = enabled
            if severity is not None:
                rule.severity = severity
            if cooldown_minutes is not None:
                rule.cooldown_minutes = cooldown_minutes
            rule.updated_at = self._clock.now()
            await self._audit.record(
                uow.audit,
                action=AuditAction.ALERT_RULE_UPDATED,
                principal=principal,
                meta=meta,
                resource_type="alert_rule",
                resource_id=rule.id,
                metadata={"enabled": rule.enabled},
            )
            await uow.commit()
            return rule

    async def delete_rule(self, principal: Principal, rule_id: UUID, meta: RequestMeta) -> None:
        principal.require(Permission.ALERTS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            rule = await uow.data.alert_rules.get_for_update(org_id, rule_id)
            if rule is None:
                raise NotFoundError()
            await uow.data.alert_rules.delete(rule)
            await self._audit.record(
                uow.audit,
                action=AuditAction.ALERT_RULE_DELETED,
                principal=principal,
                meta=meta,
                resource_type="alert_rule",
                resource_id=rule_id,
            )
            await uow.commit()

    async def list_rules(self, principal: Principal, page: PageRequest) -> Page[AlertRule]:
        principal.require(Permission.ALERTS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.alert_rules.list_page(principal.require_org(), page)

    async def _validate(
        self,
        uow: UnitOfWork,
        org_id: UUID,
        project_id: UUID,
        dataset_id: UUID | None,
        condition: AlertCondition,
        channel_ids: list[UUID],
    ) -> None:
        if await uow.data.projects.get(org_id, project_id) is None:
            raise NotFoundError()
        field_name = getattr(condition, "field", None)
        if dataset_id is not None:
            dataset = await get_dataset(uow, org_id, dataset_id)
            if dataset.project_id != project_id:
                raise NotFoundError()
            if field_name is not None and dataset.spec.field(field_name) is None:
                raise InvalidInputError(
                    f"Unknown dataset field {field_name!r}.", code="unknown_field"
                )
        elif field_name is not None:
            raise InvalidInputError("Field conditions require a dataset.", code="dataset_required")
        if len(channel_ids) > 10:
            raise InvalidInputError("At most 10 channels per rule.", code="too_many_channels")
        channels = await uow.data.channels.list_by_ids(org_id, channel_ids)
        if len(channels) != len(set(channel_ids)):
            raise NotFoundError("One or more channels were not found.")

    # ---------------------------------------------------------------- alerts

    async def list_alerts(
        self, principal: Principal, page: PageRequest, *, status: AlertStatus | None
    ) -> Page[Alert]:
        principal.require(Permission.ALERTS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.alerts.list_page(
                principal.require_org(), page, {"status": status}
            )

    async def acknowledge(
        self, principal: Principal, alert_id: UUID, *, resolve: bool, meta: RequestMeta
    ) -> Alert:
        principal.require(Permission.ALERTS_ACK)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            alert = await uow.data.alerts.get_for_update(org_id, alert_id)
            if alert is None:
                raise NotFoundError()
            if alert.status is AlertStatus.RESOLVED:
                raise ConflictError("The alert is already resolved.", code="alert_resolved")
            alert.status = AlertStatus.RESOLVED if resolve else AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = principal.actor_user_id
            alert.acknowledged_at = self._clock.now()
            await self._audit.record(
                uow.audit,
                action=AuditAction.ALERT_ACKNOWLEDGED,
                principal=principal,
                meta=meta,
                resource_type="alert",
                resource_id=alert.id,
                metadata={"status": alert.status},
            )
            await uow.commit()
            return alert

    # ------------------------------------------------------------ evaluation

    async def evaluate_changes(self, *, org_id: UUID) -> int:
        """Evaluate rules for not-yet-evaluated changes; returns alerts created.

        Batch by batch, each in a transaction of its own. A backlog larger than
        one evaluation works through is handed on to a follow-up
        ``EVALUATE_ALERTS`` job (queued with the last batch), so no change waits
        for the next event - or for ever.
        """
        created = 0
        for left in reversed(range(_BATCHES_PER_EVALUATION)):
            alerts, more = await self._evaluate_batch(org_id, hand_on=left == 0)
            created += alerts
            if not more:
                break
        return created

    async def _evaluate_batch(self, org_id: UUID, *, hand_on: bool) -> tuple[int, bool]:
        """One batch: returns the alerts created and whether more may be pending."""
        created = 0
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            changes = await uow.data.changes.pending_alerts(org_id, limit=_EVALUATION_BATCH)
            if not changes:
                return 0, False
            rules_cache: dict[UUID, list[AlertRule]] = {}
            sensitive_cache: dict[UUID, tuple[frozenset[str], bool]] = {}
            for change in changes:
                if change.dataset_id not in rules_cache:
                    dataset = await get_dataset(uow, org_id, change.dataset_id)
                    sensitive_cache[change.dataset_id] = (
                        dataset.spec.sensitive_fields,
                        dataset.classification.leaves_platform,
                    )
                    rules_cache[change.dataset_id] = await uow.data.alert_rules.enabled_for(
                        org_id, dataset_id=change.dataset_id, project_id=dataset.project_id
                    )
                sensitive, values_allowed = sensitive_cache[change.dataset_id]
                subject = _change_subject(change, sensitive, values_allowed=values_allowed)
                for rule in rules_cache[change.dataset_id]:
                    created += await self._fire(uow, rule, subject)
            await uow.data.changes.mark_alerts_evaluated([c.id for c in changes])
            more = len(changes) == _EVALUATION_BATCH
            if more and hand_on:
                await uow.outbox.add(
                    new_message(
                        TaskName.EVALUATE_ALERTS,
                        {"org_id": str(org_id)},
                        org_id=org_id,
                        now=self._clock.now(),
                    )
                )
            await uow.commit()
        return created, more

    async def evaluate_insight(self, *, org_id: UUID, insight_id: UUID) -> int:
        """Evaluate ``insight_risk_at_least`` rules for a completed AI insight."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            insight = await uow.data.insights.get(org_id, insight_id)
            if (
                insight is None
                or insight.status is not InsightStatus.COMPLETED
                or insight.risk_level is None
            ):
                return 0
            try:
                dataset = await get_dataset(uow, org_id, insight.dataset_id)
            except NotFoundError:
                return 0  # dataset deleted meanwhile
        subject = _insight_subject(
            insight, dataset.name, values_allowed=dataset.classification.leaves_platform
        )
        return await self.evaluate_subject(
            org_id=org_id, project_id=dataset.project_id, subject=subject
        )

    async def evaluate_failed_run(self, *, org_id: UUID, run_id: UUID) -> int:
        """Evaluate ``run_failed`` rules; repeated failures of one source share
        a dedup identity, so the rule cooldown suppresses alert storms."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            run = await uow.data.runs.get(org_id, run_id)
            if run is None or run.status is not RunStatus.FAILED:
                return 0
            source = await uow.data.sources.get(org_id, run.source_id)
            if source is None:
                return 0
        name = clean_text(source.name, max_length=120)
        subject = AlertSubject(
            subject_type="run",
            subject_id=run.id,
            dataset_id=source.dataset_id,
            dedup_identity=f"source:{source.id}",
            title=f"Collection failed: {name}",
            body="\n".join(
                [
                    f"Source: {name} ({source.kind.value})",
                    f"Error: {run.error_code or 'unknown'}",
                    f"Consecutive failures: {source.consecutive_failures}",
                ]
            ),
        )
        return await self.evaluate_subject(
            org_id=org_id, project_id=source.project_id, subject=subject
        )

    async def evaluate_subject(
        self, *, org_id: UUID, project_id: UUID, subject: AlertSubject
    ) -> int:
        """Evaluate rules for an insight or failed run."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            rules = await uow.data.alert_rules.enabled_for(
                org_id, dataset_id=subject.dataset_id, project_id=project_id
            )
            created = 0
            for rule in rules:
                created += await self._fire(uow, rule, subject)
            await uow.commit()
            return created

    async def _fire(self, uow: UnitOfWork, rule: AlertRule, subject: AlertSubject) -> int:
        if not matches(rule.parsed_condition, subject):
            return 0
        now = self._clock.now()
        alert = Alert(
            id=uuid7(),
            org_id=rule.org_id,
            rule_id=rule.id,
            severity=rule.severity,
            title=truncate(f"[{rule.severity.value.upper()}] {rule.name}: {subject.title}", 200),
            body=truncate(subject.body, 4000),
            dedup_key=dedup_key(rule.id, subject, cooldown_minutes=rule.cooldown_minutes, now=now),
            subject_type=subject.subject_type,
            subject_id=subject.subject_id,
            triggered_at=now,
        )
        if not await uow.data.alerts.add_if_new(alert):
            return 0  # de-duplicated within the rule's cooldown window
        channels = await uow.data.channels.list_by_ids(rule.org_id, rule.channel_ids)
        for channel in channels:
            if not channel.enabled:
                continue
            delivery = NotificationDelivery(
                id=uuid7(),
                org_id=rule.org_id,
                alert_id=alert.id,
                channel_id=channel.id,
                created_at=now,
            )
            if await uow.data.deliveries.add_if_new(delivery):
                await uow.outbox.add(
                    new_message(
                        TaskName.DELIVER_NOTIFICATION,
                        {"org_id": str(rule.org_id), "delivery_id": str(delivery.id)},
                        org_id=rule.org_id,
                        now=now,
                    )
                )
        await uow.outbox.add(
            event_message(
                EventType.ALERT_TRIGGERED,
                org_id=rule.org_id,
                payload={"alert_id": str(alert.id), "severity": alert.severity.value},
                now=now,
            )
        )
        return 1


def _change_subject(
    change: Change, sensitive: frozenset[str], *, values_allowed: bool = True
) -> AlertSubject:
    """What a rule is evaluated against (the full diff) and what an alert may say.

    Sensitive fields are masked; for a restricted dataset the message names the
    changed fields but carries no values at all, because alert messages leave
    the platform (e-mail, Slack, Telegram, webhooks).
    """
    diff = (
        mask_diff(change.diff, sensitive, reveal=False)
        if values_allowed
        else mask_diff(change.diff, frozenset(change.diff), reveal=False)
    )
    lines = []
    for field_name, entry in list(diff.items())[:10]:
        if not values_allowed:
            lines.append(f"- {field_name} changed")
        elif (described := describe_field_change(field_name, entry)) is not None:
            lines.append(f"- {described}")
    # A restricted record is identified by its platform id, never by its key.
    key = (
        clean_text(change.record_key, max_length=120)
        if values_allowed
        else f"record {change.record_id}"
    )
    return AlertSubject(
        subject_type="change",
        subject_id=change.id,
        dataset_id=change.dataset_id,
        dedup_identity=f"{change.record_id}:{change.change_type.value}",
        change_type=change.change_type,
        significance=change.significance,
        diff=diff,
        match_diff=dict(change.diff),
        title=f"{change.change_type.value} {key}",
        body="\n".join(
            [
                f"Record: {key}",
                f"Change: {change.change_type.value} (significance {change.significance.value})",
                *lines,
            ]
        ),
    )


def _insight_subject(
    insight: Insight, dataset_name: str, *, values_allowed: bool = True
) -> AlertSubject:
    risk = insight.risk_level.value if insight.risk_level else "unknown"
    if values_allowed:
        body = [clean_text(insight.summary or "", max_length=1500, multiline=True)]
        recommendations = [
            f"- {clean_text(r, max_length=300)}" for r in insight.recommendations[:5]
        ]
        if recommendations:
            body += ["", "Recommendations:", *recommendations]
    else:  # the analysis quotes records: it stays in the platform
        body = [f"Risk level: {risk}. The analysis of this restricted dataset is in NexusFlow."]
    return AlertSubject(
        subject_type="insight",
        subject_id=insight.id,
        dataset_id=insight.dataset_id,
        dedup_identity=f"insight:{insight.id}",
        risk_level=insight.risk_level,
        title=f"AI analysis of {clean_text(dataset_name, max_length=80)}: {risk} risk",
        body="\n".join(body),
    )

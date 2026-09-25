"""AI-assisted analysis of detected changes.

    request -> validation -> policy (consent, permissions) -> redaction -> AI
            -> tool permission gateway -> output validation -> storage

The slow model call happens *between* two short transactions (claim, then
store) so no database transaction or row lock is held while waiting on a
third party. External processing requires the tenant's explicit opt-in;
otherwise the deterministic offline analyser is used.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import NotFoundError, PermanentError
from nexusflow.core.ids import uuid7
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.domain.audit.model import AuditAction, AuditResult
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.automation.events import EventType, event_message
from nexusflow.domain.catalog.service import get_dataset
from nexusflow.domain.intelligence.model import AnalysisOutput, Insight, InsightStatus
from nexusflow.domain.intelligence.offline import offline_analysis
from nexusflow.domain.intelligence.ports import (
    AIProvider,
    AIRefusalError,
    AnalysisRequest,
)
from nexusflow.domain.intelligence.prompting import PROMPT_VERSION, PromptPackage, build_prompt
from nexusflow.domain.intelligence.redaction import redact_value, strip_sensitive
from nexusflow.domain.intelligence.tools import ToolContext, ToolGateway
from nexusflow.domain.intelligence.validation import OutputRejectedError, validate_output
from nexusflow.domain.records.model import Change
from nexusflow.domain.shared.context import SYSTEM_META, RequestMeta
from nexusflow.domain.shared.idempotency import client_key, ensure_same_request
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.sources.model import RestApiConfig, WebsiteConfig

_MAX_CHANGES = 200


@dataclass(frozen=True, slots=True)
class _Claim:
    insight: Insight
    dataset_name: str
    changes: list[dict[str, Any]]
    change_ids: list[UUID]
    hosts: frozenset[str]
    principal: Principal
    external_allowed: bool


class IntelligenceService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        provider: AIProvider | None,
        gateway_factory: Callable[[], ToolGateway],
        max_input_chars: int,
        max_tool_rounds: int,
        max_output_tokens: int,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._provider = provider
        self._gateway_factory = gateway_factory
        self._max_input_chars = max_input_chars
        self._max_tool_rounds = max_tool_rounds
        self._max_output_tokens = max_output_tokens

    # -------------------------------------------------------------- requests

    async def request_analysis(
        self,
        principal: Principal,
        *,
        dataset_id: UUID,
        idempotency_key: str | None,
        meta: RequestMeta,
    ) -> tuple[Insight, bool]:
        principal.require(Permission.INSIGHTS_GENERATE)
        org_id = principal.require_org()
        # Without a client key, a unique one: the column is required.
        key = client_key(idempotency_key) if idempotency_key else f"once:{uuid7()}"
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            existing = await uow.data.insights.get_by_idempotency_key(org_id, key)
            if existing is not None:
                ensure_same_request(existing.dataset_id == dataset_id)
                return existing, False
            dataset = await get_dataset(uow, org_id, dataset_id)
            insight = await self._create(
                uow, org_id, dataset.project_id, dataset.id, key, principal.actor_user_id
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.INSIGHT_REQUESTED,
                principal=principal,
                meta=meta,
                resource_type="insight",
                resource_id=insight.id,
                metadata={"dataset_id": str(dataset_id)},
            )
            await uow.commit()
        return insight, True

    async def request_automatic(self, *, org_id: UUID, dataset_id: UUID) -> Insight | None:
        """Automation-triggered analysis, de-duplicated per dataset and hour."""
        now = self._clock.now()
        key = f"auto:{dataset_id}:{int(now.timestamp() // 3600)}"
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            if await uow.data.insights.get_by_idempotency_key(org_id, key) is not None:
                return None
            dataset = await get_dataset(uow, org_id, dataset_id)
            insight = await self._create(uow, org_id, dataset.project_id, dataset.id, key, None)
            await uow.commit()
            return insight

    async def _create(
        self,
        uow: UnitOfWork,
        org_id: UUID,
        project_id: UUID,
        dataset_id: UUID,
        key: str,
        by: UUID | None,
    ) -> Insight:
        now = self._clock.now()
        insight = Insight(
            id=uuid7(),
            org_id=org_id,
            project_id=project_id,
            dataset_id=dataset_id,
            idempotency_key=key,
            requested_by=by,
            created_at=now,
        )
        await uow.data.insights.add(insight)
        await uow.outbox.add(
            new_message(
                TaskName.ANALYZE_CHANGES,
                {"org_id": str(org_id), "insight_id": str(insight.id)},
                org_id=org_id,
                now=now,
            )
        )
        return insight

    async def list(
        self, principal: Principal, page: PageRequest, *, dataset_id: UUID | None
    ) -> Page[Insight]:
        principal.require(Permission.INSIGHTS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.insights.list_page(
                principal.require_org(), page, {"dataset_id": dataset_id}
            )

    async def get(self, principal: Principal, insight_id: UUID) -> Insight:
        principal.require(Permission.INSIGHTS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            insight = await uow.data.insights.get(principal.require_org(), insight_id)
            if insight is None:
                raise NotFoundError()
            return insight

    # --------------------------------------------------------------- worker

    async def analyze(self, *, org_id: UUID, insight_id: UUID) -> Insight:
        claim = await self._claim(org_id, insight_id)
        if claim is None:
            return await self._load(org_id, insight_id)
        usage: dict[str, Any] = {}
        provider_name, model = "offline", "heuristic-v1"
        analysed = claim.change_ids
        provider = self._provider if claim.external_allowed and claim.changes else None
        try:
            package = self._package(claim) if provider is not None else None
            if provider is not None and package is not None and package.included_change_ids:
                output, usage = await self._run_model(claim, provider, package)
                provider_name, model = provider.name, provider.model
                # Only the changes the model saw are analysed; the others - over the
                # context budget - are left for the next analysis.
                analysed = [i for i in claim.change_ids if str(i) in package.included_change_ids]
            else:
                # No consent, no provider, or not one change small enough for the
                # model's context: the offline analyser covers them all.
                output = offline_analysis(claim.changes, dataset_name=claim.dataset_name)
        except (OutputRejectedError, AIRefusalError) as rejection:
            return await self._finish_rejected(claim.insight, rejection)
        except PermanentError as failure:
            return await self._finish_rejected(claim.insight, failure, status=InsightStatus.FAILED)
        except Exception:
            await self._release(claim.insight)  # transient: back to PENDING, the job retries
            raise
        return await self._finish(claim, output, provider_name, model, usage, analysed)

    async def _claim(self, org_id: UUID, insight_id: UUID) -> _Claim | None:
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            insight = await uow.data.insights.get_for_update(org_id, insight_id)
            if insight is None:
                raise NotFoundError(internal_detail=f"insight {insight_id}")
            if insight.status is not InsightStatus.PENDING:
                return None
            insight.start(self._clock.now())
            dataset = await get_dataset(uow, org_id, insight.dataset_id)
            organization = await uow.organizations.get(org_id)
            principal = await _acting_principal(uow, org_id, insight.requested_by)
            changes = await uow.data.changes.unanalyzed(org_id, dataset.id, limit=_MAX_CHANGES)
            hosts = await _source_hosts(uow, org_id, dataset.id)
            await uow.commit()
        sensitive = dataset.spec.sensitive_fields
        prepared = [_prepare_change(change, sensitive) for change in changes]
        # External AI needs the organization's opt-in, and never sees restricted data.
        external = bool(organization and organization.policy.ai_external_processing) and (
            dataset.classification.leaves_platform
        )
        return _Claim(
            insight=insight,
            dataset_name=dataset.name,
            changes=prepared,
            change_ids=[c.id for c in changes],
            hosts=hosts,
            principal=principal,
            external_allowed=external,
        )

    def _package(self, claim: _Claim) -> PromptPackage:
        return build_prompt(
            dataset_name=claim.dataset_name,
            period="since last analysis",
            changes=claim.changes,
            statistics={"changes": len(claim.changes)},
            hosts=claim.hosts,
            budget_chars=self._max_input_chars,
        )

    async def _run_model(
        self, claim: _Claim, provider: AIProvider, package: PromptPackage
    ) -> tuple[AnalysisOutput, dict[str, Any]]:
        gateway = self._gateway_factory()
        context = ToolContext(
            org_id=claim.insight.org_id,
            dataset_id=claim.insight.dataset_id,
            principal=claim.principal,
        )
        conversation = provider.start(
            AnalysisRequest(
                system_prompt=package.system_prompt,
                user_prompt=package.user_prompt,
                output_schema=package.output_schema,
                tools=gateway.specs if self._max_tool_rounds else (),
                max_output_tokens=self._max_output_tokens,
            )
        )
        turn = await conversation.send()
        tokens_in, tokens_out = turn.input_tokens, turn.output_tokens
        rounds = 0
        while turn.tool_calls and rounds < self._max_tool_rounds:
            results = [await gateway.execute(call, context) for call in turn.tool_calls]
            turn = await conversation.send(results)
            tokens_in += turn.input_tokens
            tokens_out += turn.output_tokens
            rounds += 1
        if turn.stop_reason == "refusal":
            raise AIRefusalError()
        if turn.stop_reason == "max_tokens":
            raise OutputRejectedError(code="ai_output_truncated")
        if turn.tool_calls:
            raise OutputRejectedError(code="ai_tool_budget_exceeded")
        output = validate_output(
            turn.text,
            boundary=package.boundary,
            allowed_change_ids=package.included_change_ids,
            allowed_hosts=package.allowed_hosts,
        )
        usage = {
            "input_tokens": tokens_in,
            "output_tokens": tokens_out,
            "tool_rounds": rounds,
            "tool_calls": [
                {"tool": name, "decision": decision} for name, decision in gateway.decisions
            ],
            "changes_in_context": len(package.included_change_ids),
        }
        return output, usage

    async def _finish(
        self,
        claim: _Claim,
        output: AnalysisOutput,
        provider: str,
        model: str,
        usage: dict[str, Any],
        analysed: Sequence[UUID],  # the changes the output is about
    ) -> Insight:
        now = self._clock.now()
        org_id = claim.insight.org_id
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            insight = await uow.data.insights.get_for_update(org_id, claim.insight.id)
            if insight is None:
                raise NotFoundError()
            if not insight.is_claimed_by(claim.insight.started_at):
                return insight  # reaped and re-run meanwhile: the newer run owns the insight
            insight.complete(output, provider=provider, model=model, usage=usage, now=now)
            insight.prompt_version = PROMPT_VERSION
            insight.change_count = len(analysed)
            await uow.data.changes.assign_insight(analysed, insight.id)
            await uow.outbox.add(
                event_message(
                    EventType.INSIGHT_CREATED,
                    org_id=org_id,
                    payload={
                        "insight_id": str(insight.id),
                        "dataset_id": str(insight.dataset_id),
                        "risk_level": insight.risk_level.value if insight.risk_level else None,
                    },
                    now=now,
                )
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.INSIGHT_GENERATED,
                principal=Principal.system(org_id),
                meta=SYSTEM_META,
                resource_type="insight",
                resource_id=insight.id,
                metadata={"provider": provider, "model": model, "changes": insight.change_count},
            )
            await uow.commit()
            return insight

    async def _finish_rejected(
        self,
        insight: Insight,
        error: PermanentError,
        *,
        status: InsightStatus = InsightStatus.REJECTED,
    ) -> Insight:
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(insight.org_id)) as uow:
            current = await uow.data.insights.get_for_update(insight.org_id, insight.id)
            if current is None:
                raise NotFoundError()
            if not current.is_claimed_by(insight.started_at):
                return current
            current.reject(error.code, now, status=status)
            await self._audit.record(
                uow.audit,
                action=AuditAction.INSIGHT_GENERATED,
                principal=Principal.system(insight.org_id),
                meta=SYSTEM_META,
                result=AuditResult.FAILURE,
                resource_type="insight",
                resource_id=insight.id,
                metadata={"error": error.code},
            )
            await uow.commit()
            return current

    async def _release(self, insight: Insight) -> None:
        async with self._uow_factory(TenantScope.system(insight.org_id)) as uow:
            current = await uow.data.insights.get_for_update(insight.org_id, insight.id)
            if current is not None and current.is_claimed_by(insight.started_at):
                current.status = InsightStatus.PENDING
                await uow.commit()

    async def mark_failed(self, *, org_id: UUID, insight_id: UUID, code: str) -> None:
        """Called when retries are exhausted (dead-letter path)."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            insight = await uow.data.insights.get_for_update(org_id, insight_id)
            if insight is not None and insight.status in (
                InsightStatus.PENDING,
                InsightStatus.RUNNING,
            ):
                insight.reject(code, self._clock.now(), status=InsightStatus.FAILED)
                await uow.commit()

    async def _load(self, org_id: UUID, insight_id: UUID) -> Insight:
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            insight = await uow.data.insights.get(org_id, insight_id)
            if insight is None:
                raise NotFoundError()
            return insight


def _prepare_change(change: Change, sensitive: frozenset[str]) -> dict[str, Any]:
    diff = strip_sensitive(change.diff, sensitive)
    redacted_diff, _ = redact_value(diff)
    redacted_key, _ = redact_value(change.record_key)
    return {
        "id": str(change.id),
        "record_key": redacted_key,
        "change_type": change.change_type.value,
        "significance": change.significance.value,
        "score": change.score,
        "detected_at": change.detected_at.isoformat(),
        "diff": redacted_diff,
    }


async def _acting_principal(uow: UnitOfWork, org_id: UUID, user_id: UUID | None) -> Principal:
    """Tools act with the requesting user's current role (system for automation)."""
    if user_id is None:
        return Principal.system(org_id)
    membership = await uow.memberships.get(org_id, user_id)
    if membership is None:
        return Principal.for_user(user_id=user_id, org_id=org_id, role=None, session_id=None)
    return Principal.for_user(user_id=user_id, org_id=org_id, role=membership.role, session_id=None)


async def _source_hosts(uow: UnitOfWork, org_id: UUID, dataset_id: UUID) -> frozenset[str]:
    page = await uow.data.sources.list_page(
        org_id, PageRequest(limit=100), {"dataset_id": dataset_id}
    )
    hosts = set()
    for source in page.items:
        config = source.parsed_config
        if isinstance(config, (WebsiteConfig, RestApiConfig)) and "://" in config.url:
            hosts.add(config.url.split("/")[2].split(":")[0].lower())
    return frozenset(hosts)

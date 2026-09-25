"""Source management and collection-run requests."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import ConflictError, InvalidInputError, NotFoundError
from nexusflow.core.ids import uuid7
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.core.text import required_name, single_line
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.catalog.model import Dataset
from nexusflow.domain.catalog.service import get_dataset
from nexusflow.domain.integrations.model import SOURCE_AUTH_KINDS, IntegrationStatus
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.files import file_deletions
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.domain.sources.model import (
    AnySourceConfig,
    CollectionRun,
    RestApiConfig,
    RunTrigger,
    Source,
    SourceKind,
    SourceStatus,
    WebsiteConfig,
    mapped_fields,
)

type SelectorValidator = Callable[[str], None]
_PULL_KINDS = frozenset({SourceKind.WEBSITE, SourceKind.REST_API})


class SourceService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        url_policy: UrlPolicy,
        selector_validator: SelectorValidator,
        max_items_per_run: int,
        javascript_rendering_available: bool,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._url_policy = url_policy
        self._validate_selector = selector_validator
        self._max_items = max_items_per_run
        self._js_available = javascript_rendering_available

    async def create(
        self,
        principal: Principal,
        *,
        project_id: UUID,
        dataset_id: UUID,
        name: str,
        config: AnySourceConfig,
        integration_id: UUID | None,
        meta: RequestMeta,
    ) -> Source:
        principal.require(Permission.SOURCES_WRITE)
        org_id = principal.require_org()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            dataset = await get_dataset(uow, org_id, dataset_id)
            if dataset.project_id != project_id:
                raise NotFoundError()
            await self._validate(uow, org_id, dataset, config, integration_id)
            source = Source(
                id=uuid7(),
                org_id=org_id,
                project_id=project_id,
                dataset_id=dataset_id,
                name=required_name(name),
                kind=SourceKind(config.kind),
                config=config.model_dump(mode="json"),
                integration_id=integration_id,
                created_by=principal.actor_user_id,
                created_at=now,
                updated_at=now,
            )
            await uow.data.sources.add(source)
            await self._audit.record(
                uow.audit,
                action=AuditAction.SOURCE_CREATED,
                principal=principal,
                meta=meta,
                resource_type="source",
                resource_id=source.id,
                metadata=_audit_summary(config),
            )
            await uow.commit()
        return source

    async def update(
        self,
        principal: Principal,
        source_id: UUID,
        *,
        name: str | None,
        config: AnySourceConfig | None,
        integration_id: UUID | None,
        clear_integration: bool,
        status: SourceStatus | None,
        meta: RequestMeta,
    ) -> Source:
        principal.require(Permission.SOURCES_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            source = await uow.data.sources.get_for_update(org_id, source_id)
            if source is None:
                raise NotFoundError()
            if status is SourceStatus.QUARANTINED or source.status is SourceStatus.QUARANTINED:
                principal.require(Permission.INTEGRATIONS_WRITE)
            new_config = config or source.parsed_config
            if config is not None and config.kind != source.kind:
                raise InvalidInputError("The source kind cannot be changed.", code="kind_immutable")
            new_integration = (
                None if clear_integration else (integration_id or source.integration_id)
            )
            dataset = await get_dataset(uow, org_id, source.dataset_id)
            await self._validate(uow, org_id, dataset, new_config, new_integration)
            if name is not None:
                source.name = required_name(name)
            source.config = new_config.model_dump(mode="json")
            source.integration_id = new_integration
            if status is not None:
                source.status = status
                if status is SourceStatus.ACTIVE:
                    source.consecutive_failures = 0
            source.updated_at = self._clock.now()
            await self._audit.record(
                uow.audit,
                action=AuditAction.SOURCE_UPDATED,
                principal=principal,
                meta=meta,
                resource_type="source",
                resource_id=source.id,
                metadata={**_audit_summary(new_config), "status": source.status},
            )
            await uow.commit()
            return source

    async def delete(self, principal: Principal, source_id: UUID, meta: RequestMeta) -> None:
        principal.require(Permission.SOURCES_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            source = await uow.data.sources.get_for_update(org_id, source_id)
            if source is None:
                raise NotFoundError()
            # The cascade removes the source's uploads; their files follow the commit.
            keys = await uow.data.maintenance.file_keys(org_id, source_id=source.id)
            await uow.data.sources.delete(source)
            for message in file_deletions(org_id, keys, now=self._clock.now()):
                await uow.outbox.add(message)
            await self._audit.record(
                uow.audit,
                action=AuditAction.SOURCE_DELETED,
                principal=principal,
                meta=meta,
                resource_type="source",
                resource_id=source_id,
            )
            await uow.commit()

    async def list(
        self, principal: Principal, page: PageRequest, filters: Mapping[str, Any]
    ) -> Page[Source]:
        principal.require(Permission.SOURCES_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.sources.list_page(principal.require_org(), page, filters)

    async def get(self, principal: Principal, source_id: UUID) -> Source:
        principal.require(Permission.SOURCES_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            source = await uow.data.sources.get(principal.require_org(), source_id)
            if source is None:
                raise NotFoundError()
            return source

    # ------------------------------------------------------------------ runs

    async def request_run(
        self,
        principal: Principal,
        source_id: UUID,
        *,
        idempotency_key: str | None,
        meta: RequestMeta,
    ) -> tuple[CollectionRun, bool]:
        """Queue a manual run. Returns ``(run, created)``; retries with the same
        ``Idempotency-Key`` return the original run instead of starting another."""
        principal.require(Permission.SOURCES_RUN)
        org_id = principal.require_org()
        key = _idempotency_key(idempotency_key)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            if key is not None:
                existing = await uow.data.runs.get_by_idempotency_key(org_id, key)
                if existing is not None:
                    return existing, False
            source = await uow.data.sources.get(org_id, source_id)
            if source is None:
                raise NotFoundError()
            if source.kind not in _PULL_KINDS:
                raise ConflictError(
                    "Push sources (webhooks, uploads) cannot be run manually.",
                    code="not_pull_source",
                )
            if not source.is_runnable:
                raise ConflictError(f"The source is {source.status}.", code="source_not_runnable")
            organization = await uow.organizations.get(org_id)
            if organization is not None and organization.policy.automation_frozen:
                raise ConflictError(
                    "Automation is frozen for this organization.", code="automation_frozen"
                )
            run = await queue_run(
                uow, source, trigger=RunTrigger.MANUAL, idempotency_key=key, now=now
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.SOURCE_RUN_REQUESTED,
                principal=principal,
                meta=meta,
                resource_type="source",
                resource_id=source.id,
                metadata={"run_id": str(run.id)},
            )
            await uow.commit()
        return run, True

    async def list_runs(
        self, principal: Principal, page: PageRequest, *, source_id: UUID | None
    ) -> Page[CollectionRun]:
        principal.require(Permission.SOURCES_READ)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            if source_id is not None and await uow.data.sources.get(org_id, source_id) is None:
                raise NotFoundError()  # another tenant's source is not "a source without runs"
            return await uow.data.runs.list_page(org_id, page, {"source_id": source_id})

    async def get_run(self, principal: Principal, run_id: UUID) -> CollectionRun:
        principal.require(Permission.SOURCES_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            run = await uow.data.runs.get(principal.require_org(), run_id)
            if run is None:
                raise NotFoundError()
            return run

    # ------------------------------------------------------------ validation

    async def _validate(
        self,
        uow: UnitOfWork,
        org_id: UUID,
        dataset: Dataset,
        config: AnySourceConfig,
        integration_id: UUID | None,
    ) -> None:
        spec = dataset.spec
        fields = mapped_fields(config)
        known = {f.name for f in spec.fields}
        unknown = fields - known
        if unknown:
            raise InvalidInputError(
                f"Mapped fields not in the dataset schema: {', '.join(sorted(unknown))}.",
                code="unknown_fields",
            )
        missing = {f.name for f in spec.fields if f.required} - fields
        if missing:
            raise InvalidInputError(
                f"Required dataset fields are not mapped: {', '.join(sorted(missing))}.",
                code="unmapped_required_fields",
            )
        if isinstance(config, (WebsiteConfig, RestApiConfig)):
            organization = await uow.organizations.get(org_id)
            allowed = organization.policy.allowed_source_domains if organization else None
            self._url_policy.with_allowed_domains(allowed).validate(config.url)
            if config.max_items > self._max_items:
                raise InvalidInputError(
                    f"max_items cannot exceed {self._max_items}.", code="max_items_too_large"
                )
        if isinstance(config, WebsiteConfig):
            self._validate_selector(config.item_selector)
            for extraction in config.fields.values():
                self._validate_selector(extraction.selector)
            if config.render_javascript and not self._js_available:
                raise InvalidInputError(
                    "JavaScript rendering is not enabled on this deployment.", code="js_unavailable"
                )
        if integration_id is not None:
            if not isinstance(config, RestApiConfig):
                raise InvalidInputError(
                    "Only REST API sources use integrations.", code="integration_not_supported"
                )
            integration = await uow.data.integrations.get(org_id, integration_id)
            if (
                integration is None
                or integration.status is not IntegrationStatus.ACTIVE
                or integration.kind not in SOURCE_AUTH_KINDS
            ):
                raise InvalidInputError(
                    "The integration is missing, inactive or of the wrong kind.",
                    code="invalid_integration",
                )


async def queue_run(
    uow: UnitOfWork,
    source: Source,
    *,
    trigger: RunTrigger,
    idempotency_key: str | None,
    now: datetime,
    workflow_run_id: UUID | None = None,
    enqueue: bool = True,
) -> CollectionRun:
    run = CollectionRun(
        id=uuid7(),
        org_id=source.org_id,
        source_id=source.id,
        workflow_run_id=workflow_run_id,
        trigger=trigger,
        idempotency_key=idempotency_key,
        created_at=now,
    )
    await uow.data.runs.add(run)
    if enqueue:
        await uow.outbox.add(
            new_message(
                TaskName.COLLECT_SOURCE,
                {"org_id": str(source.org_id), "run_id": str(run.id)},
                org_id=source.org_id,
                now=now,
            )
        )
    return run


def _idempotency_key(raw: str | None) -> str | None:
    if raw is None:
        return None
    key = single_line(raw, 128)
    if not 8 <= len(key) <= 128 or not all(c.isalnum() or c in "-_.:" for c in key):
        raise InvalidInputError(
            "Idempotency-Key must be 8-128 characters of [A-Za-z0-9-_.:].",
            code="invalid_idempotency_key",
        )
    return key


def _audit_summary(config: AnySourceConfig) -> dict[str, Any]:
    summary: dict[str, Any] = {"kind": config.kind}
    if isinstance(config, (WebsiteConfig, RestApiConfig)):
        summary["host"] = config.url.split("/")[2] if "://" in config.url else None
    return summary

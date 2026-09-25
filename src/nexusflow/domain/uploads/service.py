"""File upload intake: size-bounded streaming, content inspection, scanning,
deduplication and a queued (sandboxed) parse."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Literal
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import ConflictError, InvalidInputError, NotFoundError
from nexusflow.core.ids import uuid7
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.domain.audit.model import AuditAction, AuditResult
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.ports import FileStorage, MalwareScanner, StoredFile
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWorkFactory
from nexusflow.domain.sources.model import FileUploadConfig, RunTrigger, SourceKind
from nexusflow.domain.sources.service import queue_run
from nexusflow.domain.uploads.model import (
    CONTENT_TYPES,
    Upload,
    display_filename,
    inspect_file,
    storage_key,
)


class UploadService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        storage: FileStorage,
        scanner: MalwareScanner,
        max_bytes: int,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._storage = storage
        self._scanner = scanner
        self._max_bytes = max_bytes

    async def accept(
        self,
        principal: Principal,
        *,
        source_id: UUID,
        filename: str | None,
        content: AsyncIterator[bytes],
        meta: RequestMeta,
    ) -> tuple[Upload, bool]:
        """Returns ``(upload, created)``; identical re-uploads are idempotent."""
        principal.require(Permission.UPLOADS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            source = await uow.data.sources.get(org_id, source_id)
            if source is None:
                raise NotFoundError()
            if source.kind is not SourceKind.FILE_UPLOAD or not source.is_runnable:
                raise ConflictError(
                    "The source does not accept file uploads.", code="not_upload_source"
                )
            organization = await uow.organizations.get(org_id)
            if organization is not None and organization.policy.automation_frozen:
                raise ConflictError(
                    "Automation is frozen for this organization.", code="automation_frozen"
                )
            config = source.parsed_config
        if not isinstance(config, FileUploadConfig):
            raise ConflictError(
                "The source does not accept file uploads.", code="not_upload_source"
            )
        upload_id = uuid7()
        key = storage_key(org_id, upload_id, config.format)
        stored = await self._storage.save(key, content, max_bytes=self._max_bytes)
        keep = False
        try:  # the stored file is removed on every path that does not register it
            try:
                await asyncio.to_thread(
                    inspect_file, self._storage.local_path(key), expected=config.format
                )
                verdict = await self._scanner.scan(self._storage.local_path(key))
                if not verdict.clean:
                    raise InvalidInputError(
                        "The file was rejected by the malware scanner.", code="upload_malware"
                    )
            except InvalidInputError as rejection:
                await self._record_rejection(principal, source_id, rejection.code, meta)
                raise
            upload, keep = await self._register(
                principal,
                source_id=source_id,
                upload_id=upload_id,
                key=key,
                stored=stored,
                file_format=config.format,
                filename=filename,
                meta=meta,
            )
            return upload, keep
        finally:
            if not keep:
                await self._storage.delete(key)

    async def _register(
        self,
        principal: Principal,
        *,
        source_id: UUID,
        upload_id: UUID,
        key: str,
        stored: StoredFile,
        file_format: Literal["csv", "xlsx"],
        filename: str | None,
        meta: RequestMeta,
    ) -> tuple[Upload, bool]:
        org_id = principal.require_org()
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            existing = await uow.data.uploads.find_by_hash(org_id, source_id, stored.sha256)
            if existing is not None:
                return existing, False
            source = await uow.data.sources.get(org_id, source_id)
            if source is None:
                raise NotFoundError()
            run = await queue_run(
                uow, source, trigger=RunTrigger.UPLOAD, idempotency_key=None, now=now, enqueue=False
            )
            upload = Upload(
                id=upload_id,
                org_id=org_id,
                source_id=source_id,
                original_filename=display_filename(filename),
                storage_key=key,
                content_type=CONTENT_TYPES[file_format],
                size_bytes=stored.size,
                sha256=stored.sha256,
                uploaded_by=principal.actor_user_id,
                run_id=run.id,
                created_at=now,
            )
            await uow.data.uploads.add(upload)
            await uow.outbox.add(
                new_message(
                    TaskName.PROCESS_UPLOAD,
                    {"org_id": str(org_id), "upload_id": str(upload.id), "run_id": str(run.id)},
                    org_id=org_id,
                    now=now,
                )
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.UPLOAD_ACCEPTED,
                principal=principal,
                meta=meta,
                resource_type="upload",
                resource_id=upload.id,
                metadata={"size": stored.size, "sha256": stored.sha256[:16], "format": file_format},
            )
            await uow.commit()
        return upload, True

    async def list(
        self, principal: Principal, page: PageRequest, *, source_id: UUID | None
    ) -> Page[Upload]:
        principal.require(Permission.SOURCES_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.uploads.list_page(
                principal.require_org(), page, {"source_id": source_id}
            )

    async def _record_rejection(
        self, principal: Principal, source_id: UUID, code: str, meta: RequestMeta
    ) -> None:
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            await self._audit.record(
                uow.audit,
                action=AuditAction.UPLOAD_REJECTED,
                principal=principal,
                meta=meta,
                result=AuditResult.DENIED,
                resource_type="source",
                resource_id=source_id,
                metadata={"reason": code},
            )
            await uow.commit()

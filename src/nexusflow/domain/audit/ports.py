"""Audit persistence port."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from nexusflow.core.pagination import Page, PageRequest
from nexusflow.domain.audit.model import AuditEvent, AuditLogEntry


@dataclass(frozen=True, slots=True)
class AuditFilter:
    action: str | None = None
    actor_id: UUID | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    result: str | None = None
    since: datetime | None = None
    until: datetime | None = None


class AuditLogRepository(Protocol):
    async def append(self, event: AuditEvent) -> None: ...

    async def list_page(
        self, org_id: UUID, filters: AuditFilter, page: PageRequest
    ) -> Page[AuditLogEntry]: ...

    async def chain(self, chain_key: UUID, *, from_seq: int, limit: int) -> list[AuditLogEntry]: ...

    async def latest(self, chain_key: UUID) -> AuditLogEntry | None: ...

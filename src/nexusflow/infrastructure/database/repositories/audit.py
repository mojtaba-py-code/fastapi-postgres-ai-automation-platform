"""Audit log persistence via the append-only ``nf_append_audit`` function."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import Row, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from nexusflow.core.pagination import Page, PageRequest
from nexusflow.domain.audit.model import PLATFORM_CHAIN, AuditEvent, AuditLogEntry
from nexusflow.domain.audit.ports import AuditFilter
from nexusflow.infrastructure.database.pagination import paginate_rows
from nexusflow.infrastructure.database.tables import identity as t

# The application role has no INSERT/UPDATE/DELETE privilege on audit_logs;
# this SECURITY DEFINER function is the only write path. It serializes appends
# per chain, computes the hash chain and refuses cross-tenant writes.
_APPEND = text(
    "SELECT nf_append_audit(:id, :org_id, :occurred_at, :actor_type, :actor_id, :action, "
    ":resource_type, :resource_id, :result, :ip, :user_agent, :request_id, "
    "CAST(:metadata AS jsonb), :canonical)"
)
# Row-level security hides rows without a tenant from the runtime role; these
# SECURITY DEFINER functions expose exactly the platform chain (migration 0004).
_PLATFORM_PAGE = text("SELECT * FROM nf_platform_audit_page(:from_seq, :limit)")
_PLATFORM_HEAD = text("SELECT * FROM nf_platform_audit_head()")


def _to_entry(row: Row[Any]) -> AuditLogEntry:
    return AuditLogEntry(
        id=row.id,
        org_id=row.org_id,
        seq=row.seq,
        occurred_at=row.occurred_at,
        actor_type=row.actor_type,
        actor_id=row.actor_id,
        action=row.action,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        result=row.result,
        ip=row.ip,
        user_agent=row.user_agent,
        request_id=row.request_id,
        metadata=row.metadata,
        canonical=row.canonical,
        prev_hash=bytes(row.prev_hash),
        hash=bytes(row.hash),
    )


class SqlAuditLogRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def append(self, event: AuditEvent) -> None:
        await self._s.flush()  # keep audit ordering consistent with pending ORM writes
        await self._s.execute(
            _APPEND,
            {
                "id": event.id,
                "org_id": event.org_id,
                "occurred_at": event.occurred_at,
                "actor_type": event.actor_type.value,
                "actor_id": event.actor_id,
                "action": event.action.value,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
                "result": event.result.value,
                "ip": event.ip,
                "user_agent": event.user_agent,
                "request_id": event.request_id,
                "metadata": json.dumps(event.metadata),
                "canonical": event.canonical(),
            },
        )

    async def list_page(
        self, org_id: UUID, filters: AuditFilter, page: PageRequest
    ) -> Page[AuditLogEntry]:
        a = t.audit_logs
        statement = select(a).where(a.c.org_id == org_id)
        if filters.action:
            statement = statement.where(a.c.action == filters.action)
        if filters.actor_id:
            statement = statement.where(a.c.actor_id == filters.actor_id)
        if filters.resource_type:
            statement = statement.where(a.c.resource_type == filters.resource_type)
        if filters.resource_id:
            statement = statement.where(a.c.resource_id == filters.resource_id)
        if filters.result:
            statement = statement.where(a.c.result == filters.result)
        if filters.since:
            statement = statement.where(a.c.occurred_at >= filters.since)
        if filters.until:
            statement = statement.where(a.c.occurred_at < filters.until)
        return await paginate_rows(
            self._s,
            statement,
            page=page,
            sort_columns={"created_at": a.c.occurred_at, "occurred_at": a.c.occurred_at},
            id_column=a.c.id,
            convert=_to_entry,
            key=lambda e: (e.occurred_at, e.id),
        )

    async def chain(self, chain_key: UUID, *, from_seq: int, limit: int) -> list[AuditLogEntry]:
        if chain_key == PLATFORM_CHAIN:
            rows = await self._s.execute(_PLATFORM_PAGE, {"from_seq": from_seq, "limit": limit})
            return [_to_entry(row) for row in rows.all()]
        a = t.audit_logs
        statement = (
            select(a)
            .where(a.c.chain_key == chain_key, a.c.seq >= from_seq)
            .order_by(a.c.seq)
            .limit(limit)
        )
        return [_to_entry(row) for row in (await self._s.execute(statement)).all()]

    async def latest(self, chain_key: UUID) -> AuditLogEntry | None:
        if chain_key == PLATFORM_CHAIN:
            head = (await self._s.execute(_PLATFORM_HEAD)).first()
            return _to_entry(head) if head is not None else None
        a = t.audit_logs
        statement = select(a).where(a.c.chain_key == chain_key).order_by(a.c.seq.desc()).limit(1)
        row = (await self._s.execute(statement)).first()
        return _to_entry(row) if row is not None else None

"""Transactional outbox persistence."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from nexusflow.domain.shared.outbox import OutboxMessage
from nexusflow.infrastructure.database.tables import identity as t

# Messages that could not be published become visible again after this delay.
_REDELIVERY_DELAY = timedelta(seconds=30)


class SqlOutboxRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session
        self.added: list[OutboxMessage] = []

    async def add(self, message: OutboxMessage) -> None:
        self._s.add(message)
        self.added.append(message)

    async def claim_batch(self, *, now: datetime, limit: int) -> list[OutboxMessage]:
        """Lease due messages (``FOR UPDATE SKIP LOCKED`` - safe with many relays)."""
        o = t.outbox_messages
        due = (
            select(o.c.id)
            .where(o.c.dispatched_at.is_(None), o.c.available_at <= now)
            .order_by(o.c.available_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        ids = list((await self._s.execute(due)).scalars().all())
        if not ids:
            return []
        await self._s.execute(
            update(o)
            .where(o.c.id.in_(ids))
            .values(attempts=o.c.attempts + 1, available_at=now + _REDELIVERY_DELAY)
            .execution_options(synchronize_session=False)
        )
        statement = (
            select(OutboxMessage).where(o.c.id.in_(ids)).execution_options(populate_existing=True)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def mark_dispatched(self, ids: list[UUID], *, now: datetime) -> None:
        if not ids:
            return
        o = t.outbox_messages
        await self._s.execute(
            update(o)
            .where(o.c.id.in_(ids))
            .values(dispatched_at=now, last_error=None)
            .execution_options(synchronize_session=False)
        )

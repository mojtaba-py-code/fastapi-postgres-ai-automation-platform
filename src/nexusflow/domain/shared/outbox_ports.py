"""Outbox persistence port."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from nexusflow.domain.shared.outbox import OutboxMessage


class OutboxRepository(Protocol):
    async def add(self, message: OutboxMessage) -> None: ...

    async def claim_batch(self, *, now: datetime, limit: int) -> list[OutboxMessage]: ...

    async def mark_dispatched(self, ids: list[UUID], *, now: datetime) -> None: ...

"""Outbox publishing: immediate best-effort dispatch plus a relay for the rest."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any
from uuid import UUID

from celery import Celery

from nexusflow.core.clock import Clock
from nexusflow.core.correlation import CORRELATION_KWARG, current_correlation_id
from nexusflow.domain.shared.outbox import OutboxMessage
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWorkFactory
from nexusflow.infrastructure.messaging.celery_app import TASK_ROUTES
from nexusflow.infrastructure.observability.logging import get_logger

_log = get_logger("nexusflow.outbox")


class CeleryDispatcher:
    """Publishes messages to the broker (blocking kombu I/O runs in a thread)."""

    def __init__(self, celery: Celery) -> None:
        self._celery = celery

    def send(self, message: OutboxMessage) -> None:
        name, queue = TASK_ROUTES[message.task]
        kwargs = dict(message.payload)
        if message.correlation_id:
            kwargs[CORRELATION_KWARG] = message.correlation_id
        self._celery.send_task(
            name,
            kwargs=kwargs,
            queue=queue,
            routing_key=queue,
            task_id=str(message.id),  # correlates broker message <-> outbox row
        )

    def send_task(self, name: str, *, kwargs: dict[str, Any], queue: str) -> None:
        """Hand work to another pool directly, carrying the current correlation."""
        correlation_id = current_correlation_id()
        if correlation_id and CORRELATION_KWARG not in kwargs:
            kwargs = {**kwargs, CORRELATION_KWARG: correlation_id}
        self._celery.send_task(name, kwargs=kwargs, queue=queue, routing_key=queue)


class OutboxPublisher:
    """Post-commit fast path. Failures are logged; the relay retries them."""

    def __init__(
        self, dispatcher: CeleryDispatcher, uow_factory: UnitOfWorkFactory, clock: Clock
    ) -> None:
        self._dispatcher = dispatcher
        self._uow_factory = uow_factory
        self._clock = clock

    async def publish(self, messages: list[OutboxMessage]) -> None:
        now = self._clock.now()
        due = [m for m in messages if m.available_at <= now]
        sent = await self._send_all(due)
        if sent:
            async with self._uow_factory(TenantScope.system(None)) as uow:
                await uow.outbox.mark_dispatched(sent, now=now)
                await uow.commit()

    async def _send_all(self, messages: Sequence[OutboxMessage]) -> list[UUID]:
        sent: list[UUID] = []
        for message in messages:
            try:
                await asyncio.to_thread(self._dispatcher.send, message)
                sent.append(message.id)
            except Exception as exc:  # noqa: BLE001 - broker outage must not fail the request
                _log.warning(
                    "outbox_publish_deferred", task=message.task.value, error=type(exc).__name__
                )
        return sent


class OutboxRelay:
    """Periodic job: publish every committed message that is still pending."""

    def __init__(
        self, dispatcher: CeleryDispatcher, uow_factory: UnitOfWorkFactory, clock: Clock
    ) -> None:
        self._dispatcher = dispatcher
        self._uow_factory = uow_factory
        self._clock = clock

    async def run_once(self, *, batch: int = 200) -> int:
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(None)) as uow:
            messages = await uow.outbox.claim_batch(now=now, limit=batch)
            await uow.commit()
        sent: list[UUID] = []
        for message in messages:
            try:
                await asyncio.to_thread(self._dispatcher.send, message)
                sent.append(message.id)
            except Exception as exc:  # noqa: BLE001 - retried on the next relay tick
                _log.warning(
                    "outbox_relay_failed", task=message.task.value, error=type(exc).__name__
                )
        if sent:
            async with self._uow_factory(TenantScope.system(None)) as uow:
                await uow.outbox.mark_dispatched(sent, now=self._clock.now())
                await uow.commit()
        return len(sent)

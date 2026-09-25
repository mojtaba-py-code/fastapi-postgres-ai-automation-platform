"""In-process broker: the outbox relay, the broker and the worker pools in one object.

Installed as the unit of work's post-commit publisher, it records every message a
transaction commits to the outbox and runs the matching platform task handlers,
validating each payload exactly as the Celery task wrapper does.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

import pytest

from nexusflow.apps.workers.handlers import WorkerDeps
from nexusflow.apps.workers.tasks import PLATFORM_TASKS, TaskSpec
from nexusflow.bootstrap.container import Container
from nexusflow.core.correlation import correlation
from nexusflow.domain.shared.outbox import OutboxMessage, TaskName
from nexusflow.infrastructure.messaging.celery_app import TASK_ROUTES

_SPECS: dict[str, TaskSpec[Any]] = {spec.name: spec for spec in PLATFORM_TASKS}


class _NoBroker:
    """Hand-offs to other worker pools (sandbox, n8n forwarding) are recorded only."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any], str]] = []

    def send_task(self, name: str, *, kwargs: dict[str, Any], queue: str) -> None:
        self.sent.append((name, kwargs, queue))


class InProcessBus:
    def __init__(self, container: Container) -> None:
        self.messages: list[OutboxMessage] = []
        self.errors: list[tuple[str, BaseException]] = []
        self._next = 0
        self._delayed: list[OutboxMessage] = []
        self._deps = WorkerDeps(container=container, dispatcher=cast(Any, _NoBroker()))

    async def publish(self, messages: list[OutboxMessage]) -> None:
        self.messages.extend(messages)

    def published(self, task: TaskName, org_id: UUID) -> list[OutboxMessage]:
        return [m for m in self.messages if m.task is task and m.org_id == org_id]

    async def run(self, message: OutboxMessage) -> str:
        """Validate the message and run its handler as a worker does - including the
        request correlation, so the messages the handler emits carry it on."""
        name, _queue = TASK_ROUTES[message.task]
        spec = _SPECS[name]
        with correlation(message.correlation_id or str(message.id)):
            await spec.handler(self._deps, spec.model.model_validate(message.payload))
        event = message.payload.get("event")
        return f"{name}:{event}" if event else name

    async def drain(self, org_id: UUID) -> list[str]:
        """Run the tenant's due messages - and whatever they emit - until none are left."""
        handled: list[str] = []
        while self._next < len(self.messages):
            message = self.messages[self._next]
            self._next += 1
            if message.org_id == org_id and message.available_at <= datetime.now(UTC):
                handled.append(await self.run(message))
                assert len(handled) < 50, f"runaway message loop: {handled}"
        return handled

    async def work(self) -> None:
        """One pass of the worker pools over every due message, like a live stack.

        Delayed messages (retries) wait until they are due; a failing handler is
        recorded, as a worker would log it, instead of stopping the pass.
        """
        fresh = self.messages[self._next :]
        self._next = len(self.messages)
        now = datetime.now(UTC)
        due = [m for m in [*self._delayed, *fresh] if m.available_at <= now]
        self._delayed = [m for m in [*self._delayed, *fresh] if m.available_at > now]
        for message in due:
            try:
                await self.run(message)
            except Exception as exc:  # noqa: BLE001 - recorded for the test to assert on
                self.errors.append((message.task.value, exc))


@pytest.fixture
def bus(container: Container, monkeypatch: pytest.MonkeyPatch) -> InProcessBus:
    recorder = InProcessBus(container)
    monkeypatch.setattr(container.uow_factory, "_publisher", recorder)
    return recorder

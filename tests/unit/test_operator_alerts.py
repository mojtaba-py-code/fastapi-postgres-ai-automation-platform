"""Operator alerts page once per incident - and are never lost to the deduplication."""

from __future__ import annotations

from datetime import UTC, datetime
from types import TracebackType
from typing import Any, cast
from uuid import UUID

import pytest

from nexusflow.core.clock import FrozenClock
from nexusflow.core.errors import ServiceUnavailableError
from nexusflow.domain.authorization.principal import Principal, PrincipalType, ServiceScope
from nexusflow.domain.automation.service import AutomationService

PAGER = Principal(
    type=PrincipalType.SERVICE,
    id=UUID(int=7),
    org_id=None,
    role=None,
    service_scopes=frozenset({ServiceScope.OPERATOR_ALERT}),
    label="service:failure-recovery",
)


class FakeNonces:
    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.claimed: set[str] = set()
        self.released: list[str] = []

    async def first_use(self, namespace: str, nonce: str, *, ttl_seconds: int) -> bool:
        if not self.available:
            raise ServiceUnavailableError()
        if nonce in self.claimed:
            return False
        self.claimed.add(nonce)
        return True

    async def release(self, namespace: str, nonce: str) -> None:
        self.released.append(nonce)
        self.claimed.discard(nonce)


class FakeUnitOfWork:
    def __init__(self, outbox: list[Any], *, fail_commit: bool) -> None:
        self.outbox = self
        self._messages = outbox
        self._pending: list[Any] = []
        self._fail_commit = fail_commit

    async def __aenter__(self) -> FakeUnitOfWork:
        return self

    async def __aexit__(
        self, kind: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        return None

    async def add(self, message: Any) -> None:
        self._pending.append(message)

    async def commit(self) -> None:
        if self._fail_commit:
            raise ServiceUnavailableError(internal_detail="database unavailable")
        self._messages.extend(self._pending)


def _service(
    nonces: FakeNonces, outbox: list[Any], *, fail_commit: bool = False
) -> AutomationService:
    return AutomationService(
        uow_factory=cast(Any, lambda scope: FakeUnitOfWork(outbox, fail_commit=fail_commit)),
        clock=FrozenClock(datetime(2026, 9, 24, 12, 0, tzinfo=UTC)),
        detection=cast(Any, None),
        intelligence=cast(Any, None),
        alerts=cast(Any, None),
        dead_letters=cast(Any, None),
        nonces=nonces,
    )


async def test_a_failure_storm_pages_once() -> None:
    outbox: list[Any] = []
    service = _service(FakeNonces(), outbox)
    for _ in range(5):
        await service.operator_alert(PAGER, severity="critical", summary="SMTP rejects mail")
    assert len(outbox) == 1
    # A different incident (or severity) is a different page.
    assert await service.operator_alert(PAGER, severity="critical", summary="Disk full")
    assert await service.operator_alert(PAGER, severity="warning", summary="SMTP rejects mail")
    assert len(outbox) == 3


async def test_pages_are_sent_when_the_deduplication_store_is_down() -> None:
    outbox: list[Any] = []
    service = _service(FakeNonces(available=False), outbox)
    assert await service.operator_alert(PAGER, severity="critical", summary="Redis down")
    assert await service.operator_alert(PAGER, severity="critical", summary="Redis down")
    assert len(outbox) == 2  # a duplicate page beats a lost one


async def test_an_alert_that_failed_to_queue_is_not_suppressed_on_retry() -> None:
    nonces, outbox = FakeNonces(), []
    with pytest.raises(ServiceUnavailableError):
        await _service(nonces, outbox, fail_commit=True).operator_alert(
            PAGER, severity="critical", summary="Workflow 5 failing"
        )
    assert len(nonces.released) == 1
    retried = await _service(nonces, outbox).operator_alert(
        PAGER, severity="critical", summary="Workflow 5 failing"
    )
    assert retried
    assert len(outbox) == 1

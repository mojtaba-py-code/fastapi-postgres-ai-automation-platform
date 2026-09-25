"""Fixtures for adapter tests: SSRF-guarded clients over in-memory transports and a
fake Redis. Nothing here opens a real network connection."""

from __future__ import annotations

from collections.abc import AsyncIterator

import fakeredis
import httpx2
import pytest

from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.infrastructure.http.client import HttpClientLimits, SafeHttpClient
from tests.unit.adapters.fakes import USER_AGENT, Handler, SafeClientFactory


@pytest.fixture
async def safe_client_factory() -> AsyncIterator[SafeClientFactory]:
    """Builds real ``SafeHttpClient``s whose transport is ``handler``; closes them afterwards."""
    clients: list[SafeHttpClient] = []

    def make(
        handler: Handler, *, policy: UrlPolicy | None = None, **limits: float
    ) -> SafeHttpClient:
        client = SafeHttpClient(
            policy=policy or UrlPolicy(),
            user_agent=USER_AGENT,
            limits=HttpClientLimits(**limits),  # type: ignore[arg-type]
            transport=httpx2.MockTransport(handler),
        )
        clients.append(client)
        return client

    yield make
    for client in clients:
        await client.aclose()


@pytest.fixture
async def fake_redis() -> AsyncIterator[fakeredis.FakeAsyncRedis]:
    redis = fakeredis.FakeAsyncRedis()
    yield redis
    await redis.aclose()

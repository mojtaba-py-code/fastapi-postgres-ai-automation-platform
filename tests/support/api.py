"""In-process API client fixtures (real app, real database, fake Redis)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx2
import pytest
from asgi_lifespan import LifespanManager
from fastapi import FastAPI

from nexusflow.apps.api.main import create_app
from nexusflow.bootstrap.container import Container
from tests.support.fixtures import PASSWORD, unique_email


@dataclass
class ApiSession:
    client: httpx2.AsyncClient
    access_token: str
    refresh_token: str
    email: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    async def get(self, url: str, **kwargs: Any) -> httpx2.Response:
        return await self.client.get(
            url, headers={**self.headers, **kwargs.pop("headers", {})}, **kwargs
        )

    async def post(self, url: str, **kwargs: Any) -> httpx2.Response:
        return await self.client.post(
            url, headers={**self.headers, **kwargs.pop("headers", {})}, **kwargs
        )

    async def patch(self, url: str, **kwargs: Any) -> httpx2.Response:
        return await self.client.patch(
            url, headers={**self.headers, **kwargs.pop("headers", {})}, **kwargs
        )

    async def delete(self, url: str, **kwargs: Any) -> httpx2.Response:
        return await self.client.delete(
            url, headers={**self.headers, **kwargs.pop("headers", {})}, **kwargs
        )


@pytest.fixture(scope="session")
async def api_app(container: Container) -> AsyncIterator[FastAPI]:
    app = create_app(container.settings, container=container, configure_logs=False)
    async with LifespanManager(app) as manager:
        yield manager.app  # type: ignore[misc]


@pytest.fixture(scope="session")
async def internal_app(container: Container) -> AsyncIterator[FastAPI]:
    app = create_app(container.settings, mode="internal", container=container, configure_logs=False)
    async with LifespanManager(app) as manager:
        yield manager.app  # type: ignore[misc]


@pytest.fixture
async def api(api_app: FastAPI, container: Container) -> AsyncIterator[httpx2.AsyncClient]:
    await container.redis.flushall()  # fresh rate-limit / nonce state per test
    transport = httpx2.ASGITransport(app=api_app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.fixture
async def internal_api(
    internal_app: FastAPI, container: Container
) -> AsyncIterator[httpx2.AsyncClient]:
    await container.redis.flushall()
    transport = httpx2.ASGITransport(app=internal_app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


async def signup(client: httpx2.AsyncClient, *, org: str | None = None) -> ApiSession:
    email = unique_email()
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "full_name": "Api Tester",
            "organization_name": org or f"Api Org {email[:12]}",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    return ApiSession(client, body["access_token"], body["refresh_token"], email)

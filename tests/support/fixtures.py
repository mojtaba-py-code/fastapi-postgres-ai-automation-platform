"""Integration fixtures: real PostgreSQL, real migrations, application DB role."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import asyncpg
import fakeredis
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from nexusflow.bootstrap.container import Container, build_container
from nexusflow.core.clock import FrozenClock
from nexusflow.domain.identity.auth_service import TokenPair
from nexusflow.domain.shared.context import RequestMeta
from tests.conftest import make_settings
from tests.support.database import (
    ProvisionedDatabase,
    admin_url_or_none,
    create_database,
    drop_database,
)

META = RequestMeta(request_id="req-test", ip="203.0.113.10", user_agent="pytest")
PASSWORD = "Str0ng-and-unique-passphrase!"


@pytest.fixture(scope="session")
async def database() -> AsyncIterator[ProvisionedDatabase]:
    admin_url = admin_url_or_none()
    if admin_url is None:
        pytest.skip(
            "PostgreSQL not available (set NEXUSFLOW_TEST_DATABASE_URL or install pgserver)"
        )
    db = await create_database(admin_url)
    try:
        yield db
    finally:
        await drop_database(db)


@pytest.fixture(scope="session")
async def container(
    database: ProvisionedDatabase, tmp_path_factory: pytest.TempPathFactory
) -> AsyncIterator[Container]:
    root: Path = tmp_path_factory.mktemp("storage")
    settings = make_settings(
        root,
        database={"url": database.app_url},
        app={"public_base_url": "https://nexusflow.test.example", "allowed_hosts": ["testserver"]},
    )
    engine = create_async_engine(database.app_url, pool_size=5, max_overflow=5)
    built = build_container(
        settings,
        application_name="nexusflow-tests",
        engine=engine,
        redis=fakeredis.FakeAsyncRedis(),
    )
    try:
        yield built
    finally:
        await built.aclose()


@pytest.fixture
async def admin_conn(database: ProvisionedDatabase) -> AsyncIterator[asyncpg.Connection]:
    """Superuser connection for assertions that must bypass RLS."""
    conn = await asyncpg.connect(database.admin_url.rsplit("/", 1)[0] + f"/{database.name}")
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
async def app_conn(database: ProvisionedDatabase) -> AsyncIterator[asyncpg.Connection]:
    """Raw connection as the application role (subject to RLS and grants)."""
    conn = await asyncpg.connect(database.app_url.replace("postgresql+asyncpg://", "postgresql://"))
    try:
        yield conn
    finally:
        await conn.close()


def unique_email(prefix: str = "user") -> str:
    return f"{prefix}-{uuid4().hex[:10]}@example.com"


async def register(
    container: Container, *, email: str | None = None, org: str | None = None
) -> tuple[str, TokenPair]:
    address = email or unique_email()
    tokens = await container.auth.register(
        email=address,
        password=PASSWORD,
        full_name="Test User",
        organization_name=org or f"Org {uuid4().hex[:8]}",
        invitation_token=None,
        meta=META,
    )
    return address, tokens


@pytest.fixture
def frozen_clock() -> FrozenClock:
    from datetime import UTC, datetime

    return FrozenClock(datetime(2026, 9, 1, 12, 0, tzinfo=UTC))

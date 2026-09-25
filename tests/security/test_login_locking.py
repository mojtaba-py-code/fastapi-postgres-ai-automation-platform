"""Password hashing never runs under a row lock (login floods cannot starve the pool)."""

from __future__ import annotations

import asyncio

import asyncpg
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import AuthenticationError
from tests.support.fixtures import META, PASSWORD, register

pytestmark = [pytest.mark.integration, pytest.mark.security]


async def _login_while_hashing(
    container: Container,
    admin_conn: asyncpg.Connection,
    email: str,
    password: str,
    monkeypatch: pytest.MonkeyPatch,
) -> asyncio.Task[object]:
    hasher = container.auth._hasher
    entered, release = asyncio.Event(), asyncio.Event()
    original = hasher.verify

    async def slow_verify(password_hash: str, candidate: str) -> bool:
        entered.set()
        await release.wait()
        return await original(password_hash, candidate)

    monkeypatch.setattr(hasher, "verify", slow_verify)
    task = asyncio.create_task(
        container.auth.login(email=email, password=password, org_id=None, meta=META)
    )
    await asyncio.wait_for(entered.wait(), 10)
    # While the hash runs, the user's row is free: NOWAIT would fail on a lock.
    async with admin_conn.transaction():
        await admin_conn.execute(
            "SELECT 1 FROM users WHERE email = $1 FOR UPDATE NOWAIT", email.lower()
        )
    release.set()
    return task


async def test_a_successful_login_hashes_without_holding_the_row(
    container: Container, admin_conn: asyncpg.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    email, _ = await register(container)
    task = await _login_while_hashing(container, admin_conn, email, PASSWORD, monkeypatch)
    result = await asyncio.wait_for(task, 10)
    assert result.tokens is not None  # type: ignore[attr-defined]


async def test_a_failed_login_still_counts_towards_lockout(
    container: Container, admin_conn: asyncpg.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    email, _ = await register(container)
    task = await _login_while_hashing(container, admin_conn, email, "wrong-password!", monkeypatch)
    with pytest.raises(AuthenticationError):
        await asyncio.wait_for(task, 10)
    attempts = await admin_conn.fetchval(
        "SELECT failed_login_attempts FROM users WHERE email = $1", email.lower()
    )
    assert attempts == 1

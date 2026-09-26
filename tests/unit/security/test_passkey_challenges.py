"""WebAuthn challenges in Redis (``infrastructure.redis.challenges``).

A challenge is taken at most once however many answers race for it, expires
on its own, leaves no identifier in Redis, and without Redis nothing is issued
or accepted (fail closed).
"""

from __future__ import annotations

import asyncio
from typing import Any

import fakeredis
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from nexusflow.core.errors import ServiceUnavailableError
from nexusflow.infrastructure.redis.challenges import RedisChallengeStore

pytestmark = pytest.mark.security

STATE = {"challenge": "c2VjcmV0", "user_id": "u", "expires_at": "2026-09-26T12:00:00+00:00"}


@pytest.fixture
def redis() -> fakeredis.FakeAsyncRedis:
    return fakeredis.FakeAsyncRedis()


async def test_a_challenge_is_taken_once(redis: fakeredis.FakeAsyncRedis) -> None:
    store = RedisChallengeStore(redis, prefix="nf:")
    await store.put("sign-in:abc", STATE, ttl_seconds=300)
    assert await store.take("sign-in:abc") == STATE
    assert await store.take("sign-in:abc") is None
    assert await store.take("sign-in:unknown") is None


async def test_racing_answers_get_it_once(redis: fakeredis.FakeAsyncRedis) -> None:
    store = RedisChallengeStore(redis, prefix="nf:")
    await store.put("register:s1", STATE, ttl_seconds=300)
    taken = await asyncio.gather(*(store.take("register:s1") for _ in range(20)))
    assert [state for state in taken if state is not None] == [STATE]


async def test_it_expires_and_keeps_no_identifier(redis: fakeredis.FakeAsyncRedis) -> None:
    store = RedisChallengeStore(redis, prefix="nf:")
    await store.put("register:0190f5a1-session", STATE, ttl_seconds=120)
    [key] = await redis.keys("*")
    assert key.startswith(b"nf:webauthn:")
    assert b"session" not in key and b"register" not in key
    assert 0 < await redis.ttl(key) <= 120


async def test_a_new_challenge_replaces_the_pending_one(redis: fakeredis.FakeAsyncRedis) -> None:
    store = RedisChallengeStore(redis, prefix="nf:")
    await store.put("register:s1", STATE, ttl_seconds=300)
    await store.put("register:s1", {**STATE, "challenge": "bmV3"}, ttl_seconds=300)
    taken = await store.take("register:s1")
    assert taken is not None
    assert taken["challenge"] == "bmV3"


@pytest.mark.parametrize("stored", [b"not json", b"[1, 2]", b"\xff", b"{" * 20_000])
async def test_unreadable_state_counts_as_no_challenge(
    redis: fakeredis.FakeAsyncRedis, stored: bytes
) -> None:
    store = RedisChallengeStore(redis, prefix="nf:")
    await store.put("sign-in:x", STATE, ttl_seconds=60)
    [key] = await redis.keys("*")
    await redis.set(key, stored)
    assert await store.take("sign-in:x") is None


async def test_a_lifetime_is_required(redis: fakeredis.FakeAsyncRedis) -> None:
    with pytest.raises(ValueError, match="lifetime"):
        await RedisChallengeStore(redis, prefix="nf:").put("k", STATE, ttl_seconds=0)


class _BrokenRedis:
    async def set(self, *args: Any, **kwargs: Any) -> None:
        raise RedisConnectionError("down")

    async def getdel(self, *args: Any, **kwargs: Any) -> None:
        raise RedisConnectionError("down")


async def test_without_redis_nothing_is_issued_or_accepted() -> None:
    store = RedisChallengeStore(_BrokenRedis(), prefix="nf:")  # type: ignore[arg-type]
    with pytest.raises(ServiceUnavailableError):
        await store.put("k", STATE, ttl_seconds=60)
    with pytest.raises(ServiceUnavailableError):
        await store.take("k")

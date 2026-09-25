"""Per-host politeness throttle (``infrastructure.scraping.throttle``).

At most one request per host per interval, coordinated cluster-wide through a
Redis ``SET NX PX`` reservation, with a per-process fallback when Redis is
unavailable and a bounded total wait. The module's ``time`` and ``asyncio``
references are replaced by a fake monotonic clock whose ``sleep`` only
advances time, so waits are asserted exactly and nothing really sleeps.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import cast

import fakeredis
import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from nexusflow.core.errors import TransientError
from nexusflow.infrastructure.scraping import throttle as throttle_module
from nexusflow.infrastructure.scraping.throttle import HostThrottle

HOST = "shop.example.com"


class FakeTimer:
    """Stands in for ``time.monotonic`` and ``asyncio.sleep``."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start
        self.sleeps: list[float] = []
        self.after_sleep: Callable[[], Awaitable[None]] | None = None

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds
        if self.after_sleep is not None:
            await self.after_sleep()


class _BrokenRedis:
    """Every command fails, as during a Redis outage."""

    async def set(self, *args: object, **kwargs: object) -> bool:
        raise RedisConnectionError("redis is down")

    async def pttl(self, key: str) -> int:
        raise RedisConnectionError("redis is down")


@pytest.fixture
def timer(monkeypatch: pytest.MonkeyPatch) -> FakeTimer:
    fake = FakeTimer()
    monkeypatch.setattr(throttle_module, "time", fake)
    monkeypatch.setattr(throttle_module, "asyncio", fake)
    return fake


def _expire_all(redis: fakeredis.FakeAsyncRedis) -> Callable[[], Awaitable[None]]:
    """After a wait, the reservation has expired (Redis would have evicted it)."""

    async def expire() -> None:
        for key in await redis.keys("nf:throttle:*"):
            await redis.delete(key)

    return expire


class TestRedisReservations:
    async def test_the_first_request_proceeds_and_reserves_the_host(
        self, timer: FakeTimer, fake_redis: fakeredis.FakeAsyncRedis
    ) -> None:
        await HostThrottle(fake_redis, prefix="nf:").acquire(HOST, interval_seconds=2.0)

        assert timer.sleeps == []
        [key] = await fake_redis.keys("nf:throttle:*")
        assert 1_500 < await fake_redis.pttl(key) <= 2_000
        assert HOST.encode() not in key  # host names are hashed, never stored

    async def test_the_next_request_waits_out_the_reservation(
        self, timer: FakeTimer, fake_redis: fakeredis.FakeAsyncRedis
    ) -> None:
        throttle = HostThrottle(fake_redis, prefix="nf:")
        await throttle.acquire(HOST, interval_seconds=2.0)
        timer.after_sleep = _expire_all(fake_redis)

        await throttle.acquire(HOST, interval_seconds=2.0)

        [waited] = timer.sleeps
        assert 1.5 < waited <= 2.0
        [key] = await fake_redis.keys("nf:throttle:*")
        assert await fake_redis.pttl(key) > 1_500  # reserved again for the next caller

    async def test_the_reservation_is_shared_by_all_workers(self, timer: FakeTimer) -> None:
        server = fakeredis.FakeServer()
        worker_a = fakeredis.FakeAsyncRedis(server=server)
        worker_b = fakeredis.FakeAsyncRedis(server=server)
        try:
            await HostThrottle(worker_a, prefix="nf:").acquire(HOST, interval_seconds=5.0)
            timer.after_sleep = _expire_all(worker_b)
            await HostThrottle(worker_b, prefix="nf:").acquire(HOST, interval_seconds=5.0)
        finally:
            await worker_a.aclose()
            await worker_b.aclose()

        [waited] = timer.sleeps
        assert 4.5 < waited <= 5.0

    async def test_hosts_are_throttled_independently(
        self, timer: FakeTimer, fake_redis: fakeredis.FakeAsyncRedis
    ) -> None:
        throttle = HostThrottle(fake_redis, prefix="nf:")
        for host in (HOST, "blog.example.com", "api.example.com"):
            await throttle.acquire(host, interval_seconds=10.0)

        assert timer.sleeps == []
        assert len(await fake_redis.keys("nf:throttle:*")) == 3

    async def test_a_wait_beyond_the_budget_is_a_transient_error(
        self, timer: FakeTimer, fake_redis: fakeredis.FakeAsyncRedis
    ) -> None:
        throttle = HostThrottle(fake_redis, prefix="nf:", max_wait_seconds=5.0)
        await throttle.acquire(HOST, interval_seconds=30.0)

        with pytest.raises(TransientError) as exc:
            await throttle.acquire(HOST, interval_seconds=30.0)

        assert exc.value.code == "host_throttled"
        assert timer.sleeps == []  # fails fast instead of sleeping into the deadline


class TestLocalFallback:
    async def test_requests_are_spaced_by_exactly_the_interval(self, timer: FakeTimer) -> None:
        throttle = HostThrottle(None, prefix="nf:")
        await throttle.acquire(HOST, interval_seconds=2.0)
        await throttle.acquire(HOST, interval_seconds=2.0)
        assert timer.sleeps == [2.0]

        timer.now += 5.0  # idle for longer than the interval
        await throttle.acquire(HOST, interval_seconds=2.0)
        assert timer.sleeps == [2.0]

    async def test_hosts_do_not_block_each_other(self, timer: FakeTimer) -> None:
        throttle = HostThrottle(None, prefix="nf:")
        await throttle.acquire(HOST, interval_seconds=2.0)
        await throttle.acquire("blog.example.com", interval_seconds=2.0)
        assert timer.sleeps == []

    async def test_a_redis_outage_falls_back_to_per_process_spacing(self, timer: FakeTimer) -> None:
        throttle = HostThrottle(cast(Redis, _BrokenRedis()), prefix="nf:")
        await throttle.acquire(HOST, interval_seconds=3.0)
        await throttle.acquire(HOST, interval_seconds=3.0)
        assert timer.sleeps == [3.0]

    async def test_a_wait_beyond_the_budget_is_a_transient_error(self, timer: FakeTimer) -> None:
        throttle = HostThrottle(None, prefix="nf:", max_wait_seconds=5.0)
        await throttle.acquire(HOST, interval_seconds=30.0)

        with pytest.raises(TransientError) as exc:
            await throttle.acquire(HOST, interval_seconds=30.0)

        assert exc.value.code == "host_throttled"
        assert timer.sleeps == []

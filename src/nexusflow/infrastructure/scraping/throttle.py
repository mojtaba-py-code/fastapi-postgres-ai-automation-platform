"""Politeness throttle: at most one request per host per interval, cluster-wide."""

from __future__ import annotations

import asyncio
import hashlib
import time

from redis.asyncio import Redis
from redis.exceptions import RedisError

from nexusflow.core.errors import TransientError


class HostThrottle:
    def __init__(self, redis: Redis | None, *, prefix: str, max_wait_seconds: float = 60.0) -> None:
        self._redis = redis
        self._prefix = prefix
        self._max_wait = max_wait_seconds
        self._local: dict[str, float] = {}

    async def acquire(self, host: str, *, interval_seconds: float) -> None:
        """Wait until this worker may contact ``host``; raises TransientError if the
        wait would exceed ``max_wait`` (the job is then retried later)."""
        interval_ms = max(1, int(interval_seconds * 1000))
        key = f"{self._prefix}throttle:{hashlib.sha256(host.encode()).hexdigest()[:32]}"
        deadline = time.monotonic() + self._max_wait
        while True:
            wait_ms = await self._try(key, host, interval_ms)
            if wait_ms <= 0:
                return
            if time.monotonic() + wait_ms / 1000 > deadline:
                raise TransientError("Host is busy; retry later.", code="host_throttled")
            await asyncio.sleep(wait_ms / 1000)

    async def _try(self, key: str, host: str, interval_ms: int) -> int:
        if self._redis is not None:
            try:
                if await self._redis.set(key, b"1", nx=True, px=interval_ms):
                    return 0
                ttl = await self._redis.pttl(key)
                return max(int(ttl), 10)
            except RedisError:
                pass  # fall back to the per-process throttle
        now = time.monotonic()
        next_allowed = self._local.get(host, 0.0)
        if now >= next_allowed:
            self._local[host] = now + interval_ms / 1000
            return 0
        return int((next_allowed - now) * 1000)

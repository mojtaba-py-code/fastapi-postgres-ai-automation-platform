"""Distributed rate limiting with the Generic Cell Rate Algorithm (GCRA).

GCRA stores a single "theoretical arrival time" per key, evaluated atomically in
a Lua script: O(1) memory per client, smooth bursts, no fixed-window edge
effects. Identities (IPs, e-mail addresses, principal ids) are hashed before
they become Redis keys so no personal data is stored in Redis.

Failure policy per rule: ``fail_closed`` scopes (authentication, webhooks,
exports) reject requests when Redis is unavailable; other scopes degrade to a
bounded in-process limiter so the API stays available.
"""

from __future__ import annotations

import hashlib
import math
import time
from collections import OrderedDict
from dataclasses import dataclass

from redis.asyncio import Redis
from redis.exceptions import RedisError

from nexusflow.core.clock import Clock
from nexusflow.core.config import RateLimitRule
from nexusflow.core.errors import RateLimitedError, ServiceUnavailableError
from nexusflow.infrastructure.observability import metrics

_GCRA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local interval = tonumber(ARGV[2])
local tolerance = tonumber(ARGV[3])
local stored = redis.call('GET', key)
local tat = now
if stored then
  tat = math.max(tonumber(stored), now)
end
local new_tat = tat + interval
local allow_at = new_tat - tolerance
if allow_at > now then
  return {0, allow_at - now, tat - now}
end
redis.call('SET', key, string.format('%.0f', new_tat), 'PX', math.ceil((new_tat - now) / 1000))
return {1, 0, new_tat - now}
"""


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: float
    reset_after_seconds: float

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise RateLimitedError(retry_after_seconds=math.ceil(self.retry_after_seconds))


def _decision(
    rule: RateLimitRule, allowed: bool, retry_ms: float, used_ms: float
) -> RateLimitDecision:
    interval_ms = rule.period_seconds * 1000 / rule.limit
    remaining = max(0, math.floor((rule.period_seconds * 1000 - used_ms) / interval_ms))
    return RateLimitDecision(
        allowed=allowed,
        limit=rule.limit,
        remaining=remaining if allowed else 0,
        retry_after_seconds=retry_ms / 1000,
        reset_after_seconds=max(0.0, used_ms / 1000),
    )


class _LocalGcra:
    """Bounded per-process fallback used while Redis is unavailable."""

    def __init__(self, max_keys: int = 10_000) -> None:
        self._tats: OrderedDict[str, float] = OrderedDict()
        self._max_keys = max_keys

    def hit(self, key: str, rule: RateLimitRule, now_ms: float) -> RateLimitDecision:
        interval = rule.period_seconds * 1000 / rule.limit
        tolerance = rule.period_seconds * 1000
        tat = max(self._tats.get(key, now_ms), now_ms)
        new_tat = tat + interval
        allow_at = new_tat - tolerance
        if allow_at > now_ms:
            return _decision(rule, False, allow_at - now_ms, tat - now_ms)
        self._tats[key] = new_tat
        self._tats.move_to_end(key)
        while len(self._tats) > self._max_keys:
            self._tats.popitem(last=False)
        return _decision(rule, True, 0, new_tat - now_ms)


class RateLimiter:
    def __init__(
        self, redis: Redis, *, prefix: str, clock: Clock | None = None, enabled: bool = True
    ) -> None:
        self._redis = redis
        self._prefix = prefix
        self._clock = clock
        self._enabled = enabled
        self._script = redis.register_script(_GCRA)
        self._local = _LocalGcra()

    def _now_ms(self) -> float:
        if self._clock is not None:
            return self._clock.now().timestamp() * 1000
        return time.time() * 1000

    def _key(self, scope: str, identity: str) -> str:
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
        return f"{self._prefix}rl:{scope}:{digest}"

    async def hit(self, scope: str, identity: str, rule: RateLimitRule) -> RateLimitDecision:
        if not self._enabled:
            return RateLimitDecision(True, rule.limit, rule.limit, 0, 0)
        key = self._key(scope, identity)
        now_ms = self._now_ms()
        # Integer microseconds keep the Lua arithmetic exact (below 2**53, stored
        # with an explicit format). The interval is rounded *up*: 400 a second is
        # 2,500 us, and a whole-millisecond interval would have admitted 500.
        now_us = int(now_ms * 1000)
        interval_us = max(1, math.ceil(rule.period_seconds * 1_000_000 / rule.limit))
        try:
            allowed, retry_us, used_us = await self._script(
                keys=[key], args=[now_us, interval_us, rule.period_seconds * 1_000_000]
            )
            decision = _decision(rule, bool(allowed), float(retry_us) / 1000, float(used_us) / 1000)
        except RedisError as exc:
            if rule.fail_closed:
                raise ServiceUnavailableError(
                    internal_detail=f"rate limiter unavailable: {exc}"
                ) from exc
            decision = self._local.hit(key, rule, now_ms)
        if not decision.allowed:
            metrics.RATE_LIMIT_REJECTIONS.labels(scope=scope).inc()
        return decision

    async def enforce(self, scope: str, identity: str, rule: RateLimitRule) -> RateLimitDecision:
        decision = await self.hit(scope, identity, rule)
        decision.raise_if_denied()
        return decision

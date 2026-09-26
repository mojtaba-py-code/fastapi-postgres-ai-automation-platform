"""The GCRA rate limiter (``infrastructure.redis.rate_limit``) on a fake Redis.

One frozen clock drives both the limiter and the fake Redis's key expiry, so
bursts, ``Retry-After`` values, refills and TTLs are exact. Covers the burst /
refill arithmetic, isolation between identities, scopes and deployments, what
reaches Redis (hashed identities, keys that expire), the failure policy on
``RedisError`` (fail closed: 503; fail open: the bounded in-process fallback)
and recovery, the ``enabled`` switch, and the failure policy of each scope.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import fakeredis
import pytest
from fakeredis import _basefakesocket
from prometheus_client import REGISTRY

from nexusflow.core.clock import FrozenClock
from nexusflow.core.config import RateLimitRule
from nexusflow.core.errors import RateLimitedError, ServiceUnavailableError
from nexusflow.infrastructure.redis.rate_limit import RateLimitDecision, RateLimiter, _LocalGcra
from tests.conftest import make_settings

pytestmark = pytest.mark.security

START = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
RULE = RateLimitRule(limit=5, period_seconds=60)  # bursts of 5, then one per 12 s
STRICT = RateLimitRule(limit=5, period_seconds=60, fail_closed=True)
FAIL_CLOSED_SCOPES = {
    "auth.login.ip",
    "auth.login.account",
    "auth.refresh",
    "auth.password_reset",
    "auth.register",
    "auth.register.account",
    "auth.register.complete",
    "auth.mfa",
    "auth.password_change",
    "auth.sso.start",
    "auth.sso.callback",
    "scim.token",
    "api.export",
    "api.ai",
    "webhook.endpoint",
    "webhook.ip",
}
FAIL_OPEN_SCOPES = {
    "api.read",
    "api.write",
    "automation.service",
    "sandbox.gateway",
    "notifications.channel",
    "external_api.integration",
}


@dataclass
class Harness:
    limiter: RateLimiter
    clock: FrozenClock
    server: fakeredis.FakeServer
    redis: fakeredis.FakeAsyncRedis

    async def hits(
        self,
        count: int,
        *,
        scope: str = "api.read",
        identity: str = "user:alice",
        rule: RateLimitRule = RULE,
    ) -> list[RateLimitDecision]:
        return [await self.limiter.hit(scope, identity, rule) for _ in range(count)]

    async def allowed(
        self,
        count: int,
        *,
        scope: str = "api.read",
        identity: str = "user:alice",
        rule: RateLimitRule = RULE,
    ) -> list[bool]:
        decisions = await self.hits(count, scope=scope, identity=identity, rule=rule)
        return [decision.allowed for decision in decisions]

    def advance(self, seconds: float) -> None:
        self.clock.advance(timedelta(seconds=seconds))


class ClockTime:
    """Stands in for the ``time`` module inside fakeredis, which expires keys by
    ``time.time()``: Redis TTLs then run on the limiter's frozen clock too."""

    def __init__(self, clock: FrozenClock) -> None:
        self._clock = clock

    def time(self) -> float:
        return self._clock.now().timestamp()


def _text(value: bytes | str) -> str:
    return value.decode() if isinstance(value, bytes) else value


@pytest.fixture
async def harness(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Harness]:
    server = fakeredis.FakeServer()
    redis = fakeredis.FakeAsyncRedis(server=server)
    clock = FrozenClock(START)
    monkeypatch.setattr(_basefakesocket, "time", ClockTime(clock))
    try:
        yield Harness(RateLimiter(redis, prefix="nf:", clock=clock), clock, server, redis)
    finally:
        server.connected = True
        await redis.aclose()


class TestBurstAndRefill:
    async def test_a_full_burst_is_allowed_then_refused_for_one_emission_interval(
        self, harness: Harness
    ) -> None:
        decisions = await harness.hits(6)
        assert [d.allowed for d in decisions] == [True] * 5 + [False]
        assert [d.remaining for d in decisions] == [4, 3, 2, 1, 0, 0]
        refused = decisions[-1]
        assert (refused.limit, refused.retry_after_seconds) == (5, 12.0)
        decisions[0].raise_if_denied()  # allowed decisions never raise
        with pytest.raises(RateLimitedError) as exc:
            refused.raise_if_denied()
        assert exc.value.retry_after_seconds == 12

    async def test_capacity_returns_at_one_request_per_emission_interval(
        self, harness: Harness
    ) -> None:
        await harness.hits(5)
        harness.advance(11.999)
        [early] = await harness.hits(1)
        assert not early.allowed
        # A millisecond away still means "retry in 1 s": Retry-After is never 0.
        with pytest.raises(RateLimitedError) as exc:
            early.raise_if_denied()
        assert exc.value.retry_after_seconds == 1
        harness.advance(0.001)
        assert await harness.allowed(2) == [True, False]
        harness.advance(60)  # a whole period restores the whole burst
        assert await harness.allowed(6) == [True] * 5 + [False]

    async def test_refused_requests_do_not_extend_the_wait(self, harness: Harness) -> None:
        await harness.hits(5)
        hammering = await harness.hits(50)
        assert {(d.allowed, d.retry_after_seconds) for d in hammering} == {(False, 12.0)}
        harness.advance(12)  # a client honouring Retry-After gets straight back in
        assert await harness.allowed(1) == [True]

    async def test_enforce_raises_with_the_decision_rounded_up_to_seconds(
        self, harness: Harness
    ) -> None:
        await harness.hits(5)
        harness.advance(0.5)
        with pytest.raises(RateLimitedError) as exc:
            await harness.limiter.enforce("api.read", "user:alice", RULE)
        assert exc.value.retry_after_seconds == 12  # 11.5 s, rounded up
        assert exc.value.code == "rate_limited"

    @pytest.mark.parametrize(
        ("limit", "period"),
        [
            pytest.param(5, 60, id="5-per-minute"),
            pytest.param(600, 60, id="600-per-minute"),
            # 2.5 ms apart: a whole-millisecond interval would admit 500.
            pytest.param(400, 1, id="400-per-second"),
            pytest.param(7, 1, id="7-per-second"),
        ],
    )
    async def test_a_burst_never_exceeds_the_configured_limit(
        self, harness: Harness, limit: int, period: int
    ) -> None:
        rule = RateLimitRule(limit=limit, period_seconds=period)
        admitted = sum(await harness.allowed(limit + limit // 2, rule=rule))
        assert admitted <= limit


class TestIsolation:
    async def test_identities_do_not_share_a_budget(self, harness: Harness) -> None:
        await harness.hits(5, identity="user:alice")
        assert await harness.allowed(1, identity="user:alice") == [False]
        assert await harness.allowed(1, identity="user:bob") == [True]

    async def test_scopes_do_not_share_a_budget(self, harness: Harness) -> None:
        await harness.hits(5, scope="api.read")
        assert await harness.allowed(1, scope="api.read") == [False]
        assert await harness.allowed(1, scope="api.write") == [True]

    async def test_deployments_with_different_prefixes_do_not_share_a_budget(
        self, harness: Harness
    ) -> None:
        await harness.hits(5)
        other = RateLimiter(harness.redis, prefix="nf2:", clock=harness.clock)
        assert (await other.hit("api.read", "user:alice", RULE)).allowed


class TestWhatReachesRedis:
    async def test_identities_are_hashed_before_they_become_keys(self, harness: Harness) -> None:
        identities = ["alice@example.com", "203.0.113.7", "user:0192f0c1-7a2b-7c3d-8e4f"]
        for identity in identities:
            await harness.hits(1, scope="auth.login.ip", identity=identity)
        keys = sorted(_text(key) for key in await harness.redis.keys("*"))
        assert len(keys) == len(identities)
        for key in keys:
            assert re.fullmatch(r"nf:rl:auth\.login\.ip:[0-9a-f]{32}", key), key
            assert all(part not in key for part in ("alice", "example", "203.0", "0192f0c1"))
            assert (await harness.redis.get(key) or b"").isdigit()  # a timestamp, nothing else

    async def test_every_key_expires_once_its_budget_is_whole_again(self, harness: Harness) -> None:
        await harness.hits(3)
        [key] = await harness.redis.keys("*")
        assert await harness.redis.pttl(key) == 36_000  # three emission intervals
        harness.advance(35.999)
        assert await harness.redis.exists(key)
        harness.advance(0.002)
        assert not await harness.redis.exists(key)  # Redis never holds idle identities

    async def test_refusals_are_counted_per_scope(self, harness: Harness) -> None:
        scope = f"test.scope.{uuid4().hex[:8]}"
        metric = "nexusflow_rate_limit_rejections_total"
        await harness.hits(7, scope=scope)
        assert REGISTRY.get_sample_value(metric, {"scope": scope}) == 2


class TestRedisOutage:
    async def test_a_fail_closed_rule_refuses_while_redis_is_down(self, harness: Harness) -> None:
        harness.server.connected = False
        for call in (harness.limiter.hit, harness.limiter.enforce):
            with pytest.raises(ServiceUnavailableError) as exc:
                await call("auth.login.ip", "203.0.113.7", STRICT)
            assert exc.value.code == "service_unavailable"
            assert exc.value.message == "The service is temporarily unavailable."
            assert (exc.value.internal_detail or "").startswith("rate limiter unavailable")

    async def test_a_fail_open_rule_degrades_to_the_in_process_limiter(
        self, harness: Harness
    ) -> None:
        harness.server.connected = False
        decisions = await harness.hits(6)
        assert [d.allowed for d in decisions] == [True] * 5 + [False]  # still limited
        assert decisions[-1].retry_after_seconds == 12.0
        assert await harness.allowed(1, identity="user:bob") == [True]
        harness.advance(12)
        assert await harness.allowed(2) == [True, False]

    async def test_redis_is_authoritative_again_once_it_recovers(self, harness: Harness) -> None:
        assert await harness.allowed(3) == [True] * 3  # 2 left in Redis
        harness.server.connected = False
        assert await harness.allowed(6) == [True] * 5 + [False]  # a separate local budget
        harness.server.connected = True
        # Redis never saw the outage traffic and carries on from its own state.
        assert await harness.allowed(3) == [True, True, False]

    def test_the_in_process_fallback_tracks_a_bounded_number_of_identities(self) -> None:
        local = _LocalGcra(max_keys=3)
        once = RateLimitRule(limit=1, period_seconds=60)
        for identity in "abcd":  # a flood of identities cannot grow memory without bound
            assert local.hit(identity, once, 0).allowed
        assert len(local._tats) == 3
        assert not local.hit("d", once, 0).allowed  # recent identities are still limited
        assert local.hit("a", once, 0).allowed  # the least recently seen one was evicted

    async def test_a_disabled_limiter_never_touches_redis(self, harness: Harness) -> None:
        harness.server.connected = False
        disabled = RateLimiter(harness.redis, prefix="nf:", clock=harness.clock, enabled=False)
        for rule in (RULE, STRICT):
            decisions = [
                await disabled.hit("auth.login.ip", "203.0.113.7", rule) for _ in range(10)
            ]
            assert all(d.allowed and d.remaining == rule.limit for d in decisions)


class TestConfiguredPolicies:
    def test_every_scope_has_the_documented_failure_policy(self) -> None:
        rules = make_settings().rate_limits.rules
        assert set(rules) == FAIL_CLOSED_SCOPES | FAIL_OPEN_SCOPES
        assert {scope for scope, rule in rules.items() if rule.fail_closed} == FAIL_CLOSED_SCOPES

    @pytest.mark.parametrize("scope", ["auth.login.ip", "api.export"])
    def test_tuning_a_limit_keeps_the_scopes_failure_policy(self, scope: str) -> None:
        override = {scope: {"limit": 100, "period_seconds": 60}}  # as in CONFIGURATION.md
        rules = make_settings(rate_limits={"rules": override}).rate_limits.rules
        assert rules[scope].limit == 100
        assert rules[scope].fail_closed

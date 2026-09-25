"""n8n retry chains are counted by the platform, not by the caller."""

from __future__ import annotations

import fakeredis
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from nexusflow.core.errors import ServiceUnavailableError
from nexusflow.infrastructure.redis.client import RedisFailureLedger


def _ledger() -> RedisFailureLedger:
    return RedisFailureLedger(fakeredis.FakeAsyncRedis(), prefix="nf:")


async def test_a_retry_chain_is_counted_across_executions() -> None:
    ledger = _ledger()
    # A fails, is retried as B (retryOf A), which is retried as C (retryOf B).
    assert await ledger.record_failure("A", None) == 1
    assert await ledger.record_failure("B", "A") == 2
    assert await ledger.record_failure("C", "B") == 3
    # An unrelated failure starts its own count.
    assert await ledger.record_failure("X", None) == 1


async def test_reporting_the_same_failure_twice_counts_once() -> None:
    ledger = _ledger()
    assert await ledger.record_failure("A", None) == 1
    assert await ledger.record_failure("A", None) == 1  # n8n retried its HTTP call
    assert await ledger.record_failure("B", "A") == 2
    assert await ledger.record_failure("B", "A") == 2


async def test_an_unknown_parent_still_joins_its_chain() -> None:
    ledger = _ledger()
    # The parent's mapping expired or was never recorded: the parent is the root.
    assert await ledger.record_failure("B", "A") == 1
    assert await ledger.record_failure("C", "B") == 2


async def test_redis_errors_surface_as_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    redis = fakeredis.FakeAsyncRedis()

    async def broken(*args: object, **kwargs: object) -> None:
        raise RedisConnectionError("down")

    monkeypatch.setattr(redis, "set", broken)
    with pytest.raises(ServiceUnavailableError):
        await RedisFailureLedger(redis, prefix="nf:").record_failure("A", None)

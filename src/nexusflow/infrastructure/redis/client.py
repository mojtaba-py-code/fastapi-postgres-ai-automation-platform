"""Redis client factory and small Redis-backed primitives.

Redis is never used as unbounded storage: every key written by the platform
carries a TTL, and the server is configured with ``maxmemory`` +
``volatile-lru`` (see ``deployment/redis``).
"""

from __future__ import annotations

import ssl
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError

from nexusflow.core.config import RedisSettings
from nexusflow.core.errors import ServiceUnavailableError
from nexusflow.infrastructure.observability.logging import get_logger

_log = get_logger("nexusflow.redis")


def create_redis(settings: RedisSettings) -> Redis:
    kwargs: dict[str, Any] = {
        "socket_timeout": settings.socket_timeout_seconds,
        "socket_connect_timeout": settings.connect_timeout_seconds,
        "max_connections": settings.max_connections,
        "health_check_interval": 30,
        "decode_responses": False,
    }
    url = settings.url.get_secret_value()
    if url.startswith("rediss://"):
        kwargs["ssl_cert_reqs"] = "required"
        # redis-py 8 checks the host name by default; explicit, so that no
        # upgrade can relax it.
        kwargs["ssl_check_hostname"] = True
        kwargs["ssl_min_version"] = ssl.TLSVersion.TLSv1_2
        if settings.ssl_ca_certs is not None:
            kwargs["ssl_ca_certs"] = str(settings.ssl_ca_certs)
    client: Redis = Redis.from_url(url, **kwargs)
    return client


class ReplayGuard:
    """One-time nonce store (webhook delivery ids, MFA challenge ids)."""

    def __init__(self, redis: Redis, *, prefix: str) -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, namespace: str, nonce: str) -> str:
        return f"{self._prefix}nonce:{namespace}:{nonce}"

    async def first_use(self, namespace: str, nonce: str, *, ttl_seconds: int) -> bool:
        """Atomically record ``nonce``; returns False if it was seen before."""
        try:
            created = await self._redis.set(
                self._key(namespace, nonce), b"1", nx=True, ex=ttl_seconds
            )
        except RedisError as exc:
            # Fail closed: without the nonce store we cannot rule out replays.
            raise ServiceUnavailableError(
                internal_detail=f"replay guard unavailable: {exc}"
            ) from exc
        return bool(created)

    async def release(self, namespace: str, nonce: str) -> None:
        """Best effort: the caller is already failing, so this never raises. A
        nonce that cannot be released simply expires with its TTL."""
        try:
            await self._redis.delete(self._key(namespace, nonce))
        except RedisError as exc:
            _log.warning("nonce_release_failed", namespace=namespace, error=type(exc).__name__)


class RedisFailureLedger:
    """``FailureLedger`` port: failure counts per n8n retry chain (24 h TTL).

    n8n reports each failed execution and, for retries, the execution it
    retried (``retryOf``). Each execution id maps to the chain's root, so the
    count survives any number of retries. Reporting the same execution twice
    (n8n retrying the HTTP call itself) does not count twice.
    """

    TTL_SECONDS = 24 * 3600

    def __init__(self, redis: Redis, *, prefix: str) -> None:
        self._redis = redis
        self._prefix = prefix

    def _chain(self, execution_id: str) -> str:
        return f"{self._prefix}n8n:chain:{execution_id}"

    async def record_failure(self, execution_id: str, retry_of: str | None) -> int:
        try:
            root = execution_id
            if retry_of:
                stored = await self._redis.get(self._chain(retry_of))
                if isinstance(stored, bytes):
                    stored = stored.decode()
                root = stored or retry_of
            counter = f"{self._prefix}n8n:failures:{root}"
            first_report = await self._redis.set(
                self._chain(execution_id), root, nx=True, ex=self.TTL_SECONDS
            )
            if not first_report:
                return int(await self._redis.get(counter) or 1)
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.incr(counter)
                pipe.expire(counter, self.TTL_SECONDS)
                count, _ = await pipe.execute()
        except RedisError as exc:
            raise ServiceUnavailableError(
                internal_detail=f"failure ledger unavailable: {exc}"
            ) from exc
        return int(count)


class FeatureFlags:
    """Runtime switches that operators can flip without a deployment."""

    AUTOMATION_KILL_SWITCH = "automation_kill_switch"

    def __init__(self, redis: Redis, *, prefix: str) -> None:
        self._redis = redis
        self._prefix = prefix

    async def is_enabled(self, flag: str) -> bool:
        try:
            return bool(await self._redis.exists(f"{self._prefix}flag:{flag}"))
        except RedisError:
            # Kill switches fail *safe*: if state is unknown, assume engaged.
            return flag == self.AUTOMATION_KILL_SWITCH

    async def automation_disabled(self) -> bool:
        """``AutomationGate`` port: is the global automation kill switch engaged?"""
        return await self.is_enabled(self.AUTOMATION_KILL_SWITCH)

    async def set(self, flag: str, *, enabled: bool, ttl_seconds: int | None = None) -> None:
        """Flags persist until cleared (no TTL by default): an engaged kill
        switch must never silently expire. Redis runs with a ``volatile-*``
        eviction policy, so keys without a TTL are never evicted either."""
        key = f"{self._prefix}flag:{flag}"
        if enabled:
            await self._redis.set(key, b"1", ex=ttl_seconds)
        else:
            await self._redis.delete(key)

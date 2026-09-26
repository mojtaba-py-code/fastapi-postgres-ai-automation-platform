"""WebAuthn challenges in Redis: expiring, and single-use by construction.

A challenge is stored when a ceremony begins and taken with ``GETDEL`` when
its answer arrives, so it can be answered at most once however many answers
race for it, and it disappears on its own when its TTL runs out. Redis suits
this better than a table: nothing to purge, no row locks on the sign-in path,
and a lost challenge only means starting the ceremony again.

Keys are hashed (no session or challenge identifiers in Redis) under the
platform prefix, and the store fails closed: without Redis no challenge is
issued or accepted.
"""

from __future__ import annotations

import hashlib
import json

from redis.asyncio import Redis
from redis.exceptions import RedisError

from nexusflow.core.errors import ServiceUnavailableError
from nexusflow.core.jsonutil import JSONObject, canonical_json

_MAX_STATE_BYTES = 16 * 1024


class RedisChallengeStore:
    """The ``ChallengeStore`` port."""

    def __init__(self, redis: Redis, *, prefix: str) -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, key: str) -> str:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:40]
        return f"{self._prefix}webauthn:{digest}"

    async def put(self, key: str, state: JSONObject, *, ttl_seconds: int) -> None:
        if ttl_seconds < 1:
            raise ValueError("a challenge needs a positive lifetime")
        try:
            await self._redis.set(
                self._key(key), canonical_json(state).encode("ascii"), ex=ttl_seconds
            )
        except RedisError as exc:
            raise ServiceUnavailableError(
                internal_detail=f"challenge store unavailable: {exc}"
            ) from exc

    async def take(self, key: str) -> JSONObject | None:
        try:
            raw = await self._redis.getdel(self._key(key))
        except RedisError as exc:
            raise ServiceUnavailableError(
                internal_detail=f"challenge store unavailable: {exc}"
            ) from exc
        if isinstance(raw, str):  # a client that decodes responses
            raw = raw.encode("utf-8")
        if not isinstance(raw, bytes) or len(raw) > _MAX_STATE_BYTES:
            return None
        try:
            state = json.loads(raw)
        except ValueError:
            return None
        return state if isinstance(state, dict) else None

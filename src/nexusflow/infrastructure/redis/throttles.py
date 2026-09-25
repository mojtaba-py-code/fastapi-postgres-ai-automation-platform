"""Redis-backed throttles used by background services."""

from __future__ import annotations

from uuid import UUID

from nexusflow.core.config import RateLimitRule
from nexusflow.infrastructure.redis.rate_limit import RateLimiter


class ChannelDeliveryThrottle:
    """Caps notifications per channel (protects recipients and provider quotas)."""

    def __init__(self, limiter: RateLimiter, rule: RateLimitRule) -> None:
        self._limiter = limiter
        self._rule = rule

    async def retry_after(self, channel_id: UUID) -> float | None:
        decision = await self._limiter.hit("notifications.channel", str(channel_id), self._rule)
        return None if decision.allowed else max(1.0, decision.retry_after_seconds)


class WebhookDeliveryQuota:
    """Caps *authenticated* deliveries per inbound webhook endpoint.

    Consumed only after the signature is verified, so a flood of forged
    requests cannot use up a legitimate sender's quota (those are bounded by
    the per-IP limit in front of verification instead).
    """

    def __init__(self, limiter: RateLimiter, rule: RateLimitRule) -> None:
        self._limiter = limiter
        self._rule = rule

    async def consume(self, endpoint_id: UUID) -> None:
        await self._limiter.enforce("webhook.endpoint", str(endpoint_id), self._rule)

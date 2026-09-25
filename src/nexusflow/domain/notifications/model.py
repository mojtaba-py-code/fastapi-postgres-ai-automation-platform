"""Notification channels and per-channel deliveries."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, TypeAdapter

from nexusflow.domain.integrations.model import IntegrationKind


class ChannelKind(StrEnum):
    EMAIL = "email"
    SLACK = "slack"
    TELEGRAM = "telegram"
    WEBHOOK = "webhook"


REQUIRED_INTEGRATION: dict[ChannelKind, IntegrationKind | None] = {
    ChannelKind.EMAIL: None,  # platform SMTP relay
    ChannelKind.SLACK: IntegrationKind.SLACK_WEBHOOK,
    ChannelKind.TELEGRAM: IntegrationKind.TELEGRAM_BOT,
    ChannelKind.WEBHOOK: IntegrationKind.WEBHOOK_SIGNING,
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class EmailChannelConfig(_Strict):
    kind: Literal[ChannelKind.EMAIL] = ChannelKind.EMAIL
    recipients: list[EmailStr] = Field(min_length=1, max_length=20)


class SlackChannelConfig(_Strict):
    kind: Literal[ChannelKind.SLACK] = ChannelKind.SLACK


class TelegramChannelConfig(_Strict):
    kind: Literal[ChannelKind.TELEGRAM] = ChannelKind.TELEGRAM
    chat_id: str = Field(pattern=r"^(-?\d{1,20}|@[A-Za-z0-9_]{5,32})$")


class WebhookChannelConfig(_Strict):
    kind: Literal[ChannelKind.WEBHOOK] = ChannelKind.WEBHOOK
    url: str = Field(min_length=10, max_length=2048)


type ChannelConfig = (
    EmailChannelConfig | SlackChannelConfig | TelegramChannelConfig | WebhookChannelConfig
)
CHANNEL_CONFIG_ADAPTER: TypeAdapter[ChannelConfig] = TypeAdapter(
    Annotated[
        EmailChannelConfig | SlackChannelConfig | TelegramChannelConfig | WebhookChannelConfig,
        Field(discriminator="kind"),
    ]
)


@dataclass(eq=False, kw_only=True)
class NotificationChannel:
    id: UUID
    org_id: UUID
    name: str
    kind: ChannelKind
    config: dict[str, Any] = field(default_factory=dict)
    integration_id: UUID | None = None
    enabled: bool = True
    created_by: UUID | None = None
    created_at: datetime
    updated_at: datetime

    @property
    def parsed_config(self) -> ChannelConfig:
        return CHANNEL_CONFIG_ADAPTER.validate_python(self.config)


class DeliveryState(StrEnum):
    PENDING = "pending"
    SENDING = "sending"
    DELIVERED = "delivered"
    FAILED = "failed"
    DEAD = "dead"


MAX_DELIVERY_ATTEMPTS = 6


@dataclass(eq=False, kw_only=True)
class NotificationDelivery:
    id: UUID
    org_id: UUID
    alert_id: UUID
    channel_id: UUID
    status: DeliveryState = DeliveryState.PENDING
    attempts: int = 0
    next_attempt_at: datetime | None = None
    last_error_code: str | None = None
    delivered_at: datetime | None = None
    claimed_at: datetime | None = None
    created_at: datetime

    def claim(self, now: datetime) -> bool:
        """PENDING/FAILED -> SENDING; False if already delivered/in flight/dead."""
        if self.status not in (DeliveryState.PENDING, DeliveryState.FAILED):
            return False
        if self.next_attempt_at is not None and self.next_attempt_at > now:
            return False
        self.status = DeliveryState.SENDING
        self.attempts += 1
        self.claimed_at = now
        return True

    def mark_delivered(self, now: datetime) -> None:
        self.status = DeliveryState.DELIVERED
        self.delivered_at = now
        self.last_error_code = None

    def defer(self, code: str, *, until: datetime) -> None:
        """SENDING -> PENDING without spending an attempt: nothing was sent (throttled)."""
        self.status = DeliveryState.PENDING
        self.attempts = max(0, self.attempts - 1)
        self.next_attempt_at = until
        self.last_error_code = code[:64]

    def mark_failed(self, code: str, *, retry_at: datetime | None) -> None:
        self.last_error_code = code[:64]
        if retry_at is None or self.attempts >= MAX_DELIVERY_ATTEMPTS:
            self.status = DeliveryState.DEAD
            self.next_attempt_at = None
        else:
            self.status = DeliveryState.FAILED
            self.next_attempt_at = retry_at

    def reopen(self) -> None:
        """DEAD -> FAILED and due now: retried from the dead-letter store, the
        delivery gets one more attempt (it is dead again if that one fails)."""
        if self.status is DeliveryState.DEAD:
            self.status = DeliveryState.FAILED
            self.next_attempt_at = None


@dataclass(frozen=True, slots=True)
class OutboundMessage:
    """Rendered, channel-agnostic notification (plain text; no HTML)."""

    title: str
    body: str
    severity: str
    link: str | None
    idempotency_key: str

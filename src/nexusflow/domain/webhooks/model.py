"""Inbound webhook endpoints and deliveries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class EndpointStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class DeliveryStatus(StrEnum):
    ACCEPTED = "accepted"
    PROCESSED = "processed"
    FAILED = "failed"


def secret_context(org_id: UUID, endpoint_id: UUID) -> str:
    return f"org:{org_id}|webhook-endpoint:{endpoint_id}"


@dataclass(eq=False, kw_only=True)
class WebhookEndpoint:
    id: UUID
    org_id: UUID
    source_id: UUID
    name: str
    status: EndpointStatus = EndpointStatus.ACTIVE
    secret_ciphertext: bytes
    previous_secret_ciphertext: bytes | None = None
    previous_secret_expires_at: datetime | None = None
    created_by: UUID | None = None
    created_at: datetime
    updated_at: datetime
    last_received_at: datetime | None = None

    @property
    def is_active(self) -> bool:
        return self.status is EndpointStatus.ACTIVE

    def previous_secret_valid(self, now: datetime) -> bool:
        return (
            self.previous_secret_ciphertext is not None
            and self.previous_secret_expires_at is not None
            and self.previous_secret_expires_at > now
        )


@dataclass(eq=False, kw_only=True)
class InboundWebhookEvent:
    id: UUID
    org_id: UUID
    endpoint_id: UUID
    delivery_id: str
    received_at: datetime
    payload_sha256: str
    payload_size: int
    item_count: int
    status: DeliveryStatus = DeliveryStatus.ACCEPTED
    run_id: UUID | None = None

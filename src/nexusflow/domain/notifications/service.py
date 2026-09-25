"""Notification channels and at-least-once delivery with backoff.

Delivery is idempotent per ``(alert, channel)`` (unique constraint) and
guarded by a small state machine (``PENDING/FAILED -> SENDING -> ...``), so a
redelivered task never sends twice concurrently. Transient failures are
retried with exponential backoff + jitter; permanent failures go straight to
``DEAD`` and the dead-letter store.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import InvalidInputError, NexusFlowError, NotFoundError, TransientError
from nexusflow.core.ids import uuid7
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.core.resilience import backoff_delay
from nexusflow.core.text import required_name
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.automation.dead_letters import stage_dead_letter
from nexusflow.domain.automation.model import DeadLetter
from nexusflow.domain.integrations.model import IntegrationStatus, ResolvedCredential
from nexusflow.domain.integrations.service import IntegrationService
from nexusflow.domain.notifications.model import (
    REQUIRED_INTEGRATION,
    ChannelConfig,
    ChannelKind,
    DeliveryState,
    NotificationChannel,
    NotificationDelivery,
    OutboundMessage,
    WebhookChannelConfig,
)
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.shared.url_policy import UrlPolicy


class NotificationSender(Protocol):
    async def send(
        self,
        channel: NotificationChannel,
        message: OutboundMessage,
        credential: ResolvedCredential | None,
    ) -> None: ...


class DeliveryThrottle(Protocol):
    async def retry_after(self, channel_id: UUID) -> float | None:
        """Seconds to wait if the channel is over its rate limit, else None."""
        ...


class NotificationService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        url_policy: UrlPolicy,
        integrations: IntegrationService,
        sender: NotificationSender | None,
        throttle: DeliveryThrottle | None,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._url_policy = url_policy
        self._integrations = integrations
        self._sender = sender
        self._throttle = throttle

    # ---------------------------------------------------------------- channels

    async def create_channel(
        self,
        principal: Principal,
        *,
        name: str,
        config: ChannelConfig,
        integration_id: UUID | None,
        meta: RequestMeta,
    ) -> NotificationChannel:
        principal.require(Permission.CHANNELS_WRITE)
        org_id = principal.require_org()
        now = self._clock.now()
        kind = ChannelKind(config.kind)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            await self._validate(uow, org_id, kind, config, integration_id)
            channel = NotificationChannel(
                id=uuid7(),
                org_id=org_id,
                name=required_name(name, max_length=100),
                kind=kind,
                config=config.model_dump(mode="json"),
                integration_id=integration_id,
                created_by=principal.actor_user_id,
                created_at=now,
                updated_at=now,
            )
            await uow.data.channels.add(channel)
            await self._audit.record(
                uow.audit,
                action=AuditAction.CHANNEL_CREATED,
                principal=principal,
                meta=meta,
                resource_type="channel",
                resource_id=channel.id,
                metadata={"kind": kind},
            )
            await uow.commit()
        return channel

    async def set_enabled(
        self, principal: Principal, channel_id: UUID, *, enabled: bool, meta: RequestMeta
    ) -> NotificationChannel:
        principal.require(Permission.CHANNELS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            channel = await uow.data.channels.get_for_update(org_id, channel_id)
            if channel is None:
                raise NotFoundError()
            channel.enabled = enabled
            channel.updated_at = self._clock.now()
            await self._audit.record(
                uow.audit,
                action=AuditAction.CHANNEL_UPDATED,
                principal=principal,
                meta=meta,
                resource_type="channel",
                resource_id=channel.id,
                metadata={"enabled": enabled},
            )
            await uow.commit()
            return channel

    async def delete_channel(
        self, principal: Principal, channel_id: UUID, meta: RequestMeta
    ) -> None:
        principal.require(Permission.CHANNELS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            channel = await uow.data.channels.get_for_update(org_id, channel_id)
            if channel is None:
                raise NotFoundError()
            await uow.data.channels.delete(channel)
            await self._audit.record(
                uow.audit,
                action=AuditAction.CHANNEL_DELETED,
                principal=principal,
                meta=meta,
                resource_type="channel",
                resource_id=channel_id,
            )
            await uow.commit()

    async def list_channels(
        self, principal: Principal, page: PageRequest
    ) -> Page[NotificationChannel]:
        principal.require(Permission.CHANNELS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.channels.list_page(principal.require_org(), page)

    async def _validate(
        self,
        uow: UnitOfWork,
        org_id: UUID,
        kind: ChannelKind,
        config: ChannelConfig,
        integration_id: UUID | None,
    ) -> None:
        if isinstance(config, WebhookChannelConfig):
            self._url_policy.validate(config.url)
        required = REQUIRED_INTEGRATION[kind]
        if required is None:
            if integration_id is not None:
                raise InvalidInputError("This channel kind does not use an integration.")
            return
        if integration_id is None:
            raise InvalidInputError(
                f"A {required.value} integration is required.", code="integration_required"
            )
        integration = await uow.data.integrations.get(org_id, integration_id)
        if (
            integration is None
            or integration.kind is not required
            or integration.status is not IntegrationStatus.ACTIVE
        ):
            raise InvalidInputError(
                "The integration is missing, inactive or of the wrong kind.",
                code="invalid_integration",
            )

    # ---------------------------------------------------------------- delivery

    async def deliver(self, *, org_id: UUID, delivery_id: UUID) -> DeliveryState:
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            delivery = await uow.data.deliveries.get_for_update(org_id, delivery_id)
            if delivery is None:
                raise NotFoundError(internal_detail=f"delivery {delivery_id}")
            if not delivery.claim(now):
                return delivery.status
            alert = await uow.data.alerts.get(org_id, delivery.alert_id)
            channel = await uow.data.channels.get(org_id, delivery.channel_id)
            if alert is None or channel is None or not channel.enabled or self._sender is None:
                delivery.mark_failed("channel_unavailable", retry_at=None)
                await uow.commit()
                return delivery.status
            await uow.commit()
        message = OutboundMessage(
            title=alert.title,
            body=alert.body,
            severity=alert.severity.value,
            link=None,
            idempotency_key=str(delivery.id),
        )
        wait = await self._throttle.retry_after(channel.id) if self._throttle else None
        if wait is not None:
            return await self._defer(org_id, delivery_id, delay=wait)
        try:
            credential = None
            if channel.integration_id is not None:
                required = REQUIRED_INTEGRATION[channel.kind]
                credential = await self._integrations.resolve(
                    org_id,
                    channel.integration_id,
                    allowed=frozenset({required} if required else set()),
                )
            await self._sender.send(channel, message, credential)
        except NexusFlowError as error:
            # Transient errors retry with backoff; everything else - a rejected
            # message, a revoked credential, a destination the URL policy blocks -
            # settles the delivery at once, so none is left in SENDING.
            return await self._settle(org_id, delivery_id, error=error)
        return await self._settle(org_id, delivery_id, error=None)

    async def _defer(self, org_id: UUID, delivery_id: UUID, *, delay: float) -> DeliveryState:
        """The channel is rate limited: try again later without spending an attempt."""
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            delivery = await uow.data.deliveries.get_for_update(org_id, delivery_id)
            if delivery is None:
                raise NotFoundError()
            delivery.defer("channel_rate_limited", until=now + timedelta(seconds=delay))
            await uow.outbox.add(
                new_message(
                    TaskName.DELIVER_NOTIFICATION,
                    {"org_id": str(org_id), "delivery_id": str(delivery.id)},
                    org_id=org_id,
                    now=now,
                    delay=timedelta(seconds=delay),
                )
            )
            await uow.commit()
            return delivery.status

    async def _settle(
        self,
        org_id: UUID,
        delivery_id: UUID,
        *,
        error: NexusFlowError | None,
    ) -> DeliveryState:
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            delivery = await uow.data.deliveries.get_for_update(org_id, delivery_id)
            if delivery is None:
                raise NotFoundError()
            if error is None:
                delivery.mark_delivered(now)
            else:
                code = error.code or "delivery_failed"
                retryable = isinstance(error, TransientError)
                wait = backoff_delay(delivery.attempts, base_seconds=30, cap_seconds=3600)
                delivery.mark_failed(
                    code, retry_at=now + timedelta(seconds=wait) if retryable else None
                )
                if delivery.status is DeliveryState.FAILED:
                    await uow.outbox.add(
                        new_message(
                            TaskName.DELIVER_NOTIFICATION,
                            {"org_id": str(org_id), "delivery_id": str(delivery.id)},
                            org_id=org_id,
                            now=now,
                            delay=timedelta(seconds=wait),
                        )
                    )
                else:
                    await stage_dead_letter(uow, delivery_dead_letter(delivery, code, now), now=now)
            await uow.commit()
            return delivery.status


def delivery_dead_letter(delivery: NotificationDelivery, code: str, now: datetime) -> DeadLetter:
    return DeadLetter(
        id=uuid7(),
        org_id=delivery.org_id,
        origin="celery",
        task_name=TaskName.DELIVER_NOTIFICATION.value,
        reference_type="notification_delivery",
        reference_id=str(delivery.id),
        payload={"delivery_id": str(delivery.id)},
        error_code=code[:64],
        attempts=delivery.attempts,
        first_failed_at=now,
        last_failed_at=now,
    )

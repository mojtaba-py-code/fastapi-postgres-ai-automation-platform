"""The core value chain, driven through the real services and PostgreSQL.

* Notification delivery: the delivery state machine behind alert notifications
  (sent; retried later with exponential backoff; dead-lettered on permanent
  failure or after the last attempt; throttled per channel; never sent twice),
  with a scripted stand-in for the channel sender.
* AI analysis: context preparation, redaction of sensitive data, tool calls
  through the tool gateway, output validation and storage - plus the consent,
  refusal, truncation, invalid-output, tool-budget and outage paths - with a
  scripted stand-in for the AI provider.
* The whole chain: a signed webhook delivery is ingested, its changes are
  detected, an alert rule matches, the notification is delivered and a JSON
  report is generated. Every outbox message is handled in-process by the worker
  handler the broker would have invoked.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import httpx2
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.core.clock import FrozenClock
from nexusflow.core.config import RateLimitRule
from nexusflow.core.errors import PermanentError, PolicyViolationError, TransientError
from nexusflow.domain.automation.maintenance import (
    MAX_ANALYSIS_ATTEMPTS,
    MAX_RUN_ATTEMPTS,
    STUCK_INSIGHT_AFTER,
    STUCK_RUN_AFTER,
)
from nexusflow.domain.integrations.model import IntegrationKind, ResolvedCredential
from nexusflow.domain.intelligence.model import Insight, InsightStatus
from nexusflow.domain.intelligence.ports import (
    AIConversation,
    AIUnavailableError,
    AnalysisRequest,
    ModelTurn,
    ToolCall,
    ToolResult,
)
from nexusflow.domain.intelligence.prompting import PROMPT_VERSION, SYSTEM_PROMPT
from nexusflow.domain.notifications.model import (
    MAX_DELIVERY_ATTEMPTS,
    DeliveryState,
    NotificationChannel,
    NotificationDelivery,
    OutboundMessage,
)
from nexusflow.domain.shared.outbox import TaskName
from nexusflow.domain.shared.unit_of_work import TenantScope
from nexusflow.domain.sources.model import RunStatus
from nexusflow.infrastructure.redis.rate_limit import RateLimiter
from nexusflow.infrastructure.redis.throttles import ChannelDeliveryThrottle
from tests.support.api import ApiSession, signup
from tests.support.bus import InProcessBus
from tests.support.business import (
    SCHEMA,
    WEBHOOK_CONFIG,
    create_source,
    org_id_of,
    signed_headers,
)

pytestmark = pytest.mark.integration

SENT, FAILED, DEAD = DeliveryState.DELIVERED, DeliveryState.FAILED, DeliveryState.DEAD

# --------------------------------------------------------------------------
# Tenants, datasets and collected data
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Tenant:
    owner: ApiSession
    org_id: UUID
    project_id: str


async def _tenant(api: httpx2.AsyncClient, *, external_ai: bool = False) -> Tenant:
    owner = await signup(api)
    if external_ai:
        opted_in = await owner.patch(
            "/api/v1/organizations/current", json={"settings": {"ai_external_processing": True}}
        )
        assert opted_in.status_code == 200, opted_in.text
    project = await owner.post("/api/v1/projects", json={"name": "Pricing"})
    assert project.status_code == 201, project.text
    return Tenant(owner, await org_id_of(owner), str(project.json()["id"]))


async def _dataset(
    tenant: Tenant, schema: dict[str, Any] = SCHEMA, *, classification: str = "internal"
) -> str:
    created = await tenant.owner.post(
        "/api/v1/datasets",
        json={
            "project_id": tenant.project_id,
            "name": f"products-{uuid4().hex[:6]}",
            "schema": schema,
            "classification": classification,
        },
    )
    assert created.status_code == 201, created.text
    return str(created.json()["id"])


def _website(key_field: str = "sku") -> dict[str, Any]:
    return {
        "kind": "website",
        "url": "https://shop.example.com/products",
        "item_selector": "div.product",
        "fields": {key_field: {"selector": ".key"}},
    }


async def _collect(
    tenant: Tenant, container: Container, source_id: str, items: list[dict[str, Any]]
) -> None:
    """One collection run of ``source_id`` that yielded ``items``."""
    run = await tenant.owner.post(f"/api/v1/sources/{source_id}/runs")
    assert run.status_code == 202, run.text
    outcome = await container.ingestion.ingest(
        org_id=tenant.org_id, run_id=UUID(run.json()["id"]), items=items
    )
    assert outcome.status.value == "succeeded", outcome.stats


async def _changes(tenant: Tenant, dataset_id: str, **params: str) -> list[dict[str, Any]]:
    response = await tenant.owner.get(
        "/api/v1/changes", params={"dataset_id": dataset_id, "limit": "200", **params}
    )
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


async def _alerts(tenant: Tenant) -> list[dict[str, Any]]:
    response = await tenant.owner.get("/api/v1/alerts", params={"limit": "200"})
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


async def _rule(tenant: Tenant, **body: Any) -> dict[str, Any]:
    created = await tenant.owner.post(
        "/api/v1/alert-rules", json={"project_id": tenant.project_id, **body}
    )
    assert created.status_code == 201, created.text
    rule: dict[str, Any] = created.json()
    return rule


async def _email_channel(tenant: Tenant, name: str) -> UUID:
    created = await tenant.owner.post(
        "/api/v1/channels",
        json={"name": name, "config": {"kind": "email", "recipients": ["oncall@example.com"]}},
    )
    assert created.status_code == 201, created.text
    return UUID(created.json()["id"])


def assert_in_order(handled: list[str], *steps: str) -> None:
    assert all(step in handled for step in steps), handled
    positions = [handled.index(step) for step in steps]
    assert positions == sorted(positions), handled


# --------------------------------------------------------------------------
# Notification delivery
# --------------------------------------------------------------------------


@dataclass
class FakeSender:
    """Scripted stand-in for ``ChannelSender``: records every attempt and raises
    the scripted failures in order (``None`` = success)."""

    failures: list[Exception | None] = field(default_factory=list)
    delay_seconds: float = 0.0
    attempts: list[UUID] = field(default_factory=list)
    credentials: list[ResolvedCredential | None] = field(default_factory=list)
    sent: list[tuple[NotificationChannel, OutboundMessage]] = field(default_factory=list)

    async def send(
        self,
        channel: NotificationChannel,
        message: OutboundMessage,
        credential: ResolvedCredential | None,
    ) -> None:
        self.attempts.append(channel.id)
        self.credentials.append(credential)
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        failure = self.failures.pop(0) if self.failures else None
        if failure is not None:
            raise failure
        self.sent.append((channel, message))


@pytest.fixture
def sender(container: Container, monkeypatch: pytest.MonkeyPatch) -> FakeSender:
    fake = FakeSender()
    monkeypatch.setattr(container.notifications, "_sender", fake)
    return fake


@pytest.fixture
def delivery_clock(container: Container, monkeypatch: pytest.MonkeyPatch) -> FrozenClock:
    """The notification service's clock, so retries can be made due on demand.

    Whole seconds keep the rate limiter's millisecond arithmetic exact."""
    clock = FrozenClock(datetime.now(UTC).replace(microsecond=0))
    monkeypatch.setattr(container.notifications, "_clock", clock)
    return clock


@dataclass(frozen=True)
class Alerting:
    tenant: Tenant
    dataset_id: str
    channel_ids: tuple[UUID, ...]


async def _alerting(api: httpx2.AsyncClient, *, channels: int = 1) -> Alerting:
    """A tenant with e-mail channels and a critical rule for failed collections."""
    tenant = await _tenant(api)
    dataset_id = await _dataset(tenant)
    channel_ids = tuple([await _email_channel(tenant, f"on-call-{n}") for n in range(channels)])
    await _rule(
        tenant,
        name="Broken sources",
        condition={"type": "run_failed"},
        severity="critical",
        channel_ids=[str(c) for c in channel_ids],
    )
    return Alerting(tenant, dataset_id, channel_ids)


async def _fire(alerting: Alerting, container: Container) -> dict[UUID, UUID]:
    """A collection fails and the rule fires: returns the new deliveries by channel."""
    tenant = alerting.tenant
    source_id = await create_source(
        tenant.owner, tenant.project_id, alerting.dataset_id, _website()
    )
    run = await tenant.owner.post(f"/api/v1/sources/{source_id}/runs")
    assert run.status_code == 202, run.text
    run_id = UUID(run.json()["id"])
    await container.ingestion.fail_run(
        org_id=tenant.org_id, run_id=run_id, code="http_503", detail=None
    )
    assert await container.alerts.evaluate_failed_run(org_id=tenant.org_id, run_id=run_id) == 1
    [alert] = [a for a in await _alerts(tenant) if a["subject_id"] == str(run_id)]
    async with container.uow_factory(TenantScope.system(tenant.org_id)) as uow:
        deliveries = await uow.data.deliveries.for_alert(tenant.org_id, UUID(alert["id"]))
    return {delivery.channel_id: delivery.id for delivery in deliveries}


async def _delivery(container: Container, org_id: UUID, delivery_id: UUID) -> NotificationDelivery:
    async with container.uow_factory(TenantScope.system(org_id)) as uow:
        delivery = await uow.data.deliveries.get(org_id, delivery_id)
    assert delivery is not None
    return delivery


async def _dead_letters(tenant: Tenant) -> list[dict[str, Any]]:
    response = await tenant.owner.get("/api/v1/dead-letters")
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


class TestNotificationDelivery:
    async def test_a_delivery_is_sent_once_and_marked_delivered(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        sender: FakeSender,
        delivery_clock: FrozenClock,
    ) -> None:
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        pending = await _delivery(container, org_id, delivery_id)
        assert (pending.status, pending.attempts) == (DeliveryState.PENDING, 0)

        state = await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id)

        assert state is SENT
        [(channel, message)] = sender.sent
        assert channel.id == channel_id
        assert message.severity == "critical"
        assert message.title.startswith("[CRITICAL] Broken sources: Collection failed: ")
        assert "Error: http_503" in message.body
        assert message.idempotency_key == str(delivery_id)  # lets receivers de-duplicate
        assert sender.credentials == [None]  # e-mail goes through the platform relay
        delivered = await _delivery(container, org_id, delivery_id)
        assert (delivered.status, delivered.attempts, delivered.last_error_code) == (SENT, 1, None)
        assert delivered.delivered_at == delivery_clock.now()

        # The broker delivers at least once: a redelivered task finds the work done.
        again = await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id)
        assert again is SENT
        assert len(sender.attempts) == 1

    async def test_concurrent_redeliveries_send_exactly_once(
        self, api: httpx2.AsyncClient, container: Container, sender: FakeSender
    ) -> None:
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        sender.delay_seconds = 0.05  # keep the first attempt in flight a little

        states = await asyncio.gather(
            *(
                container.notifications.deliver(org_id=org_id, delivery_id=delivery_id)
                for _ in range(3)
            )
        )

        assert len(sender.attempts) == 1
        assert SENT in states
        assert set(states) <= {SENT, DeliveryState.SENDING}  # the others found it claimed
        delivered = await _delivery(container, org_id, delivery_id)
        assert (delivered.status, delivered.attempts) == (SENT, 1)

    async def test_a_transient_failure_is_retried_later_with_exponential_backoff(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        bus: InProcessBus,
        sender: FakeSender,
        delivery_clock: FrozenClock,
    ) -> None:
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        sender.failures = [TransientError(code="smtp_unavailable")] * 2

        async def deliver() -> DeliveryState:
            return await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id)

        assert await deliver() is FAILED
        failed = await _delivery(container, org_id, delivery_id)
        assert (failed.attempts, failed.last_error_code) == (1, "smtp_unavailable")
        assert failed.next_attempt_at is not None
        first_wait = (failed.next_attempt_at - delivery_clock.now()).total_seconds()
        assert 24 <= first_wait <= 36  # 30 s, +/- 20 % jitter
        [retry] = [
            m
            for m in bus.published(TaskName.DELIVER_NOTIFICATION, org_id)
            if m.available_at > m.created_at
        ]
        assert retry.payload == {"org_id": str(org_id), "delivery_id": str(delivery_id)}
        assert retry.available_at == failed.next_attempt_at  # the retry job is scheduled for then

        # A redelivery before the retry is due does nothing.
        assert await deliver() is FAILED
        assert len(sender.attempts) == 1

        delivery_clock.set(failed.next_attempt_at)  # due
        assert await deliver() is FAILED
        second = await _delivery(container, org_id, delivery_id)
        assert second.attempts == 2
        assert second.next_attempt_at is not None
        second_wait = (second.next_attempt_at - delivery_clock.now()).total_seconds()
        assert 48 <= second_wait <= 72  # doubled

        delivery_clock.set(second.next_attempt_at)
        assert await deliver() is SENT
        delivered = await _delivery(container, org_id, delivery_id)
        assert (delivered.attempts, delivered.last_error_code) == (3, None)
        assert delivered.delivered_at == second.next_attempt_at
        assert len(sender.attempts) == 3
        assert len(sender.sent) == 1

    async def test_retries_stop_after_the_last_attempt_with_a_dead_letter(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        sender: FakeSender,
        delivery_clock: FrozenClock,
    ) -> None:
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        sender.failures = [TransientError(code="smtp_unavailable")] * MAX_DELIVERY_ATTEMPTS

        states = []
        for _ in range(MAX_DELIVERY_ATTEMPTS):
            states.append(
                await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id)
            )
            delivery_clock.advance(timedelta(hours=2))  # beyond the longest backoff

        assert states == [FAILED] * (MAX_DELIVERY_ATTEMPTS - 1) + [DEAD]
        dead = await _delivery(container, org_id, delivery_id)
        assert (dead.attempts, dead.next_attempt_at) == (MAX_DELIVERY_ATTEMPTS, None)
        assert dead.last_error_code == "smtp_unavailable"
        [letter] = await _dead_letters(alerting.tenant)
        assert letter["task_name"] == TaskName.DELIVER_NOTIFICATION.value
        assert (letter["reference_type"], letter["reference_id"]) == (
            "notification_delivery",
            str(delivery_id),
        )
        assert (letter["error_code"], letter["attempts"], letter["status"]) == (
            "smtp_unavailable",
            MAX_DELIVERY_ATTEMPTS,
            "open",
        )
        # Dead is final.
        assert await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id) is DEAD
        assert len(sender.attempts) == MAX_DELIVERY_ATTEMPTS

    async def test_a_permanent_failure_is_dead_lettered_at_once(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        bus: InProcessBus,
        sender: FakeSender,
    ) -> None:
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        sender.failures = [PermanentError(code="smtp_rejected")]

        state = await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id)

        assert state is DEAD
        dead = await _delivery(container, org_id, delivery_id)
        assert (dead.attempts, dead.next_attempt_at, dead.last_error_code) == (
            1,
            None,
            "smtp_rejected",
        )
        [letter] = await _dead_letters(alerting.tenant)
        assert (letter["reference_id"], letter["error_code"], letter["attempts"]) == (
            str(delivery_id),
            "smtp_rejected",
            1,
        )
        scheduled = [
            m
            for m in bus.published(TaskName.DELIVER_NOTIFICATION, org_id)
            if m.available_at > m.created_at
        ]
        assert scheduled == []  # no retry job
        assert await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id) is DEAD
        assert len(sender.attempts) == 1

    async def test_a_dead_lettered_notification_is_reported_as_a_failed_job(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        bus: InProcessBus,
        sender: FakeSender,
    ) -> None:
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        sender.failures = [PermanentError(code="smtp_rejected")]
        assert await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id) is DEAD
        [letter] = await _dead_letters(alerting.tenant)
        failed_jobs = [
            m.payload
            for m in bus.published(TaskName.WORKFLOW_EVENT, org_id)
            if m.payload.get("event") == "job.failed"
        ]
        assert [job["dead_letter_id"] for job in failed_jobs] == [letter["id"]]

    async def test_an_unexpected_sender_error_is_retried_like_a_transient_one(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        bus: InProcessBus,
        sender: FakeSender,
        delivery_clock: FrozenClock,
    ) -> None:
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        # No application error: a bug, or a library failing in a way nobody mapped.
        sender.failures = [ValueError("invalid literal for int() with base 10: '²'")]

        with pytest.raises(ValueError):  # still raised, so the worker logs it
            await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id)

        failed = await _delivery(container, org_id, delivery_id)  # settled, not left SENDING
        assert (failed.status, failed.attempts, failed.last_error_code) == (
            FAILED,
            1,
            "unexpected_error",
        )
        assert failed.next_attempt_at is not None
        [retry] = [
            m
            for m in bus.published(TaskName.DELIVER_NOTIFICATION, org_id)
            if m.available_at > m.created_at
        ]
        assert retry.available_at == failed.next_attempt_at
        delivery_clock.set(failed.next_attempt_at)
        assert await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id) is SENT

    async def test_a_blocked_destination_settles_the_delivery(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        sender: FakeSender,
    ) -> None:
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        sender.failures = [
            PolicyViolationError(
                "The destination address is not allowed.", code="address_not_allowed"
            )
        ]
        state = await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id)
        assert state is DEAD
        assert (await _delivery(container, org_id, delivery_id)).status is DEAD

    async def test_each_channel_is_throttled_on_its_own(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        sender: FakeSender,
        delivery_clock: FrozenClock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The real Redis-backed throttle, at one notification per channel and minute.
        limiter = RateLimiter(container.redis, prefix="core-chain:", clock=delivery_clock)
        throttle = ChannelDeliveryThrottle(limiter, RateLimitRule(limit=1, period_seconds=60))
        monkeypatch.setattr(container.notifications, "_throttle", throttle)
        alerting = await _alerting(api, channels=2)
        org_id, (email, pager) = alerting.tenant.org_id, alerting.channel_ids
        first, second = await _fire(alerting, container), await _fire(alerting, container)

        async def deliver(delivery_id: UUID) -> DeliveryState:
            return await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id)

        assert await deliver(first[email]) is SENT
        # The second alert on the same channel within the minute is held back,
        # without spending one of its delivery attempts ...
        assert await deliver(second[email]) is DeliveryState.PENDING
        held = await _delivery(container, org_id, second[email])
        assert held.last_error_code == "channel_rate_limited"
        assert held.attempts == 0
        assert held.next_attempt_at == delivery_clock.now() + timedelta(seconds=60)
        # ... while another channel still has its own budget.
        assert await deliver(second[pager]) is SENT
        assert sender.attempts == [email, pager]  # the held one never reached the sender

        delivery_clock.advance(timedelta(seconds=60))
        assert await deliver(second[email]) is SENT
        assert sender.attempts == [email, pager, email]

    async def test_throttling_never_uses_up_delivery_attempts(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        sender: FakeSender,
        delivery_clock: FrozenClock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class AlwaysBusy:
            async def retry_after(self, channel_id: UUID) -> float | None:
                return 60.0

        monkeypatch.setattr(container.notifications, "_throttle", AlwaysBusy())
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        for _ in range(MAX_DELIVERY_ATTEMPTS * 2):  # an alert storm on a busy channel
            state = await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id)
            assert state is DeliveryState.PENDING
            delivery_clock.advance(timedelta(seconds=60))
        assert (await _delivery(container, org_id, delivery_id)).attempts == 0
        assert sender.attempts == []

        monkeypatch.setattr(container.notifications, "_throttle", None)  # the storm is over
        assert await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id) is SENT

    async def test_disabled_channels_are_not_notified(
        self, api: httpx2.AsyncClient, container: Container, sender: FakeSender
    ) -> None:
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        disabled = await alerting.tenant.owner.patch(
            f"/api/v1/channels/{channel_id}", json={"enabled": False}
        )
        assert disabled.status_code == 200, disabled.text

        state = await container.notifications.deliver(org_id=org_id, delivery_id=delivery_id)

        assert state is DEAD
        assert (await _delivery(container, org_id, delivery_id)).last_error_code == (
            "channel_unavailable"
        )
        assert await _fire(alerting, container) == {}  # later alerts skip the channel
        assert sender.attempts == []

    async def test_credentials_are_resolved_for_the_sender_and_fail_closed(
        self, api: httpx2.AsyncClient, container: Container, sender: FakeSender
    ) -> None:
        tenant = await _tenant(api)
        hook = "https://hooks.slack.com/services/T0000001/B0000001/abcdefghijklmnopqrstuvwx"
        integration = await tenant.owner.post(
            "/api/v1/integrations", json={"name": "slack", "kind": "slack_webhook", "secret": hook}
        )
        assert integration.status_code == 201, integration.text
        integration_id = integration.json()["id"]
        channel = await tenant.owner.post(
            "/api/v1/channels",
            json={"name": "slack", "config": {"kind": "slack"}, "integration_id": integration_id},
        )
        assert channel.status_code == 201, channel.text
        channel_id = UUID(channel.json()["id"])
        await _rule(
            tenant,
            name="Broken sources",
            condition={"type": "run_failed"},
            channel_ids=[str(channel_id)],
        )
        alerting = Alerting(tenant, await _dataset(tenant), (channel_id,))

        first = (await _fire(alerting, container))[channel_id]
        assert (
            await container.notifications.deliver(org_id=tenant.org_id, delivery_id=first) is SENT
        )
        [credential] = sender.credentials
        assert credential is not None
        assert (credential.kind, credential.secret) == (IntegrationKind.SLACK_WEBHOOK, hook)

        revoked = await tenant.owner.post(
            f"/api/v1/integrations/{integration_id}/status",
            json={"status": "revoked", "reason": "webhook URL leaked"},
        )
        assert revoked.status_code == 200, revoked.text
        second = (await _fire(alerting, container))[channel_id]
        assert (
            await container.notifications.deliver(org_id=tenant.org_id, delivery_id=second) is DEAD
        )
        dead = await _delivery(container, tenant.org_id, second)
        assert dead.last_error_code == "integration_unavailable"
        assert len(sender.attempts) == 1  # a revoked credential never reaches the sender


# --------------------------------------------------------------------------
# AI analysis
# --------------------------------------------------------------------------

type Step = Callable[[AnalysisRequest, tuple[ToolResult, ...]], ModelTurn]

_UNTRUSTED = re.compile(
    r'<untrusted-data marker="(?P<boundary>[0-9a-f]+)">\n(?P<data>.*)\n'
    r'</untrusted-data marker="(?P=boundary)">',
    re.DOTALL,
)


def untrusted(request: AnalysisRequest) -> tuple[str, dict[str, Any]]:
    """The per-request boundary and the collected data it fences."""
    match = _UNTRUSTED.search(request.user_prompt)
    assert match is not None, "collected data must be fenced by the per-request boundary"
    data: dict[str, Any] = json.loads(match["data"])
    return match["boundary"], data


class ScriptedProvider:
    """Stand-in for the AI provider: replays scripted turns, records what it was sent."""

    def __init__(self, *steps: Step) -> None:
        self.steps = list(steps)
        self.requests: list[AnalysisRequest] = []
        self.received: list[tuple[ToolResult, ...]] = []

    @property
    def name(self) -> str:
        return "scripted"

    @property
    def model(self) -> str:
        return "scripted-1"

    def start(self, request: AnalysisRequest) -> AIConversation:
        self.requests.append(request)
        return _Conversation(self, request)


class _Conversation:
    def __init__(self, provider: ScriptedProvider, request: AnalysisRequest) -> None:
        self._provider = provider
        self._request = request

    async def send(self, tool_results: Sequence[ToolResult] = ()) -> ModelTurn:
        results = tuple(tool_results)
        self._provider.received.append(results)
        assert self._provider.steps, "the model was called more often than scripted"
        return self._provider.steps.pop(0)(self._request, results)


def reply(text: str | Callable[[str], str] | None, *, stop_reason: str = "end_turn") -> Step:
    """A final turn; ``text`` may be built from the request's secret boundary."""

    def step(request: AnalysisRequest, results: tuple[ToolResult, ...]) -> ModelTurn:
        body = text(untrusted(request)[0]) if callable(text) else text
        return ModelTurn(text=body, stop_reason=stop_reason, input_tokens=100, output_tokens=50)

    return step


def use_tools(*calls: ToolCall) -> Step:
    def step(request: AnalysisRequest, results: tuple[ToolResult, ...]) -> ModelTurn:
        return ModelTurn(
            text=None, tool_calls=calls, stop_reason="tool_use", input_tokens=120, output_tokens=10
        )

    return step


def fail(error: Exception) -> Step:
    def step(request: AnalysisRequest, results: tuple[ToolResult, ...]) -> ModelTurn:
        raise error

    return step


def answer(*refs: str, **overrides: Any) -> str:
    document: dict[str, Any] = {
        "summary": "Two products were listed.",
        "risk_level": "medium",
        "confidence": 0.7,
        "findings": [
            {
                "title": "New listings",
                "detail": "Both products are new.",
                "impact": "medium",
                "change_refs": list(refs),
            }
        ],
        "recommendations": ["Review the new listings"],
    }
    document.update(overrides)
    return json.dumps(document)


PRODUCTS: list[dict[str, Any]] = [
    {
        "sku": "A-1",
        "title": "Widget - ask jane.doe@example.com",
        "price": "10.00",
        "supplier_email": "buyer@supplier.example",
    },
    {"sku": "A-2", "title": "Gadget", "price": "5.00", "supplier_email": "sales@supplier.example"},
]
PERSONAL_DATA = ("jane.doe@example.com", "buyer@supplier.example", "sales@supplier.example")


@dataclass(frozen=True)
class Analysed:
    tenant: Tenant
    dataset_id: str
    change_ids: dict[str, str]  # record key -> change id


async def _with_changes(
    api: httpx2.AsyncClient, container: Container, *, external_ai: bool = True
) -> Analysed:
    """A tenant whose product dataset has two new, not yet analysed, changes."""
    tenant = await _tenant(api, external_ai=external_ai)
    dataset_id = await _dataset(tenant)
    source_id = await create_source(tenant.owner, tenant.project_id, dataset_id, _website())
    await _collect(tenant, container, source_id, PRODUCTS)
    detected = await container.detection.detect(org_id=tenant.org_id, dataset_id=UUID(dataset_id))
    assert detected.changes_created == len(PRODUCTS)
    changes = await _changes(tenant, dataset_id)
    return Analysed(tenant, dataset_id, {c["record_key"]: c["id"] for c in changes})


async def _request_analysis(analysed: Analysed) -> UUID:
    requested = await analysed.tenant.owner.post(
        "/api/v1/intelligence/analyses", json={"dataset_id": analysed.dataset_id}
    )
    assert requested.status_code == 202, requested.text
    assert requested.json()["status"] == "pending"
    return UUID(requested.json()["id"])


async def _insight(analysed: Analysed, insight_id: UUID) -> dict[str, Any]:
    response = await analysed.tenant.owner.get(f"/api/v1/intelligence/insights/{insight_id}")
    assert response.status_code == 200, response.text
    insight: dict[str, Any] = response.json()
    return insight


def _use(container: Container, monkeypatch: pytest.MonkeyPatch, provider: ScriptedProvider) -> None:
    monkeypatch.setattr(container.intelligence, "_provider", provider)


class TestAiAnalysis:
    async def test_analysis_with_redaction_tool_calls_and_validated_output(
        self, api: httpx2.AsyncClient, container: Container, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        analysed = await _with_changes(api, container)
        a1, a2 = analysed.change_ids["A-1"], analysed.change_ids["A-2"]
        provider = ScriptedProvider(
            use_tools(
                ToolCall(id="call-1", name="get_record_history", arguments={"record_key": "A-1"}),
                ToolCall(id="call-2", name="get_dataset_overview", arguments={}),
                ToolCall(id="call-3", name="run_shell", arguments={"command": "cat /etc/passwd"}),
            ),
            reply(
                answer(
                    a1,
                    a2,
                    "invented-change",
                    summary=(
                        "Two listings appeared. Log in at https://evil.example/login to see "
                        "https://shop.example.com/products/A-1"
                    ),
                    risk_level="high",
                    confidence=0.8,
                )
            ),
        )
        _use(container, monkeypatch, provider)
        insight_id = await _request_analysis(analysed)

        insight = await container.intelligence.analyze(
            org_id=analysed.tenant.org_id, insight_id=insight_id
        )

        # Context: trusted instructions in the system prompt, data fenced and budgeted.
        [request] = provider.requests
        assert request.system_prompt == SYSTEM_PROMPT
        assert request.output_schema["additionalProperties"] is False
        assert {tool.name for tool in request.tools} == {
            "get_record_history",
            "get_dataset_overview",
        }
        _, data = untrusted(request)
        assert (data["changes_total"], data["changes_included"]) == (2, 2)
        prepared = {change["record_key"]: change for change in data["changes"]}
        assert {change["id"] for change in data["changes"]} == {a1, a2}
        assert prepared["A-1"]["change_type"] == "created"
        # Redaction: sensitive fields are dropped, personal data in free text is scrubbed.
        assert "supplier_email" not in prepared["A-1"]["diff"]
        assert prepared["A-1"]["diff"]["title"]["new"] == "Widget - ask [REDACTED:email]"
        assert not any(value in request.user_prompt for value in PERSONAL_DATA)

        # Tool calls went through the gateway: allowed tools ran with redacted results.
        assert provider.received[0] == ()
        history, overview, shell = provider.received[1]
        assert [r.call_id for r in provider.received[1]] == ["call-1", "call-2", "call-3"]
        assert [r.is_error for r in provider.received[1]] == [False, False, True]
        record = json.loads(history.content)
        assert (record["found"], record["record_key"]) == (True, "A-1")
        [version] = record["versions"]
        assert "supplier_email" not in version["data"]
        assert version["data"]["title"] == "Widget - ask [REDACTED:email]"
        fields = {f["name"] for f in json.loads(overview.content)["fields"]}
        assert "price" in fields and "supplier_email" not in fields
        assert json.loads(shell.content) == {"error": "This tool is not available."}
        assert not any(value in r.content for r in provider.received[1] for value in PERSONAL_DATA)
        assert insight.usage["tool_calls"] == [
            {"tool": "get_record_history", "decision": "allowed"},
            {"tool": "get_dataset_overview", "decision": "allowed"},
            {"tool": "run_shell", "decision": "unknown_tool"},
        ]
        assert (insight.usage["tool_rounds"], insight.usage["changes_in_context"]) == (1, 2)
        assert (insight.usage["input_tokens"], insight.usage["output_tokens"]) == (220, 60)
        assert insight.prompt_version == PROMPT_VERSION

        # The validated output is stored and the analysed changes are linked to it.
        stored = await _insight(analysed, insight_id)
        assert (stored["status"], stored["provider"], stored["model"]) == (
            "completed",
            "scripted",
            "scripted-1",
        )
        assert (stored["risk_level"], stored["confidence"], stored["change_count"]) == (
            "high",
            0.8,
            2,
        )
        assert "evil.example" not in stored["summary"]  # phishing link removed ...
        assert "[link removed]" in stored["summary"]
        assert "https://shop.example.com/products/A-1" in stored["summary"]  # ... source kept
        assert stored["findings"][0]["change_refs"] == [a1, a2]  # invented reference dropped
        assert stored["recommendations"] == ["Review the new listings"]
        assert stored["error_code"] is None
        changes = await _changes(analysed.tenant, analysed.dataset_id)
        assert {change["insight_id"] for change in changes} == {str(insight_id)}

    async def test_without_consent_the_offline_analyser_is_used_and_nothing_is_sent(
        self, api: httpx2.AsyncClient, container: Container, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        analysed = await _with_changes(api, container, external_ai=False)
        provider = ScriptedProvider()
        _use(container, monkeypatch, provider)
        insight_id = await _request_analysis(analysed)

        await container.intelligence.analyze(org_id=analysed.tenant.org_id, insight_id=insight_id)

        assert provider.requests == []  # nothing left the platform
        stored = await _insight(analysed, insight_id)
        assert (stored["status"], stored["provider"], stored["model"]) == (
            "completed",
            "offline",
            "heuristic-v1",
        )
        assert (stored["risk_level"], stored["change_count"]) == ("medium", 2)
        assert stored["summary"].startswith("2 changes detected in 'products-")
        assert sorted(ref for f in stored["findings"] for ref in f["change_refs"]) == sorted(
            analysed.change_ids.values()
        )

    @pytest.mark.parametrize(
        ("step", "code"),
        [
            pytest.param(reply(None, stop_reason="refusal"), "ai_refused", id="refusal"),
            pytest.param(
                reply('{"summary": "Prices rose', stop_reason="max_tokens"),
                "ai_output_truncated",
                id="truncated",
            ),
            pytest.param(reply("Prices went up."), "ai_output_not_json", id="prose"),
            pytest.param(reply(""), "ai_output_empty_or_too_long", id="empty"),
            pytest.param(
                reply(answer(risk_level="apocalyptic")), "ai_output_schema_violation", id="schema"
            ),
            pytest.param(
                reply(lambda boundary: answer(summary=f"The data ends at {boundary}.")),
                "ai_output_prompt_echo",
                id="boundary-echo",
            ),
            pytest.param(
                reply(answer("made-up-1", "made-up-2")),
                "ai_output_hallucinated_references",
                id="invented-references",
            ),
        ],
    )
    async def test_untrustworthy_answers_are_rejected_and_nothing_is_marked_analysed(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        monkeypatch: pytest.MonkeyPatch,
        step: Step,
        code: str,
    ) -> None:
        analysed = await _with_changes(api, container)
        provider = ScriptedProvider(step)
        _use(container, monkeypatch, provider)
        insight_id = await _request_analysis(analysed)

        insight = await container.intelligence.analyze(
            org_id=analysed.tenant.org_id, insight_id=insight_id
        )

        assert insight.completed_at is not None
        stored = await _insight(analysed, insight_id)
        assert (stored["status"], stored["error_code"]) == ("rejected", code)
        assert (stored["summary"], stored["findings"], stored["risk_level"]) == (None, [], None)
        assert len(provider.requests) == 1  # a rejection is final, not retried
        changes = await _changes(analysed.tenant, analysed.dataset_id)
        assert {change["insight_id"] for change in changes} == {None}  # left for a later analysis

    async def test_a_model_that_keeps_calling_tools_is_stopped(
        self, api: httpx2.AsyncClient, container: Container, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        analysed = await _with_changes(api, container)
        rounds = container.settings.ai.max_tool_rounds
        provider = ScriptedProvider(
            *(
                use_tools(ToolCall(id=f"call-{n}", name="get_dataset_overview", arguments={}))
                for n in range(rounds + 1)
            )
        )
        _use(container, monkeypatch, provider)
        insight_id = await _request_analysis(analysed)

        await container.intelligence.analyze(org_id=analysed.tenant.org_id, insight_id=insight_id)

        stored = await _insight(analysed, insight_id)
        assert (stored["status"], stored["error_code"]) == ("rejected", "ai_tool_budget_exceeded")
        assert len(provider.received) == rounds + 1
        assert [len(results) for results in provider.received] == [0] + [1] * rounds

    async def test_a_provider_outage_hands_the_analysis_back_for_the_retry(
        self, api: httpx2.AsyncClient, container: Container, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        analysed = await _with_changes(api, container)
        provider = ScriptedProvider(
            fail(AIUnavailableError()), reply(answer(*analysed.change_ids.values()))
        )
        _use(container, monkeypatch, provider)
        insight_id = await _request_analysis(analysed)
        org_id = analysed.tenant.org_id

        with pytest.raises(AIUnavailableError):
            await container.intelligence.analyze(org_id=org_id, insight_id=insight_id)
        assert (await _insight(analysed, insight_id))["status"] == "pending"  # not stuck running

        retried = await container.intelligence.analyze(org_id=org_id, insight_id=insight_id)

        assert retried.status.value == "completed"
        stored = await _insight(analysed, insight_id)
        assert (stored["status"], stored["provider"], stored["change_count"]) == (
            "completed",
            "scripted",
            2,
        )
        assert len(provider.requests) == 2

    async def test_only_the_changes_the_model_saw_are_marked_analysed(
        self, api: httpx2.AsyncClient, container: Container, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = await _tenant(api, external_ai=True)
        schema = {
            "fields": [
                {"name": "sku", "type": "string", "required": True},
                {"name": "notes", "type": "text"},
            ],
            "key_field": "sku",
        }
        dataset_id = await _dataset(tenant, schema)
        source_id = await create_source(tenant.owner, tenant.project_id, dataset_id, _website())
        items = [{"sku": "B-1", "notes": "x" * 3000}, {"sku": "B-2", "notes": "Short."}]
        await _collect(tenant, container, source_id, items)
        await container.detection.detect(org_id=tenant.org_id, dataset_id=UUID(dataset_id))
        ids = {c["record_key"]: c["id"] for c in await _changes(tenant, dataset_id)}
        # The context budget holds B-2, but B-1 alone is larger than all of it.
        monkeypatch.setattr(container.intelligence, "_max_input_chars", 1000)
        provider = ScriptedProvider(reply(answer(ids["B-2"])))
        _use(container, monkeypatch, provider)
        analysed = Analysed(tenant, dataset_id, ids)

        first = await _request_analysis(analysed)
        await container.intelligence.analyze(org_id=tenant.org_id, insight_id=first)

        _, data = untrusted(provider.requests[0])
        assert (data["changes_total"], data["changes_included"]) == (2, 1)
        stored = await _insight(analysed, first)
        assert (stored["status"], stored["provider"], stored["change_count"]) == (
            "completed",
            "scripted",
            1,
        )
        linked = {c["record_key"]: c["insight_id"] for c in await _changes(tenant, dataset_id)}
        assert linked == {"B-1": None, "B-2": str(first)}  # B-1 waits for the next analysis

        # Nothing that is left fits the model's context: it is analysed offline
        # (nothing is sent), so it cannot hold up the analyses after it.
        second = await _request_analysis(analysed)
        await container.intelligence.analyze(org_id=tenant.org_id, insight_id=second)
        assert len(provider.requests) == 1
        stored = await _insight(analysed, second)
        assert (stored["status"], stored["provider"], stored["change_count"]) == (
            "completed",
            "offline",
            1,
        )
        linked = {c["record_key"]: c["insight_id"] for c in await _changes(tenant, dataset_id)}
        assert linked == {"B-1": str(second), "B-2": str(first)}

    async def test_a_stored_insight_feeds_insight_risk_rules(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        analysed = await _with_changes(api, container, external_ai=False)
        tenant = analysed.tenant
        for level in ("medium", "high"):
            await _rule(
                tenant,
                dataset_id=analysed.dataset_id,
                name=f"Risk {level} or above",
                condition={"type": "insight_risk_at_least", "level": level},
            )
        insight_id = await _request_analysis(analysed)
        insight = await container.intelligence.analyze(org_id=tenant.org_id, insight_id=insight_id)
        assert insight.risk_level is not None
        assert insight.risk_level.value == "medium"

        assert (
            await container.alerts.evaluate_insight(org_id=tenant.org_id, insight_id=insight_id)
            == 1
        )

        [alert] = await _alerts(tenant)
        assert (alert["subject_type"], alert["subject_id"]) == ("insight", str(insight_id))
        assert alert["title"].startswith("[WARNING] Risk medium or above: AI analysis of ")
        assert alert["title"].endswith(": medium risk")
        # A redelivered insight.created event adds nothing.
        assert (
            await container.alerts.evaluate_insight(org_id=tenant.org_id, insight_id=insight_id)
            == 0
        )

    async def test_a_sensitive_key_field_is_refused(self, api: httpx2.AsyncClient) -> None:
        # Record keys appear in alerts, reports and AI prompts, so they cannot be masked.
        tenant = await _tenant(api, external_ai=True)
        schema = {
            "fields": [
                {"name": "customer_id", "type": "string", "required": True, "sensitive": True},
                {"name": "plan", "type": "string"},
            ],
            "key_field": "customer_id",
        }
        created = await tenant.owner.post(
            "/api/v1/datasets",
            json={"project_id": tenant.project_id, "name": "customers", "schema": schema},
        )
        assert created.status_code == 422, created.text
        assert "key_field cannot be sensitive" in created.text


# --------------------------------------------------------------------------
# Restricted data never leaves the platform
# --------------------------------------------------------------------------


class TestRestrictedData:
    async def test_restricted_data_is_never_sent_to_the_external_provider(
        self, api: httpx2.AsyncClient, container: Container, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = await _tenant(api, external_ai=True)  # the organization opted in ...
        dataset_id = await _dataset(tenant, classification="restricted")  # ... but not for this
        source_id = await create_source(tenant.owner, tenant.project_id, dataset_id, _website())
        await _collect(tenant, container, source_id, PRODUCTS)
        await container.detection.detect(org_id=tenant.org_id, dataset_id=UUID(dataset_id))
        provider = ScriptedProvider()  # any call would fail: nothing is scripted
        _use(container, monkeypatch, provider)
        requested = await tenant.owner.post(
            "/api/v1/intelligence/analyses", json={"dataset_id": dataset_id}
        )
        insight = await container.intelligence.analyze(
            org_id=tenant.org_id, insight_id=UUID(requested.json()["id"])
        )
        assert provider.requests == []
        assert (insight.status.value, insight.provider) == ("completed", "offline")

    async def test_alerts_about_restricted_data_carry_no_values(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        tenant = await _tenant(api)
        dataset_id = await _dataset(tenant, classification="restricted")
        await _rule(
            tenant,
            dataset_id=dataset_id,
            name="Price moved",
            condition={"type": "numeric_change", "field": "price", "min_pct": 5},
        )
        source_id = await create_source(tenant.owner, tenant.project_id, dataset_id, _website())
        for price in ("100.00", "150.00"):
            await _collect(tenant, container, source_id, [{"sku": "SECRET-SKU-7", "price": price}])
            await container.detection.detect(org_id=tenant.org_id, dataset_id=UUID(dataset_id))
            await container.alerts.evaluate_changes(org_id=tenant.org_id)

        [alert] = await _alerts(tenant)  # the rule still sees the numbers and fires ...
        record = r"record [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        # ... but the message names the record by its platform id and the field only.
        assert re.fullmatch(rf"\[WARNING\] Price moved: updated {record}", alert["title"])
        assert re.fullmatch(
            rf"Record: {record}\nChange: updated \(significance \w+\)\n- price changed",
            alert["body"],
        ), alert["body"]


# --------------------------------------------------------------------------
# Alert rules on sensitive data
# --------------------------------------------------------------------------


class TestAlertRulesOnSensitiveFields:
    async def test_numeric_rules_on_sensitive_fields_fire_or_are_refused(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        tenant = await _tenant(api)
        dataset_id = await _dataset(
            tenant,
            {
                "fields": [
                    {"name": "sku", "type": "string", "required": True},
                    {"name": "cost", "type": "decimal", "sensitive": True},
                ],
                "key_field": "sku",
            },
        )
        await _rule(
            tenant,
            dataset_id=dataset_id,
            name="Cost changed",
            condition={"type": "field_changed", "field": "cost"},
        )
        numeric = await tenant.owner.post(
            "/api/v1/alert-rules",
            json={
                "project_id": tenant.project_id,
                "dataset_id": dataset_id,
                "name": "Cost up 10 percent",
                "condition": {
                    "type": "numeric_change",
                    "field": "cost",
                    "direction": "increase",
                    "min_pct": 10,
                },
            },
        )
        if numeric.status_code == 422:
            return  # refusing rules that could never fire would fix it, too
        source_id = await create_source(tenant.owner, tenant.project_id, dataset_id, _website())
        for cost in ("100", "150"):
            await _collect(tenant, container, source_id, [{"sku": "P-1", "cost": cost}])
            await container.detection.detect(org_id=tenant.org_id, dataset_id=UUID(dataset_id))
            await container.alerts.evaluate_changes(org_id=tenant.org_id)
        alerts = await _alerts(tenant)
        titles = {alert["title"] for alert in alerts}
        assert "[WARNING] Cost changed: updated P-1" in titles  # control: the update was seen
        assert "[WARNING] Cost up 10 percent: updated P-1" in titles
        for alert in alerts:  # the rule saw the numbers; the alert still does not show them
            assert "150" not in alert["body"]
            assert "%" not in alert["body"]


# --------------------------------------------------------------------------
# Recovery from crashed workers (the maintenance reaper)
# --------------------------------------------------------------------------


async def _abandon(
    container: Container, org_id: UUID, insight_id: UUID, *, attempts: int | None = None
) -> None:
    """Make an analysis look abandoned: claimed longer ago than any analysis takes."""
    async with container.uow_factory(TenantScope.system(org_id)) as uow:
        insight = await uow.data.insights.get_for_update(org_id, insight_id)
        assert insight is not None
        insight.status = InsightStatus.RUNNING
        insight.started_at = datetime.now(UTC) - STUCK_INSIGHT_AFTER - timedelta(minutes=1)
        if attempts is not None:
            insight.attempts = attempts
        await uow.commit()


async def _stored_insight(container: Container, org_id: UUID, insight_id: UUID) -> Insight:
    async with container.uow_factory(TenantScope.system(org_id)) as uow:
        insight = await uow.data.insights.get(org_id, insight_id)
    assert insight is not None
    return insight


class TestCrashRecovery:
    async def test_an_analysis_whose_worker_died_is_requeued_then_failed(
        self, api: httpx2.AsyncClient, container: Container, bus: InProcessBus
    ) -> None:
        analysed = await _with_changes(api, container)
        org_id = analysed.tenant.org_id
        insight_id = await _request_analysis(analysed)
        queued = len(bus.published(TaskName.ANALYZE_CHANGES, org_id))

        await _abandon(container, org_id, insight_id, attempts=1)
        assert (await container.maintenance.reap(org_id)).requeued_insights == 1
        assert (
            await _stored_insight(container, org_id, insight_id)
        ).status is InsightStatus.PENDING
        assert len(bus.published(TaskName.ANALYZE_CHANGES, org_id)) == queued + 1

        await _abandon(container, org_id, insight_id, attempts=MAX_ANALYSIS_ATTEMPTS)
        assert (await container.maintenance.reap(org_id)).failed_insights == 1
        failed = await _stored_insight(container, org_id, insight_id)
        assert (failed.status, failed.error_code) == (InsightStatus.FAILED, "worker_lost")

    async def test_a_running_analysis_is_left_alone(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        analysed = await _with_changes(api, container)
        org_id = analysed.tenant.org_id
        insight_id = await _request_analysis(analysed)
        async with container.uow_factory(TenantScope.system(org_id)) as uow:
            insight = await uow.data.insights.get_for_update(org_id, insight_id)
            assert insight is not None
            insight.start(datetime.now(UTC))  # claimed a moment ago
            await uow.commit()
        report = await container.maintenance.reap(org_id)
        assert (report.requeued_insights, report.failed_insights) == (0, 0)

    async def test_a_reaped_workers_late_result_is_discarded(
        self, api: httpx2.AsyncClient, container: Container, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        analysed = await _with_changes(api, container)
        org_id = analysed.tenant.org_id
        refs = list(analysed.change_ids.values())
        insight_id = await _request_analysis(analysed)
        rerun = ScriptedProvider(reply(answer(*refs, summary="The re-run's analysis.")))

        class HungWorker:
            """The first worker hangs in the model call; meanwhile the reaper hands the
            analysis to a new run, which completes. Then the old worker wakes up."""

            name, model = "hung", "hung-1"

            def start(self, request: AnalysisRequest) -> HungWorker:
                return self

            async def send(self, tool_results: Sequence[ToolResult] = ()) -> ModelTurn:
                await _abandon(container, org_id, insight_id)
                assert (await container.maintenance.reap(org_id)).requeued_insights == 1
                _use(container, monkeypatch, rerun)
                await container.intelligence.analyze(org_id=org_id, insight_id=insight_id)
                late = answer(*refs, summary="The stale worker's analysis.")
                return ModelTurn(text=late, stop_reason="end_turn", input_tokens=1, output_tokens=1)

        _use(container, monkeypatch, cast(Any, HungWorker()))
        await container.intelligence.analyze(org_id=org_id, insight_id=insight_id)

        stored = await _stored_insight(container, org_id, insight_id)
        assert (stored.status, stored.summary) == (
            InsightStatus.COMPLETED,
            "The re-run's analysis.",
        )
        assert stored.attempts == 2

    async def test_a_delivery_whose_workers_keep_dying_is_dead_lettered_and_reported(
        self, api: httpx2.AsyncClient, container: Container, bus: InProcessBus
    ) -> None:
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        async with container.uow_factory(TenantScope.system(org_id)) as uow:
            delivery = await uow.data.deliveries.get_for_update(org_id, delivery_id)
            assert delivery is not None
            delivery.status = DeliveryState.SENDING  # its last worker died mid-send ...
            delivery.attempts = MAX_DELIVERY_ATTEMPTS  # ... as every one before it did
            delivery.claimed_at = datetime.now(UTC) - timedelta(hours=1)
            await uow.commit()

        assert (await container.maintenance.reap(org_id)).dead_deliveries == 1

        assert (await _delivery(container, org_id, delivery_id)).status is DEAD
        [letter] = await _dead_letters(alerting.tenant)
        assert (letter["reference_id"], letter["error_code"]) == (str(delivery_id), "worker_lost")
        failed_jobs = [
            m.payload
            for m in bus.published(TaskName.WORKFLOW_EVENT, org_id)
            if m.payload.get("event") == "job.failed"
        ]
        assert [job["dead_letter_id"] for job in failed_jobs] == [letter["id"]]

    async def test_a_run_whose_workers_keep_dying_fails_like_any_failed_run(
        self, api: httpx2.AsyncClient, container: Container, bus: InProcessBus
    ) -> None:
        tenant = await _tenant(api)
        source_id = await create_source(
            tenant.owner, tenant.project_id, await _dataset(tenant), _website()
        )
        await _rule(tenant, name="Broken sources", condition={"type": "run_failed"})
        workflow = await tenant.owner.post(
            "/api/v1/workflows",
            json={
                "project_id": tenant.project_id,
                "name": "Nightly",
                "trigger": "manual",
                "source_ids": [source_id],
            },
        )
        assert workflow.status_code == 201, workflow.text
        workflow_path = f"/api/v1/workflows/{workflow.json()['id']}"
        started = await tenant.owner.post(f"{workflow_path}/runs")
        assert started.status_code == 202, started.text
        await bus.drain(tenant.org_id)  # the run starts and goes to the sandbox
        async with container.uow_factory(TenantScope.system(tenant.org_id)) as uow:
            [run] = await uow.data.runs.list_for_workflow_run(
                tenant.org_id, UUID(started.json()["id"])
            )
            assert run.status is RunStatus.RUNNING
            run.started_at = datetime.now(UTC) - STUCK_RUN_AFTER * 2
            run.attempt = MAX_RUN_ATTEMPTS  # every sandbox job of it died with its worker
            await uow.commit()

        assert (await container.maintenance.reap(tenant.org_id)).failed_runs == 1
        await bus.drain(tenant.org_id)

        failed = (await tenant.owner.get(f"/api/v1/runs/{run.id}")).json()
        assert (failed["status"], failed["error_code"]) == ("failed", "worker_lost")
        source = (await tenant.owner.get(f"/api/v1/sources/{source_id}")).json()
        assert source["consecutive_failures"] == 1
        [alert] = await _alerts(tenant)  # the run_failed rule fired
        assert "Error: worker_lost" in alert["body"]
        [workflow_run] = (await tenant.owner.get(f"{workflow_path}/runs")).json()["items"]
        assert workflow_run["status"] == "failed"  # not left "running" for ever

    async def test_a_delivery_stuck_once_is_retried_with_backoff(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        alerting = await _alerting(api)
        org_id, [channel_id] = alerting.tenant.org_id, alerting.channel_ids
        delivery_id = (await _fire(alerting, container))[channel_id]
        async with container.uow_factory(TenantScope.system(org_id)) as uow:
            delivery = await uow.data.deliveries.get_for_update(org_id, delivery_id)
            assert delivery is not None
            delivery.status, delivery.attempts = DeliveryState.SENDING, 2
            delivery.claimed_at = datetime.now(UTC) - timedelta(hours=1)
            await uow.commit()

        before = datetime.now(UTC)
        assert (await container.maintenance.reap(org_id)).reset_deliveries == 1
        reset = await _delivery(container, org_id, delivery_id)
        assert reset.status is FAILED
        assert reset.next_attempt_at is not None
        assert reset.next_attempt_at > before + timedelta(seconds=30)  # not immediately


# --------------------------------------------------------------------------
# The whole chain
# --------------------------------------------------------------------------


class TestCoreChain:
    async def test_signed_webhook_to_notification_and_report(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        bus: InProcessBus,
        sender: FakeSender,
    ) -> None:
        tenant = await _tenant(api)
        org_id, owner = tenant.org_id, tenant.owner
        dataset_id = await _dataset(tenant)
        source_id = await create_source(owner, tenant.project_id, dataset_id, WEBHOOK_CONFIG)
        endpoint = await owner.post(
            "/api/v1/webhook-endpoints", json={"source_id": source_id, "name": "shop"}
        )
        assert endpoint.status_code == 201, endpoint.text
        path = endpoint.json()["url"].removeprefix("https://nexusflow.test.example")
        secret = endpoint.json()["secret"]
        channel_id = await _email_channel(tenant, "pricing-team")
        await _rule(
            tenant,
            dataset_id=dataset_id,
            name="Price jumps",
            condition={
                "type": "numeric_change",
                "field": "price",
                "direction": "increase",
                "min_pct": 10,
            },
            severity="critical",
            channel_ids=[str(channel_id)],
        )

        def product(sku: str, price: str, contact: str) -> dict[str, Any]:
            return {
                "sku": sku,
                "title": f"Product {sku}",
                "price": price,
                "supplier": {"email": contact},
            }

        async def deliver_webhook(delivery_id: str, items: list[dict[str, Any]]) -> httpx2.Response:
            body = json.dumps({"items": items}).encode()
            return await api.post(
                path, content=body, headers=signed_headers(secret, body, delivery_id)
            )

        # 1. Two products are listed: new records, but no price moved - the rule stays quiet.
        listing = [product("A-1", "10.00", "a@s.example"), product("A-2", "5.00", "b@s.example")]
        listed = await deliver_webhook("dlv-chain-0001", listing)
        assert listed.status_code == 202, listed.text
        handled = await bus.drain(org_id)
        assert_in_order(
            handled,
            "nexusflow.collect.dispatch",
            "nexusflow.events.route:collection.completed",
            "nexusflow.events.route:changes.detected",
        )
        created = await _changes(tenant, dataset_id)
        assert sorted(
            (c["record_key"], c["change_type"], c["from_version"], c["to_version"]) for c in created
        ) == [("A-1", "created", None, 1), ("A-2", "created", None, 1)]
        assert await _alerts(tenant) == []
        assert sender.attempts == []

        # 2. A-1 gets 25 % dearer (and a new supplier contact), A-2 20 % cheaper.
        repricing = [product("A-1", "12.50", "c@s.example"), product("A-2", "4.00", "b@s.example")]
        repriced = await deliver_webhook("dlv-chain-0002", repricing)
        assert repriced.status_code == 202, repriced.text
        handled = await bus.drain(org_id)
        assert_in_order(
            handled,
            "nexusflow.collect.dispatch",
            "nexusflow.events.route:collection.completed",
            "nexusflow.events.route:changes.detected",
            "nexusflow.notifications.deliver",
        )
        assert "nexusflow.events.route:alert.triggered" in handled
        updates = {
            c["record_key"]: c for c in await _changes(tenant, dataset_id, change_type="updated")
        }
        rise, cut = updates["A-1"], updates["A-2"]
        assert (rise["from_version"], rise["to_version"]) == (1, 2)
        assert (rise["diff"]["price"]["pct"], rise["diff"]["price"]["delta"]) == (25.0, "2.5")
        assert set(rise["diff"]) == {"price", "supplier_email"}
        assert (rise["significance"], rise["score"]) == ("high", 77)
        assert (cut["diff"]["price"]["pct"], cut["significance"]) == (-20.0, "high")

        # Only the increase matched the rule: exactly one notification went out.
        [alert] = await _alerts(tenant)
        assert (alert["subject_type"], alert["subject_id"]) == ("change", rise["id"])
        [(channel, message)] = sender.sent
        assert channel.id == channel_id
        assert (message.severity, message.title) == (
            "critical",
            "[CRITICAL] Price jumps: updated A-1",
        )
        assert "(+25.0%)" in message.body
        assert "[masked]" in message.body
        assert "c@s.example" not in message.body  # sensitive values never leave in alerts
        async with container.uow_factory(TenantScope.system(org_id)) as uow:
            [delivery] = await uow.data.deliveries.for_alert(org_id, UUID(alert["id"]))
        assert (delivery.status, delivery.attempts) == (SENT, 1)
        assert message.idempotency_key == str(delivery.id)

        # 3. Retries change nothing: the sender replays its delivery, the broker
        #    redelivers the notification task.
        replay = await deliver_webhook("dlv-chain-0002", repricing)
        assert (replay.status_code, replay.json()["status"]) == (200, "duplicate")
        assert await bus.drain(org_id) == []
        [notification] = bus.published(TaskName.DELIVER_NOTIFICATION, org_id)
        await bus.run(notification)
        assert len(sender.attempts) == 1
        assert len(await _changes(tenant, dataset_id)) == 4

        # 4. A JSON report of the period is generated by the worker and covers the changes.
        now = datetime.now(UTC)
        requested = await owner.post(
            "/api/v1/reports",
            json={
                "project_id": tenant.project_id,
                "dataset_id": dataset_id,
                "format": "json",
                "title": "Pricing digest",
                "period_start": (now - timedelta(hours=1)).isoformat(),
                "period_end": (now + timedelta(hours=1)).isoformat(),
            },
        )
        assert requested.status_code == 202, requested.text
        report_id = requested.json()["id"]
        assert "nexusflow.reports.generate" in await bus.drain(org_id)
        report = await owner.get(f"/api/v1/reports/{report_id}")
        assert report.json()["status"] == "ready"
        download = await owner.get(f"/api/v1/reports/{report_id}/download")
        assert download.status_code == 200, download.text
        for change in [*created, rise, cut]:
            assert change["id"] in download.text

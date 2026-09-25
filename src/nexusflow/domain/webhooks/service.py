"""Inbound webhook endpoints: management and verified receipt.

Receipt pipeline (every step fails closed):

1. endpoint lookup scoped to the tenant in the URL, without a row lock
   (unknown/disabled endpoints get the same 401 as bad signatures, after the
   same HMAC work on a decoy secret - no endpoint enumeration, not even by
   timing);
2. HMAC-SHA256 signature over ``timestamp.delivery_id.body`` with a freshness
   window (current + previous secret during rotation grace);
3. the per-endpoint delivery quota - consumed by authenticated requests only,
   so forged floods cannot exhaust a legitimate sender's quota;
4. replay protection in two layers: a Redis nonce (fast path) and a unique
   ``(endpoint_id, delivery_id)`` row (durable). The nonce is released when
   storing fails and "duplicate" is only answered for deliveries that really
   are stored, so a failed delivery always stays retryable;
5. bounded JSON parsing (size, depth) and field mapping onto the dataset schema;
6. staging + a queued collection run (processed asynchronously).
"""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from secrets import token_bytes
from typing import Literal, Protocol
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import AuthenticationError, ConflictError, NotFoundError
from nexusflow.core.ids import uuid7
from nexusflow.core.jsonutil import JSONValue, loads_limited
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.core.text import clean_text
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.ports import NonceStore
from nexusflow.domain.shared.security import SecretCipher, TokenGenerator
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory
from nexusflow.domain.sources.model import RunTrigger, SourceKind, WebhookConfig
from nexusflow.domain.sources.paths import extract_items, map_fields
from nexusflow.domain.sources.service import queue_run
from nexusflow.domain.webhooks.model import (
    EndpointStatus,
    InboundWebhookEvent,
    WebhookEndpoint,
    secret_context,
)
from nexusflow.domain.webhooks.signatures import (
    DELIVERY_HEADER,
    REJECTION_CODE,
    SIGNATURE_HEADER,
    verify_signature,
)

ROTATION_GRACE = timedelta(hours=24)


class DeliveryQuota(Protocol):
    async def consume(self, endpoint_id: UUID) -> None:
        """Count one authenticated delivery; raises ``RateLimitedError`` when spent."""
        ...


@dataclass(frozen=True, slots=True)
class CreatedEndpoint:
    endpoint: WebhookEndpoint
    secret: str  # shown exactly once
    url: str


@dataclass(frozen=True, slots=True)
class ReceiptResult:
    status: Literal["accepted", "duplicate"]
    run_id: UUID | None
    truncated: bool = False  # items beyond the source's max_items were not taken


def _generic_rejection(reason: str) -> AuthenticationError:
    """Indistinguishable from a bad signature: unknown or disabled endpoints
    must not be discoverable by unauthenticated callers."""
    return AuthenticationError(
        "Webhook signature verification failed.", code=REJECTION_CODE, internal_detail=reason
    )


class WebhookService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        cipher: SecretCipher,
        token_generator: TokenGenerator,
        nonces: NonceStore,
        tolerance_seconds: int,
        max_body_bytes: int,
        public_base_url: str,
        quota: DeliveryQuota | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._cipher = cipher
        self._tokens = token_generator
        self._nonces = nonces
        self._tolerance = tolerance_seconds
        self._max_body = max_body_bytes
        self._base_url = public_base_url.rstrip("/")
        self._quota = quota
        # Never matches (random, never stored): only there to cost the same work.
        self._decoy_secret = token_bytes(32)

    def url_for(self, endpoint: WebhookEndpoint) -> str:
        return f"{self._base_url}/api/v1/webhooks/{endpoint.org_id}/{endpoint.id}"

    # ---------------------------------------------------------- management

    async def create_endpoint(
        self, principal: Principal, *, source_id: UUID, name: str, meta: RequestMeta
    ) -> CreatedEndpoint:
        principal.require(Permission.WEBHOOKS_WRITE)
        org_id = principal.require_org()
        now = self._clock.now()
        secret = "whsec_" + self._tokens.generate(32)
        endpoint_id = uuid7()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            source = await uow.data.sources.get(org_id, source_id)
            if source is None:
                raise NotFoundError()
            if source.kind is not SourceKind.WEBHOOK:
                raise ConflictError(
                    "The source is not a webhook source.", code="not_webhook_source"
                )
            endpoint = WebhookEndpoint(
                id=endpoint_id,
                org_id=org_id,
                source_id=source.id,
                name=clean_text(name, max_length=100) or "webhook",
                secret_ciphertext=self._cipher.encrypt(
                    secret, context=secret_context(org_id, endpoint_id)
                ),
                created_by=principal.actor_user_id,
                created_at=now,
                updated_at=now,
            )
            await uow.data.webhook_endpoints.add(endpoint)
            await self._audit.record(
                uow.audit,
                action=AuditAction.WEBHOOK_ENDPOINT_CREATED,
                principal=principal,
                meta=meta,
                resource_type="webhook_endpoint",
                resource_id=endpoint.id,
                metadata={"source_id": str(source.id)},
            )
            await uow.commit()
        return CreatedEndpoint(endpoint=endpoint, secret=secret, url=self.url_for(endpoint))

    async def rotate_secret(
        self, principal: Principal, endpoint_id: UUID, meta: RequestMeta
    ) -> CreatedEndpoint:
        principal.require(Permission.WEBHOOKS_WRITE)
        org_id = principal.require_org()
        now = self._clock.now()
        secret = "whsec_" + self._tokens.generate(32)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            endpoint = await uow.data.webhook_endpoints.get_for_update(org_id, endpoint_id)
            if endpoint is None:
                raise NotFoundError()
            endpoint.previous_secret_ciphertext = endpoint.secret_ciphertext
            endpoint.previous_secret_expires_at = now + ROTATION_GRACE
            endpoint.secret_ciphertext = self._cipher.encrypt(
                secret, context=secret_context(org_id, endpoint.id)
            )
            endpoint.updated_at = now
            await self._audit.record(
                uow.audit,
                action=AuditAction.WEBHOOK_SECRET_ROTATED,
                principal=principal,
                meta=meta,
                resource_type="webhook_endpoint",
                resource_id=endpoint.id,
            )
            await uow.commit()
        return CreatedEndpoint(endpoint=endpoint, secret=secret, url=self.url_for(endpoint))

    async def set_status(
        self, principal: Principal, endpoint_id: UUID, *, status: EndpointStatus, meta: RequestMeta
    ) -> WebhookEndpoint:
        principal.require(Permission.WEBHOOKS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            endpoint = await uow.data.webhook_endpoints.get_for_update(org_id, endpoint_id)
            if endpoint is None:
                raise NotFoundError()
            endpoint.status = status
            endpoint.updated_at = self._clock.now()
            if status is EndpointStatus.DISABLED:
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.WEBHOOK_ENDPOINT_DISABLED,
                    principal=principal,
                    meta=meta,
                    resource_type="webhook_endpoint",
                    resource_id=endpoint.id,
                )
            await uow.commit()
            return endpoint

    async def rewrap(self, org_id: UUID, *, active_key_id: str, batch: int = 500) -> int:
        """Re-encrypt signing secrets under the active KEK (key rotation): every
        endpoint with a secret under an older key, a batch at a time, by id."""
        rewrapped = 0
        after: UUID | None = None
        while True:
            async with self._uow_factory(TenantScope.system(org_id)) as uow:
                endpoints = await uow.data.webhook_endpoints.stale_for_update(
                    org_id, active_key_id, after=after, limit=batch
                )
                for endpoint in endpoints:
                    context = secret_context(org_id, endpoint.id)
                    if self._cipher.needs_rewrap(endpoint.secret_ciphertext):
                        endpoint.secret_ciphertext = self._cipher.rewrap(
                            endpoint.secret_ciphertext, context=context
                        )
                    previous = endpoint.previous_secret_ciphertext
                    if previous is not None and self._cipher.needs_rewrap(previous):
                        endpoint.previous_secret_ciphertext = self._cipher.rewrap(
                            previous, context=context
                        )
                await uow.commit()
            rewrapped += len(endpoints)
            if len(endpoints) < batch:
                return rewrapped
            after = endpoints[-1].id

    async def list_endpoints(
        self, principal: Principal, page: PageRequest
    ) -> Page[WebhookEndpoint]:
        principal.require(Permission.WEBHOOKS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.webhook_endpoints.list_page(principal.require_org(), page)

    # -------------------------------------------------------------- receipt

    async def receive(
        self,
        *,
        org_id: UUID,
        endpoint_id: UUID,
        headers: Mapping[str, str],
        body: bytes,
    ) -> ReceiptResult:
        now = self._clock.now()
        delivery_id = headers.get(DELIVERY_HEADER.lower())
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            # Unlocked read: unauthenticated requests must not take row locks
            # that would queue up legitimate deliveries behind a flood.
            endpoint = await uow.data.webhook_endpoints.get(org_id, endpoint_id)
            if endpoint is None or not endpoint.is_active:
                self._decoy_verification(headers, body, now)
                raise _generic_rejection("endpoint_unknown")
            self._verify(endpoint, headers, delivery_id, body, now)
            if delivery_id is None:  # already rejected by _verify; narrows the type
                raise _generic_rejection("delivery_id_invalid")
            # Everything below runs for authenticated senders only: forged
            # requests learn nothing and cannot use up the sender's quota.
            if self._quota is not None:
                await self._quota.consume(endpoint.id)
            organization = await uow.organizations.get(org_id)
            if (
                organization is None
                or not organization.is_active
                or organization.policy.automation_frozen
            ):
                raise ConflictError("The endpoint is not accepting data.", code="source_inactive")
            namespace = f"webhook:{endpoint.id}"
            fresh = await self._nonces.first_use(
                namespace, delivery_id, ttl_seconds=self._tolerance * 2
            )
            if not fresh:
                return await self._seen_before(uow, endpoint.id, delivery_id)
            try:
                return await self._store(uow, org_id, endpoint_id, delivery_id, body, now)
            except BaseException:
                # "duplicate" must mean "stored": a delivery that failed here
                # has to stay retryable under the same delivery id.
                await self._nonces.release(namespace, delivery_id)
                raise

    async def _seen_before(
        self, uow: UnitOfWork, endpoint_id: UUID, delivery_id: str
    ) -> ReceiptResult:
        if await uow.data.webhook_events.exists(endpoint_id, delivery_id):
            return ReceiptResult(status="duplicate", run_id=None)
        # Claimed by the fast path but not stored (yet): an earlier attempt is
        # still running, or failed without releasing its nonce. Acknowledging it
        # as a duplicate would silently drop the data - ask for a retry instead.
        raise ConflictError(
            "An earlier attempt of this delivery has not completed; retry later.",
            code="delivery_in_progress",
        )

    async def _store(
        self,
        uow: UnitOfWork,
        org_id: UUID,
        endpoint_id: UUID,
        delivery_id: str,
        body: bytes,
        now: datetime,
    ) -> ReceiptResult:
        endpoint = await uow.data.webhook_endpoints.get_for_update(org_id, endpoint_id)
        if endpoint is None or not endpoint.is_active:  # disabled since verification
            raise ConflictError("The endpoint is not accepting data.", code="source_inactive")
        source = await uow.data.sources.get(org_id, endpoint.source_id)
        if source is None or not source.is_runnable:
            raise ConflictError("The target source is not accepting data.", code="source_inactive")
        config = source.parsed_config
        if not isinstance(config, WebhookConfig):
            raise ConflictError(
                "The target source is not a webhook source.", code="not_webhook_source"
            )
        document = loads_limited(body, max_bytes=self._max_body, max_depth=20)
        raw_items, truncated = extract_items(
            document, config.items_path, max_items=config.max_items
        )
        items: list[JSONValue] = [map_fields(item, config.field_mapping) for item in raw_items]
        event = InboundWebhookEvent(
            id=uuid7(),
            org_id=org_id,
            endpoint_id=endpoint.id,
            delivery_id=delivery_id,
            received_at=now,
            payload_sha256=hashlib.sha256(body).hexdigest(),
            payload_size=len(body),
            item_count=len(items),
        )
        # A digest of the whole delivery id: cut to the column's 128 characters,
        # two long ids with a common prefix became one key, and the second
        # delivery was refused as a duplicate for ever.
        run_key = hashlib.sha256(f"{endpoint.id}:{delivery_id}".encode()).hexdigest()
        run = await queue_run(
            uow, source, trigger=RunTrigger.WEBHOOK, idempotency_key=f"wh:{run_key}", now=now
        )
        event.run_id = run.id
        if not await uow.data.webhook_events.add(event):
            # Stored long ago (the fast-path nonce had expired): a true duplicate.
            await uow.rollback()
            return ReceiptResult(status="duplicate", run_id=None)
        await uow.data.payloads.put(org_id, run.id, items, now)
        # Like a sandbox result, the run carries the cut-off: ingestion reports
        # the run truncated (and the sender learns it from the receipt).
        run.stats = {"source_truncated": truncated}
        endpoint.last_received_at = now
        await uow.commit()
        return ReceiptResult(status="accepted", run_id=run.id, truncated=truncated)

    def _verify(
        self,
        endpoint: WebhookEndpoint,
        headers: Mapping[str, str],
        delivery_id: str | None,
        body: bytes,
        now: datetime,
    ) -> None:
        secrets = [self._secret(endpoint, endpoint.secret_ciphertext)]
        if endpoint.previous_secret_valid(now) and endpoint.previous_secret_ciphertext:
            secrets.append(self._secret(endpoint, endpoint.previous_secret_ciphertext))
        verify_signature(
            secrets=secrets,
            header=headers.get(SIGNATURE_HEADER.lower()),
            delivery_id=delivery_id,
            body=body,
            now_timestamp=int(now.timestamp()),
            tolerance_seconds=self._tolerance,
        )

    def _decoy_verification(self, headers: Mapping[str, str], body: bytes, now: datetime) -> None:
        """Do the same parsing and HMAC work as for a real endpoint, so response
        timing does not reveal whether an organization/endpoint pair exists."""
        with contextlib.suppress(AuthenticationError):
            verify_signature(
                secrets=[self._decoy_secret],
                header=headers.get(SIGNATURE_HEADER.lower()),
                delivery_id=headers.get(DELIVERY_HEADER.lower()),
                body=body,
                now_timestamp=int(now.timestamp()),
                tolerance_seconds=self._tolerance,
            )

    def _secret(self, endpoint: WebhookEndpoint, blob: bytes) -> bytes:
        return self._cipher.decrypt(
            blob, context=secret_context(endpoint.org_id, endpoint.id)
        ).encode()

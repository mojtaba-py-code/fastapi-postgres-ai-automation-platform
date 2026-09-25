"""Credential vault use cases."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import ConflictError, InvalidInputError, NotFoundError, PermanentError
from nexusflow.core.ids import uuid7
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.core.text import clean_text, required_name
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.integrations.model import (
    Integration,
    IntegrationKind,
    IntegrationStatus,
    ResolvedCredential,
    encryption_context,
    validate_secret,
)
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.security import SecretCipher, TokenGenerator
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWorkFactory

_LAST_USED_RESOLUTION = timedelta(minutes=5)


class IntegrationUnavailableError(PermanentError):
    default_code = "integration_unavailable"
    default_message = "The referenced integration is revoked, quarantined or missing."


@dataclass(frozen=True, slots=True)
class CreatedIntegration:
    integration: Integration
    generated_secret: str | None  # only for server-generated signing secrets; shown once


def _fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def _hint(secret: str) -> str:
    return "••••" + secret[-4:] if len(secret) >= 12 else "••••"


class IntegrationService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        cipher: SecretCipher,
        token_generator: TokenGenerator,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._cipher = cipher
        self._tokens = token_generator

    async def create(
        self,
        principal: Principal,
        *,
        name: str,
        kind: IntegrationKind,
        secret: str | None,
        metadata: dict[str, Any],
        meta: RequestMeta,
    ) -> CreatedIntegration:
        principal.require(Permission.INTEGRATIONS_WRITE)
        org_id = principal.require_org()
        generated = None
        if kind is IntegrationKind.WEBHOOK_SIGNING and secret is None:
            generated = secret = "whsec_" + self._tokens.generate(32)
        if secret is None:
            raise InvalidInputError(
                "A secret is required for this integration kind.", code="secret_required"
            )
        clean_meta = validate_secret(kind, secret, metadata)
        now = self._clock.now()
        integration_id = uuid7()
        integration = Integration(
            id=integration_id,
            org_id=org_id,
            name=required_name(name, max_length=100),
            kind=kind,
            secret_ciphertext=self._cipher.encrypt(
                secret, context=encryption_context(org_id, integration_id, kind)
            ),
            secret_key_id="",  # nosec B106
            secret_fingerprint=_fingerprint(secret),
            secret_hint=_hint(secret),
            metadata=clean_meta,
            created_by=principal.actor_user_id,
            created_at=now,
            updated_at=now,
        )
        integration.secret_key_id = self._key_id(integration.secret_ciphertext)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            await uow.data.integrations.add(integration)
            await self._audit.record(
                uow.audit,
                action=AuditAction.INTEGRATION_CREATED,
                principal=principal,
                meta=meta,
                resource_type="integration",
                resource_id=integration.id,
                metadata={"kind": kind, "fingerprint": integration.secret_fingerprint},
            )
            await uow.commit()
        return CreatedIntegration(integration=integration, generated_secret=generated)

    async def list(self, principal: Principal, page: PageRequest) -> Page[Integration]:
        principal.require(Permission.INTEGRATIONS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.data.integrations.list_page(principal.require_org(), page)

    async def get(self, principal: Principal, integration_id: UUID) -> Integration:
        principal.require(Permission.INTEGRATIONS_READ)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            integration = await uow.data.integrations.get(principal.require_org(), integration_id)
            if integration is None:
                raise NotFoundError()
            return integration

    async def rotate(
        self,
        principal: Principal,
        integration_id: UUID,
        *,
        secret: str,
        metadata: dict[str, Any] | None,
        meta: RequestMeta,
    ) -> Integration:
        principal.require(Permission.INTEGRATIONS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            integration = await uow.data.integrations.get_for_update(org_id, integration_id)
            if integration is None:
                raise NotFoundError()
            if integration.status is IntegrationStatus.REVOKED:
                raise ConflictError(
                    "Revoked integrations cannot be rotated.", code="integration_revoked"
                )
            clean_meta = validate_secret(
                integration.kind, secret, metadata if metadata is not None else integration.metadata
            )
            now = self._clock.now()
            integration.secret_ciphertext = self._cipher.encrypt(
                secret, context=integration.context
            )
            integration.secret_key_id = self._key_id(integration.secret_ciphertext)
            integration.secret_fingerprint = _fingerprint(secret)
            integration.secret_hint = _hint(secret)
            integration.metadata = clean_meta
            integration.rotated_at = now
            integration.updated_at = now
            await self._audit.record(
                uow.audit,
                action=AuditAction.INTEGRATION_ROTATED,
                principal=principal,
                meta=meta,
                resource_type="integration",
                resource_id=integration.id,
                metadata={"fingerprint": integration.secret_fingerprint},
            )
            await uow.commit()
            return integration

    async def set_status(
        self,
        principal: Principal,
        integration_id: UUID,
        *,
        status: IntegrationStatus,
        reason: str,
        meta: RequestMeta,
    ) -> Integration:
        """Revoke (permanent), quarantine (incident isolation) or reinstate."""
        principal.require(Permission.INTEGRATIONS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            integration = await uow.data.integrations.get_for_update(org_id, integration_id)
            if integration is None:
                raise NotFoundError()
            if integration.status is IntegrationStatus.REVOKED:
                raise ConflictError(
                    "The integration is permanently revoked.", code="integration_revoked"
                )
            integration.status = status
            integration.updated_at = self._clock.now()
            action = {
                IntegrationStatus.REVOKED: AuditAction.INTEGRATION_REVOKED,
                IntegrationStatus.QUARANTINED: AuditAction.INTEGRATION_QUARANTINED,
            }.get(status, AuditAction.INTEGRATION_ROTATED)
            await self._audit.record(
                uow.audit,
                action=action,
                principal=principal,
                meta=meta,
                resource_type="integration",
                resource_id=integration.id,
                metadata={"status": status, "reason": clean_text(reason, max_length=200)},
            )
            await uow.commit()
            return integration

    async def delete(self, principal: Principal, integration_id: UUID, meta: RequestMeta) -> None:
        principal.require(Permission.INTEGRATIONS_WRITE)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            integration = await uow.data.integrations.get_for_update(org_id, integration_id)
            if integration is None:
                raise NotFoundError()
            if await uow.data.integrations.references(org_id, integration_id):
                raise ConflictError(
                    "The integration is still used by sources or channels.",
                    code="integration_in_use",
                )
            await uow.data.integrations.delete(integration)
            await self._audit.record(
                uow.audit,
                action=AuditAction.INTEGRATION_REVOKED,
                principal=principal,
                meta=meta,
                resource_type="integration",
                resource_id=integration_id,
                metadata={"deleted": True},
            )
            await uow.commit()

    # ------------------------------------------------- system (workers only)

    async def resolve(
        self, org_id: UUID, integration_id: UUID, *, allowed: frozenset[IntegrationKind]
    ) -> ResolvedCredential:
        """Decrypt for an outbound call. Fails closed if not active."""
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            integration = await uow.data.integrations.get_for_update(org_id, integration_id)
            if integration is None or not integration.is_usable or integration.kind not in allowed:
                raise IntegrationUnavailableError(internal_detail=f"integration {integration_id}")
            secret = self._cipher.decrypt(
                integration.secret_ciphertext, context=integration.context
            )
            if (
                integration.last_used_at is None
                or now - integration.last_used_at > _LAST_USED_RESOLUTION
            ):
                integration.last_used_at = now
                await uow.commit()
            return ResolvedCredential(
                kind=integration.kind, secret=secret, metadata=dict(integration.metadata)
            )

    async def rewrap(self, org_id: UUID, *, active_key_id: str, batch: int = 100) -> int:
        """Re-encrypt secrets under the active key-encryption key (key rotation)."""
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            stale = await uow.data.integrations.needing_rewrap(org_id, active_key_id, batch)
            for integration in stale:
                integration.secret_ciphertext = self._cipher.rewrap(
                    integration.secret_ciphertext, context=integration.context
                )
                integration.secret_key_id = active_key_id
            await uow.commit()
            return len(stale)

    def _key_id(self, blob: bytes) -> str:
        return self._cipher.key_id_of(blob)

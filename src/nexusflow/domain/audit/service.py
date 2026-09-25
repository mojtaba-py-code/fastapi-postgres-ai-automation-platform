"""Audit trail queries and tenant-facing integrity verification."""

from __future__ import annotations

from uuid import UUID

from nexusflow.core.pagination import Page, PageRequest
from nexusflow.domain.audit.model import (
    PLATFORM_CHAIN,
    AuditLogEntry,
    ChainVerification,
    verify_chain,
)
from nexusflow.domain.audit.ports import AuditFilter
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory

_BATCH = 1000


class AuditService:
    def __init__(
        self, *, uow_factory: UnitOfWorkFactory, max_verify_entries: int = 100_000
    ) -> None:
        self._uow_factory = uow_factory
        self._max_verify_entries = max_verify_entries

    async def list_entries(
        self, principal: Principal, filters: AuditFilter, page: PageRequest
    ) -> Page[AuditLogEntry]:
        principal.require(Permission.AUDIT_READ)
        org_id = principal.require_org()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.audit.list_page(org_id, filters, page)

    async def verify_integrity(
        self, principal: Principal, *, complete: bool = False
    ) -> ChainVerification:
        """Recompute the tenant's hash chain in batches.

        The API bounds the work per request (``max_verify_entries``) and says
        so in the result (``complete=False``); the daily job and the CLI pass
        ``complete=True`` and check the whole chain.
        """
        principal.require(Permission.AUDIT_READ)
        org_id = principal.require_org()
        limit = None if complete else self._max_verify_entries
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await self._verify(uow, org_id, limit)

    async def verify_platform_chain(self) -> ChainVerification:
        """Recompute the whole chain of events without a tenant (job and CLI)."""
        async with self._uow_factory(TenantScope.system(None)) as uow:
            return await self._verify(uow, PLATFORM_CHAIN, None)

    async def _verify(
        self, uow: UnitOfWork, chain_key: UUID, limit: int | None
    ) -> ChainVerification:
        checked = 0
        previous: AuditLogEntry | None = None
        next_seq = 1
        while limit is None or checked < limit:
            batch = await uow.audit.chain(
                chain_key,
                from_seq=next_seq,
                limit=_BATCH if limit is None else min(_BATCH, limit - checked),
            )
            if not batch:
                break
            window = [previous, *batch] if previous is not None else batch
            result = verify_chain(window)
            if not result.ok:
                return ChainVerification(
                    False,
                    checked + max(0, result.checked - (1 if previous else 0)),
                    result.first_invalid_seq,
                    result.reason,
                )
            checked += len(batch)
            previous = batch[-1]
            next_seq = previous.seq + 1
        else:  # stopped at the bound: is there more?
            if await uow.audit.chain(chain_key, from_seq=next_seq, limit=1):
                return ChainVerification(True, checked, complete=False)
        return ChainVerification(True, checked)

    async def anchor(self, org_id: UUID | None) -> tuple[int, str] | None:
        """Latest ``(seq, hash)`` of a tenant chain - or, for ``None``, of the
        platform chain - for external anchoring.

        Shipping these to an independent, append-only log store means a
        database-level rewrite of history (even by a superuser recomputing the
        chain) is detectable by comparing against the anchors.
        """
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            entry = await uow.audit.latest(org_id or PLATFORM_CHAIN)
        return (entry.seq, entry.hash.hex()) if entry is not None else None

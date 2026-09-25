"""Platform service accounts: one credential per n8n workflow.

Service accounts are managed only by platform operators through the CLI -
never through the tenant API. Each n8n workflow gets its own token with the
narrowest scopes it needs, so disabling one account stops exactly one workflow
(the per-workflow kill switch) and a leaked token is limited to its scopes.
Only a keyed hash of the token is stored; the token is shown once.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from nexusflow.core.clock import Clock
from nexusflow.core.errors import ConflictError, InvalidInputError, NotFoundError
from nexusflow.core.ids import uuid7
from nexusflow.core.text import single_line
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal, ServiceScope
from nexusflow.domain.identity.api_keys import CredentialKind, generate_credential
from nexusflow.domain.identity.model import ServiceAccount
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.security import TokenHasher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWorkFactory

_KEY = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")


@dataclass(frozen=True, slots=True)
class IssuedServiceAccount:
    account: ServiceAccount
    token: str  # shown exactly once


def _key(value: str, what: str) -> str:
    if not _KEY.fullmatch(value):
        raise InvalidInputError(f"The {what} must match {_KEY.pattern}.", code="invalid_identifier")
    return value


class ServiceAccountService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        token_hasher: TokenHasher,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._hasher = token_hasher

    async def create(
        self, *, name: str, workflow_key: str, scopes: Iterable[ServiceScope], meta: RequestMeta
    ) -> IssuedServiceAccount:
        granted = sorted({ServiceScope(scope).value for scope in scopes})
        if not granted:
            raise InvalidInputError("At least one scope is required.", code="scopes_required")
        credential = generate_credential(CredentialKind.SERVICE_TOKEN)
        account = ServiceAccount(
            id=uuid7(),
            name=_key(name, "name"),
            workflow_key=_key(workflow_key, "workflow key"),
            key_prefix=credential.prefix,
            key_hash=self._hasher.hash(credential.token),
            scopes=granted,
            created_at=self._clock.now(),
        )
        async with self._uow_factory(TenantScope.auth()) as uow:
            if await uow.service_accounts.get_by_workflow_key(account.workflow_key) is not None:
                raise ConflictError("A service account for this workflow exists.", code="duplicate")
            await uow.service_accounts.add(account)
            await self._audit.record(
                uow.audit,
                action=AuditAction.SERVICE_ACCOUNT_CREATED,
                principal=Principal.system(),
                meta=meta,
                resource_type="service_account",
                resource_id=account.id,
                metadata={"workflow_key": account.workflow_key, "scopes": granted},
            )
            await uow.commit()
        return IssuedServiceAccount(account=account, token=credential.token)

    async def rotate(self, *, workflow_key: str, meta: RequestMeta) -> IssuedServiceAccount:
        """Replace the token; the previous one stops working immediately."""
        credential = generate_credential(CredentialKind.SERVICE_TOKEN)
        async with self._uow_factory(TenantScope.auth()) as uow:
            account = await uow.service_accounts.get_by_workflow_key(workflow_key)
            if account is None:
                raise NotFoundError()
            account.key_prefix = credential.prefix
            account.key_hash = self._hasher.hash(credential.token)
            await self._audit.record(
                uow.audit,
                action=AuditAction.SERVICE_ACCOUNT_ROTATED,
                principal=Principal.system(),
                meta=meta,
                resource_type="service_account",
                resource_id=account.id,
            )
            await uow.commit()
        return IssuedServiceAccount(account=account, token=credential.token)

    async def set_enabled(
        self, *, workflow_key: str, enabled: bool, reason: str | None, meta: RequestMeta
    ) -> ServiceAccount:
        async with self._uow_factory(TenantScope.auth()) as uow:
            account = await uow.service_accounts.get_by_workflow_key(workflow_key)
            if account is None:
                raise NotFoundError()
            account.enabled = enabled
            account.disabled_reason = None if enabled else single_line(reason or "disabled", 200)
            await self._audit.record(
                uow.audit,
                action=AuditAction.SERVICE_ACCOUNT_ENABLED
                if enabled
                else AuditAction.SERVICE_ACCOUNT_DISABLED,
                principal=Principal.system(),
                meta=meta,
                resource_type="service_account",
                resource_id=account.id,
                metadata={"reason": account.disabled_reason},
            )
            await uow.commit()
            return account

    async def list(self) -> list[ServiceAccount]:
        async with self._uow_factory(TenantScope.auth()) as uow:
            return await uow.service_accounts.list_all()

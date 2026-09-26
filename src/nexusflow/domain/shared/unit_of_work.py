"""Unit of Work: one database transaction with tenant context.

A unit of work is always opened with an explicit :class:`TenantScope`. The
infrastructure implementation pins the scope into the PostgreSQL session
(``SET LOCAL app.current_org_id`` / ``app.current_user_id``) so that row-level
security policies isolate tenants *in the database itself*, independent of
application-level filtering. Leaving the block without ``commit()`` rolls back.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING, Protocol, Self
from uuid import UUID

if TYPE_CHECKING:
    from nexusflow.domain.audit.ports import AuditLogRepository
    from nexusflow.domain.authorization.principal import Principal
    from nexusflow.domain.identity.ports import (
        ApiKeyRepository,
        DirectoryUserRepository,
        PasswordResetRepository,
        RecoveryCodeRepository,
        RefreshTokenRepository,
        ScimTokenRepository,
        ServiceAccountRepository,
        SessionRepository,
        SignupRequestRepository,
        SsoConnectionRepository,
        SsoIdentityRepository,
        SsoLoginStateRepository,
        UserRepository,
    )
    from nexusflow.domain.organizations.ports import (
        InvitationRepository,
        MembershipRepository,
        OrganizationRepository,
    )
    from nexusflow.domain.shared.outbox_ports import OutboxRepository
    from nexusflow.domain.shared.repositories import DataRepositories


@dataclass(frozen=True, slots=True)
class TenantScope:
    org_id: UUID | None = None
    user_id: UUID | None = None
    # Authentication lookups (login, token refresh, API-key and invitation
    # resolution) need to find rows before the tenant is known.
    auth_context: bool = False

    @classmethod
    def of(cls, principal: Principal) -> TenantScope:
        return cls(org_id=principal.org_id, user_id=principal.user_id)

    @classmethod
    def auth(cls) -> TenantScope:
        return cls(auth_context=True)

    @classmethod
    def system(cls, org_id: UUID | None) -> TenantScope:
        return cls(org_id=org_id)


class UnitOfWork(Protocol):
    # Read-only properties (covariant) so implementations may expose concrete
    # repository types.
    @property
    def users(self) -> UserRepository: ...

    @property
    def sessions(self) -> SessionRepository: ...

    @property
    def refresh_tokens(self) -> RefreshTokenRepository: ...

    @property
    def password_resets(self) -> PasswordResetRepository: ...

    @property
    def signup_requests(self) -> SignupRequestRepository: ...

    @property
    def recovery_codes(self) -> RecoveryCodeRepository: ...

    @property
    def api_keys(self) -> ApiKeyRepository: ...

    @property
    def service_accounts(self) -> ServiceAccountRepository: ...

    @property
    def organizations(self) -> OrganizationRepository: ...

    @property
    def memberships(self) -> MembershipRepository: ...

    @property
    def invitations(self) -> InvitationRepository: ...

    @property
    def sso_connections(self) -> SsoConnectionRepository: ...

    @property
    def sso_states(self) -> SsoLoginStateRepository: ...

    @property
    def sso_identities(self) -> SsoIdentityRepository: ...

    @property
    def scim_tokens(self) -> ScimTokenRepository: ...

    @property
    def scim_users(self) -> DirectoryUserRepository: ...

    @property
    def audit(self) -> AuditLogRepository: ...

    @property
    def outbox(self) -> OutboxRepository: ...

    @property
    def data(self) -> DataRepositories: ...

    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...

    async def switch_tenant(self, org_id: UUID | None) -> None: ...


class UnitOfWorkFactory(Protocol):
    def __call__(self, scope: TenantScope) -> UnitOfWork: ...

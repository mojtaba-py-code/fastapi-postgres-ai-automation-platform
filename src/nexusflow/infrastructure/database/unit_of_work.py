"""SQLAlchemy Unit of Work with PostgreSQL row-level-security context.

Every transaction started on a :class:`TenantSession` - including the implicit
ones SQLAlchemy begins after a commit - first executes::

    SELECT set_config('app.current_org_id', ..., true),
           set_config('app.current_user_id', ..., true),
           set_config('app.auth_context', ..., true)

``set_config(..., is_local => true)`` scopes the values to the transaction, so
they can never leak to another request through the connection pool. If the
scope is missing, the settings are empty and RLS policies match no tenant rows
(fail-closed).
"""

from __future__ import annotations

from types import TracebackType
from typing import Protocol, Self
from uuid import UUID

from sqlalchemy import Connection, event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session, SessionTransaction

from nexusflow.domain.shared.outbox import OutboxMessage
from nexusflow.domain.shared.unit_of_work import TenantScope
from nexusflow.infrastructure.database.repositories.audit import SqlAuditLogRepository
from nexusflow.infrastructure.database.repositories.data import (
    SqlAlertRepository,
    SqlAlertRuleRepository,
    SqlChangeRepository,
    SqlChannelRepository,
    SqlCollectionRunRepository,
    SqlDatasetRepository,
    SqlDeadLetterRepository,
    SqlDeliveryRepository,
    SqlInsightRepository,
    SqlIntegrationRepository,
    SqlMaintenanceRepository,
    SqlProjectRepository,
    SqlRecordRepository,
    SqlReportRepository,
    SqlRunPayloadRepository,
    SqlSourceRepository,
    SqlSystemQueries,
    SqlUploadRepository,
    SqlWebhookEndpointRepository,
    SqlWebhookEventRepository,
    SqlWorkflowRepository,
    SqlWorkflowRunRepository,
)
from nexusflow.infrastructure.database.repositories.identity import (
    SqlApiKeyRepository,
    SqlInvitationRepository,
    SqlMembershipRepository,
    SqlOrganizationRepository,
    SqlPasswordResetRepository,
    SqlRecoveryCodeRepository,
    SqlRefreshTokenRepository,
    SqlServiceAccountRepository,
    SqlSessionRepository,
    SqlUserRepository,
)
from nexusflow.infrastructure.database.repositories.outbox import SqlOutboxRepository

_SCOPE_KEY = "tenant_scope"
_SET_SCOPE = text(
    "SELECT set_config('app.current_org_id', :org, true), "
    "set_config('app.current_user_id', :user, true), "
    "set_config('app.auth_context', :auth, true)"
)


class TenantSession(Session):
    """Sync session class whose transactions always carry the tenant scope."""


def _scope_params(scope: TenantScope | None) -> dict[str, str]:
    if scope is None:
        return {"org": "", "user": "", "auth": "off"}
    return {
        "org": str(scope.org_id) if scope.org_id else "",
        "user": str(scope.user_id) if scope.user_id else "",
        "auth": "on" if scope.auth_context else "off",
    }


@event.listens_for(TenantSession, "after_begin")
def _apply_scope(session: Session, transaction: SessionTransaction, connection: Connection) -> None:
    connection.execute(_SET_SCOPE, _scope_params(session.info.get(_SCOPE_KEY)))


class OutboxPublisher(Protocol):
    async def publish(self, messages: list[OutboxMessage]) -> None:
        """Best-effort immediate publish of committed messages (relay is the fallback)."""
        ...


class SqlDataRepositories:
    """Business-data repositories sharing the unit of work's session."""

    def __init__(self, session: AsyncSession) -> None:
        self.projects = SqlProjectRepository(session)
        self.datasets = SqlDatasetRepository(session)
        self.integrations = SqlIntegrationRepository(session)
        self.sources = SqlSourceRepository(session)
        self.runs = SqlCollectionRunRepository(session)
        self.payloads = SqlRunPayloadRepository(session)
        self.records = SqlRecordRepository(session)
        self.changes = SqlChangeRepository(session)
        self.insights = SqlInsightRepository(session)
        self.alert_rules = SqlAlertRuleRepository(session)
        self.alerts = SqlAlertRepository(session)
        self.channels = SqlChannelRepository(session)
        self.deliveries = SqlDeliveryRepository(session)
        self.reports = SqlReportRepository(session)
        self.uploads = SqlUploadRepository(session)
        self.webhook_endpoints = SqlWebhookEndpointRepository(session)
        self.webhook_events = SqlWebhookEventRepository(session)
        self.workflows = SqlWorkflowRepository(session)
        self.workflow_runs = SqlWorkflowRunRepository(session)
        self.dead_letters = SqlDeadLetterRepository(session)
        self.system = SqlSystemQueries(session)
        self.maintenance = SqlMaintenanceRepository(session)


class SqlUnitOfWork:
    users: SqlUserRepository
    sessions: SqlSessionRepository
    refresh_tokens: SqlRefreshTokenRepository
    password_resets: SqlPasswordResetRepository
    recovery_codes: SqlRecoveryCodeRepository
    api_keys: SqlApiKeyRepository
    service_accounts: SqlServiceAccountRepository
    organizations: SqlOrganizationRepository
    memberships: SqlMembershipRepository
    invitations: SqlInvitationRepository
    audit: SqlAuditLogRepository
    outbox: SqlOutboxRepository
    data: SqlDataRepositories

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        scope: TenantScope,
        publisher: OutboxPublisher | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._scope = scope
        self._publisher = publisher
        self._session: AsyncSession | None = None

    @property
    def session(self) -> AsyncSession:
        if self._session is None:
            raise RuntimeError("unit of work used outside its context manager")
        return self._session

    @property
    def scope(self) -> TenantScope:
        return self._scope

    async def __aenter__(self) -> Self:
        session = self._session_factory()
        session.info[_SCOPE_KEY] = self._scope
        self._session = session
        self.users = SqlUserRepository(session)
        self.sessions = SqlSessionRepository(session)
        self.refresh_tokens = SqlRefreshTokenRepository(session)
        self.password_resets = SqlPasswordResetRepository(session)
        self.recovery_codes = SqlRecoveryCodeRepository(session)
        self.api_keys = SqlApiKeyRepository(session)
        self.service_accounts = SqlServiceAccountRepository(session)
        self.organizations = SqlOrganizationRepository(session)
        self.memberships = SqlMembershipRepository(session)
        self.invitations = SqlInvitationRepository(session)
        self.audit = SqlAuditLogRepository(session)
        self.outbox = SqlOutboxRepository(session)
        self.data = SqlDataRepositories(session)
        await session.begin()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        session = self.session
        try:
            if exc_type is None:
                # Read-only units of work end with a rollback (never an implicit
                # commit). Detach loaded entities first so the rollback does not
                # expire them - services return them after the transaction ends.
                session.expunge_all()
            if session.in_transaction():
                await session.rollback()
        finally:
            await session.close()
            self._session = None

    async def commit(self) -> None:
        session = self.session
        await session.commit()
        pending = list(self.outbox.added)
        self.outbox.added.clear()
        if pending and self._publisher is not None:
            await self._publisher.publish(pending)

    async def rollback(self) -> None:
        await self.session.rollback()
        self.outbox.added.clear()

    async def switch_tenant(self, org_id: UUID | None) -> None:
        """Re-pin the RLS context (e.g. right after creating a new organization)."""
        self._scope = TenantScope(
            org_id=org_id, user_id=self._scope.user_id, auth_context=self._scope.auth_context
        )
        session = self.session
        session.info[_SCOPE_KEY] = self._scope
        if session.in_transaction():
            await session.flush()
            await session.execute(_SET_SCOPE, _scope_params(self._scope))


class SqlUnitOfWorkFactory:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        publisher: OutboxPublisher | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._publisher = publisher

    def set_publisher(self, publisher: OutboxPublisher | None) -> None:
        self._publisher = publisher

    def __call__(self, scope: TenantScope) -> SqlUnitOfWork:
        return SqlUnitOfWork(self._session_factory, scope, self._publisher)

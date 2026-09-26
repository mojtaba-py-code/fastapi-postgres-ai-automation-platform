"""SQL repositories for identity, tenancy and machine credentials.

Every tenant-scoped query filters by ``org_id`` explicitly *and* runs inside a
transaction whose PostgreSQL row-level-security context is pinned to the same
tenant - two independent layers against cross-tenant access (IDOR).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Table, delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from nexusflow.core.errors import ConflictError
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.domain.authorization.roles import Role
from nexusflow.domain.identity.directory import (
    DirectoryFilter,
    DirectoryFilterField,
    DirectoryUser,
    ScimToken,
)
from nexusflow.domain.identity.model import (
    ApiKey,
    MfaRecoveryCode,
    PasswordResetToken,
    RefreshToken,
    ServiceAccount,
    SignupRequest,
    User,
    UserSession,
)
from nexusflow.domain.identity.sso import SsoConnection, SsoIdentity, SsoLoginState
from nexusflow.domain.organizations.model import (
    Invitation,
    Membership,
    MembershipView,
    Organization,
    OrganizationStatus,
    OrganizationView,
)
from nexusflow.infrastructure.database.pagination import paginate, paginate_rows
from nexusflow.infrastructure.database.tables import identity as t


async def _purge_expired(session: AsyncSession, table: Table, before: datetime, limit: int) -> int:
    """Delete up to ``limit`` rows of ``table`` that expired before ``before``."""
    doomed = select(table.c.id).where(table.c.expires_at < before).limit(limit).scalar_subquery()
    result = await session.execute(
        delete(table).where(table.c.id.in_(doomed)).execution_options(synchronize_session=False)
    )
    return int(getattr(result, "rowcount", 0) or 0)


class SqlUserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def get(self, user_id: UUID) -> User | None:
        return await self._s.get(User, user_id)

    async def get_for_update(self, user_id: UUID) -> User | None:
        return await self._s.get(User, user_id, with_for_update=True, populate_existing=True)

    async def get_by_email(self, email: str, *, for_update: bool = False) -> User | None:
        statement = select(User).where(t.users.c.email == email)
        if for_update:
            statement = statement.with_for_update().execution_options(populate_existing=True)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def add(self, user: User) -> None:
        self._s.add(user)
        try:
            await self._s.flush()  # deterministic insert order (no ORM relationships)
        except IntegrityError as exc:  # the same address, signed up at the same moment
            raise ConflictError(
                "An account with this e-mail address already exists.",
                code="account_exists",
                internal_detail=str(exc.orig)[:300],
            ) from exc


class SqlSessionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def get(self, session_id: UUID) -> UserSession | None:
        return await self._s.get(UserSession, session_id)

    async def get_for_update(self, session_id: UUID) -> UserSession | None:
        return await self._s.get(
            UserSession, session_id, with_for_update=True, populate_existing=True
        )

    async def add(self, session: UserSession) -> None:
        self._s.add(session)
        await self._s.flush()  # deterministic insert order (no ORM relationships)

    async def list_recent_for_user(self, user_id: UUID, *, since: datetime) -> list[UserSession]:
        statement = (
            select(UserSession)
            .where(t.user_sessions.c.user_id == user_id, t.user_sessions.c.created_at >= since)
            .order_by(t.user_sessions.c.created_at.desc())
            .limit(50)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def list_active_for_user(
        self, user_id: UUID, *, now: datetime, limit: int, sso_org_id: UUID | None = None
    ) -> list[UserSession]:
        s = t.user_sessions
        statement = (
            select(UserSession)
            .where(s.c.user_id == user_id, s.c.revoked_at.is_(None), s.c.expires_at > now)
            .order_by(s.c.last_used_at.desc())
            .limit(limit)
        )
        if sso_org_id is not None:
            statement = statement.where(s.c.sso_org_id == sso_org_id)
        return list((await self._s.execute(statement)).scalars().all())

    async def revoke_all_for_user(
        self,
        user_id: UUID,
        *,
        now: datetime,
        reason: str,
        except_session: UUID | None = None,
        sso_org_id: UUID | None = None,
    ) -> int:
        statement = (
            update(t.user_sessions)
            .where(t.user_sessions.c.user_id == user_id, t.user_sessions.c.revoked_at.is_(None))
            .values(revoked_at=now, revoke_reason=reason)
        )
        if except_session is not None:
            statement = statement.where(t.user_sessions.c.id != except_session)
        if sso_org_id is not None:
            statement = statement.where(t.user_sessions.c.sso_org_id == sso_org_id)
        result = await self._s.execute(statement.execution_options(synchronize_session=False))
        return int(getattr(result, "rowcount", 0) or 0)

    async def revoke_sso_sessions(self, org_id: UUID, *, now: datetime, reason: str) -> int:
        s = t.user_sessions
        result = await self._s.execute(
            update(s)
            .where(s.c.sso_org_id == org_id, s.c.revoked_at.is_(None))
            .values(revoked_at=now, revoke_reason=reason)
            .execution_options(synchronize_session=False)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def list_for_user(self, user_id: UUID, *, limit: int) -> list[UserSession]:
        statement = (
            select(UserSession)
            .where(t.user_sessions.c.user_id == user_id)
            .order_by(t.user_sessions.c.created_at.desc())
            .limit(limit)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def purge_expired(self, before: datetime, *, limit: int) -> int:
        return await _purge_expired(self._s, t.user_sessions, before, limit)


class SqlRefreshTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, token: RefreshToken) -> None:
        self._s.add(token)
        await self._s.flush()  # deterministic insert order (no ORM relationships)

    async def get_by_hash_for_update(self, token_hash: str) -> RefreshToken | None:
        statement = (
            select(RefreshToken)
            .where(t.refresh_tokens.c.token_hash == token_hash)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def purge_expired(self, before: datetime, *, limit: int) -> int:
        return await _purge_expired(self._s, t.refresh_tokens, before, limit)


class SqlPasswordResetRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, token: PasswordResetToken) -> None:
        self._s.add(token)
        await self._s.flush()  # deterministic insert order (no ORM relationships)

    async def get(self, token_id: UUID) -> PasswordResetToken | None:
        return await self._s.get(PasswordResetToken, token_id)

    async def get_by_hash_for_update(self, token_hash: str) -> PasswordResetToken | None:
        statement = (
            select(PasswordResetToken)
            .where(t.password_reset_tokens.c.token_hash == token_hash)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def purge_expired(self, before: datetime, *, limit: int) -> int:
        return await _purge_expired(self._s, t.password_reset_tokens, before, limit)

    async def invalidate_for_user(self, user_id: UUID, *, now: datetime) -> None:
        await self._s.execute(
            update(t.password_reset_tokens)
            .where(
                t.password_reset_tokens.c.user_id == user_id,
                t.password_reset_tokens.c.used_at.is_(None),
            )
            .values(used_at=now)
            .execution_options(synchronize_session=False)
        )


class SqlSignupRequestRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, request: SignupRequest) -> None:
        self._s.add(request)
        await self._s.flush()  # deterministic insert order (no ORM relationships)

    async def get(self, request_id: UUID) -> SignupRequest | None:
        return await self._s.get(SignupRequest, request_id)

    async def get_by_hash(self, token_hash: str) -> SignupRequest | None:
        statement = select(SignupRequest).where(t.signup_requests.c.token_hash == token_hash)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def lock_for_email(self, email: str) -> list[SignupRequest]:
        statement = (
            select(SignupRequest)
            .where(t.signup_requests.c.email == email)
            .order_by(t.signup_requests.c.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def purge_expired(self, before: datetime, *, limit: int) -> int:
        return await _purge_expired(self._s, t.signup_requests, before, limit)


class SqlRecoveryCodeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def replace_for_user(self, user_id: UUID, codes: list[MfaRecoveryCode]) -> None:
        await self.delete_for_user(user_id)
        self._s.add_all(codes)
        await self._s.flush()  # deterministic insert order (no ORM relationships)

    async def find_unused(self, user_id: UUID, code_hash: str) -> MfaRecoveryCode | None:
        statement = (
            select(MfaRecoveryCode)
            .where(
                t.mfa_recovery_codes.c.user_id == user_id,
                t.mfa_recovery_codes.c.code_hash == code_hash,
                t.mfa_recovery_codes.c.used_at.is_(None),
            )
            .with_for_update()
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def delete_for_user(self, user_id: UUID) -> None:
        await self._s.execute(
            delete(t.mfa_recovery_codes)
            .where(t.mfa_recovery_codes.c.user_id == user_id)
            .execution_options(synchronize_session=False)
        )


class SqlApiKeyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, key: ApiKey) -> None:
        self._s.add(key)
        await self._s.flush()  # deterministic insert order (no ORM relationships)

    async def get(self, org_id: UUID, key_id: UUID) -> ApiKey | None:
        statement = select(ApiKey).where(t.api_keys.c.org_id == org_id, t.api_keys.c.id == key_id)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def find_by_prefix(self, prefix: str) -> ApiKey | None:
        statement = select(ApiKey).where(t.api_keys.c.key_prefix == prefix)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def revoke_created_by(self, org_id: UUID, user_id: UUID, *, now: datetime) -> int:
        keys = t.api_keys
        statement = (
            update(keys)
            .where(
                keys.c.org_id == org_id,
                keys.c.created_by == user_id,
                keys.c.revoked_at.is_(None),
            )
            .values(revoked_at=now)
            .execution_options(synchronize_session=False)
            .returning(keys.c.id)
        )
        return len((await self._s.execute(statement)).all())

    async def list_created_by(self, org_id: UUID, user_id: UUID, limit: int) -> list[ApiKey]:
        statement = (
            select(ApiKey)
            .where(t.api_keys.c.org_id == org_id, t.api_keys.c.created_by == user_id)
            .order_by(t.api_keys.c.created_at.desc())
            .limit(limit)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def list_page(self, org_id: UUID, page: PageRequest) -> Page[ApiKey]:
        return await paginate(
            self._s,
            select(ApiKey).where(t.api_keys.c.org_id == org_id),
            page=page,
            sort_columns={"created_at": t.api_keys.c.created_at, "name": t.api_keys.c.name},
            id_column=t.api_keys.c.id,
            key=lambda k: (k.created_at if page.sort.field == "created_at" else k.name, k.id),
        )


class SqlServiceAccountRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, account: ServiceAccount) -> None:
        self._s.add(account)
        await self._s.flush()  # deterministic insert order (no ORM relationships)

    async def find_by_prefix(self, prefix: str) -> ServiceAccount | None:
        statement = select(ServiceAccount).where(t.service_accounts.c.key_prefix == prefix)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def get_by_workflow_key(self, workflow_key: str) -> ServiceAccount | None:
        statement = select(ServiceAccount).where(t.service_accounts.c.workflow_key == workflow_key)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def list_all(self) -> list[ServiceAccount]:
        statement = select(ServiceAccount).order_by(t.service_accounts.c.name)
        return list((await self._s.execute(statement)).scalars().all())


class SqlOrganizationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, org: Organization) -> None:
        self._s.add(org)
        await self._s.flush()  # deterministic insert order (no ORM relationships)

    async def get(self, org_id: UUID) -> Organization | None:
        return await self._s.get(Organization, org_id)

    async def get_for_update(self, org_id: UUID) -> Organization | None:
        return await self._s.get(Organization, org_id, with_for_update=True, populate_existing=True)

    async def slug_exists(self, slug: str) -> bool:
        statement = (
            select(func.count()).select_from(t.organizations).where(t.organizations.c.slug == slug)
        )
        return bool((await self._s.execute(statement)).scalar_one())

    async def get_by_slug(self, slug: str) -> Organization | None:
        statement = select(Organization).where(t.organizations.c.slug == slug)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def list_for_user(self, user_id: UUID) -> list[OrganizationView]:
        o, m = t.organizations, t.memberships
        statement = (
            select(o.c.id, o.c.name, o.c.slug, o.c.status, m.c.role)
            .join(m, m.c.org_id == o.c.id)
            .where(m.c.user_id == user_id)
            .order_by(o.c.name)
        )
        rows = (await self._s.execute(statement)).all()
        return [
            OrganizationView(
                org_id=row.id,
                name=row.name,
                slug=row.slug,
                role=Role(row.role),
                status=OrganizationStatus(row.status),
            )
            for row in rows
        ]


class SqlMembershipRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, membership: Membership) -> None:
        self._s.add(membership)
        await self._s.flush()  # deterministic insert order (no ORM relationships)

    async def get(self, org_id: UUID, user_id: UUID) -> Membership | None:
        statement = select(Membership).where(
            t.memberships.c.org_id == org_id, t.memberships.c.user_id == user_id
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def get_by_id(self, org_id: UUID, membership_id: UUID) -> Membership | None:
        statement = (
            select(Membership)
            .where(t.memberships.c.org_id == org_id, t.memberships.c.id == membership_id)
            .with_for_update()
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def list_views(self, org_id: UUID, page: PageRequest) -> Page[MembershipView]:
        m, u = t.memberships, t.users
        statement = (
            select(
                m.c.id,
                m.c.user_id,
                m.c.role,
                m.c.created_at,
                u.c.email,
                u.c.full_name,
                u.c.mfa_enabled,
            )
            .join(u, u.c.id == m.c.user_id)
            .where(m.c.org_id == org_id)
        )
        return await paginate_rows(
            self._s,
            statement,
            page=page,
            sort_columns={"created_at": m.c.created_at},
            id_column=m.c.id,
            convert=lambda row: MembershipView(
                membership_id=row.id,
                user_id=row.user_id,
                email=row.email,
                full_name=row.full_name,
                role=Role(row.role),
                mfa_enabled=row.mfa_enabled,
                joined_at=row.created_at,
            ),
            key=lambda view: (view.joined_at, view.membership_id),
        )

    async def count_owners(self, org_id: UUID) -> int:
        statement = (
            select(func.count())
            .select_from(t.memberships)
            .where(t.memberships.c.org_id == org_id, t.memberships.c.role == Role.OWNER.value)
        )
        return int((await self._s.execute(statement)).scalar_one())

    async def delete(self, membership: Membership) -> None:
        await self._s.delete(membership)

    async def first_for_user(self, user_id: UUID) -> Membership | None:
        statement = (
            select(Membership)
            .where(t.memberships.c.user_id == user_id)
            .order_by(t.memberships.c.created_at)
            .limit(1)
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def list_org_ids_for_user(self, user_id: UUID) -> list[UUID]:
        statement = select(t.memberships.c.org_id).where(t.memberships.c.user_id == user_id)
        return list((await self._s.execute(statement)).scalars().all())


class SqlInvitationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, invitation: Invitation) -> None:
        self._s.add(invitation)
        await self._s.flush()  # deterministic insert order (no ORM relationships)

    async def get(self, org_id: UUID, invitation_id: UUID) -> Invitation | None:
        statement = select(Invitation).where(
            t.invitations.c.org_id == org_id, t.invitations.c.id == invitation_id
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def find_pending_by_email(self, org_id: UUID, email: str) -> Invitation | None:
        statement = select(Invitation).where(
            t.invitations.c.org_id == org_id,
            t.invitations.c.email == email,
            t.invitations.c.accepted_at.is_(None),
            t.invitations.c.revoked_at.is_(None),
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def find_by_token_hash(self, token_hash: str) -> Invitation | None:
        # No FOR UPDATE: row locks require the UPDATE policy, which only matches
        # once the tenant is known. Double acceptance is prevented by the unique
        # (org_id, user_id) membership constraint instead.
        statement = select(Invitation).where(t.invitations.c.token_hash == token_hash)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def list_pending(self, org_id: UUID, page: PageRequest) -> Page[Invitation]:
        return await paginate(
            self._s,
            select(Invitation).where(
                t.invitations.c.org_id == org_id,
                t.invitations.c.accepted_at.is_(None),
                t.invitations.c.revoked_at.is_(None),
            ),
            page=page,
            sort_columns={"created_at": t.invitations.c.created_at},
            id_column=t.invitations.c.id,
            key=lambda i: (i.created_at, i.id),
        )


# ------------------------------------------------------------ single sign-on


class SqlSsoConnectionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, connection: SsoConnection) -> None:
        self._s.add(connection)
        try:
            await self._s.flush()
        except IntegrityError as exc:  # one connection per organization
            raise ConflictError(
                "Single sign-on is already configured.",
                code="duplicate",
                internal_detail=str(exc.orig)[:300],
            ) from exc

    async def get_for_org(self, org_id: UUID, *, for_update: bool = False) -> SsoConnection | None:
        statement = select(SsoConnection).where(t.sso_connections.c.org_id == org_id)
        if for_update:
            statement = statement.with_for_update().execution_options(populate_existing=True)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def delete(self, connection: SsoConnection) -> None:
        await self._s.delete(connection)
        await self._s.flush()

    async def needing_rewrap(
        self, org_id: UUID, active_key_id: str, limit: int
    ) -> list[SsoConnection]:
        c = t.sso_connections
        statement = (
            select(SsoConnection)
            .where(c.c.org_id == org_id, c.c.secret_key_id != active_key_id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return list((await self._s.execute(statement)).scalars().all())

    async def count_needing_rewrap(self, org_id: UUID, active_key_id: str) -> int:
        c = t.sso_connections
        statement = (
            select(func.count())
            .select_from(c)
            .where(c.c.org_id == org_id, c.c.secret_key_id != active_key_id)
        )
        return int((await self._s.execute(statement)).scalar_one())


class SqlSsoLoginStateRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, state: SsoLoginState) -> None:
        self._s.add(state)
        await self._s.flush()

    async def find_by_hash(self, state_hash: str) -> SsoLoginState | None:
        statement = select(SsoLoginState).where(t.sso_login_states.c.state_hash == state_hash)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def consume(self, org_id: UUID, state_id: UUID, *, now: datetime) -> bool:
        s = t.sso_login_states
        result = await self._s.execute(
            update(s)
            .where(
                s.c.org_id == org_id,
                s.c.id == state_id,
                s.c.used_at.is_(None),
                s.c.expires_at > now,
            )
            .values(used_at=now)
            .returning(s.c.id)
            .execution_options(synchronize_session=False)
        )
        return result.first() is not None

    async def delete_for_org(self, org_id: UUID) -> int:
        result = await self._s.execute(
            delete(t.sso_login_states)
            .where(t.sso_login_states.c.org_id == org_id)
            .execution_options(synchronize_session=False)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def purge_expired(self, before: datetime, *, limit: int) -> int:
        return await _purge_expired(self._s, t.sso_login_states, before, limit)


class SqlSsoIdentityRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, identity: SsoIdentity) -> None:
        self._s.add(identity)
        try:
            await self._s.flush()
        except IntegrityError as exc:  # a concurrent sign-in linked it first
            raise ConflictError(
                "The identity is already linked.",
                code="identity_conflict",
                internal_detail=str(exc.orig)[:300],
            ) from exc

    async def find_by_subject(self, org_id: UUID, issuer: str, subject: str) -> SsoIdentity | None:
        i = t.sso_identities
        statement = select(SsoIdentity).where(
            i.c.org_id == org_id, i.c.issuer == issuer, i.c.subject == subject
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def find_for_user(self, org_id: UUID, issuer: str, user_id: UUID) -> SsoIdentity | None:
        i = t.sso_identities
        statement = select(SsoIdentity).where(
            i.c.org_id == org_id, i.c.issuer == issuer, i.c.user_id == user_id
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def delete_for_org(self, org_id: UUID) -> int:
        result = await self._s.execute(
            delete(t.sso_identities)
            .where(t.sso_identities.c.org_id == org_id)
            .execution_options(synchronize_session=False)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def delete_for_user(self, user_id: UUID) -> int:
        result = await self._s.execute(
            delete(t.sso_identities)
            .where(t.sso_identities.c.user_id == user_id)
            .execution_options(synchronize_session=False)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def list_for_user(self, user_id: UUID, limit: int) -> list[SsoIdentity]:
        i = t.sso_identities
        statement = (
            select(SsoIdentity)
            .where(i.c.user_id == user_id)
            .order_by(i.c.created_at.desc())
            .limit(limit)
        )
        return list((await self._s.execute(statement)).scalars().all())


# ------------------------------------------------------------ SCIM provisioning


class SqlScimTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, token: ScimToken) -> None:
        self._s.add(token)
        await self._s.flush()

    async def get(self, org_id: UUID, token_id: UUID) -> ScimToken | None:
        s = t.scim_tokens
        statement = select(ScimToken).where(s.c.org_id == org_id, s.c.id == token_id)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def find_by_prefix(self, prefix: str) -> ScimToken | None:
        statement = select(ScimToken).where(t.scim_tokens.c.token_prefix == prefix)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def list_for_org(self, org_id: UUID) -> list[ScimToken]:
        s = t.scim_tokens
        statement = (
            select(ScimToken)
            .where(s.c.org_id == org_id)
            .order_by(s.c.created_at.desc(), s.c.id.desc())
            .limit(200)
        )
        return list((await self._s.execute(statement)).scalars().all())


# Past this offset a SCIM page is empty anyway; larger values would not fit OFFSET.
_MAX_OFFSET = 2_000_000_000


class SqlDirectoryUserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, user: DirectoryUser) -> None:
        self._s.add(user)
        try:
            await self._s.flush()
        except IntegrityError as exc:  # the same person or externalId, provisioned at once
            raise ConflictError(
                "The user is already provisioned.",
                code="uniqueness",
                internal_detail=str(exc.orig)[:300],
            ) from exc

    async def get(
        self, org_id: UUID, record_id: UUID, *, for_update: bool = False
    ) -> DirectoryUser | None:
        u = t.scim_users
        statement = select(DirectoryUser).where(u.c.org_id == org_id, u.c.id == record_id)
        if for_update:
            statement = statement.with_for_update().execution_options(populate_existing=True)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def get_by_user(self, org_id: UUID, user_id: UUID) -> DirectoryUser | None:
        u = t.scim_users
        statement = select(DirectoryUser).where(u.c.org_id == org_id, u.c.user_id == user_id)
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def get_by_external_id(self, org_id: UUID, external_id: str) -> DirectoryUser | None:
        u = t.scim_users
        statement = select(DirectoryUser).where(
            u.c.org_id == org_id, u.c.external_id == external_id
        )
        return (await self._s.execute(statement)).scalar_one_or_none()

    async def list_page(
        self,
        org_id: UUID,
        *,
        directory_filter: DirectoryFilter | None,
        offset: int,
        limit: int,
    ) -> tuple[int, list[DirectoryUser]]:
        u = t.scim_users
        conditions = [u.c.org_id == org_id]
        if directory_filter is not None:
            if directory_filter.field is DirectoryFilterField.EXTERNAL_ID:
                conditions.append(u.c.external_id == directory_filter.value)
            else:  # userName and emails.value: the account's address, in any case
                conditions.append(u.c.user_name == directory_filter.value.lower())
        counted = await self._s.execute(select(func.count()).select_from(u).where(*conditions))
        total = int(counted.scalar_one())
        if limit <= 0 or offset >= total:
            return total, []
        statement = (
            select(DirectoryUser)
            .where(*conditions)
            .order_by(u.c.created_at, u.c.id)
            .offset(min(offset, _MAX_OFFSET))
            .limit(limit)
        )
        return total, list((await self._s.execute(statement)).scalars().all())

    async def delete(self, user: DirectoryUser) -> None:
        await self._s.delete(user)
        await self._s.flush()

    async def delete_for_user(self, user_id: UUID) -> int:
        result = await self._s.execute(
            delete(t.scim_users)
            .where(t.scim_users.c.user_id == user_id)
            .execution_options(synchronize_session=False)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def list_for_user(self, user_id: UUID, limit: int) -> list[DirectoryUser]:
        u = t.scim_users
        statement = (
            select(DirectoryUser)
            .where(u.c.user_id == user_id)
            .order_by(u.c.created_at.desc())
            .limit(limit)
        )
        return list((await self._s.execute(statement)).scalars().all())

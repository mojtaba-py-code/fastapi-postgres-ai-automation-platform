"""Repository and service ports for the identity context."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from nexusflow.core.pagination import Page, PageRequest
from nexusflow.domain.identity.directory import DirectoryFilter, DirectoryUser, ScimToken
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


class UserRepository(Protocol):
    async def get(self, user_id: UUID) -> User | None: ...

    async def get_for_update(self, user_id: UUID) -> User | None: ...

    async def get_by_email(self, email: str, *, for_update: bool = False) -> User | None: ...

    async def add(self, user: User) -> None: ...


class SessionRepository(Protocol):
    async def get(self, session_id: UUID) -> UserSession | None: ...

    async def get_for_update(self, session_id: UUID) -> UserSession | None: ...

    async def add(self, session: UserSession) -> None: ...

    async def list_recent_for_user(
        self, user_id: UUID, *, since: datetime
    ) -> list[UserSession]: ...

    async def list_active_for_user(
        self, user_id: UUID, *, now: datetime, limit: int, sso_org_id: UUID | None = None
    ) -> list[UserSession]:
        """Live sessions, most recently used first; with ``sso_org_id``, only the
        sessions that organization's identity provider opened."""
        ...

    async def revoke_all_for_user(
        self,
        user_id: UUID,
        *,
        now: datetime,
        reason: str,
        except_session: UUID | None = None,
        sso_org_id: UUID | None = None,
    ) -> int: ...

    async def revoke_sso_sessions(self, org_id: UUID, *, now: datetime, reason: str) -> int:
        """End every session an organization's identity provider opened."""
        ...

    async def list_for_user(self, user_id: UUID, *, limit: int) -> list[UserSession]:
        """Every session still kept, ended ones too, newest first."""
        ...

    async def purge_expired(self, before: datetime, *, limit: int) -> int:
        """Delete up to ``limit`` sessions that expired before ``before`` (their
        refresh tokens go with them); returns how many."""
        ...


class RefreshTokenRepository(Protocol):
    async def add(self, token: RefreshToken) -> None: ...

    async def get_by_hash_for_update(self, token_hash: str) -> RefreshToken | None: ...

    async def purge_expired(self, before: datetime, *, limit: int) -> int: ...


class PasswordResetRepository(Protocol):
    async def add(self, token: PasswordResetToken) -> None: ...

    async def get(self, token_id: UUID) -> PasswordResetToken | None: ...

    async def get_by_hash_for_update(self, token_hash: str) -> PasswordResetToken | None: ...

    async def invalidate_for_user(self, user_id: UUID, *, now: datetime) -> None: ...

    async def purge_expired(self, before: datetime, *, limit: int) -> int: ...


class SignupRequestRepository(Protocol):
    async def add(self, request: SignupRequest) -> None: ...

    async def get(self, request_id: UUID) -> SignupRequest | None: ...

    async def get_by_hash(self, token_hash: str) -> SignupRequest | None: ...

    async def lock_for_email(self, email: str) -> list[SignupRequest]:
        """Every request for the address, locked in one order (no deadlocks)."""
        ...

    async def purge_expired(self, before: datetime, *, limit: int) -> int: ...


class RecoveryCodeRepository(Protocol):
    async def replace_for_user(self, user_id: UUID, codes: list[MfaRecoveryCode]) -> None: ...

    async def find_unused(self, user_id: UUID, code_hash: str) -> MfaRecoveryCode | None: ...

    async def delete_for_user(self, user_id: UUID) -> None: ...


class ApiKeyRepository(Protocol):
    async def add(self, key: ApiKey) -> None: ...

    async def get(self, org_id: UUID, key_id: UUID) -> ApiKey | None: ...

    async def find_by_prefix(self, prefix: str) -> ApiKey | None: ...

    async def list_page(self, org_id: UUID, page: PageRequest) -> Page[ApiKey]: ...

    async def list_created_by(self, org_id: UUID, user_id: UUID, limit: int) -> list[ApiKey]: ...

    async def revoke_created_by(self, org_id: UUID, user_id: UUID, *, now: datetime) -> int:
        """Revoke every live key a member created in this org; returns the count."""
        ...


class ServiceAccountRepository(Protocol):
    async def add(self, account: ServiceAccount) -> None: ...

    async def find_by_prefix(self, prefix: str) -> ServiceAccount | None: ...

    async def get_by_workflow_key(self, workflow_key: str) -> ServiceAccount | None: ...

    async def list_all(self) -> list[ServiceAccount]: ...


class SsoConnectionRepository(Protocol):
    async def add(self, connection: SsoConnection) -> None: ...

    async def get_for_org(
        self, org_id: UUID, *, for_update: bool = False
    ) -> SsoConnection | None: ...

    async def delete(self, connection: SsoConnection) -> None: ...

    async def needing_rewrap(
        self, org_id: UUID, active_key_id: str, limit: int
    ) -> list[SsoConnection]: ...

    async def count_needing_rewrap(self, org_id: UUID, active_key_id: str) -> int: ...


class SsoLoginStateRepository(Protocol):
    async def add(self, state: SsoLoginState) -> None: ...

    async def find_by_hash(self, state_hash: str) -> SsoLoginState | None:
        """Authentication context: the tenant is not known yet."""
        ...

    async def consume(self, org_id: UUID, state_id: UUID, *, now: datetime) -> bool:
        """Mark a live state used; False when it was used or expired already
        (one statement: two callbacks cannot both consume it)."""
        ...

    async def delete_for_org(self, org_id: UUID) -> int: ...

    async def purge_expired(self, before: datetime, *, limit: int) -> int: ...


class SsoIdentityRepository(Protocol):
    async def add(self, identity: SsoIdentity) -> None: ...

    async def find_by_subject(
        self, org_id: UUID, issuer: str, subject: str
    ) -> SsoIdentity | None: ...

    async def find_for_user(self, org_id: UUID, issuer: str, user_id: UUID) -> SsoIdentity | None:
        """The user's identity at this organization's provider, if linked."""
        ...

    async def delete_for_org(self, org_id: UUID) -> int: ...

    async def delete_for_user(self, user_id: UUID) -> int: ...

    async def list_for_user(self, user_id: UUID, limit: int) -> list[SsoIdentity]: ...


class ScimTokenRepository(Protocol):
    async def add(self, token: ScimToken) -> None: ...

    async def get(self, org_id: UUID, token_id: UUID) -> ScimToken | None: ...

    async def find_by_prefix(self, prefix: str) -> ScimToken | None:
        """Authentication context: the tenant is not known yet."""
        ...

    async def list_for_org(self, org_id: UUID) -> list[ScimToken]: ...


class DirectoryUserRepository(Protocol):
    async def add(self, user: DirectoryUser) -> None: ...

    async def get(
        self, org_id: UUID, record_id: UUID, *, for_update: bool = False
    ) -> DirectoryUser | None: ...

    async def get_by_user(self, org_id: UUID, user_id: UUID) -> DirectoryUser | None: ...

    async def get_by_external_id(self, org_id: UUID, external_id: str) -> DirectoryUser | None: ...

    async def list_page(
        self,
        org_id: UUID,
        *,
        directory_filter: DirectoryFilter | None,
        offset: int,
        limit: int,
    ) -> tuple[int, list[DirectoryUser]]:
        """The total that match, and one page of them (oldest first)."""
        ...

    async def delete(self, user: DirectoryUser) -> None: ...

    async def delete_for_user(self, user_id: UUID) -> int: ...

    async def list_for_user(self, user_id: UUID, limit: int) -> list[DirectoryUser]: ...


class TotpVerifier(Protocol):
    def generate_secret(self) -> str: ...

    def provisioning_uri(self, secret: str, *, account_name: str, issuer: str) -> str: ...

    def verify(
        self, secret: str, code: str, *, now: datetime, last_used_step: int | None
    ) -> int | None: ...

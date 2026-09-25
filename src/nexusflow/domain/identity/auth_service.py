"""Authentication use cases: registration, login (+MFA), refresh rotation,
logout, password change/reset and MFA enrollment.

Security design notes
---------------------
* **No user enumeration** on login and password reset: identical responses and
  comparable timing (dummy Argon2 verification for unknown accounts).
* **Brute force**: per-account counters with exponential lockout (in addition
  to Redis rate limits at the edge). The user row is locked ``FOR UPDATE``
  while counters change, so concurrent attempts cannot race the counter.
* **Refresh-token rotation with reuse detection**: every refresh token is
  single-use. Presenting an already-used token means the token family leaked;
  the whole session is revoked and the user is notified.
* **Revocation**: sessions are checked on every request, and ``token_version``
  invalidates every access token after password changes or "log out everywhere".
* Only keyed hashes of opaque tokens are stored.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import (
    AuthenticationError,
    ConflictError,
    InvalidInputError,
    NotFoundError,
    PermissionDeniedError,
)
from nexusflow.core.ids import uuid7
from nexusflow.core.jsonutil import JSONObject
from nexusflow.core.text import clean_text, slugify
from nexusflow.domain.audit.model import AuditAction, AuditResult
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Role
from nexusflow.domain.identity.authenticator import network_not_allowed
from nexusflow.domain.identity.login_risk import (
    LoginAssessment,
    LoginRisk,
    SignInDetails,
    assess_login,
    sign_in_details,
)
from nexusflow.domain.identity.model import (
    MfaRecoveryCode,
    PasswordResetToken,
    RefreshToken,
    User,
    UserSession,
)
from nexusflow.domain.identity.password_policy import PasswordPolicy
from nexusflow.domain.identity.ports import TotpVerifier
from nexusflow.domain.identity.tokens import TokenCodec
from nexusflow.domain.organizations.model import Membership, Organization
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.security import (
    PasswordHasher,
    SecretCipher,
    TokenGenerator,
    TokenHasher,
)
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory

_INVALID_CREDENTIALS = "Invalid email or password."
_RECOVERY_CODE_COUNT = 10
_FAMILIARITY_WINDOW = timedelta(days=90)  # sign-ins a new one is compared with
_MAX_LISTED_SESSIONS = 100


@dataclass(frozen=True, slots=True)
class AuthPolicy:
    access_ttl_seconds: int
    refresh_ttl_seconds: int
    session_absolute_ttl_seconds: int
    lockout_threshold: int
    lockout_base_seconds: int
    lockout_max_seconds: int
    password_reset_ttl_seconds: int
    signup_enabled: bool
    mfa_issuer: str
    password: PasswordPolicy


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
    expires_in: int
    org_id: UUID | None
    token_type: str = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    # How familiar the sign-in looked (monitoring only; never sent to the client).
    login_risk: LoginRisk | None = None


@dataclass(frozen=True, slots=True)
class LoginResult:
    tokens: TokenPair | None = None
    mfa_challenge: str | None = None
    mfa_challenge_expires_in: int | None = None


@dataclass(frozen=True, slots=True)
class MfaEnrollment:
    secret: str
    provisioning_uri: str


def normalize_email(email: str) -> str:
    return clean_text(email, max_length=254).lower()


class AuthService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        password_hasher: PasswordHasher,
        token_codec: TokenCodec,
        token_hasher: TokenHasher,
        token_generator: TokenGenerator,
        cipher: SecretCipher,
        totp: TotpVerifier,
        audit: AuditRecorder,
        policy: AuthPolicy,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._hasher = password_hasher
        self._codec = token_codec
        self._token_hasher = token_hasher
        self._tokens = token_generator
        self._cipher = cipher
        self._totp = totp
        self._audit = audit
        self._policy = policy

    # ------------------------------------------------------------ registration

    async def register(
        self,
        *,
        email: str,
        password: str,
        full_name: str,
        organization_name: str | None,
        invitation_token: str | None,
        meta: RequestMeta,
    ) -> TokenPair:
        if not self._policy.signup_enabled and invitation_token is None:
            raise PermissionDeniedError("Self-service sign-up is disabled.", code="signup_disabled")
        email_n = normalize_email(email)
        name = clean_text(full_name, max_length=120)
        if not name:
            raise InvalidInputError("Full name is required.", code="name_required")
        self._policy.password.validate(password, email=email_n, name=name)
        password_hash = await self._hasher.hash(password)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.auth()) as uow:
            if await uow.users.get_by_email(email_n) is not None:
                raise ConflictError(
                    "An account with this email already exists.", code="email_taken"
                )
            user = User(
                id=uuid7(),
                email=email_n,
                password_hash=password_hash,
                full_name=name,
                password_changed_at=now,
                created_at=now,
                updated_at=now,
            )
            await uow.users.add(user)
            if invitation_token is not None:
                org_id, role = await self._join_via_invitation(uow, user, invitation_token, now)
            else:
                org_id, role = await self._create_organization(uow, user, organization_name, now)
            await uow.switch_tenant(org_id)
            principal = Principal.for_user(
                user_id=user.id, org_id=org_id, role=role, session_id=None
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.REGISTERED,
                principal=principal,
                meta=meta,
                resource_type="user",
                resource_id=user.id,
            )
            if invitation_token is None:
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.ORG_CREATED,
                    principal=principal,
                    meta=meta,
                    resource_type="organization",
                    resource_id=org_id,
                )
            tokens = await self._start_session(uow, user, org_id, meta, now, mfa_verified=False)
            await uow.commit()
        return tokens

    async def _create_organization(
        self, uow: UnitOfWork, user: User, organization_name: str | None, now: datetime
    ) -> tuple[UUID, Role]:
        name = clean_text(organization_name or "", max_length=120)
        if not name:
            raise InvalidInputError("Organization name is required.", code="organization_required")
        slug = await self._unique_slug(uow, name)
        org = Organization(id=uuid7(), name=name, slug=slug, created_at=now, updated_at=now)
        await uow.switch_tenant(org.id)
        await uow.organizations.add(org)
        await uow.memberships.add(
            Membership(
                id=uuid7(),
                org_id=org.id,
                user_id=user.id,
                role=Role.OWNER,
                created_at=now,
                updated_at=now,
            )
        )
        return org.id, Role.OWNER

    async def _join_via_invitation(
        self, uow: UnitOfWork, user: User, token: str, now: datetime
    ) -> tuple[UUID, Role]:
        invitation = await uow.invitations.find_by_token_hash(self._token_hasher.hash(token))
        if invitation is None or not invitation.is_pending(now) or invitation.email != user.email:
            raise InvalidInputError(
                "The invitation is invalid or has expired.", code="invalid_invitation"
            )
        await uow.switch_tenant(invitation.org_id)
        invitation.accepted_at = now
        await uow.memberships.add(
            Membership(
                id=uuid7(),
                org_id=invitation.org_id,
                user_id=user.id,
                role=invitation.role,
                invited_by=invitation.invited_by,
                created_at=now,
                updated_at=now,
            )
        )
        return invitation.org_id, invitation.role

    async def _unique_slug(self, uow: UnitOfWork, name: str) -> str:
        base = slugify(name, max_length=50) or "org"
        candidate = base
        for _ in range(5):
            if not await uow.organizations.slug_exists(candidate):
                return candidate
            candidate = f"{base}-{secrets.token_hex(3)}"
        raise ConflictError("Could not allocate an organization slug.", code="slug_unavailable")

    # ------------------------------------------------------------------ login

    async def login(
        self, *, email: str, password: str, org_id: UUID | None, meta: RequestMeta
    ) -> LoginResult:
        email_n = normalize_email(email)
        now = self._clock.now()
        # 1. Read without a row lock. The deliberately slow hash below must never
        #    run while an unauthenticated request holds a lock and a pooled
        #    connection - a login flood would otherwise starve every tenant.
        async with self._uow_factory(TenantScope.auth()) as uow:
            snapshot = await uow.users.get_by_email(email_n)
            checked_hash = (
                snapshot.password_hash
                if snapshot is not None and snapshot.is_active and not snapshot.is_locked(now)
                else None
            )
        # 2. Verify outside any transaction; unknown, inactive and locked accounts
        #    cost the same work, so response timing reveals nothing.
        if checked_hash is None:
            await self._hasher.dummy_verify(password)
            verified = False
        else:
            verified = await self._hasher.verify(checked_hash, password)
        upgraded_hash = (
            await self._hasher.hash(password)
            if verified and checked_hash is not None and self._hasher.needs_rehash(checked_hash)
            else None
        )
        # 3. Apply the outcome under the row lock, re-checking what may have
        #    changed in between (a concurrent lockout, a password change).
        async with self._uow_factory(TenantScope.auth()) as uow:
            user = await uow.users.get_by_email(email_n, for_update=True)
            if user is None or not user.is_active or user.is_locked(now):
                reason = (
                    "unknown_account"
                    if user is None
                    else ("locked" if user.is_locked(now) else "inactive")
                )
                await self._record_failure(uow, user, email_n, reason, meta)
                await uow.commit()
                raise AuthenticationError(_INVALID_CREDENTIALS, code="invalid_credentials")
            if user.password_hash != checked_hash:
                # The password changed while this attempt was being verified.
                raise AuthenticationError(_INVALID_CREDENTIALS, code="invalid_credentials")
            if not verified:
                locked = user.register_failed_login(
                    now,
                    threshold=self._policy.lockout_threshold,
                    base_seconds=self._policy.lockout_base_seconds,
                    max_seconds=self._policy.lockout_max_seconds,
                )
                await self._record_failure(uow, user, email_n, "bad_password", meta)
                if locked:
                    await self._on_lockout(uow, user, meta)
                await uow.commit()
                raise AuthenticationError(_INVALID_CREDENTIALS, code="invalid_credentials")
            if upgraded_hash is not None:
                user.password_hash = upgraded_hash
            if user.mfa_enabled:
                # The counter restarts for the second factor; the failures so far
                # travel in the (signed) challenge to the risk assessment.
                prior_failures = user.failed_login_attempts
                user.failed_login_attempts = 0
                challenge = self._codec.issue_mfa_challenge(
                    user_id=user.id, org_id=org_id, now=now, prior_failures=prior_failures
                )
                await uow.commit()
                return LoginResult(
                    mfa_challenge=challenge.token, mfa_challenge_expires_in=challenge.expires_in
                )
            tokens = await self._complete_login(uow, user, org_id, meta, now, mfa_verified=False)
            await uow.commit()
        return LoginResult(tokens=tokens)

    async def verify_mfa(self, *, challenge_token: str, code: str, meta: RequestMeta) -> TokenPair:
        now = self._clock.now()
        claims = self._codec.decode_mfa_challenge(challenge_token, now=now)
        async with self._uow_factory(TenantScope.auth()) as uow:
            user = await uow.users.get_for_update(claims.user_id)
            if user is None or not user.is_active or user.is_locked(now) or not user.mfa_enabled:
                raise AuthenticationError("Verification failed.", code="mfa_failed")
            if not await self._check_second_factor(uow, user, code, now, meta):
                locked = user.register_failed_login(
                    now,
                    threshold=self._policy.lockout_threshold,
                    base_seconds=self._policy.lockout_base_seconds,
                    max_seconds=self._policy.lockout_max_seconds,
                )
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.MFA_FAILED,
                    principal=None,
                    meta=meta,
                    result=AuditResult.FAILURE,
                    actor_id=user.id,
                    resource_type="user",
                    resource_id=user.id,
                )
                if locked:
                    await self._on_lockout(uow, user, meta)
                await uow.commit()
                raise AuthenticationError("Verification failed.", code="mfa_failed")
            tokens = await self._complete_login(
                uow,
                user,
                claims.org_id,
                meta,
                now,
                mfa_verified=True,
                prior_failures=claims.prior_failures,
            )
            await uow.commit()
        return tokens

    async def _check_second_factor(
        self, uow: UnitOfWork, user: User, code: str, now: datetime, meta: RequestMeta
    ) -> bool:
        candidate = code.strip()
        if len(candidate) == 6 and candidate.isdigit():
            secret = self._decrypt_mfa_secret(user, user.mfa_secret_encrypted)
            step = self._totp.verify(
                secret, candidate, now=now, last_used_step=user.mfa_last_used_step
            )
            if step is None:
                return False
            user.mfa_last_used_step = step
            blob = user.mfa_secret_encrypted
            if blob is not None and self._cipher.needs_rewrap(blob):
                # Lazy key rotation: re-encrypt under the active KEK on use.
                user.mfa_secret_encrypted = self._cipher.rewrap(blob, context=_mfa_context(user.id))
            return True
        recovery = await uow.recovery_codes.find_unused(
            user.id, self._token_hasher.hash(_normalize_recovery_code(candidate))
        )
        if recovery is None:
            return False
        recovery.used_at = now
        await self._audit.record(
            uow.audit,
            action=AuditAction.MFA_RECOVERY_USED,
            principal=None,
            meta=meta,
            actor_id=user.id,
            resource_type="user",
            resource_id=user.id,
        )
        await self._notify(uow, user, "mfa_recovery_code_used", now)
        return True

    async def _complete_login(
        self,
        uow: UnitOfWork,
        user: User,
        requested_org: UUID | None,
        meta: RequestMeta,
        now: datetime,
        *,
        mfa_verified: bool,
        prior_failures: int = 0,
    ) -> TokenPair:
        org_id, role = await self._resolve_login_org(uow, user, requested_org, meta)
        # Before the success resets the failure counters the assessment looks at.
        assessment = await self._assess_login(uow, user, meta, now, prior_failures)
        user.register_successful_login(now)
        await uow.switch_tenant(org_id)
        principal = Principal.for_user(user_id=user.id, org_id=org_id, role=role, session_id=None)
        await self._audit.record(
            uow.audit,
            action=AuditAction.LOGIN_SUCCEEDED,
            principal=principal,
            meta=meta,
            resource_type="user",
            resource_id=user.id,
            metadata={
                "mfa": mfa_verified,
                "risk": assessment.risk.value,
                "signals": list(assessment.signals),
            },
        )
        if assessment.risk is not LoginRisk.FAMILIAR:
            suspicious = assessment.risk is LoginRisk.SUSPICIOUS
            await self._audit.record(
                uow.audit,
                action=AuditAction.LOGIN_SUSPICIOUS if suspicious else AuditAction.LOGIN_NEW_DEVICE,
                principal=principal,
                meta=meta,
                resource_type="user",
                resource_id=user.id,
                metadata={"signals": list(assessment.signals)},
            )
            await self._notify(
                uow,
                user,
                "suspicious_login" if suspicious else "new_device_login",
                now,
                sign_in=sign_in_details(at=now, ip=meta.ip, user_agent=meta.user_agent),
            )
        tokens = await self._start_session(uow, user, org_id, meta, now, mfa_verified=mfa_verified)
        return replace(tokens, login_risk=assessment.risk)

    async def _resolve_login_org(
        self, uow: UnitOfWork, user: User, requested: UUID | None, meta: RequestMeta
    ) -> tuple[UUID | None, Role | None]:
        """The organization the new session opens in.

        An organization's network allowlist is enforced here too: signing in to
        it by name from elsewhere is refused; when it was only the default, the
        session starts without an organization - the account stays reachable,
        the organization's data does not.
        """
        if requested is not None:
            await uow.switch_tenant(requested)
            membership = await uow.memberships.get(requested, user.id)
            org = await uow.organizations.get(requested) if membership else None
            if membership is None or org is None or not org.is_active:
                raise AuthenticationError(_INVALID_CREDENTIALS, code="invalid_credentials")
            if not org.policy.allows_ip(meta.ip):
                await self._record_network_denied(uow, user.id, membership, meta, via="sign_in")
                await uow.commit()
                raise network_not_allowed(f"org={org.id} credential=user:{user.id} ip={meta.ip}")
            return requested, membership.role
        membership = await uow.memberships.first_for_user(user.id)
        if membership is None:
            return None, None
        await uow.switch_tenant(membership.org_id)
        org = await uow.organizations.get(membership.org_id)
        if org is not None and not org.policy.allows_ip(meta.ip):
            await self._record_network_denied(uow, user.id, membership, meta, via="sign_in")
            return None, None
        return membership.org_id, membership.role

    async def _record_network_denied(
        self,
        uow: UnitOfWork,
        user_id: UUID,
        membership: Membership,
        meta: RequestMeta,
        *,
        via: str,
    ) -> None:
        """Tell the organization a member's valid credentials came from outside."""
        await self._audit.record(
            uow.audit,
            action=AuditAction.NETWORK_ACCESS_DENIED,
            principal=Principal.for_user(
                user_id=user_id, org_id=membership.org_id, role=membership.role, session_id=None
            ),
            meta=meta,
            result=AuditResult.DENIED,
            resource_type="organization",
            resource_id=membership.org_id,
            metadata={"via": via},
        )

    async def _assess_login(
        self,
        uow: UnitOfWork,
        user: User,
        meta: RequestMeta,
        now: datetime,
        prior_failures: int = 0,
    ) -> LoginAssessment:
        recent = await uow.sessions.list_recent_for_user(user.id, since=now - _FAMILIARITY_WINDOW)
        return assess_login(
            ip=meta.ip,
            user_agent=meta.user_agent,
            history=[(session.ip, session.user_agent) for session in recent],
            # With MFA, wrong passwords before the challenge plus wrong codes after it.
            failed_attempts=user.failed_login_attempts + prior_failures,
            lockouts=user.lockout_count,
        )

    async def _start_session(
        self,
        uow: UnitOfWork,
        user: User,
        org_id: UUID | None,
        meta: RequestMeta,
        now: datetime,
        *,
        mfa_verified: bool,
    ) -> TokenPair:
        session = UserSession(
            id=uuid7(),
            user_id=user.id,
            org_id=org_id,
            created_at=now,
            last_used_at=now,
            expires_at=now + timedelta(seconds=self._policy.session_absolute_ttl_seconds),
            ip=meta.ip,
            user_agent=meta.user_agent,
            mfa_verified=mfa_verified,
        )
        await uow.sessions.add(session)
        return await self._issue_tokens(uow, user, session, now)

    async def _issue_tokens(
        self, uow: UnitOfWork, user: User, session: UserSession, now: datetime
    ) -> TokenPair:
        raw_refresh = self._tokens.generate(32)
        expires = min(now + timedelta(seconds=self._policy.refresh_ttl_seconds), session.expires_at)
        await uow.refresh_tokens.add(
            RefreshToken(
                id=uuid7(),
                session_id=session.id,
                user_id=user.id,
                token_hash=self._token_hasher.hash(raw_refresh),
                issued_at=now,
                expires_at=expires,
            )
        )
        access = self._codec.issue_access_token(
            user_id=user.id,
            org_id=session.org_id,
            session_id=session.id,
            token_version=user.token_version,
            now=now,
        )
        return TokenPair(
            access_token=access.token,
            refresh_token=raw_refresh,
            expires_in=access.expires_in,
            org_id=session.org_id,
        )

    async def _record_failure(
        self, uow: UnitOfWork, user: User | None, email: str, reason: str, meta: RequestMeta
    ) -> None:
        # Store a keyed hash of the attempted identifier instead of the raw
        # value: people regularly type passwords into the email field.
        identifier = self._token_hasher.hash(f"login:{email}")[:16]
        await self._audit.record(
            uow.audit,
            action=AuditAction.LOGIN_FAILED,
            principal=None,
            meta=meta,
            result=AuditResult.FAILURE,
            actor_id=user.id if user else None,
            resource_type="user",
            resource_id=user.id if user else None,
            metadata={"reason": reason, "identifier_hash": identifier},
        )

    async def _on_lockout(self, uow: UnitOfWork, user: User, meta: RequestMeta) -> None:
        await self._audit.record(
            uow.audit,
            action=AuditAction.LOGIN_LOCKED,
            principal=None,
            meta=meta,
            result=AuditResult.DENIED,
            actor_id=user.id,
            resource_type="user",
            resource_id=user.id,
            metadata={"locked_until": user.locked_until.isoformat() if user.locked_until else None},
        )
        await self._notify(uow, user, "account_locked", self._clock.now())

    # ----------------------------------------------------------------- refresh

    async def refresh(self, *, refresh_token: str, meta: RequestMeta) -> TokenPair:
        now = self._clock.now()
        invalid = AuthenticationError("The refresh token is invalid.", code="invalid_refresh_token")
        if not refresh_token or len(refresh_token) > 256:
            raise invalid
        async with self._uow_factory(TenantScope.auth()) as uow:
            token = await uow.refresh_tokens.get_by_hash_for_update(
                self._token_hasher.hash(refresh_token)
            )
            if token is None:
                raise invalid
            session = await uow.sessions.get_for_update(token.session_id)
            if session is None or not session.is_valid(now):
                raise invalid
            user = await uow.users.get(token.user_id)
            if token.used_at is not None:
                await self._handle_reuse(uow, session, user, meta, now)
                await uow.commit()
                raise invalid
            if token.expires_at <= now or user is None or not user.is_active:
                raise invalid
            if session.org_id is not None:
                await uow.switch_tenant(session.org_id)
                if await uow.memberships.get(session.org_id, user.id) is None:
                    session.org_id = None
            token.used_at = now
            session.last_used_at = now
            tokens = await self._issue_tokens(uow, user, session, now)
            await uow.commit()
        return tokens

    async def _handle_reuse(
        self,
        uow: UnitOfWork,
        session: UserSession,
        user: User | None,
        meta: RequestMeta,
        now: datetime,
    ) -> None:
        """A rotated (single-use) token came back: treat the family as stolen."""
        session.revoke(now, "refresh_token_reuse")
        await self._audit.record(
            uow.audit,
            action=AuditAction.REFRESH_REUSE_DETECTED,
            principal=None,
            meta=meta,
            result=AuditResult.DENIED,
            actor_id=session.user_id,
            resource_type="session",
            resource_id=session.id,
        )
        if user is not None:
            await self._notify(uow, user, "session_revoked_token_reuse", now)

    # ------------------------------------------------------------------ logout

    async def logout(self, principal: Principal, meta: RequestMeta) -> None:
        if principal.session_id is None or principal.user_id is None:
            return
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            session = await uow.sessions.get_for_update(principal.session_id)
            if session is not None:
                session.revoke(now, "logout")
            await self._audit.record(
                uow.audit,
                action=AuditAction.LOGOUT,
                principal=principal,
                meta=meta,
                resource_type="session",
                resource_id=principal.session_id,
            )
            await uow.commit()

    async def list_sessions(self, principal: Principal) -> list[UserSession]:
        """The caller's live sign-in sessions, most recently used first."""
        user_id = _require_session(principal)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.sessions.list_active_for_user(
                user_id, now=self._clock.now(), limit=_MAX_LISTED_SESSIONS
            )

    async def revoke_session(
        self, principal: Principal, session_id: UUID, meta: RequestMeta
    ) -> None:
        """End one of the caller's sessions: its tokens stop working at once."""
        user_id = _require_session(principal)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            session = await uow.sessions.get_for_update(session_id)
            if session is None or session.user_id != user_id:
                raise NotFoundError()  # another user's session does not exist for you
            session.revoke(now, "revoked_by_user")
            await self._audit.record(
                uow.audit,
                action=AuditAction.SESSION_REVOKED,
                principal=principal,
                meta=meta,
                resource_type="session",
                resource_id=session_id,
                metadata={"current": session_id == principal.session_id},
            )
            await uow.commit()

    async def logout_everywhere(self, principal: Principal, meta: RequestMeta) -> None:
        user_id = _require_user(principal)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get_for_update(user_id)
            if user is None:
                raise NotFoundError()
            user.revoke_all_tokens(now)
            await uow.sessions.revoke_all_for_user(user.id, now=now, reason="logout_all")
            await self._audit.record(
                uow.audit,
                action=AuditAction.LOGOUT_ALL,
                principal=principal,
                meta=meta,
                resource_type="user",
                resource_id=user.id,
            )
            await uow.commit()

    async def switch_organization(
        self, principal: Principal, org_id: UUID, meta: RequestMeta
    ) -> TokenPair:
        user_id = _require_user(principal)
        if principal.session_id is None:
            raise PermissionDeniedError()
        now = self._clock.now()
        async with self._uow_factory(TenantScope(org_id=org_id, user_id=user_id)) as uow:
            membership = await uow.memberships.get(org_id, user_id)
            org = await uow.organizations.get(org_id) if membership else None
            user = await uow.users.get(user_id)
            session = await uow.sessions.get_for_update(principal.session_id)
            if membership is None or org is None or user is None or session is None:
                raise NotFoundError()
            if not org.is_active:
                raise PermissionDeniedError("The organization is not active.", code="org_inactive")
            if org.policy.require_mfa and not session.mfa_verified:
                raise PermissionDeniedError(
                    "This organization requires multi-factor authentication.", code="mfa_required"
                )
            if not org.policy.allows_ip(meta.ip):
                await self._record_network_denied(uow, user_id, membership, meta, via="switch")
                await uow.commit()
                raise network_not_allowed(f"org={org_id} credential=user:{user_id} ip={meta.ip}")
            session.org_id = org_id
            session.last_used_at = now
            await self._audit.record(
                uow.audit,
                action=AuditAction.ORG_SWITCHED,
                principal=principal,
                meta=meta,
                org_id=org_id,
                resource_type="organization",
                resource_id=org_id,
            )
            tokens = await self._issue_tokens(uow, user, session, now)
            await uow.commit()
        return tokens

    # ---------------------------------------------------------------- password

    async def change_password(
        self, principal: Principal, *, current_password: str, new_password: str, meta: RequestMeta
    ) -> TokenPair:
        user_id = _require_user(principal)
        now = self._clock.now()
        # 1. Read, then hash outside any row lock (hashing is deliberately slow).
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get(user_id)
            if user is None:
                raise NotFoundError()
            if user.is_locked(now):
                raise _account_locked()
            checked_hash, email, name = user.password_hash, user.email, user.full_name
        verified = await self._hasher.verify(checked_hash, current_password)
        new_hash: str | None = None
        if verified:
            if current_password == new_password:
                raise InvalidInputError(
                    "Choose a password you have not used here.", code="password_reused"
                )
            self._policy.password.validate(new_password, email=email, name=name)
            new_hash = await self._hasher.hash(new_password)
        # 2. Apply under the lock, re-checking what may have changed in between.
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get_for_update(user_id)
            session = (
                await uow.sessions.get_for_update(principal.session_id)
                if principal.session_id
                else None
            )
            if user is None or session is None:
                raise NotFoundError()
            if new_hash is None or user.password_hash != checked_hash:
                # A wrong current password counts like a failed sign-in: whoever
                # holds a stolen access token cannot use this to guess it.
                locked = user.register_failed_login(
                    now,
                    threshold=self._policy.lockout_threshold,
                    base_seconds=self._policy.lockout_base_seconds,
                    max_seconds=self._policy.lockout_max_seconds,
                )
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.PASSWORD_CHANGE_FAILED,
                    principal=principal,
                    meta=meta,
                    result=AuditResult.FAILURE,
                    resource_type="user",
                    resource_id=user.id,
                )
                if locked:
                    await self._on_lockout(uow, user, meta)
                await uow.commit()
                raise _wrong_password()
            user.change_password_hash(new_hash, now)
            await uow.sessions.revoke_all_for_user(
                user.id, now=now, reason="password_changed", except_session=session.id
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.PASSWORD_CHANGED,
                principal=principal,
                meta=meta,
                resource_type="user",
                resource_id=user.id,
            )
            await self._notify(uow, user, "password_changed", now)
            tokens = await self._issue_tokens(uow, user, session, now)
            await uow.commit()
        return tokens

    async def request_password_reset(self, *, email: str, meta: RequestMeta) -> None:
        """Always succeeds from the caller's perspective (no account enumeration)."""
        now = self._clock.now()
        async with self._uow_factory(TenantScope.auth()) as uow:
            user = await uow.users.get_by_email(normalize_email(email))
            if user is None or not user.is_active:
                return
            await uow.password_resets.invalidate_for_user(user.id, now=now)
            reset = PasswordResetToken(
                id=uuid7(),
                user_id=user.id,
                token_hash=None,  # generated by the mail worker; never leaves it in clear
                created_at=now,
                expires_at=now + timedelta(seconds=self._policy.password_reset_ttl_seconds),
                requested_ip=meta.ip,
            )
            await uow.password_resets.add(reset)
            await self._audit.record(
                uow.audit,
                action=AuditAction.PASSWORD_RESET_REQUESTED,
                principal=None,
                meta=meta,
                actor_id=user.id,
                resource_type="user",
                resource_id=user.id,
            )
            await uow.outbox.add(
                new_message(
                    TaskName.SEND_PASSWORD_RESET, {"reset_id": str(reset.id)}, org_id=None, now=now
                )
            )
            await uow.commit()

    async def reset_password(self, *, token: str, new_password: str, meta: RequestMeta) -> None:
        now = self._clock.now()
        invalid = InvalidInputError(
            "The reset link is invalid or has expired.", code="invalid_token"
        )
        if not token or len(token) > 256:
            raise invalid
        async with self._uow_factory(TenantScope.auth()) as uow:
            reset = await uow.password_resets.get_by_hash_for_update(self._token_hasher.hash(token))
            if reset is None or not reset.is_usable(now):
                raise invalid
            user = await uow.users.get_for_update(reset.user_id)
            if user is None or not user.is_active:
                raise invalid
            self._policy.password.validate(new_password, email=user.email, name=user.full_name)
            user.change_password_hash(await self._hasher.hash(new_password), now)
            user.locked_until = None
            reset.used_at = now
            await uow.sessions.revoke_all_for_user(user.id, now=now, reason="password_reset")
            await self._audit.record(
                uow.audit,
                action=AuditAction.PASSWORD_RESET_COMPLETED,
                principal=None,
                meta=meta,
                actor_id=user.id,
                resource_type="user",
                resource_id=user.id,
            )
            await self._notify(uow, user, "password_changed", now)
            await uow.commit()

    # --------------------------------------------------------------------- mfa

    async def begin_mfa_enrollment(
        self, principal: Principal, *, password: str, meta: RequestMeta
    ) -> MfaEnrollment:
        user_id = _require_session(principal)
        verified = await self.confirm_password(principal, password, meta, purpose="mfa_enrollment")
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get_for_update(user_id)
            if user is None:
                raise NotFoundError()
            if user.password_hash != verified:  # changed since it was confirmed
                raise _wrong_password()
            if user.mfa_enabled:
                raise ConflictError(
                    "Multi-factor authentication is already enabled.", code="mfa_enabled"
                )
            secret = self._totp.generate_secret()
            user.mfa_pending_secret_encrypted = self._cipher.encrypt(
                secret, context=_mfa_context(user.id)
            )
            user.updated_at = now
            await uow.commit()
        return MfaEnrollment(
            secret=secret,
            provisioning_uri=self._totp.provisioning_uri(
                secret, account_name=user.email, issuer=self._policy.mfa_issuer
            ),
        )

    async def confirm_mfa_enrollment(
        self, principal: Principal, *, code: str, meta: RequestMeta
    ) -> list[str]:
        """Activate MFA and return one-time recovery codes (shown exactly once)."""
        user_id = _require_session(principal)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get_for_update(user_id)
            if user is None or user.mfa_pending_secret_encrypted is None:
                raise ConflictError("Start MFA enrollment first.", code="mfa_not_started")
            secret = self._decrypt_mfa_secret(user, user.mfa_pending_secret_encrypted)
            step = self._totp.verify(secret, code, now=now, last_used_step=None)
            if step is None:
                raise InvalidInputError("The verification code is incorrect.", code="invalid_code")
            user.mfa_secret_encrypted = user.mfa_pending_secret_encrypted
            user.mfa_pending_secret_encrypted = None
            user.mfa_enabled = True
            user.mfa_last_used_step = step
            user.updated_at = now
            codes = [_generate_recovery_code() for _ in range(_RECOVERY_CODE_COUNT)]
            await uow.recovery_codes.replace_for_user(
                user.id,
                [
                    MfaRecoveryCode(
                        id=uuid7(),
                        user_id=user.id,
                        created_at=now,
                        code_hash=self._token_hasher.hash(_normalize_recovery_code(c)),
                    )
                    for c in codes
                ],
            )
            await self._audit.record(
                uow.audit,
                action=AuditAction.MFA_ENABLED,
                principal=principal,
                meta=meta,
                resource_type="user",
                resource_id=user.id,
            )
            await self._notify(uow, user, "mfa_enabled", now)
            await uow.commit()
        return codes

    async def disable_mfa(
        self, principal: Principal, *, password: str, code: str, meta: RequestMeta
    ) -> None:
        user_id = _require_session(principal)
        verified = await self.confirm_password(principal, password, meta, purpose="mfa_disable")
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get_for_update(user_id)
            if user is None or not user.mfa_enabled:
                raise ConflictError(
                    "Multi-factor authentication is not enabled.", code="mfa_disabled"
                )
            if user.password_hash != verified:  # changed since it was confirmed
                raise _wrong_password()
            if not await self._check_second_factor(uow, user, code, now, meta):
                # A wrong code counts toward lockout as at sign-in.
                locked = self._register_failure(user, now)
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.MFA_FAILED,
                    principal=principal,
                    meta=meta,
                    result=AuditResult.FAILURE,
                    resource_type="user",
                    resource_id=user.id,
                )
                if locked:
                    await self._on_lockout(uow, user, meta)
                await uow.commit()
                raise InvalidInputError("The verification code is incorrect.", code="invalid_code")
            user.mfa_enabled = False
            user.mfa_secret_encrypted = None
            user.mfa_last_used_step = None
            user.revoke_all_tokens(now)
            await uow.recovery_codes.delete_for_user(user.id)
            await uow.sessions.revoke_all_for_user(user.id, now=now, reason="mfa_disabled")
            await self._audit.record(
                uow.audit,
                action=AuditAction.MFA_DISABLED,
                principal=principal,
                meta=meta,
                resource_type="user",
                resource_id=user.id,
            )
            await self._notify(uow, user, "mfa_disabled", now)
            await uow.commit()

    async def confirm_password(
        self, principal: Principal, password: str, meta: RequestMeta, *, purpose: str
    ) -> str:
        """Check the account password before a sensitive action, like a sign-in.

        Only from a signed-in session (a leaked API key is no password oracle
        for its creator's account); a locked account is refused; a wrong
        password counts toward the lockout and is audited; the deliberately
        slow hash never runs under the row lock. Returns the hash that was
        verified, so the caller can check it is still the account's password
        when it applies the action.
        """
        user_id = _require_session(principal)
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get(user_id)
            if user is None:
                raise NotFoundError()
            if user.is_locked(now):
                raise _account_locked()
            checked_hash = user.password_hash
        if await self._hasher.verify(checked_hash, password):
            return checked_hash
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get_for_update(user_id)
            if user is None:
                raise NotFoundError()
            locked = self._register_failure(user, now)
            await self._audit.record(
                uow.audit,
                action=AuditAction.PASSWORD_CONFIRMATION_FAILED,
                principal=principal,
                meta=meta,
                result=AuditResult.FAILURE,
                resource_type="user",
                resource_id=user.id,
                metadata={"purpose": purpose},
            )
            if locked:
                await self._on_lockout(uow, user, meta)
            await uow.commit()
        raise _wrong_password()

    # ----------------------------------------------------------------- helpers

    def _register_failure(self, user: User, now: datetime) -> bool:
        return user.register_failed_login(
            now,
            threshold=self._policy.lockout_threshold,
            base_seconds=self._policy.lockout_base_seconds,
            max_seconds=self._policy.lockout_max_seconds,
        )

    def _decrypt_mfa_secret(self, user: User, blob: bytes | None) -> str:
        if blob is None:
            raise AuthenticationError("Verification failed.", code="mfa_failed")
        return self._cipher.decrypt(blob, context=_mfa_context(user.id))

    async def _notify(
        self,
        uow: UnitOfWork,
        user: User,
        template: str,
        now: datetime,
        *,
        sign_in: SignInDetails | None = None,
    ) -> None:
        """Queue a security notification e-mail (rendered by the mail worker)."""
        payload: JSONObject = {"user_id": str(user.id), "template": template}
        if sign_in is not None:
            payload["sign_in"] = {
                "at": sign_in.at.isoformat(),
                "ip": sign_in.ip,
                "client": sign_in.client,
            }
        await uow.outbox.add(
            new_message(TaskName.SEND_SECURITY_EMAIL, payload, org_id=None, now=now)
        )


def _require_session(principal: Principal) -> UUID:
    """Sessions are managed from a signed-in session - never with an API key,
    so a leaked key can neither list its creator's devices nor end their sessions."""
    if principal.session_id is None or principal.user_id is None:
        raise PermissionDeniedError(
            "This action requires a signed-in user session.", code="session_required"
        )
    return principal.user_id


def _wrong_password() -> PermissionDeniedError:
    # 403, not 401: the caller's credentials are valid - a 401 would tell a
    # client to drop its tokens because someone mistyped a password.
    return PermissionDeniedError("The password is incorrect.", code="invalid_password")


def _account_locked() -> PermissionDeniedError:
    return PermissionDeniedError("The account is temporarily locked.", code="account_locked")


def _require_user(principal: Principal) -> UUID:
    if principal.user_id is None:
        raise PermissionDeniedError("This action requires a user session.", code="user_required")
    return principal.user_id


def _mfa_context(user_id: UUID) -> str:
    return f"user:{user_id}|mfa-totp"


def _generate_recovery_code() -> str:
    raw = secrets.token_hex(6)  # 48 bits, formatted for humans
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def _normalize_recovery_code(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")

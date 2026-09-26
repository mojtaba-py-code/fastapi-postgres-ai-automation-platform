"""Passkeys as a second factor: registering, listing, renaming, removing.

Signing in with a passkey is part of the sign-in flow (``AuthService``);
this service manages an account's passkeys, always from a signed-in session.

* **Registering** needs the password (it counts toward the lockout like a
  sign-in) and, when the account has a second factor already, a session that
  passed it. The challenge is random, single-use, expires after five minutes
  and is bound to the account and the session that asked for it. The first
  second factor of an account turns MFA on and yields recovery codes, shown
  once - as confirming TOTP does.
* **Removing** needs the password and a session that passed a second factor.
  The last passkey of an account without TOTP cannot be removed: that would
  turn MFA off, which only ``POST /auth/mfa/disable`` does - with the password
  *and* a code, and ending every session.
* Every change is audited and e-mailed to the account's address.
* A session an organization's identity provider opened neither lists nor
  changes passkeys (``403 sso_session_restricted``): its MFA speaks for that
  organization only, the account's second factors guard all of them.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.errors import (
    ConflictError,
    InvalidInputError,
    NotFoundError,
    PermissionDeniedError,
    ServiceUnavailableError,
)
from nexusflow.core.ids import uuid7
from nexusflow.core.jsonutil import JSONObject
from nexusflow.core.text import clean_text
from nexusflow.domain.audit.model import AuditAction, AuditResult
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.identity.account_service import PasswordConfirmation
from nexusflow.domain.identity.factors import (
    factor_session_of,
    generate_recovery_codes,
    queue_security_email,
    verified_session_required,
)
from nexusflow.domain.identity.model import WebAuthnCredential
from nexusflow.domain.identity.webauthn import (
    ALGORITHMS,
    CHALLENGE_BYTES,
    CHALLENGE_TTL_SECONDS,
    MAX_PASSKEY_NAME,
    MAX_PASSKEYS_PER_USER,
    TRANSPORTS,
    USER_HANDLE_BYTES,
    AttestationResponse,
    CreationOptions,
    CredentialDescriptor,
    PasskeyRejectedError,
    PasskeySupport,
    RelyingParty,
    b64url,
    b64url_decode,
)
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.security import TokenHasher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWorkFactory

_DEFAULT_NAME = "Passkey"


@dataclass(frozen=True, slots=True)
class PasskeyRegistration:
    passkey: WebAuthnCredential
    # Only when this passkey turned MFA on; shown exactly once.
    recovery_codes: list[str]


def descriptor(credential: WebAuthnCredential) -> CredentialDescriptor:
    return CredentialDescriptor(
        id=credential.credential_id, transports=tuple(credential.transports)
    )


def passkeys_unavailable() -> ServiceUnavailableError:
    return ServiceUnavailableError(
        "Passkeys are not available on this deployment.", code="passkeys_unavailable"
    )


def _registration_key(session_id: UUID) -> str:
    return f"register:{session_id}"


def _passkey_name(name: str | None) -> str:
    cleaned = clean_text(name or "", max_length=MAX_PASSKEY_NAME)
    return cleaned or _DEFAULT_NAME


def _transports(values: tuple[str, ...]) -> list[str]:
    """The known transports the browser reported, once each (they are hints)."""
    return [value for value in TRANSPORTS if value in values]


def _wrong_password() -> PermissionDeniedError:
    return PermissionDeniedError("The password is incorrect.", code="invalid_password")


class PasskeyService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        audit: AuditRecorder,
        token_hasher: TokenHasher,
        confirm_password: PasswordConfirmation,
        support: PasskeySupport,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._audit = audit
        self._hasher = token_hasher
        self._confirm_password = confirm_password
        self._support = support

    def _relying_party(self) -> RelyingParty:
        if self._support.relying_party is None:
            raise passkeys_unavailable()
        return self._support.relying_party

    # ------------------------------------------------------------ registration

    async def begin_registration(
        self, principal: Principal, *, password: str, meta: RequestMeta
    ) -> CreationOptions:
        user_id, session_id = factor_session_of(principal)
        rp = self._relying_party()
        verified = await self._confirm_password(
            principal, password, meta, purpose="passkey_registration"
        )
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get(user_id)
            session = await uow.sessions.get(session_id)
            if user is None or session is None or session.user_id != user_id:
                raise NotFoundError()
            if user.password_hash != verified:  # changed since it was confirmed
                raise _wrong_password()
            if user.mfa_enabled and not session.mfa_verified:
                raise verified_session_required()
            existing = await uow.webauthn_credentials.list_for_user(user_id)
        if len(existing) >= MAX_PASSKEYS_PER_USER:
            raise _too_many_passkeys()
        # One random handle per account (WebAuthn 14.6.1), kept with its passkeys.
        handle = existing[0].user_handle if existing else secrets.token_bytes(USER_HANDLE_BYTES)
        challenge = secrets.token_bytes(CHALLENGE_BYTES)
        state: JSONObject = {
            "challenge": b64url(challenge),
            "user_id": str(user_id),
            "session_id": str(session_id),
            "user_handle": b64url(handle),
            "expires_at": (now + timedelta(seconds=CHALLENGE_TTL_SECONDS)).isoformat(),
        }
        await self._support.challenges.put(
            _registration_key(session_id), state, ttl_seconds=CHALLENGE_TTL_SECONDS
        )
        return CreationOptions(
            rp=rp,
            user_handle=handle,
            user_name=user.email,
            user_display_name=user.full_name,
            challenge=challenge,
            algorithms=ALGORITHMS,
            exclude=tuple(descriptor(credential) for credential in existing),
            timeout_ms=CHALLENGE_TTL_SECONDS * 1000,
        )

    async def finish_registration(
        self,
        principal: Principal,
        *,
        response: AttestationResponse,
        transports: tuple[str, ...],
        name: str | None,
        meta: RequestMeta,
    ) -> PasskeyRegistration:
        user_id, session_id = factor_session_of(principal)
        rp = self._relying_party()
        now = self._clock.now()
        # Taken whatever happens next: each challenge is answered at most once.
        state = await self._support.challenges.take(_registration_key(session_id))
        try:
            challenge, handle = _registration_state(state, user_id, session_id, now)
            verified = self._support.verifier.verify_registration(
                response, challenge=challenge, rp=rp
            )
        except PasskeyRejectedError as rejected:
            await self._record_refusal(principal, rejected.reason, meta)
            raise
        passkey = WebAuthnCredential(
            id=uuid7(),
            user_id=user_id,
            credential_id=verified.credential_id,
            user_handle=handle,
            public_key=verified.public_key,
            algorithm=verified.algorithm,
            sign_count=verified.sign_count,
            transports=_transports(transports),
            name=_passkey_name(name),
            backup_eligible=verified.backup_eligible,
            backed_up=verified.backed_up,
            created_at=now,
        )
        try:
            codes = await self._store(principal, passkey, meta, now)
        except ConflictError as conflict:
            if conflict.code == "passkey_exists":
                await self._record_refusal(principal, "credential_exists", meta)
            raise
        return PasskeyRegistration(passkey=passkey, recovery_codes=codes)

    async def _store(
        self, principal: Principal, passkey: WebAuthnCredential, meta: RequestMeta, now: datetime
    ) -> list[str]:
        user_id, session_id = factor_session_of(principal)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get_for_update(user_id)
            session = await uow.sessions.get_for_update(session_id)
            if user is None or session is None or session.user_id != user_id:
                raise NotFoundError()
            if not session.is_valid(now):
                raise PermissionDeniedError("This session has ended.", code="session_required")
            if user.mfa_enabled and not session.mfa_verified:
                raise verified_session_required()
            if await uow.webauthn_credentials.count_for_user(user_id) >= MAX_PASSKEYS_PER_USER:
                raise _too_many_passkeys()
            await uow.webauthn_credentials.add(passkey)
            codes: list[str] = []
            if not user.mfa_enabled:
                user.mfa_enabled = True
                user.updated_at = now
                codes, stored = generate_recovery_codes(self._hasher, user_id, now)
                await uow.recovery_codes.replace_for_user(user_id, stored)
                await self._audit.record(
                    uow.audit,
                    action=AuditAction.MFA_ENABLED,
                    principal=principal,
                    meta=meta,
                    resource_type="user",
                    resource_id=user_id,
                    metadata={"method": "webauthn"},
                )
            # The ceremony verified the user on the new passkey: as after
            # confirming TOTP, this session counts as having passed MFA.
            session.mfa_verified = True
            await self._audit.record(
                uow.audit,
                action=AuditAction.WEBAUTHN_REGISTERED,
                principal=principal,
                meta=meta,
                resource_type="webauthn_credential",
                resource_id=passkey.id,
                metadata={
                    "algorithm": passkey.algorithm,
                    "backup_eligible": passkey.backup_eligible,
                    "backed_up": passkey.backed_up,
                    "transports": list(passkey.transports),
                },
            )
            await queue_security_email(uow, user_id, "passkey_added", now)
            await uow.commit()
        return codes

    async def _record_refusal(self, principal: Principal, reason: str, meta: RequestMeta) -> None:
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            await self._audit.record(
                uow.audit,
                action=AuditAction.WEBAUTHN_REGISTRATION_FAILED,
                principal=principal,
                meta=meta,
                result=AuditResult.FAILURE,
                resource_type="user",
                resource_id=principal.user_id,
                metadata={"reason": reason},
            )
            await uow.commit()

    # ------------------------------------------------------------- management

    async def list_passkeys(self, principal: Principal) -> list[WebAuthnCredential]:
        user_id, _ = factor_session_of(principal)
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            return await uow.webauthn_credentials.list_for_user(user_id)

    async def rename(
        self, principal: Principal, passkey_id: UUID, *, name: str, meta: RequestMeta
    ) -> WebAuthnCredential:
        user_id, _ = factor_session_of(principal)
        label = clean_text(name, max_length=MAX_PASSKEY_NAME)
        if not label:
            raise InvalidInputError("A name is required.", code="name_required")
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            passkey = await uow.webauthn_credentials.get(user_id, passkey_id, for_update=True)
            if passkey is None:
                raise NotFoundError()  # another account's passkey does not exist for you
            passkey.name = label
            await self._audit.record(
                uow.audit,
                action=AuditAction.WEBAUTHN_RENAMED,
                principal=principal,
                meta=meta,
                resource_type="webauthn_credential",
                resource_id=passkey.id,
            )
            await uow.commit()
            return passkey

    async def remove(
        self, principal: Principal, passkey_id: UUID, *, password: str, meta: RequestMeta
    ) -> None:
        user_id, session_id = factor_session_of(principal)
        verified = await self._confirm_password(
            principal, password, meta, purpose="passkey_removal"
        )
        now = self._clock.now()
        async with self._uow_factory(TenantScope.of(principal)) as uow:
            user = await uow.users.get_for_update(user_id)
            session = await uow.sessions.get(session_id)
            if user is None or session is None or session.user_id != user_id:
                raise NotFoundError()
            if user.password_hash != verified:  # changed since it was confirmed
                raise _wrong_password()
            passkey = await uow.webauthn_credentials.get(user_id, passkey_id, for_update=True)
            if passkey is None:
                raise NotFoundError()
            if not session.mfa_verified:
                raise verified_session_required()
            remaining = await uow.webauthn_credentials.count_for_user(user_id) - 1
            if remaining == 0 and not user.has_totp:
                raise ConflictError(
                    "This passkey is your only second factor. Register another passkey or set "
                    "up an authenticator app first - or turn two-factor authentication off "
                    "(POST /api/v1/auth/mfa/disable).",
                    code="last_second_factor",
                )
            await uow.webauthn_credentials.delete(passkey)
            await self._audit.record(
                uow.audit,
                action=AuditAction.WEBAUTHN_REMOVED,
                principal=principal,
                meta=meta,
                resource_type="webauthn_credential",
                resource_id=passkey.id,
                metadata={"remaining": remaining},
            )
            await queue_security_email(uow, user_id, "passkey_removed", now)
            await uow.commit()


def _too_many_passkeys() -> ConflictError:
    return ConflictError(
        f"An account can have at most {MAX_PASSKEYS_PER_USER} passkeys: remove one first.",
        code="too_many_passkeys",
    )


def _registration_state(
    state: JSONObject | None, user_id: UUID, session_id: UUID, now: datetime
) -> tuple[bytes, bytes]:
    """The challenge and user handle of the pending registration of this
    account in this session, while it is valid."""
    if state is None:
        raise PasskeyRejectedError("challenge_missing")
    try:
        bound = state["user_id"] == str(user_id) and state["session_id"] == str(session_id)
        challenge = b64url_decode(str(state["challenge"]))
        handle = b64url_decode(str(state["user_handle"]))
        expires_at = datetime.fromisoformat(str(state["expires_at"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise PasskeyRejectedError("challenge_missing") from exc
    if not bound:
        raise PasskeyRejectedError("challenge_missing")
    if now >= expires_at:
        raise PasskeyRejectedError("challenge_expired")
    return challenge, handle

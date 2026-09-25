"""Security e-mails: notifications, password reset and invitation links.

Reset and invitation tokens are generated *here*, inside the mail worker, and
only their keyed hash is written to the database - the raw token never passes
through the API process, the message broker or the logs. Links carry the
token in the URL *fragment* (``#token=...``), which browsers do not send to
servers, proxies or ``Referer`` headers.
"""

from __future__ import annotations

from datetime import UTC
from typing import Protocol
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.domain.identity.login_risk import SignInDetails
from nexusflow.domain.shared.security import TokenGenerator, TokenHasher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWorkFactory


class EmailPort(Protocol):
    async def send_email(self, recipients: list[str], subject: str, body: str) -> None: ...


_TEMPLATES: dict[str, tuple[str, str]] = {
    "new_device_login": (
        "New sign-in to your NexusFlow account",
        (
            "We noticed a sign-in from a new device or network. If this was you, no action is "
            "needed. If not, reset your password immediately and sign out of all sessions."
        ),
    ),
    "suspicious_login": (
        "Unusual sign-in to your NexusFlow account",
        (
            "Someone signed in to your account from a device and a network you have not used "
            "recently, or right after several wrong passwords. If this was you, no action is "
            "needed. If not, reset your password now, sign out of all sessions and turn on "
            "two-factor authentication."
        ),
    ),
    "account_locked": (
        "Your NexusFlow account was temporarily locked",
        (
            "Several failed sign-in attempts were made. Your account is locked for a short "
            "period. If these attempts were not yours, consider changing your password."
        ),
    ),
    "password_changed": (
        "Your NexusFlow password was changed",
        (
            "Your password was changed and your other sessions were signed out. If you did "
            "not do this, contact your administrator immediately."
        ),
    ),
    "session_revoked_token_reuse": (
        "Suspicious session activity was blocked",
        (
            "A previously used session token was presented again, which can indicate token "
            "theft. The session was revoked. Please sign in again and review your devices."
        ),
    ),
    "mfa_enabled": (
        "Two-factor authentication enabled",
        "Two-factor authentication is now active.",
    ),
    "mfa_disabled": (
        "Two-factor authentication disabled",
        (
            "Two-factor authentication was turned off and all sessions were signed out. If "
            "this was not you, reset your password now."
        ),
    ),
    "mfa_recovery_code_used": (
        "A recovery code was used",
        (
            "One of your MFA recovery codes was used to sign in. Generate new codes if you "
            "are running low, and contact your administrator if this was not you."
        ),
    ),
}


class SecurityEmailService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        email: EmailPort,
        token_generator: TokenGenerator,
        token_hasher: TokenHasher,
        public_base_url: str,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._email = email
        self._tokens = token_generator
        self._hasher = token_hasher
        self._base = public_base_url.rstrip("/")

    async def send_notification(
        self, *, user_id: UUID, template: str, sign_in: SignInDetails | None = None
    ) -> bool:
        if template not in _TEMPLATES:
            return False
        async with self._uow_factory(TenantScope.auth()) as uow:
            user = await uow.users.get(user_id)
        if user is None or not user.is_active:
            return False
        subject, body = _TEMPLATES[template]
        text = f"Hello {user.full_name},\n\n{body}\n"
        if sign_in is not None:
            # Fixed vocabulary only: the IP is a parsed address and the device a
            # description chosen by the platform, never the sender's own words.
            text += (
                f"\nWhen: {sign_in.at.astimezone(UTC):%Y-%m-%d %H:%M} UTC\n"
                f"IP address: {sign_in.ip or 'unknown'}\n"
                f"Device: {sign_in.client}\n"
            )
        await self._email.send_email([user.email], subject, text)
        return True

    async def send_password_reset(self, *, reset_id: UUID) -> bool:
        now = self._clock.now()
        raw = self._tokens.generate(32)
        async with self._uow_factory(TenantScope.auth()) as uow:
            reset = await uow.password_resets.get(reset_id)
            if (
                reset is None
                or reset.used_at is not None
                or reset.expires_at <= now
                or reset.token_hash
            ):
                return False  # idempotent: never issue a second token for one request
            user = await uow.users.get(reset.user_id)
            if user is None or not user.is_active:
                return False
            reset.token_hash = self._hasher.hash(raw)
            await uow.commit()
        link = f"{self._base}/reset-password#token={raw}"
        await self._email.send_email(
            [user.email],
            "Reset your NexusFlow password",
            (
                f"Hello {user.full_name},\n\nUse this link within 30 minutes to choose a new "
                f"password:\n\n{link}\n\nIf you did not request this, ignore this e-mail.\n"
            ),
        )
        return True

    async def send_invitation(self, *, org_id: UUID, invitation_id: UUID) -> bool:
        now = self._clock.now()
        raw = self._tokens.generate(32)
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            invitation = await uow.invitations.get(org_id, invitation_id)
            if invitation is None or not invitation.is_pending(now) or invitation.token_hash:
                return False
            organization = await uow.organizations.get(org_id)
            invitation.token_hash = self._hasher.hash(raw)
            await uow.commit()
        org_name = organization.name if organization else "an organization"
        link = f"{self._base}/accept-invitation#token={raw}"
        await self._email.send_email(
            [invitation.email],
            f"You were invited to {org_name} on NexusFlow",
            (
                f"You were invited to join {org_name} as {invitation.role.value}.\n\n"
                f"Accept the invitation:\n\n{link}\n\n"
                f"The link expires on {invitation.expires_at:%Y-%m-%d}.\n"
            ),
        )
        return True

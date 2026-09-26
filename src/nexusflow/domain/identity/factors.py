"""What the second-factor flows share - TOTP and passkeys alike.

Recovery codes, the security e-mails, and the rule for changing second
factors: from a signed-in session only, and - once an account has a second
factor - only from a session that passed it at sign-in (or that set it up).
A stolen session or API key, even with the password, cannot add a factor of
its own to an account that has one, nor take one away.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from uuid import UUID

from nexusflow.core.errors import PermissionDeniedError
from nexusflow.core.ids import uuid7
from nexusflow.core.jsonutil import JSONObject
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.identity.login_risk import SignInDetails
from nexusflow.domain.identity.model import MfaRecoveryCode
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.domain.shared.security import TokenHasher
from nexusflow.domain.shared.unit_of_work import UnitOfWork

RECOVERY_CODE_COUNT = 10


def generate_recovery_codes(
    hasher: TokenHasher, user_id: UUID, now: datetime
) -> tuple[list[str], list[MfaRecoveryCode]]:
    """New single-use recovery codes: the codes to show once, and the keyed
    hashes that are all the platform keeps of them."""
    codes = [_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
    stored = [
        MfaRecoveryCode(
            id=uuid7(),
            user_id=user_id,
            created_at=now,
            code_hash=hasher.hash(normalize_recovery_code(code)),
        )
        for code in codes
    ]
    return codes, stored


def normalize_recovery_code(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")


def _recovery_code() -> str:
    raw = secrets.token_hex(6)  # 48 bits, formatted for humans
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


async def queue_security_email(
    uow: UnitOfWork,
    user_id: UUID,
    template: str,
    now: datetime,
    *,
    sign_in: SignInDetails | None = None,
) -> None:
    """Queue a security notification e-mail (rendered by the mail worker)."""
    payload: JSONObject = {"user_id": str(user_id), "template": template}
    if sign_in is not None:
        payload["sign_in"] = {
            "at": sign_in.at.isoformat(),
            "ip": sign_in.ip,
            "client": sign_in.client,
        }
    await uow.outbox.add(new_message(TaskName.SEND_SECURITY_EMAIL, payload, org_id=None, now=now))


def session_of(principal: Principal) -> tuple[UUID, UUID]:
    """The user and session behind ``principal``; second factors (like the
    sessions themselves) are managed from a signed-in session - never with
    an API key."""
    if principal.session_id is None or principal.user_id is None:
        raise PermissionDeniedError(
            "This action requires a signed-in user session.", code="session_required"
        )
    return principal.user_id, principal.session_id


def verified_session_required() -> PermissionDeniedError:
    return PermissionDeniedError(
        "Sign in with your second factor first: second factors are changed only from a "
        "session that passed one.",
        code="mfa_session_required",
    )

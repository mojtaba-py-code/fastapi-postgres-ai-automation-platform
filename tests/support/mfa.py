"""Second factors through the API: sign-in steps, passkeys, TOTP, organizations
that require passkeys - for tests that walk those flows end to end.

TOTP codes: a code verifies within a step of the platform's clock, and each
step once - after confirming the code of one step, a sign-in uses the next
step's (``STEP``).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import httpx2
import pyotp

from nexusflow.bootstrap.container import Container
from tests.support.api import ApiSession
from tests.support.fixtures import PASSWORD
from tests.support.webauthn import SoftwareAuthenticator

ORG = "/api/v1/organizations/current"
LOGIN = "/api/v1/auth/login"
SESSIONS = "/api/v1/users/me/sessions"
REGISTER_BEGIN = "/api/v1/auth/webauthn/register/begin"
REGISTER_FINISH = "/api/v1/auth/webauthn/register/finish"
PASSKEYS = "/api/v1/auth/webauthn/credentials"
REQUIRE = {"settings": {"require_passkey": True}}
STEP = timedelta(seconds=30)  # one TOTP time step


async def register_passkey(
    session: ApiSession, authenticator: SoftwareAuthenticator | None = None
) -> tuple[SoftwareAuthenticator, dict[str, Any]]:
    authenticator = authenticator or SoftwareAuthenticator()
    begun = await session.post(REGISTER_BEGIN, json={"password": PASSWORD})
    assert begun.status_code == 200, begun.text
    credential = authenticator.attestation(begun.json()["options"])
    finished = await session.post(
        REGISTER_FINISH, json={"name": "Laptop", "credential": credential}
    )
    assert finished.status_code == 201, finished.text
    body: dict[str, Any] = finished.json()
    return authenticator, body


async def enroll_totp(session: ApiSession, at: datetime) -> tuple[pyotp.TOTP, list[str]]:
    """TOTP set up in ``session``, confirmed with the code for ``at``; returns
    the app and the recovery codes (which replace any earlier ones)."""
    enrolled = await session.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD})
    assert enrolled.status_code == 200, enrolled.text
    totp = pyotp.TOTP(enrolled.json()["secret"])
    confirmed = await session.post("/api/v1/auth/mfa/confirm", json={"code": totp.at(at)})
    assert confirmed.status_code == 200, confirmed.text
    codes: list[str] = confirmed.json()["recovery_codes"]
    return totp, codes


async def password_step(
    api: httpx2.AsyncClient, email: str, organization: UUID | None = None
) -> str:
    """The password step of an account with MFA: its ``mfa_token``."""
    body: dict[str, Any] = {"email": email, "password": PASSWORD}
    if organization is not None:
        body["organization_id"] = str(organization)
    response = await api.post(LOGIN, json=body)
    assert response.status_code == 200, response.text
    assert response.json()["mfa_required"] is True, response.text
    token: str = response.json()["mfa_token"]
    return token


async def with_code(api: httpx2.AsyncClient, mfa_token: str, code: str) -> httpx2.Response:
    return await api.post("/api/v1/auth/mfa/verify", json={"mfa_token": mfa_token, "code": code})


async def with_passkey(
    api: httpx2.AsyncClient, mfa_token: str, authenticator: SoftwareAuthenticator
) -> httpx2.Response:
    begun = await api.post("/api/v1/auth/mfa/webauthn/begin", json={"mfa_token": mfa_token})
    assert begun.status_code == 200, begun.text
    credential = authenticator.assertion(begun.json()["options"])
    return await api.post(
        "/api/v1/auth/mfa/webauthn/verify", json={"mfa_token": mfa_token, "credential": credential}
    )


def session_from(api: httpx2.AsyncClient, response: httpx2.Response, email: str) -> ApiSession:
    assert response.status_code == 200, response.text
    body = response.json()
    return ApiSession(api, body["access_token"], body["refresh_token"], email)


async def password_session(api: httpx2.AsyncClient, email: str) -> ApiSession:
    """Signed in with the password alone (an account without MFA)."""
    response = await api.post(LOGIN, json={"email": email, "password": PASSWORD})
    return session_from(api, response, email)


async def code_session(api: httpx2.AsyncClient, email: str, code: str) -> ApiSession:
    """Signed in with the password and a TOTP or recovery code."""
    return session_from(api, await with_code(api, await password_step(api, email), code), email)


async def passkey_session(
    api: httpx2.AsyncClient, email: str, authenticator: SoftwareAuthenticator
) -> ApiSession:
    """Signed in with the password and a passkey."""
    return session_from(
        api, await with_passkey(api, await password_step(api, email), authenticator), email
    )


async def factor_of(session: ApiSession) -> tuple[bool, str | None]:
    """This session's ``mfa_verified`` and ``mfa_method``, as the session list shows them."""
    response = await session.get(SESSIONS)
    assert response.status_code == 200, response.text
    [current] = [listed for listed in response.json() if listed["current"]]
    return current["mfa_verified"], current["mfa_method"]


async def trail(admin_conn: asyncpg.Connection, org_id: UUID, action: str) -> list[dict[str, Any]]:
    """The metadata of the organization's ``action`` entries, oldest first."""
    rows = await admin_conn.fetch(
        "SELECT metadata FROM audit_logs WHERE org_id = $1 AND action = $2 ORDER BY seq",
        org_id,
        action,
    )
    return [json.loads(row["metadata"]) for row in rows]


async def join_organization(
    organization: ApiSession,
    member: ApiSession,
    container: Container,
    admin_conn: asyncpg.Connection,
    role: str = "analyst",
) -> None:
    """``member`` accepts an invitation to ``organization``'s organization."""
    invited = await organization.post(
        f"{ORG}/invitations", json={"email": member.email, "role": role}
    )
    assert invited.status_code == 201, invited.text
    raw = "invite-" + uuid4().hex  # as the mail worker does: only the hash is stored
    await admin_conn.execute(
        "UPDATE invitations SET token_hash = $1 WHERE id = $2",
        container.token_hasher.hash(raw),
        UUID(invited.json()["id"]),
    )
    accepted = await member.post("/api/v1/auth/invitations/accept", json={"token": raw})
    assert accepted.status_code == 204, accepted.text


async def require_passkeys(
    api: httpx2.AsyncClient, owner: ApiSession
) -> tuple[ApiSession, SoftwareAuthenticator]:
    """The owner registers a passkey, signs in with it and requires passkeys;
    returns that passkey session and the passkey."""
    authenticator, _ = await register_passkey(owner)
    admin = await passkey_session(api, owner.email, authenticator)
    required = await admin.patch(ORG, json=REQUIRE)
    assert required.status_code == 200, required.text
    return admin, authenticator

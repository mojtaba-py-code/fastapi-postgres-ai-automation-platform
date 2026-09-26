"""An organization that requires passkeys (``require_passkey``), end to end.

* Only sessions that signed in with a passkey reach it. A session whose second
  factor was TOTP or a recovery code - or none - is refused on every request,
  at sign-in naming the organization (which its trail shows) and when
  switching to it: ``403 passkey_required``. A passkey session passes.
* Turning it on needs such a session - never an API key
  (``422 would_lock_you_out``); turning it off is always allowed. API keys are
  not sessions: the policy does not apply to them.
* Every session records the second factor it passed (``mfa_method``, listed in
  ``GET /users/me/sessions``). Registering a passkey does not make a session a
  passkey session; confirming TOTP does not make a passkey session less.
* Recovery: an owner who lost every passkey signs in with a recovery code, is
  refused the organization, registers a new passkey from that session (the
  set-up mode) and signs in with it.
* Single sign-on: the provider's MFA never stands in for a passkey, trusted or
  not. The platform's step offers a passkey only and completes only with one; a
  code is refused (and audited), and a person without a passkey gets nowhere.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import httpx2
import pyotp
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.core.clock import FrozenClock
from tests.support.api import ApiSession, signup
from tests.support.business import expect_error, org_id_of
from tests.support.fixtures import PASSWORD
from tests.support.oidc import FakeIdp, FakeNetwork, fresh_domain, ready, session_of, sign_in
from tests.support.webauthn import SoftwareAuthenticator

pytestmark = [pytest.mark.security, pytest.mark.integration]

ORG = "/api/v1/organizations/current"
LOGIN = "/api/v1/auth/login"
SESSIONS = "/api/v1/users/me/sessions"
REGISTER_BEGIN = "/api/v1/auth/webauthn/register/begin"
REQUIRE = {"settings": {"require_passkey": True}}
# One TOTP time step. A code verifies within a step of the platform's clock,
# once: after confirming the code of one step, a sign-in uses the next one's.
STEP = timedelta(seconds=30)


# ------------------------------------------------------------------ helpers


async def _register_passkey(
    session: ApiSession, authenticator: SoftwareAuthenticator | None = None
) -> tuple[SoftwareAuthenticator, dict[str, Any]]:
    authenticator = authenticator or SoftwareAuthenticator()
    begun = await session.post(REGISTER_BEGIN, json={"password": PASSWORD})
    assert begun.status_code == 200, begun.text
    credential = authenticator.attestation(begun.json()["options"])
    finished = await session.post(
        "/api/v1/auth/webauthn/register/finish", json={"name": "Laptop", "credential": credential}
    )
    assert finished.status_code == 201, finished.text
    body: dict[str, Any] = finished.json()
    return authenticator, body


async def _enroll_totp(session: ApiSession, at: datetime) -> tuple[pyotp.TOTP, list[str]]:
    """TOTP set up in ``session``, confirmed with the code for ``at``; returns
    the app and the recovery codes (which replace any earlier ones)."""
    enrolled = await session.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD})
    assert enrolled.status_code == 200, enrolled.text
    totp = pyotp.TOTP(enrolled.json()["secret"])
    confirmed = await session.post("/api/v1/auth/mfa/confirm", json={"code": totp.at(at)})
    assert confirmed.status_code == 200, confirmed.text
    codes: list[str] = confirmed.json()["recovery_codes"]
    return totp, codes


async def _password_step(
    api: httpx2.AsyncClient, email: str, organization: UUID | None = None
) -> str:
    body: dict[str, Any] = {"email": email, "password": PASSWORD}
    if organization is not None:
        body["organization_id"] = str(organization)
    response = await api.post(LOGIN, json=body)
    assert response.status_code == 200, response.text
    assert response.json()["mfa_required"] is True, response.text
    token: str = response.json()["mfa_token"]
    return token


async def _with_code(api: httpx2.AsyncClient, mfa_token: str, code: str) -> httpx2.Response:
    return await api.post("/api/v1/auth/mfa/verify", json={"mfa_token": mfa_token, "code": code})


async def _with_passkey(
    api: httpx2.AsyncClient, mfa_token: str, authenticator: SoftwareAuthenticator
) -> httpx2.Response:
    begun = await api.post("/api/v1/auth/mfa/webauthn/begin", json={"mfa_token": mfa_token})
    assert begun.status_code == 200, begun.text
    credential = authenticator.assertion(begun.json()["options"])
    return await api.post(
        "/api/v1/auth/mfa/webauthn/verify", json={"mfa_token": mfa_token, "credential": credential}
    )


def _session(api: httpx2.AsyncClient, response: httpx2.Response, email: str) -> ApiSession:
    assert response.status_code == 200, response.text
    body = response.json()
    return ApiSession(api, body["access_token"], body["refresh_token"], email)


async def _code_session(api: httpx2.AsyncClient, email: str, code: str) -> ApiSession:
    """Signed in with the password and a TOTP or recovery code."""
    return _session(api, await _with_code(api, await _password_step(api, email), code), email)


async def _passkey_session(
    api: httpx2.AsyncClient, email: str, authenticator: SoftwareAuthenticator
) -> ApiSession:
    """Signed in with the password and a passkey."""
    return _session(
        api, await _with_passkey(api, await _password_step(api, email), authenticator), email
    )


async def _factor(session: ApiSession) -> tuple[bool, str | None]:
    """This session's ``mfa_verified`` and ``mfa_method``, as the session list shows them."""
    response = await session.get(SESSIONS)
    assert response.status_code == 200, response.text
    [current] = [listed for listed in response.json() if listed["current"]]
    return current["mfa_verified"], current["mfa_method"]


async def _trail(admin_conn: asyncpg.Connection, org_id: UUID, action: str) -> list[dict[str, Any]]:
    """The metadata of the organization's ``action`` entries, oldest first."""
    rows = await admin_conn.fetch(
        "SELECT metadata FROM audit_logs WHERE org_id = $1 AND action = $2 ORDER BY seq",
        org_id,
        action,
    )
    return [json.loads(row["metadata"]) for row in rows]


async def _join(
    organization: ApiSession,
    member: ApiSession,
    container: Container,
    admin_conn: asyncpg.Connection,
) -> None:
    """``member`` accepts an invitation to ``organization``'s organization."""
    invited = await organization.post(
        f"{ORG}/invitations", json={"email": member.email, "role": "analyst"}
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


async def _require_passkeys(api: httpx2.AsyncClient, owner: ApiSession) -> ApiSession:
    """The owner registers a passkey, signs in with it and requires passkeys;
    returns that passkey session."""
    authenticator, _ = await _register_passkey(owner)
    admin = await _passkey_session(api, owner.email, authenticator)
    required = await admin.patch(ORG, json=REQUIRE)
    assert required.status_code == 200, required.text
    return admin


# ---------------------------------------------------------------- the setting


async def test_only_a_session_that_signed_in_with_a_passkey_can_require_passkeys(
    api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
) -> None:
    owner = await signup(api)
    org_id = await org_id_of(owner)
    created = await owner.post(
        "/api/v1/api-keys",
        json={
            "name": "ops",
            "role": "admin",
            "scopes": ["org:read", "org:update"],
            "expires_in_days": 1,
        },
    )
    assert created.status_code == 201, created.text
    key = {"Authorization": f"Bearer {created.json()['token']}"}

    # Each of these would be shut out by its own change: the sign-up session
    # (no second factor) ...
    expect_error(await owner.patch(ORG, json=REQUIRE), 422, "would_lock_you_out")
    # ... the same session once a passkey is registered in it (a registration
    # is no sign-in with the passkey) ...
    authenticator, registered = await _register_passkey(owner)
    expect_error(await owner.patch(ORG, json=REQUIRE), 422, "would_lock_you_out")
    # ... a session that signed in with a recovery code ...
    by_code = await _code_session(api, owner.email, registered["recovery_codes"][0])
    expect_error(await by_code.patch(ORG, json=REQUIRE), 422, "would_lock_you_out")
    # ... and an API key: the policy does not reach it, and it shows no one
    # could still sign in.
    expect_error(await api.patch(ORG, json=REQUIRE, headers=key), 422, "would_lock_you_out")
    assert (await owner.get(ORG)).json()["settings"]["require_passkey"] is False

    # A session that signed in with a passkey turns it on - audited.
    by_passkey = await _passkey_session(api, owner.email, authenticator)
    enabled = await by_passkey.patch(ORG, json=REQUIRE)
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["settings"]["require_passkey"] is True
    assert (await by_passkey.get(ORG)).json()["settings"]["require_passkey"] is True
    assert (await _trail(admin_conn, org_id, "org.updated"))[-1] == {
        "settings": {"require_passkey": True}
    }
    expect_error(await by_code.get(ORG), 403, "passkey_required")

    # API keys are not sessions: the key still works ...
    assert (await api.get(ORG, headers=key)).status_code == 200
    # ... and turning the policy off is always allowed, even from it.
    lifted = await api.patch(ORG, json={"settings": {"require_passkey": False}}, headers=key)
    assert lifted.status_code == 200, lifted.text
    assert lifted.json()["settings"]["require_passkey"] is False
    assert (await _trail(admin_conn, org_id, "org.updated"))[-1] == {
        "settings": {"require_passkey": False}
    }
    assert (await by_code.get(ORG)).status_code == 200


# ------------------------------------------------------------- enforcement


async def test_a_totp_session_is_refused_on_every_request_and_when_naming_the_organization(
    api: httpx2.AsyncClient,
    admin_conn: asyncpg.Connection,
    container: Container,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The sign-in clock stopped: the codes of three consecutive steps (the
    # confirmation's, then two sign-ins') all verify, each once.
    clock = FrozenClock(datetime.now(UTC))
    monkeypatch.setattr(container.auth, "_clock", clock)
    owner = await signup(api)
    org_id = await org_id_of(owner)
    totp, _ = await _enroll_totp(owner, clock.now() - STEP)
    admin = await _require_passkeys(api, owner)

    # Password and TOTP, the organization being the default: the session opens
    # in it, and every request to it is refused ...
    signed_in = await _with_code(api, await _password_step(api, owner.email), totp.at(clock.now()))
    by_totp = _session(api, signed_in, owner.email)
    assert signed_in.json()["organization_id"] == str(org_id)
    refused = expect_error(await by_totp.get(ORG), 403, "passkey_required")
    assert refused["message"].startswith("This organization requires signing in with a passkey")
    for path in ("/api/v1/projects", SESSIONS):
        expect_error(await by_totp.get(path), 403, "passkey_required")
    # ... but a passkey can be registered from it: it passed a second factor.
    assert (await by_totp.post(REGISTER_BEGIN, json={"password": PASSWORD})).status_code == 200

    # Naming the organization at sign-in is refused, and its trail shows it.
    named = await _with_code(
        api, await _password_step(api, owner.email, org_id), totp.at(clock.now() + STEP)
    )
    expect_error(named, 403, "passkey_required")
    [denied] = await admin_conn.fetch(
        "SELECT metadata, result FROM audit_logs WHERE org_id = $1 AND action = $2",
        org_id,
        "auth.login.failed",
    )
    assert json.loads(denied["metadata"]) == {
        "reason": "passkey_required",
        "mfa": True,
        "mfa_method": "totp",
    }
    assert denied["result"] == "denied"

    # The passkey session passes - and still does once refreshed.
    assert (await admin.get(ORG)).status_code == 200
    renewed = await api.post("/api/v1/auth/refresh", json={"refresh_token": admin.refresh_token})
    assert (await _session(api, renewed, owner.email).get("/api/v1/projects")).status_code == 200
    assert await _factor(admin) == (True, "webauthn")


async def test_switching_into_the_organization_needs_a_passkey_session(
    api: httpx2.AsyncClient, admin_conn: asyncpg.Connection, container: Container
) -> None:
    admin = await _require_passkeys(api, await signup(api))
    org_id = await org_id_of(admin)
    bob = await signup(api)  # his own organization comes first
    authenticator, _ = await _register_passkey(bob)
    enrolled_at = datetime.now(UTC)
    totp, _ = await _enroll_totp(bob, enrolled_at)
    await _join(admin, bob, container, admin_conn)
    switch = {"organization_id": str(org_id)}

    by_totp = await _code_session(api, bob.email, totp.at(enrolled_at + STEP))
    assert (await by_totp.get(ORG)).json()["id"] != str(org_id)  # his own organization
    refused = await by_totp.post("/api/v1/auth/switch-organization", json=switch)
    expect_error(refused, 403, "passkey_required")

    by_passkey = await _passkey_session(api, bob.email, authenticator)
    switched = await by_passkey.post("/api/v1/auth/switch-organization", json=switch)
    assert (await _session(api, switched, bob.email).get(ORG)).json()["id"] == str(org_id)


# ------------------------------------------------------------ the record


async def test_each_session_records_the_second_factor_it_passed(
    api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
) -> None:
    owner = await signup(api)
    authenticator, _ = await _register_passkey(owner)
    by_passkey = await _passkey_session(api, owner.email, authenticator)
    # An authenticator app set up in a passkey session leaves it a passkey session.
    enrolled_at = datetime.now(UTC)
    totp, codes = await _enroll_totp(by_passkey, enrolled_at)
    by_totp = await _code_session(api, owner.email, totp.at(enrolled_at + STEP))
    by_code = await _code_session(api, owner.email, codes[0])

    # Registering the first passkey made the sign-up session MFA-verified, but
    # no passkey session: it signed in with none.
    assert await _factor(owner) == (True, None)
    assert await _factor(by_passkey) == (True, "webauthn")
    assert await _factor(by_totp) == (True, "totp")
    assert await _factor(by_code) == (True, "recovery_code")
    exported = (await by_totp.get("/api/v1/users/me/export")).json()["sessions"]
    assert sorted(str(session["mfa_method"]) for session in exported) == [
        "None",
        "recovery_code",
        "totp",
        "webauthn",
    ]

    # Confirming TOTP in a session that had passed no factor records TOTP.
    newcomer = await signup(api)
    await _enroll_totp(newcomer, datetime.now(UTC))
    assert await _factor(newcomer) == (True, "totp")
    stored = await admin_conn.fetch(
        "SELECT mfa_verified, mfa_method FROM user_sessions WHERE user_id ="
        " (SELECT id FROM users WHERE email = $1)",
        newcomer.email,
    )
    assert [(row["mfa_verified"], row["mfa_method"]) for row in stored] == [(True, "totp")]


# ----------------------------------------------------------------- recovery


async def test_an_owner_who_lost_every_passkey_registers_a_new_one_and_gets_back_in(
    api: httpx2.AsyncClient,
) -> None:
    owner = await signup(api)
    # Signed in on another device before any second factor: it never passed one.
    old_laptop = _session(
        api, await api.post(LOGIN, json={"email": owner.email, "password": PASSWORD}), owner.email
    )
    lost, registered = await _register_passkey(owner)
    admin = await _passkey_session(api, owner.email, lost)
    assert (await admin.patch(ORG, json=REQUIRE)).status_code == 200

    # Every passkey lost, a recovery code signs in - to a session the
    # organization refuses ...
    recovered = await _code_session(api, owner.email, registered["recovery_codes"][0])
    expect_error(await recovered.get(ORG), 403, "passkey_required")
    # ... from which, as it passed a second factor, a new passkey is registered
    # (the set-up mode) - which does not make it a passkey session.
    replacement, _ = await _register_passkey(recovered)
    expect_error(await recovered.get(ORG), 403, "passkey_required")
    # A session that passed no second factor cannot register one, as ever.
    expect_error(await old_laptop.get(ORG), 403, "passkey_required")
    expect_error(
        await old_laptop.post(REGISTER_BEGIN, json={"password": PASSWORD}),
        403,
        "mfa_session_required",
    )

    # Signing in with the new passkey opens the organization.
    back = await _passkey_session(api, owner.email, replacement)
    assert (await back.get(ORG)).status_code == 200
    assert await _factor(back) == (True, "webauthn")
    # From here, the lost passkey can be removed.
    assert len((await back.get("/api/v1/auth/webauthn/credentials")).json()) == 2


# ------------------------------------------------------------ single sign-on


async def test_the_providers_mfa_never_stands_in_for_a_passkey(
    api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
) -> None:
    domain = fresh_domain()
    alice = await signup(api, email=f"alice@{domain}")
    authenticator, _ = await _register_passkey(alice)
    enrolled_at = datetime.now(UTC)
    totp, codes = await _enroll_totp(alice, enrolled_at)
    owner = await signup(api)
    idp = FakeIdp()
    slug = await ready(owner, network, idp, domain, trust_idp_mfa=True)
    org_id = await org_id_of(owner)
    hardware_key = {"email": alice.email, "amr": ["pwd", "hwk"]}  # reported, and trusted

    # Before the policy, the trusted provider's MFA made her session
    # MFA-verified - with no platform factor recorded ...
    earlier = session_of(api, await sign_in(api, idp, slug, **hardware_key), alice.email)
    assert await _factor(earlier) == (True, None)
    await _require_passkeys(api, owner)
    # ... so once passkeys are required, that session is refused.
    expect_error(await earlier.get("/api/v1/projects"), 403, "passkey_required")

    # The platform asks for its own step - a passkey, and nothing else.
    challenge = await sign_in(api, idp, slug, **hardware_key)
    body = challenge.json()
    assert body["mfa_required"] is True and "access_token" not in body, body
    assert body["methods"] == ["webauthn"]
    # A TOTP or recovery code proves the account, not a passkey: refused, audited.
    by_totp = await _with_code(api, body["mfa_token"], totp.at(enrolled_at + STEP))
    expect_error(by_totp, 403, "passkey_required")
    again = (await sign_in(api, idp, slug, **hardware_key)).json()
    expect_error(await _with_code(api, again["mfa_token"], codes[0]), 403, "passkey_required")
    assert await _trail(admin_conn, org_id, "auth.sso.failed") == [
        {"reason": "passkey_required", "step": "mfa", "mfa_method": "totp"},
        {"reason": "passkey_required", "step": "mfa", "mfa_method": "recovery_code"},
    ]

    # A passkey completes it, into a bound session that signed in with one.
    third = (await sign_in(api, idp, slug, **hardware_key)).json()
    verified = await _with_passkey(api, third["mfa_token"], authenticator)
    session = _session(api, verified, alice.email)
    assert verified.json()["organization_id"] == str(org_id)
    assert (await session.get("/api/v1/projects")).status_code == 200
    assert await _factor(session) == (True, "webauthn")
    success = (await _trail(admin_conn, org_id, "auth.sso.succeeded"))[-1]
    assert (success["mfa"], success["mfa_method"]) == (True, "webauthn")


async def test_single_sign_on_without_a_passkey_gets_nowhere(
    api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
) -> None:
    domain = fresh_domain()
    bob = await signup(api, email=f"bob@{domain}")
    await _enroll_totp(bob, datetime.now(UTC))  # a second factor, but no passkey
    owner = await signup(api)
    idp = FakeIdp()
    slug = await ready(owner, network, idp, domain, trust_idp_mfa=True)
    org_id = await org_id_of(owner)
    await _require_passkeys(api, owner)

    refused = await sign_in(api, idp, slug, email=bob.email, amr=["pwd", "otp"])
    expect_error(refused, 403, "passkey_required")
    # Nor does a newcomer - an account created now would have no password to
    # register a passkey with: refused before anything is created.
    newcomer = f"newcomer@{domain}"
    expect_error(await sign_in(api, idp, slug, email=newcomer), 403, "passkey_required")
    assert await admin_conn.fetchval("SELECT count(*) FROM users WHERE email = $1", newcomer) == 0
    reasons = [entry["reason"] for entry in await _trail(admin_conn, org_id, "auth.sso.failed")]
    assert reasons == ["passkey_required", "passkey_required"]

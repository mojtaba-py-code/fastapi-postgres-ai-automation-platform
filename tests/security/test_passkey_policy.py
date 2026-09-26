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
  refused the organization - and cannot register a passkey from that session
  (a code is what a phishing site relays). An operator resets their second
  factors; they register a first passkey again (the set-up mode) and sign in
  with it. What else binds an account to passkeys is in
  ``test_passkey_bound_accounts.py``.
* Single sign-on: the provider's MFA never stands in for a passkey, trusted or
  not. The platform's step offers a passkey only and completes only with one; a
  code is refused (and audited), and a person without a passkey gets nowhere.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import asyncpg
import httpx2
import pytest

from nexusflow.apps.cli.main import build_parser
from nexusflow.bootstrap.container import Container
from nexusflow.core.clock import FrozenClock
from tests.support.api import signup
from tests.support.business import expect_error, org_id_of
from tests.support.fixtures import PASSWORD
from tests.support.mfa import (
    ORG,
    REGISTER_BEGIN,
    REQUIRE,
    SESSIONS,
    STEP,
    code_session,
    enroll_totp,
    factor_of,
    join_organization,
    passkey_session,
    password_session,
    password_step,
    register_passkey,
    require_passkeys,
    session_from,
    trail,
    with_code,
    with_passkey,
)
from tests.support.oidc import FakeIdp, FakeNetwork, fresh_domain, ready, session_of, sign_in

pytestmark = [pytest.mark.security, pytest.mark.integration]

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
    authenticator, registered = await register_passkey(owner)
    expect_error(await owner.patch(ORG, json=REQUIRE), 422, "would_lock_you_out")
    # ... a session that signed in with a recovery code ...
    by_code = await code_session(api, owner.email, registered["recovery_codes"][0])
    expect_error(await by_code.patch(ORG, json=REQUIRE), 422, "would_lock_you_out")
    # ... and an API key: the policy does not reach it, and it shows no one
    # could still sign in.
    expect_error(await api.patch(ORG, json=REQUIRE, headers=key), 422, "would_lock_you_out")
    assert (await owner.get(ORG)).json()["settings"]["require_passkey"] is False

    # A session that signed in with a passkey turns it on - audited.
    by_passkey = await passkey_session(api, owner.email, authenticator)
    enabled = await by_passkey.patch(ORG, json=REQUIRE)
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["settings"]["require_passkey"] is True
    assert (await by_passkey.get(ORG)).json()["settings"]["require_passkey"] is True
    assert (await trail(admin_conn, org_id, "org.updated"))[-1] == {
        "settings": {"require_passkey": True}
    }
    expect_error(await by_code.get(ORG), 403, "passkey_required")

    # API keys are not sessions: the key still works ...
    assert (await api.get(ORG, headers=key)).status_code == 200
    # ... and turning the policy off is always allowed, even from it.
    lifted = await api.patch(ORG, json={"settings": {"require_passkey": False}}, headers=key)
    assert lifted.status_code == 200, lifted.text
    assert lifted.json()["settings"]["require_passkey"] is False
    assert (await trail(admin_conn, org_id, "org.updated"))[-1] == {
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
    totp, _ = await enroll_totp(owner, clock.now() - STEP)
    admin, _ = await require_passkeys(api, owner)

    # Password and TOTP, the organization being the default: the session opens
    # in it, and every request to it is refused ...
    signed_in = await with_code(api, await password_step(api, owner.email), totp.at(clock.now()))
    by_totp = session_from(api, signed_in, owner.email)
    assert signed_in.json()["organization_id"] == str(org_id)
    refused = expect_error(await by_totp.get(ORG), 403, "passkey_required")
    assert refused["message"].startswith("This organization requires signing in with a passkey")
    for path in ("/api/v1/projects", SESSIONS):
        expect_error(await by_totp.get(path), 403, "passkey_required")
    # ... but the set-up endpoints answer for the account - which has a passkey
    # already, so only a session that signed in with one adds another.
    begun = await by_totp.post(REGISTER_BEGIN, json={"password": PASSWORD})
    expect_error(begun, 403, "passkey_session_required")

    # Naming the organization at sign-in is refused, and its trail shows it.
    named = await with_code(
        api, await password_step(api, owner.email, org_id), totp.at(clock.now() + STEP)
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
    assert (
        await session_from(api, renewed, owner.email).get("/api/v1/projects")
    ).status_code == 200
    assert await factor_of(admin) == (True, "webauthn")


async def test_switching_into_the_organization_needs_a_passkey_session(
    api: httpx2.AsyncClient, admin_conn: asyncpg.Connection, container: Container
) -> None:
    admin, _ = await require_passkeys(api, await signup(api))
    org_id = await org_id_of(admin)
    bob = await signup(api)  # his own organization comes first
    authenticator, _ = await register_passkey(bob)
    enrolled_at = datetime.now(UTC)
    totp, _ = await enroll_totp(bob, enrolled_at)
    await join_organization(admin, bob, container, admin_conn)
    switch = {"organization_id": str(org_id)}

    by_totp = await code_session(api, bob.email, totp.at(enrolled_at + STEP))
    assert (await by_totp.get(ORG)).json()["id"] != str(org_id)  # his own organization
    refused = await by_totp.post("/api/v1/auth/switch-organization", json=switch)
    expect_error(refused, 403, "passkey_required")

    by_passkey = await passkey_session(api, bob.email, authenticator)
    switched = await by_passkey.post("/api/v1/auth/switch-organization", json=switch)
    assert (await session_from(api, switched, bob.email).get(ORG)).json()["id"] == str(org_id)


# ------------------------------------------------------------ the record


async def test_each_session_records_the_second_factor_it_passed(
    api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
) -> None:
    owner = await signup(api)
    authenticator, _ = await register_passkey(owner)
    by_passkey = await passkey_session(api, owner.email, authenticator)
    # An authenticator app set up in a passkey session leaves it a passkey session.
    enrolled_at = datetime.now(UTC)
    totp, codes = await enroll_totp(by_passkey, enrolled_at)
    by_totp = await code_session(api, owner.email, totp.at(enrolled_at + STEP))
    by_code = await code_session(api, owner.email, codes[0])

    # Registering the first passkey made the sign-up session MFA-verified, but
    # no passkey session: it signed in with none.
    assert await factor_of(owner) == (True, None)
    assert await factor_of(by_passkey) == (True, "webauthn")
    assert await factor_of(by_totp) == (True, "totp")
    assert await factor_of(by_code) == (True, "recovery_code")
    exported = (await by_totp.get("/api/v1/users/me/export")).json()["sessions"]
    assert sorted(str(session["mfa_method"]) for session in exported) == [
        "None",
        "recovery_code",
        "totp",
        "webauthn",
    ]

    # Confirming TOTP in a session that had passed no factor records TOTP.
    newcomer = await signup(api)
    await enroll_totp(newcomer, datetime.now(UTC))
    assert await factor_of(newcomer) == (True, "totp")
    stored = await admin_conn.fetch(
        "SELECT mfa_verified, mfa_method FROM user_sessions WHERE user_id ="
        " (SELECT id FROM users WHERE email = $1)",
        newcomer.email,
    )
    assert [(row["mfa_verified"], row["mfa_method"]) for row in stored] == [(True, "totp")]


# ----------------------------------------------------------------- recovery


async def test_an_owner_who_lost_every_passkey_gets_back_in_through_an_operator(
    api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
) -> None:
    owner = await signup(api)
    org_id = await org_id_of(owner)
    # Signed in on another device before any second factor: it never passed one.
    old_laptop = await password_session(api, owner.email)
    lost, registered = await register_passkey(owner)
    admin = await passkey_session(api, owner.email, lost)
    assert (await admin.patch(ORG, json=REQUIRE)).status_code == 200

    # Every passkey lost, a recovery code signs in - to a session the
    # organization refuses, and from which no passkey is added: a code is
    # what a phishing site relays.
    recovered = await code_session(api, owner.email, registered["recovery_codes"][0])
    expect_error(await recovered.get(ORG), 403, "passkey_required")
    begun = await recovered.post(REGISTER_BEGIN, json={"password": PASSWORD})
    expect_error(begun, 403, "passkey_session_required")
    # Nor from a session that passed no second factor, as ever.
    expect_error(await old_laptop.get(ORG), 403, "passkey_required")
    begun = await old_laptop.post(REGISTER_BEGIN, json={"password": PASSWORD})
    expect_error(begun, 403, "mfa_session_required")

    # An operator, having checked who they are, resets their second factors ...
    reset = build_parser().parse_args(
        ["user", "reset-second-factors", "--email", owner.email, "--reason", "ticket 7: lost"]
    )
    await reset.handler(container, reset)
    # ... and they start again: the password - a session in the organization,
    # refused but for the set-up endpoints - then a first passkey, then a
    # sign-in with it. The organization's trail shows the first passkey.
    fresh = await password_session(api, owner.email)
    expect_error(await fresh.get(ORG), 403, "passkey_required")
    replacement, _ = await register_passkey(fresh)
    assert len(await trail(admin_conn, org_id, "auth.webauthn.registered_without_passkey")) == 1
    back = await passkey_session(api, owner.email, replacement)
    assert (await back.get(ORG)).status_code == 200
    assert await factor_of(back) == (True, "webauthn")


# ------------------------------------------------------------ single sign-on


async def test_the_providers_mfa_never_stands_in_for_a_passkey(
    api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
) -> None:
    domain = fresh_domain()
    alice = await signup(api, email=f"alice@{domain}")
    authenticator, _ = await register_passkey(alice)
    enrolled_at = datetime.now(UTC)
    totp, codes = await enroll_totp(alice, enrolled_at)
    owner = await signup(api)
    idp = FakeIdp()
    slug = await ready(owner, network, idp, domain, trust_idp_mfa=True)
    org_id = await org_id_of(owner)
    hardware_key = {"email": alice.email, "amr": ["pwd", "hwk"]}  # reported, and trusted

    # Before the policy, the trusted provider's MFA made her session
    # MFA-verified - with no platform factor recorded ...
    earlier = session_of(api, await sign_in(api, idp, slug, **hardware_key), alice.email)
    assert await factor_of(earlier) == (True, None)
    await require_passkeys(api, owner)
    # ... so once passkeys are required, that session is refused.
    expect_error(await earlier.get("/api/v1/projects"), 403, "passkey_required")

    # The platform asks for its own step - a passkey, and nothing else.
    challenge = await sign_in(api, idp, slug, **hardware_key)
    body = challenge.json()
    assert body["mfa_required"] is True and "access_token" not in body, body
    assert body["methods"] == ["webauthn"]
    # A TOTP or recovery code proves the account, not a passkey: refused, audited.
    by_totp = await with_code(api, body["mfa_token"], totp.at(enrolled_at + STEP))
    expect_error(by_totp, 403, "passkey_required")
    again = (await sign_in(api, idp, slug, **hardware_key)).json()
    expect_error(await with_code(api, again["mfa_token"], codes[0]), 403, "passkey_required")
    assert await trail(admin_conn, org_id, "auth.sso.failed") == [
        {"reason": "passkey_required", "step": "mfa", "mfa_method": "totp"},
        {"reason": "passkey_required", "step": "mfa", "mfa_method": "recovery_code"},
    ]

    # A passkey completes it, into a bound session that signed in with one.
    third = (await sign_in(api, idp, slug, **hardware_key)).json()
    verified = await with_passkey(api, third["mfa_token"], authenticator)
    session = session_from(api, verified, alice.email)
    assert verified.json()["organization_id"] == str(org_id)
    assert (await session.get("/api/v1/projects")).status_code == 200
    assert await factor_of(session) == (True, "webauthn")
    success = (await trail(admin_conn, org_id, "auth.sso.succeeded"))[-1]
    assert (success["mfa"], success["mfa_method"]) == (True, "webauthn")


async def test_single_sign_on_without_a_passkey_gets_nowhere(
    api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
) -> None:
    domain = fresh_domain()
    bob = await signup(api, email=f"bob@{domain}")
    await enroll_totp(bob, datetime.now(UTC))  # a second factor, but no passkey
    owner = await signup(api)
    idp = FakeIdp()
    slug = await ready(owner, network, idp, domain, trust_idp_mfa=True)
    org_id = await org_id_of(owner)
    await require_passkeys(api, owner)

    refused = await sign_in(api, idp, slug, email=bob.email, amr=["pwd", "otp"])
    expect_error(refused, 403, "passkey_required")
    # Nor does a newcomer - an account created now would have no password to
    # register a passkey with: refused before anything is created.
    newcomer = f"newcomer@{domain}"
    expect_error(await sign_in(api, idp, slug, email=newcomer), 403, "passkey_required")
    assert await admin_conn.fetchval("SELECT count(*) FROM users WHERE email = $1", newcomer) == 0
    reasons = [entry["reason"] for entry in await trail(admin_conn, org_id, "auth.sso.failed")]
    assert reasons == ["passkey_required", "passkey_required"]

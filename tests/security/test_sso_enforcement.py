"""An organization that requires single sign-on, and what an identity
provider's session may do.

* Members reach such an organization only with a session its identity
  provider opened - not with a password session, not by switching into it and
  not by naming it at sign-in (which the organization's trail shows).
* Owners keep a break-glass way in: password plus the platform's own MFA. An
  administrator with the same does not get in. Setting MFA up stays possible.
* API keys are unaffected (they are machine credentials, confined by their
  scopes and the network allowlist).
* An identity provider's session is its organization's only: account-wide
  actions from it (the session list, ending sessions, the personal-data
  export) never reach the person's other organizations or sessions, and it
  leaves the account's own security alone - password, second factors, the
  account itself - even when the provider's MFA made it MFA-verified.
"""

from __future__ import annotations

from uuid import uuid4

import asyncpg
import httpx2
import pyotp
import pytest

from tests.support.api import ApiSession, signup
from tests.support.business import expect_error, org_id_of
from tests.support.fixtures import PASSWORD
from tests.support.oidc import (
    FakeIdp,
    FakeNetwork,
    configure,
    fresh_domain,
    ready,
    session_of,
    sign_in,
)

pytestmark = [pytest.mark.security, pytest.mark.integration]

ORG = "/api/v1/organizations/current"


async def _enroll_mfa(session: ApiSession) -> list[str]:
    enrolled = await session.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD})
    assert enrolled.status_code == 200, enrolled.text
    code = pyotp.TOTP(enrolled.json()["secret"]).now()
    confirmed = await session.post("/api/v1/auth/mfa/confirm", json={"code": code})
    assert confirmed.status_code == 200, confirmed.text
    codes: list[str] = confirmed.json()["recovery_codes"]
    return codes


async def _require_sso(
    api: httpx2.AsyncClient, network: FakeNetwork
) -> tuple[ApiSession, ApiSession, FakeIdp, str, str]:
    """An organization that requires single sign-on. Returns its owner's
    password session, the owner's SSO session, the provider, the slug and domain."""
    domain = fresh_domain()
    owner = await signup(api, email=f"owner@{domain}")
    idp = FakeIdp()
    slug = await ready(owner, network, idp, domain)
    owner_sso = session_of(api, await sign_in(api, idp, slug, email=owner.email), owner.email)
    required = await configure(owner_sso, idp, [domain], sso_required=True)
    assert required.status_code == 200, required.text
    assert required.json()["sso_required"] is True
    return owner, owner_sso, idp, slug, domain


async def test_members_reach_the_organization_only_through_its_identity_provider(
    api: httpx2.AsyncClient, network: FakeNetwork
) -> None:
    _, owner_sso, idp, slug, domain = await _require_sso(api, network)
    org_id = await org_id_of(owner_sso)
    carol = await signup(api, email=f"carol@{domain}")  # her own organization, by password
    carol_sso = session_of(api, await sign_in(api, idp, slug, email=carol.email), carol.email)
    assert (await carol_sso.get(ORG)).status_code == 200

    # Her password session cannot switch into it ...
    switched = await carol.post(
        "/api/v1/auth/switch-organization", json={"organization_id": str(org_id)}
    )
    expect_error(switched, 403, "sso_required")
    # ... nor sign in to it by name, and the organization sees the attempt.
    named = await api.post(
        "/api/v1/auth/login",
        json={"email": carol.email, "password": PASSWORD, "organization_id": str(org_id)},
    )
    expect_error(named, 403, "sso_required")
    denied = await owner_sso.get("/api/v1/audit", params={"action": "auth.login.failed"})
    [event] = denied.json()["items"]
    assert (event["metadata"], event["result"]) == (
        {"reason": "sso_required", "mfa": False},
        "denied",
    )
    # Signing in without naming it still works: her own organization opens.
    plain = await api.post("/api/v1/auth/login", json={"email": carol.email, "password": PASSWORD})
    assert plain.json()["organization_id"] == str(await org_id_of(carol))


async def test_owners_break_the_glass_with_password_and_mfa_administrators_do_not(
    api: httpx2.AsyncClient, network: FakeNetwork
) -> None:
    owner, owner_sso, idp, slug, domain = await _require_sso(api, network)
    org_id = await org_id_of(owner_sso)
    expect_error(await owner.get(ORG), 403, "sso_required")  # password, no MFA
    await _enroll_mfa(owner)  # still possible: the enrolment endpoints stay open
    assert (await owner.get(ORG)).status_code == 200  # password + MFA: the owner is in

    # Signing in afresh with password and TOTP opens it too.
    challenge = await api.post(
        "/api/v1/auth/login",
        json={"email": owner.email, "password": PASSWORD, "organization_id": str(org_id)},
    )
    assert challenge.json()["mfa_required"] is True

    # An administrator with password and MFA does not get in.
    dave = await signup(api, email=f"dave@{domain}")
    await sign_in(api, idp, slug, email=dave.email)  # joins as viewer
    members = (await owner_sso.get(f"{ORG}/members")).json()["items"]
    [membership] = [m for m in members if m["email"] == dave.email]
    promoted = await owner_sso.patch(
        f"{ORG}/members/{membership['membership_id']}", json={"role": "admin"}
    )
    assert promoted.status_code == 204, promoted.text
    await _enroll_mfa(dave)
    switched = await dave.post(
        "/api/v1/auth/switch-organization", json={"organization_id": str(org_id)}
    )
    expect_error(switched, 403, "sso_required")


async def test_api_keys_are_not_affected(api: httpx2.AsyncClient, network: FakeNetwork) -> None:
    domain = fresh_domain()
    owner = await signup(api, email=f"owner@{domain}")
    key = await owner.post(
        "/api/v1/api-keys",
        json={"name": "ci", "role": "viewer", "scopes": ["projects:read"], "expires_in_days": 1},
    )
    headers = {"Authorization": f"Bearer {key.json()['token']}"}
    idp = FakeIdp()
    slug = await ready(owner, network, idp, domain)
    owner_sso = session_of(api, await sign_in(api, idp, slug, email=owner.email), owner.email)
    assert (await configure(owner_sso, idp, [domain], sso_required=True)).status_code == 200
    assert (await api.get("/api/v1/projects", headers=headers)).status_code == 200


async def test_a_single_sign_on_session_keeps_to_its_organization(
    api: httpx2.AsyncClient, network: FakeNetwork
) -> None:
    domain = fresh_domain()
    alice = await signup(api, email=f"alice@{domain}")  # a password session, her own org
    owner = await signup(api)
    idp = FakeIdp()
    slug = await ready(owner, network, idp, domain)
    sso = session_of(api, await sign_in(api, idp, slug, email=alice.email), alice.email)

    # The session list shows the provider's sessions only ...
    listed = (await sso.get("/api/v1/users/me/sessions")).json()
    assert [s["current"] for s in listed] == [True]
    everything = (await alice.get("/api/v1/users/me/sessions")).json()
    assert len(everything) == 2
    [password_session] = [s for s in everything if s["current"]]
    # ... another session of the account does not exist for it ...
    ended = await sso.delete(f"/api/v1/users/me/sessions/{password_session['id']}")
    expect_error(ended, 404)
    # ... the personal-data export (every organization of the person) is refused ...
    expect_error(await sso.get("/api/v1/users/me/export"), 403, "sso_session_restricted")
    # ... and "log out everywhere" ends the provider's sessions only.
    assert (await sso.post("/api/v1/auth/logout-all")).status_code == 204
    expect_error(await sso.get("/api/v1/users/me"), 401)
    assert (await alice.get("/api/v1/users/me")).status_code == 200


ACCOUNT_SECURITY = [
    ("post", "/api/v1/auth/webauthn/register/begin", {"password": PASSWORD}),
    ("get", "/api/v1/auth/webauthn/credentials", None),
    ("patch", "/api/v1/auth/webauthn/credentials/{passkey}", {"name": "Mine now"}),
    ("post", "/api/v1/auth/webauthn/credentials/{passkey}/delete", {"password": PASSWORD}),
    ("post", "/api/v1/auth/mfa/enroll", {"password": PASSWORD}),
    ("post", "/api/v1/auth/mfa/confirm", {"code": "123456"}),
    ("post", "/api/v1/auth/mfa/disable", {"password": PASSWORD, "code": "123456"}),
    (
        "post",
        "/api/v1/auth/password/change",
        {"current_password": PASSWORD, "new_password": "Another-long-passphrase-7"},
    ),
    ("post", "/api/v1/users/me/delete", {"password": PASSWORD}),
]


async def test_a_single_sign_on_session_leaves_the_accounts_security_alone(
    api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
) -> None:
    domain = fresh_domain()
    alice = await signup(api, email=f"alice@{domain}")
    await _enroll_mfa(alice)  # the account has a second factor
    owner = await signup(api)
    idp = FakeIdp()
    slug = await ready(owner, network, idp, domain)
    await admin_conn.execute(
        "UPDATE sso_connections SET trust_idp_mfa = true WHERE org_id = $1",
        await org_id_of(owner),
    )
    signed_in = await sign_in(api, idp, slug, email=alice.email, amr=["pwd", "hwk"])
    sso = session_of(api, signed_in, alice.email)
    # The provider's MFA counts - for its organization ...
    [current] = (await sso.get("/api/v1/users/me/sessions")).json()
    assert current["mfa_verified"] is True
    # ... never for the account, which every organization of the person relies on.
    passkey = str(uuid4())
    for method, path, body in ACCOUNT_SECURITY:
        call = getattr(sso, method)
        url = path.format(passkey=passkey)
        response = await (call(url) if body is None else call(url, json=body))
        expect_error(response, 403, "sso_session_restricted")
    # Refused before any password was checked: nothing counted toward the
    # lockout, and the account is as it was.
    account = await admin_conn.fetchrow(
        "SELECT failed_login_attempts, status, mfa_enabled FROM users WHERE email = $1",
        alice.email,
    )
    assert tuple(account) == (0, "active", True)
    # Her password session, which passed her second factor, still manages them.
    assert (await alice.get("/api/v1/auth/webauthn/credentials")).status_code == 200


async def test_leaving_the_organization_ends_the_single_sign_on_session(
    api: httpx2.AsyncClient, network: FakeNetwork
) -> None:
    owner = await signup(api)
    domain = fresh_domain()
    idp = FakeIdp()
    slug = await ready(owner, network, idp, domain)
    email = f"leaver@{domain}"
    member = session_of(api, await sign_in(api, idp, slug, email=email), email)
    members = (await owner.get(f"{ORG}/members")).json()["items"]
    [membership] = [m for m in members if m["email"] == email]
    removed = await owner.delete(f"{ORG}/members/{membership['membership_id']}")
    assert removed.status_code == 204, removed.text
    expect_error(await member.get(ORG), 401)
    refreshed = await api.post("/api/v1/auth/refresh", json={"refresh_token": member.refresh_token})
    expect_error(refreshed, 401, "invalid_refresh_token")

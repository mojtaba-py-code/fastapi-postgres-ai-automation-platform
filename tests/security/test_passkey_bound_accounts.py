"""Accounts bound to passkeys: a phishable factor mints no passkey for them.

An account is bound to passkeys while it belongs to an active organization
that requires them. Then:

* its passkeys are added and removed - and MFA turned off - only from a session
  that signed in with one of its passkeys (``403 passkey_session_required``):
  whoever relays its password and a TOTP code through a phishing site cannot
  plant a passkey of their own, take the member's away, or wipe every factor
  to start afresh;
* only its very first passkey comes from another session - how a member
  starts - and each binding organization's own trail shows it, and its owners
  and administrators are e-mailed;
* an operator resets the second factors of a member who lost them all
  (``nexusflow user reset-second-factors``), audited with the reason; the
  member then starts again - announced as above.

Accounts that are not bound keep the ordinary rules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import asyncpg
import httpx2
import pyotp
import pytest

from nexusflow.apps.cli.main import build_parser
from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import InvalidInputError, NotFoundError
from tests.support.api import ApiSession, signup
from tests.support.business import expect_error, org_id_of
from tests.support.fixtures import PASSWORD
from tests.support.mfa import (
    ORG,
    PASSKEYS,
    REGISTER_BEGIN,
    REGISTER_FINISH,
    STEP,
    code_session,
    enroll_totp,
    join_organization,
    passkey_session,
    password_session,
    password_step,
    register_passkey,
    require_passkeys,
    session_from,
    trail,
    with_passkey,
)
from tests.support.webauthn import SoftwareAuthenticator

pytestmark = [pytest.mark.security, pytest.mark.integration]

DISABLE = "/api/v1/auth/mfa/disable"
ANNOUNCED = "auth.webauthn.registered_without_passkey"
NOTICE = "member_first_passkey"


@dataclass
class Bound:
    """Bob, bound to passkeys by an organization he joined."""

    admin: ApiSession  # the organization's owner, signed in with a passkey
    org_id: UUID  # the organization that requires passkeys
    bob: ApiSession  # his sign-up session; his own organization comes first
    totp: pyotp.TOTP
    enrolled_at: datetime
    codes: list[str]  # recovery codes
    authenticator: SoftwareAuthenticator | None  # his passkey, if any


async def _bound_member(
    api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection, *, passkey: bool
) -> Bound:
    """TOTP - and a passkey when ``passkey`` - set up before Bob joins."""
    admin, _ = await require_passkeys(api, await signup(api))
    bob = await signup(api)
    authenticator = (await register_passkey(bob))[0] if passkey else None
    enrolled_at = datetime.now(UTC)
    totp, codes = await enroll_totp(bob, enrolled_at)
    await join_organization(admin, bob, container, admin_conn)
    return Bound(admin, await org_id_of(admin), bob, totp, enrolled_at, codes, authenticator)


async def _cli(container: Container, *argv: str) -> Any:
    args = build_parser().parse_args(argv)
    return await args.handler(container, args)


async def _user_id(admin_conn: asyncpg.Connection, email: str) -> UUID:
    user_id: UUID = await admin_conn.fetchval("SELECT id FROM users WHERE email = $1", email)
    return user_id


async def _notices(admin_conn: asyncpg.Connection, member_id: UUID) -> list[dict[str, Any]]:
    """The queued notices about ``member_id``'s first passkey."""
    rows = await admin_conn.fetch(
        "SELECT payload FROM outbox_messages WHERE task = 'security.send_email'"
        " AND payload->>'template' = $1 AND payload->>'member_id' = $2",
        NOTICE,
        str(member_id),
    )
    return [json.loads(row["payload"]) for row in rows]


async def _templates_for(admin_conn: asyncpg.Connection, user_id: UUID) -> list[str]:
    rows = await admin_conn.fetch(
        "SELECT payload->>'template' AS template FROM outbox_messages"
        " WHERE task = 'security.send_email' AND payload->>'user_id' = $1",
        str(user_id),
    )
    return [row["template"] for row in rows]


async def _passkey_count(admin_conn: asyncpg.Connection, user_id: UUID) -> int:
    count: int = await admin_conn.fetchval(
        "SELECT count(*) FROM webauthn_credentials WHERE user_id = $1", user_id
    )
    return count


# ------------------------------------------------------------- the rule


async def test_a_session_that_passed_a_code_changes_no_passkey_of_a_bound_account(
    api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
) -> None:
    admin, _ = await require_passkeys(api, await signup(api))
    bob = await signup(api)  # his own organization comes first
    authenticator, _ = await register_passkey(bob)
    enrolled_at = datetime.now(UTC)
    totp, codes = await enroll_totp(bob, enrolled_at)
    # What a phishing site relays in real time: the password and a TOTP code.
    phished = await code_session(api, bob.email, totp.at(enrolled_at + STEP))
    pending = await phished.post(REGISTER_BEGIN, json={"password": PASSWORD})
    assert pending.status_code == 200, pending.text  # Bob is not bound yet
    await join_organization(admin, bob, container, admin_conn)
    bob_id = await _user_id(admin_conn, bob.email)

    # Bound now: the pending registration is refused when it finishes ...
    credential = SoftwareAuthenticator().attestation(pending.json()["options"])
    finished = await phished.post(REGISTER_FINISH, json={"credential": credential})
    refused = expect_error(finished, 403, "passkey_session_required")
    assert refused["message"] == (
        "Add passkeys from a session that signed in with one of your passkeys."
    )
    # ... and a new one when it starts.
    begun = await phished.post(REGISTER_BEGIN, json={"password": PASSWORD})
    expect_error(begun, 403, "passkey_session_required")
    # Nor does such a session remove his passkey, or wipe every factor with a code.
    [listed] = (await phished.get(PASSKEYS)).json()
    removal = await phished.post(f"{PASSKEYS}/{listed['id']}/delete", json={"password": PASSWORD})
    expect_error(removal, 403, "passkey_session_required")
    wipe = await phished.post(DISABLE, json={"password": PASSWORD, "code": codes[0]})
    expect_error(wipe, 403, "passkey_session_required")
    # Refused before the code was checked: no recovery code was used up.
    unused = await admin_conn.fetchval(
        "SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL", bob_id
    )
    assert unused == len(codes)
    assert await _passkey_count(admin_conn, bob_id) == 1

    # His passkey session adds and removes passkeys.
    by_passkey = await passkey_session(api, bob.email, authenticator)
    await register_passkey(by_passkey)
    first, second = (await by_passkey.get(PASSKEYS)).json()
    removed = await by_passkey.post(f"{PASSKEYS}/{first['id']}/delete", json={"password": PASSWORD})
    assert removed.status_code == 204, removed.text
    assert [p["id"] for p in (await by_passkey.get(PASSKEYS)).json()] == [second["id"]]


async def test_a_passkey_session_turns_mfa_off(
    api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
) -> None:
    bound = await _bound_member(api, container, admin_conn, passkey=True)
    assert bound.authenticator is not None
    by_passkey = await passkey_session(api, bound.bob.email, bound.authenticator)
    disabled = await by_passkey.post(DISABLE, json={"password": PASSWORD, "code": bound.codes[0]})
    assert disabled.status_code == 204, disabled.text
    bob_id = await _user_id(admin_conn, bound.bob.email)
    assert not await admin_conn.fetchval("SELECT mfa_enabled FROM users WHERE id = $1", bob_id)
    assert await _passkey_count(admin_conn, bob_id) == 0
    expect_error(await by_passkey.get("/api/v1/users/me"), 401)  # every session ended


# ------------------------------------------------------ the first passkey


async def test_a_bound_members_first_passkey_is_announced_to_the_organization(
    api: httpx2.AsyncClient,
    container: Container,
    admin_conn: asyncpg.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bound = await _bound_member(api, container, admin_conn, passkey=False)
    carol = await signup(api)
    await join_organization(bound.admin, carol, container, admin_conn, role="admin")
    bob_id = await _user_id(admin_conn, bound.bob.email)
    own_org = await org_id_of(bound.bob)

    # From a session that signed in with TOTP: his first passkey - allowed.
    by_totp = await code_session(api, bound.bob.email, bound.totp.at(bound.enrolled_at + STEP))
    await register_passkey(by_totp)
    passkey_id = await admin_conn.fetchval(
        "SELECT id FROM webauthn_credentials WHERE user_id = $1", bob_id
    )
    # The organization's own trail shows it ...
    assert await trail(admin_conn, bound.org_id, ANNOUNCED) == [
        {"user_id": str(bob_id), "session_mfa_method": "totp"}
    ]
    entry = await admin_conn.fetchrow(
        "SELECT actor_id, resource_id FROM audit_logs WHERE org_id = $1 AND action = $2",
        bound.org_id,
        ANNOUNCED,
    )
    assert (entry["actor_id"], entry["resource_id"]) == (bob_id, str(passkey_id))
    assert await trail(admin_conn, own_org, ANNOUNCED) == []  # not a binding organization
    # ... and its owner and administrator are e-mailed - Bob as the account's owner.
    owner_id = await _user_id(admin_conn, bound.admin.email)
    carol_id = await _user_id(admin_conn, carol.email)
    notices = await _notices(admin_conn, bob_id)
    assert sorted(notice["user_id"] for notice in notices) == sorted([str(owner_id), str(carol_id)])
    assert {notice["org_id"] for notice in notices} == {str(bound.org_id)}
    assert "passkey_added" in await _templates_for(admin_conn, bob_id)

    # A second passkey needs a passkey session.
    again = await by_totp.post(REGISTER_BEGIN, json={"password": PASSWORD})
    expect_error(again, 403, "passkey_session_required")
    # Carol, an administrator without MFA, starts too - from her password
    # session. The owner is told; she is not told about herself.
    await register_passkey(carol)
    assert [notice["user_id"] for notice in await _notices(admin_conn, carol_id)] == [str(owner_id)]
    assert (await trail(admin_conn, bound.org_id, ANNOUNCED))[-1] == {
        "user_id": str(carol_id),
        "session_mfa_method": None,
    }

    # The notice names the member by address, and the organization.
    sent: list[tuple[list[str], str, str]] = []

    class Recording:
        async def send_email(self, recipients: list[str], subject: str, body: str) -> None:
            sent.append((recipients, subject, body))

    monkeypatch.setattr(container.security_emails, "_email", Recording())
    assert await container.security_emails.send_notification(
        user_id=owner_id, template=NOTICE, member_id=bob_id, org_id=bound.org_id
    )
    org_name = (await bound.admin.get(ORG)).json()["name"]
    [(recipients, subject, body)] = sent
    assert recipients == [bound.admin.email]
    assert subject == f"A member of {org_name} registered their first passkey"
    assert bound.bob.email in body and org_name in body and ANNOUNCED in body


# ---------------------------------------------------------- not bound


async def test_accounts_that_are_not_bound_keep_the_ordinary_rules(
    api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
) -> None:
    # Dave belongs to no organization that requires passkeys: a session that
    # passed TOTP adds a passkey, removes one and turns MFA off, as ever.
    dave = await signup(api)
    await register_passkey(dave)
    enrolled_at = datetime.now(UTC)
    totp, codes = await enroll_totp(dave, enrolled_at)
    by_totp = await code_session(api, dave.email, totp.at(enrolled_at + STEP))
    await register_passkey(by_totp)
    first, _ = (await by_totp.get(PASSKEYS)).json()
    removed = await by_totp.post(f"{PASSKEYS}/{first['id']}/delete", json={"password": PASSWORD})
    assert removed.status_code == 204, removed.text
    disabled = await by_totp.post(DISABLE, json={"password": PASSWORD, "code": codes[0]})
    assert disabled.status_code == 204, disabled.text

    # Bob belongs to one that does - but it is suspended, so it binds nobody.
    bound = await _bound_member(api, container, admin_conn, passkey=True)
    await admin_conn.execute(
        "UPDATE organizations SET status = 'suspended' WHERE id = $1", bound.org_id
    )
    by_totp = await code_session(api, bound.bob.email, bound.totp.at(bound.enrolled_at + STEP))
    await register_passkey(by_totp)

    for email in (dave.email, bound.bob.email):
        member_id = await _user_id(admin_conn, email)
        assert await _notices(admin_conn, member_id) == []
        assert not await admin_conn.fetchval(
            "SELECT count(*) FROM audit_logs WHERE action = $1 AND actor_id = $2",
            ANNOUNCED,
            member_id,
        )


# ------------------------------------------------------ operator reset


async def test_an_operator_resets_the_second_factors_of_a_member_who_lost_them(
    api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
) -> None:
    bound = await _bound_member(api, container, admin_conn, passkey=True)
    bob_id = await _user_id(admin_conn, bound.bob.email)
    own_org = await org_id_of(bound.bob)
    reason = "ticket 99: identity checked on a video call"

    result = await _cli(
        container, "user", "reset-second-factors", "--email", bound.bob.email, "--reason", reason
    )

    assert result == {
        "user_id": bob_id,
        "passkeys_removed": 1,
        "authenticator_app_removed": True,
        "sessions_ended": True,
    }
    account = await admin_conn.fetchrow(
        "SELECT mfa_enabled, mfa_secret_encrypted FROM users WHERE id = $1", bob_id
    )
    assert (account["mfa_enabled"], account["mfa_secret_encrypted"]) == (False, None)
    assert await _passkey_count(admin_conn, bob_id) == 0
    assert not await admin_conn.fetchval(
        "SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1", bob_id
    )
    expect_error(await bound.bob.get("/api/v1/users/me"), 401)  # every session ended
    entries = await admin_conn.fetch(
        "SELECT org_id, actor_type, metadata FROM audit_logs"
        " WHERE action = 'auth.mfa.reset' AND resource_id = $1",
        str(bob_id),
    )
    # In each of his organizations' trails, and in the platform's.
    assert sorted(str(row["org_id"]) for row in entries) == sorted(
        [str(own_org), str(bound.org_id), "None"]
    )
    for row in entries:
        assert row["actor_type"] == "system"
        assert json.loads(row["metadata"]) == {
            "by": "operator",
            "reason": reason,
            "webauthn_removed": 1,
            "totp_removed": True,
        }
    assert "second_factors_reset" in await _templates_for(admin_conn, bob_id)

    # He starts again: the password, then a first passkey - announced.
    fresh = await password_session(api, bound.bob.email)
    authenticator, _ = await register_passkey(fresh)
    assert await trail(admin_conn, bound.org_id, ANNOUNCED) == [
        {"user_id": str(bob_id), "session_mfa_method": None}
    ]
    signed_in = await with_passkey(
        api, await password_step(api, bound.bob.email, bound.org_id), authenticator
    )
    reached = await session_from(api, signed_in, bound.bob.email).get(ORG)
    assert reached.json()["id"] == str(bound.org_id)


async def test_the_reset_needs_a_reason_and_an_account(container: Container) -> None:
    command = ("user", "reset-second-factors", "--email")
    with pytest.raises(InvalidInputError) as unexplained:
        await _cli(container, *command, "someone@example.com", "--reason", " ")
    assert unexplained.value.code == "reason_required"
    with pytest.raises(NotFoundError):
        await _cli(container, *command, "nobody-here@example.com", "--reason", "ticket 100")

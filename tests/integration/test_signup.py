"""Self-service sign-up proves the e-mail address first.

It used to create the account at once and to answer ``409 email_taken`` for
an address that had one: anyone could learn who has an account, and could
open an account in someone else's name (with a password they chose, before
the owner ever signed up). Now a sign-up stores the address only and mails
it a link; the account is created by whoever opens that link, with the
password chosen then.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import asyncpg
import httpx2
import pytest

from nexusflow.apps.cli.main import build_parser
from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import ConflictError, InvalidInputError, PermissionDeniedError
from nexusflow.domain.authorization.roles import Role
from tests.support.fixtures import META, PASSWORD, register, unique_email

pytestmark = [pytest.mark.integration, pytest.mark.security]


class RecordingEmail:
    def __init__(self) -> None:
        self.sent: list[tuple[list[str], str, str]] = []

    async def send_email(self, recipients: list[str], subject: str, body: str) -> None:
        self.sent.append((recipients, subject, body))


@pytest.fixture
def mailbox(container: Container, monkeypatch: pytest.MonkeyPatch) -> RecordingEmail:
    recording = RecordingEmail()
    monkeypatch.setattr(container.security_emails, "_email", recording)
    return recording


def _now() -> datetime:
    # The application's clock, not the database's: on Windows the two can be
    # milliseconds apart, and events are stamped by the application.
    return datetime.now(UTC)


def _token(body: str) -> str:
    match = re.search(r"/complete-signup#token=([A-Za-z0-9_-]{20,})\s", body)
    assert match, body
    return match[1]


async def _request_id(admin_conn: asyncpg.Connection, email: str) -> UUID:
    request_id: UUID = await admin_conn.fetchval(
        "SELECT id FROM signup_requests WHERE email = $1 ORDER BY id DESC LIMIT 1", email
    )
    assert request_id is not None
    return request_id


async def _audit(admin_conn: asyncpg.Connection, action: str, since: datetime) -> list[dict]:
    rows = await admin_conn.fetch(
        "SELECT action, org_id, resource_id, metadata FROM audit_logs"
        " WHERE action = $1 AND occurred_at >= $2 ORDER BY seq",
        action,
        since,
    )
    return [{**dict(r), "metadata": json.loads(r["metadata"])} for r in rows]


async def _complete(container: Container, token: str, **overrides: str) -> object:
    fields = {
        "password": PASSWORD,
        "full_name": "New Owner",
        "organization_name": f"Signup {uuid4().hex[:6]}",
        **overrides,
    }
    return await container.auth.complete_signup(token=token, meta=META, **fields)


class TestStartingASignUp:
    async def test_a_new_address_is_mailed_a_link_and_nothing_else_happens(
        self, container: Container, admin_conn: asyncpg.Connection, mailbox: RecordingEmail
    ) -> None:
        email = unique_email("new")
        since = _now()
        await container.auth.start_signup(email=email.upper(), meta=META)

        request = await admin_conn.fetchrow("SELECT * FROM signup_requests WHERE email = $1", email)
        assert request is not None
        assert request["token_hash"] is None  # the mail worker creates the token
        assert not request["operator_issued"]
        assert await admin_conn.fetchval("SELECT count(*) FROM users WHERE email = $1", email) == 0
        message = await admin_conn.fetchrow(
            "SELECT task, payload FROM outbox_messages WHERE payload->>'signup_id' = $1",
            str(request["id"]),
        )
        assert message["task"] == "security.send_signup_link"
        assert json.loads(message["payload"]) == {"signup_id": str(request["id"])}  # ids only
        [event] = await _audit(admin_conn, "auth.signup.started", since)
        assert event["org_id"] is None  # the platform chain
        assert event["metadata"]["existing_account"] is False
        assert email not in json.dumps(event["metadata"])  # a keyed hash, not the address

        assert await container.security_emails.send_signup_link(signup_id=request["id"])
        [(recipients, subject, body)] = mailbox.sent
        assert recipients == [email]
        assert subject == "Finish creating your NexusFlow account"
        assert "within 24 hours" in body
        assert _token(body)
        # One token per request, however often the message is delivered.
        assert not await container.security_emails.send_signup_link(signup_id=request["id"])
        assert len(mailbox.sent) == 1

    async def test_a_taken_address_gets_a_notice_and_the_very_same_answer(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email, _ = await register(container)
        since = _now()
        assert await container.auth.start_signup(email=email, meta=META) is None
        pending = "SELECT count(*) FROM signup_requests WHERE email = $1 AND used_at IS NULL"
        assert await admin_conn.fetchval(pending, email) == 0
        user_id = await admin_conn.fetchval("SELECT id FROM users WHERE email = $1", email)
        notices = await admin_conn.fetch(
            "SELECT payload FROM outbox_messages WHERE task = 'security.send_email'"
            " AND payload->>'user_id' = $1",
            str(user_id),
        )
        templates = [json.loads(n["payload"])["template"] for n in notices]
        assert "signup_existing_account" in templates
        [event] = await _audit(admin_conn, "auth.signup.started", since)
        assert event["metadata"]["existing_account"] is True

    async def test_the_mail_carries_nothing_the_requester_chose(
        self, container: Container, admin_conn: asyncpg.Connection, mailbox: RecordingEmail
    ) -> None:
        # Anyone can start a sign-up for any address: the mail must not let them
        # put their words into a message from the platform. The request holds
        # the address only - no name, no organization, no password.
        columns = {
            row["column_name"]
            for row in await admin_conn.fetch(
                "SELECT column_name FROM information_schema.columns"
                " WHERE table_name = 'signup_requests'"
            )
        }
        assert columns == {
            "id",
            "email",
            "token_hash",
            "created_at",
            "expires_at",
            "used_at",
            "requested_ip",
            "operator_issued",
        }
        email = unique_email("victim")
        await container.auth.start_signup(email=email, meta=META)
        await container.security_emails.send_signup_link(
            signup_id=await _request_id(admin_conn, email)
        )
        [(_, _, body)] = mailbox.sent
        assert "no account is created without it" in body

    async def test_switched_off_self_service_refuses_starts_and_its_links(
        self,
        container: Container,
        admin_conn: asyncpg.Connection,
        mailbox: RecordingEmail,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        email = unique_email()
        await container.auth.start_signup(email=email, meta=META)
        await container.security_emails.send_signup_link(
            signup_id=await _request_id(admin_conn, email)
        )
        self_service = _token(mailbox.sent[0][2])
        operator, _ = await container.auth.issue_signup_link(email=unique_email(), meta=META)

        policy = replace(container.auth._policy, signup_enabled=False)
        monkeypatch.setattr(container.auth, "_policy", policy)
        with pytest.raises(PermissionDeniedError) as refused:
            await container.auth.start_signup(email=unique_email(), meta=META)
        assert refused.value.code == "signup_disabled"
        with pytest.raises(PermissionDeniedError):
            await _complete(container, self_service)
        await _complete(container, operator)  # how operators onboard while it is off

    async def test_an_address_must_look_like_one(self, container: Container) -> None:
        for address in ("no-at-sign", "two@@example.com", "spaces in@example.com", "a@b"):
            with pytest.raises(InvalidInputError) as exc:
                await container.auth.issue_signup_link(email=address, meta=META)
            assert exc.value.code == "invalid_email"


class TestFinishingASignUp:
    async def test_the_link_creates_a_verified_owner_and_works_once(
        self, container: Container, admin_conn: asyncpg.Connection, mailbox: RecordingEmail
    ) -> None:
        email = unique_email()
        await container.auth.start_signup(email=email, meta=META)
        await container.security_emails.send_signup_link(
            signup_id=await _request_id(admin_conn, email)
        )
        token = _token(mailbox.sent[0][2])
        tokens = await _complete(container, token)
        principal = await container.authenticator.authenticate(tokens.access_token)  # type: ignore[attr-defined]
        assert principal.role is Role.OWNER
        user = await admin_conn.fetchrow(
            "SELECT email_verified_at, created_at FROM users WHERE email = $1", email
        )
        assert user["email_verified_at"] == user["created_at"]
        with pytest.raises(InvalidInputError) as reused:
            await _complete(container, token)
        assert reused.value.code == "invalid_token"
        result = await container.auth.login(email=email, password=PASSWORD, org_id=None, meta=META)
        assert result.tokens is not None

    async def test_expired_unknown_and_malformed_links_are_refused_alike(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email = unique_email()
        expired, _ = await container.auth.issue_signup_link(email=email, meta=META)
        await admin_conn.execute(
            "UPDATE signup_requests SET expires_at = now() - interval '1 second' WHERE email = $1",
            email,
        )
        codes = set()
        for token in (expired, "unknown-" + uuid4().hex, "x" * 300, ""):
            with pytest.raises(InvalidInputError) as exc:
                await _complete(container, token)
            codes.add((exc.value.code, exc.value.message))
        assert codes == {("invalid_token", "The sign-up link is invalid or has expired.")}
        assert await admin_conn.fetchval("SELECT count(*) FROM users WHERE email = $1", email) == 0

    async def test_the_password_rules_know_the_address(self, container: Container) -> None:
        email = unique_email("robin")
        token, _ = await container.auth.issue_signup_link(email=email, meta=META)
        with pytest.raises(InvalidInputError) as exc:
            await _complete(container, token, password=email + "-2026!")
        assert exc.value.code == "weak_password"
        await _complete(container, token)  # a refused attempt does not use the link up

    async def test_two_links_for_one_address_make_one_account(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email = unique_email()
        first, _ = await container.auth.issue_signup_link(email=email, meta=META)
        second, _ = await container.auth.issue_signup_link(email=email, meta=META)
        await _complete(container, second)
        with pytest.raises(InvalidInputError):
            await _complete(container, first)
        assert await admin_conn.fetchval("SELECT count(*) FROM users WHERE email = $1", email) == 1
        open_requests = await admin_conn.fetchval(
            "SELECT count(*) FROM signup_requests WHERE email = $1 AND used_at IS NULL", email
        )
        assert open_requests == 0

    async def test_the_account_and_its_organization_are_audited(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        since = _now()
        token, _ = await container.auth.issue_signup_link(email=unique_email(), meta=META)
        await _complete(container, token)
        [issued] = await _audit(admin_conn, "auth.signup.link_issued", since)
        assert issued["org_id"] is None
        [registered] = await _audit(admin_conn, "auth.registered", since)
        assert registered["org_id"] is not None  # the new organization's own chain
        assert registered["metadata"] == {"via": "operator_link"}
        [created] = await _audit(admin_conn, "org.created", since)
        assert created["org_id"] == registered["org_id"]


class TestInvitations:
    async def _invite(
        self, container: Container, admin_conn: asyncpg.Connection, email: str
    ) -> tuple[str, UUID]:
        _, owner_tokens = await register(container)
        owner = await container.authenticator.authenticate(owner_tokens.access_token)
        invitation = await container.organizations.invite(
            owner, email=email, role=Role.ANALYST, meta=META
        )
        raw = "invite-" + uuid4().hex
        await admin_conn.execute(
            "UPDATE invitations SET token_hash = $1 WHERE id = $2",
            container.token_hasher.hash(raw),
            invitation.id,
        )
        assert owner.org_id is not None
        return raw, owner.org_id

    async def test_an_invitation_creates_the_account_at_the_invited_address(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email = unique_email("invitee")
        raw, org_id = await self._invite(container, admin_conn, email)
        since = _now()
        tokens = await container.auth.register_invited(
            token=raw, password=PASSWORD, full_name="Invited Analyst", meta=META
        )
        principal = await container.authenticator.authenticate(tokens.access_token)
        assert (principal.org_id, principal.role) == (org_id, Role.ANALYST)
        assert await admin_conn.fetchval(
            "SELECT email_verified_at IS NOT NULL FROM users WHERE email = $1", email
        )
        [joined] = await _audit(admin_conn, "member.joined", since)
        assert joined["org_id"] == org_id
        with pytest.raises(InvalidInputError) as reused:
            await container.auth.register_invited(
                token=raw, password=PASSWORD, full_name="Again", meta=META
            )
        assert reused.value.code == "invalid_invitation"

    async def test_an_invited_address_with_an_account_is_told_to_sign_in(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email, _ = await register(container)
        raw, _ = await self._invite(container, admin_conn, email)
        with pytest.raises(ConflictError) as exc:
            await container.auth.register_invited(
                token=raw, password=PASSWORD, full_name="Twice", meta=META
            )
        assert exc.value.code == "account_exists"

    async def test_an_invitation_closes_open_sign_up_links_for_the_address(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email = unique_email()
        link, _ = await container.auth.issue_signup_link(email=email, meta=META)
        raw, _ = await self._invite(container, admin_conn, email)
        await container.auth.register_invited(
            token=raw, password=PASSWORD, full_name="Joined First", meta=META
        )
        with pytest.raises(InvalidInputError):
            await _complete(container, link)


class TestTheApi:
    async def test_the_whole_sign_up_through_the_api(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        admin_conn: asyncpg.Connection,
        mailbox: RecordingEmail,
    ) -> None:
        email = unique_email()
        started = await api.post("/api/v1/auth/register", json={"email": email})
        assert started.status_code == 202, started.text
        assert started.json()["status"] == "check_email"
        await container.security_emails.send_signup_link(
            signup_id=await _request_id(admin_conn, email)
        )
        finished = await api.post(
            "/api/v1/auth/register/complete",
            json={
                "token": _token(mailbox.sent[0][2]),
                "password": PASSWORD,
                "full_name": "Api Owner",
                "organization_name": "Api Signup Ltd",
            },
        )
        assert finished.status_code == 201, finished.text
        me = await api.get(
            "/api/v1/organizations/current",
            headers={"Authorization": f"Bearer {finished.json()['access_token']}"},
        )
        assert me.status_code == 200
        assert me.json()["name"] == "Api Signup Ltd"

    async def test_a_refused_link_says_nothing_more_through_the_api(
        self, api: httpx2.AsyncClient
    ) -> None:
        response = await api.post(
            "/api/v1/auth/register/complete",
            json={
                "token": "made-up-token",
                "password": PASSWORD,
                "full_name": "Nobody",
                "organization_name": "Nothing Ltd",
            },
        )
        assert response.status_code == 422, response.text
        assert response.json()["error"] == "invalid_token"


class TestOperatorCli:
    async def test_signup_issue_prints_a_working_link_once(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email = unique_email("customer")
        args = build_parser().parse_args(["signup", "issue", "--email", email])
        result = await args.handler(container, args)
        assert result["link"] == (
            f"https://nexusflow.test.example/complete-signup#token={result['token']}"
        )
        stored = await admin_conn.fetchval(
            "SELECT token_hash FROM signup_requests WHERE email = $1", email
        )
        assert stored == container.token_hasher.hash(result["token"])  # only the hash
        await _complete(container, result["token"])
        with pytest.raises(ConflictError) as exc:
            await args.handler(container, args)  # the address has an account now
        assert exc.value.code == "account_exists"


async def test_signup_requests_are_reachable_only_in_the_authentication_context(
    container: Container, app_conn: asyncpg.Connection
) -> None:
    await container.auth.issue_signup_link(email=unique_email(), meta=META)
    await app_conn.execute(
        "SELECT set_config('app.current_org_id', '', false),"
        " set_config('app.current_user_id', '', false),"
        " set_config('app.auth_context', 'off', false)"
    )
    assert await app_conn.fetchval("SELECT count(*) FROM signup_requests") == 0
    await app_conn.execute("SELECT set_config('app.auth_context', 'on', false)")
    assert await app_conn.fetchval("SELECT count(*) FROM signup_requests") > 0

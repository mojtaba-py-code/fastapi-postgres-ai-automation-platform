"""Personal data: kept only while it serves, handed out and erased on request.

UK GDPR / GDPR storage limitation (art. 5(1)(e)), access and portability
(art. 15, 20) and erasure (art. 17). Sign-in sessions - device and address -
and expired tokens used to be kept for ever; nothing produced a person's copy
of their data; audit entries could not be removed after any retention period.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import httpx2
import pytest

from nexusflow.apps.cli.main import audit_purge, build_parser, purge_audit_logs
from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import (
    AuthenticationError,
    ConflictError,
    InvalidInputError,
    PermissionDeniedError,
)
from nexusflow.domain.authorization.roles import Role
from tests.support.api import signup
from tests.support.database import ProvisionedDatabase
from tests.support.fixtures import META, PASSWORD, register, unique_email

pytestmark = [pytest.mark.integration, pytest.mark.security]


async def _cli(container: Container, *argv: str) -> Any:
    args = build_parser().parse_args(argv)
    return await args.handler(container, args)


async def _user_id(admin_conn: asyncpg.Connection, email: str) -> UUID:
    user_id: UUID = await admin_conn.fetchval("SELECT id FROM users WHERE email = $1", email)
    return user_id


class TestIdentityRetention:
    async def test_expired_sign_in_data_is_deleted_and_recent_data_kept(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email, _ = await register(container)
        await container.auth.login(email=email, password=PASSWORD, org_id=None, meta=META)
        user_id = await _user_id(admin_conn, email)
        await container.auth.request_password_reset(email=email, meta=META)
        await container.auth.issue_signup_link(email=unique_email(), meta=META)
        sessions = [
            r["id"]
            for r in await admin_conn.fetch(
                "SELECT id FROM user_sessions WHERE user_id = $1 ORDER BY created_at", user_id
            )
        ]
        assert len(sessions) == 2
        old, recent = sessions
        now = datetime.now(UTC)
        # One session expired 91 days ago (past sessions_days = 90), one is live;
        # the tokens expired eight days ago (past the week of grace).
        await admin_conn.execute(
            "UPDATE user_sessions SET expires_at = $2 WHERE id = $1", old, now - timedelta(days=91)
        )
        await admin_conn.execute(
            "UPDATE refresh_tokens SET expires_at = $2 WHERE session_id = $1",
            recent,
            now - timedelta(days=8),
        )
        await admin_conn.execute(
            "UPDATE password_reset_tokens SET expires_at = $2 WHERE user_id = $1",
            user_id,
            now - timedelta(days=8),
        )
        await admin_conn.execute(
            "UPDATE signup_requests SET expires_at = $1", now - timedelta(days=8)
        )

        purged = await container.maintenance.apply_identity_retention()

        assert purged["user_sessions"] >= 1
        assert purged["refresh_tokens"] >= 1
        assert purged["password_reset_tokens"] >= 1
        assert purged["signup_requests"] >= 1
        remaining = {
            r["id"]
            for r in await admin_conn.fetch(
                "SELECT id FROM user_sessions WHERE user_id = $1", user_id
            )
        }
        assert remaining == {recent}
        assert await admin_conn.fetchval("SELECT count(*) FROM signup_requests") == 0
        event = await admin_conn.fetchrow(
            "SELECT org_id, metadata FROM audit_logs WHERE action = 'data.retention_purged'"
            " AND org_id IS NULL ORDER BY occurred_at DESC LIMIT 1"
        )
        assert json.loads(event["metadata"]) == purged
        assert await container.maintenance.apply_identity_retention() == {}  # idempotent


class TestAccessRequests:
    async def test_a_person_downloads_a_copy_of_their_data(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        session = await signup(api, org="Export Ltd")
        key = await session.post(
            "/api/v1/api-keys",
            json={
                "name": "reporting",
                "role": "viewer",
                "scopes": ["sources:read"],
                "expires_in_days": 30,
            },
        )
        assert key.status_code == 201, key.text

        response = await session.get("/api/v1/users/me/export")

        assert response.status_code == 200, response.text
        assert response.headers["content-disposition"] == (
            'attachment; filename="nexusflow-personal-data.json"'
        )
        assert response.headers["cache-control"] == "no-store"
        document = response.json()
        assert document["format"] == "nexusflow-personal-data/1"
        assert document["account"]["email"] == session.email
        assert document["account"]["email_verified_at"] is not None
        assert [(o["name"], o["role"]) for o in document["organizations"]] == [
            ("Export Ltd", "owner")
        ]
        assert document["sessions"] and document["sessions"][0]["ip"]
        assert [k["name"] for k in document["api_keys"]] == ["reporting"]
        actions = {entry["action"] for entry in document["activity"]}
        assert {"org.created", "api_key.created"} <= actions
        assert "platform_activity" not in document  # the operator export adds it
        user_id = await _user_id(admin_conn, session.email)
        assert await admin_conn.fetchval(
            "SELECT count(*) FROM audit_logs WHERE action = 'privacy.data_exported'"
            " AND actor_id = $1 AND org_id IS NULL",
            user_id,
        )

    async def test_an_api_key_cannot_export_its_creators_data(
        self, api: httpx2.AsyncClient
    ) -> None:
        session = await signup(api)
        created = await session.post(
            "/api/v1/api-keys",
            json={
                "name": "leaky",
                "role": "viewer",
                "scopes": ["sources:read"],
                "expires_in_days": 30,
            },
        )
        token = created.json()["token"]
        response = await api.get(
            "/api/v1/users/me/export", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403
        assert response.json()["error"] == "session_required"

    async def test_an_operator_export_adds_the_platform_audit_entries(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email, _ = await register(container)
        with pytest.raises(AuthenticationError):
            await container.auth.login(
                email=email, password="not-the-password-1", org_id=None, meta=META
            )
        document = await _cli(container, "user", "export", "--email", email.upper())
        assert document["account"]["email"] == email
        platform = {entry["action"] for entry in document["platform_activity"]}
        assert "auth.login.failed" in platform
        assert await admin_conn.fetchval(
            "SELECT count(*) FROM audit_logs WHERE action = 'privacy.data_exported'"
            " AND resource_id = $1 AND actor_type = 'system'",
            str(await _user_id(admin_conn, email)),
        )


class TestErasureRequests:
    async def test_an_operator_erases_a_member_who_cannot_sign_in(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        _, owner_tokens = await register(container)
        owner = await container.authenticator.authenticate(owner_tokens.access_token)
        email = unique_email("leaver")
        invitation = await container.organizations.invite(
            owner, email=email, role=Role.ANALYST, meta=META
        )
        raw = "invite-" + uuid4().hex
        await admin_conn.execute(
            "UPDATE invitations SET token_hash = $1 WHERE id = $2",
            container.token_hasher.hash(raw),
            invitation.id,
        )
        member_tokens = await container.auth.register_invited(
            token=raw, password=PASSWORD, full_name="Leaving Member", meta=META
        )
        user_id = await _user_id(admin_conn, email)

        result = await _cli(container, "user", "erase", "--email", email, "--reason", "ticket 4711")

        assert result == {"user_id": user_id, "erased": True}
        user = await admin_conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
        assert user["email"] == f"deleted-{user_id}@invalid"
        assert user["status"] == "deleted"
        assert (
            await admin_conn.fetchval(
                "SELECT count(*) FROM memberships WHERE user_id = $1", user_id
            )
            == 0
        )
        with pytest.raises(AuthenticationError):
            await container.authenticator.authenticate(member_tokens.access_token)
        deleted = await admin_conn.fetchrow(
            "SELECT actor_type, metadata FROM audit_logs WHERE action = 'auth.account_deleted'"
            " AND resource_id = $1",
            str(user_id),
        )
        assert deleted["actor_type"] == "system"
        assert json.loads(deleted["metadata"]) == {"by": "operator", "reason": "ticket 4711"}

    async def test_the_sole_owner_is_refused_and_a_reason_is_required(
        self, container: Container
    ) -> None:
        email, _ = await register(container)
        with pytest.raises(ConflictError) as sole:
            await _cli(container, "user", "erase", "--email", email, "--reason", "request")
        assert sole.value.code == "sole_owner"
        with pytest.raises(InvalidInputError) as unexplained:
            await _cli(container, "user", "erase", "--email", email, "--reason", " ")
        assert unexplained.value.code == "reason_required"


class TestAuditRetention:
    async def test_only_the_migrator_can_purge_audit_entries(
        self,
        container: Container,
        database: ProvisionedDatabase,
        app_conn: asyncpg.Connection,
    ) -> None:
        await register(container)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app_conn.fetchval("SELECT nf_purge_audit_logs(now())")
        before = datetime.now(UTC) - timedelta(days=36500)
        assert await purge_audit_logs(database.migrator_url, before) == 0  # nothing that old

    async def test_the_command_keeps_a_minimum_and_needs_the_migrator(self) -> None:
        settings = SimpleNamespace(database=SimpleNamespace(migrator_url=None))
        c: Any = SimpleNamespace(settings=settings, clock=SimpleNamespace(now=datetime.now))
        with pytest.raises(InvalidInputError) as short:
            await audit_purge(c, SimpleNamespace(older_than_days=30))
        assert short.value.code == "retention_too_short"
        with pytest.raises(InvalidInputError) as missing:
            await audit_purge(c, SimpleNamespace(older_than_days=400))
        assert missing.value.code == "migrator_required"


async def test_the_export_of_an_unknown_address_is_not_found(container: Container) -> None:
    from nexusflow.core.errors import NotFoundError

    with pytest.raises(NotFoundError):
        await _cli(container, "user", "export", "--email", unique_email())
    with pytest.raises(PermissionDeniedError):
        await container.privacy.export_own(
            SimpleNamespace(session_id=None, user_id=uuid4()),  # type: ignore[arg-type]
            META,
        )

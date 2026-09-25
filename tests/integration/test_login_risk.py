"""Unfamiliar and suspicious sign-ins are audited, e-mailed with details and counted."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import asyncpg
import httpx2
import pytest
from prometheus_client import REGISTRY

from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import AuthenticationError
from nexusflow.domain.identity.login_risk import (
    FAILURES_BEFORE_SUCCESS,
    LoginRisk,
    sign_in_details,
)
from nexusflow.domain.shared.context import RequestMeta
from tests.support.api import signup
from tests.support.fixtures import META, PASSWORD, register

pytestmark = pytest.mark.integration

CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/129.0.0.0 Safari/537.36"
)


async def _login(container: Container, email: str, *, ip: str, agent: str) -> LoginRisk | None:
    result = await container.auth.login(
        email=email,
        password=PASSWORD,
        org_id=None,
        meta=RequestMeta(request_id="req-risk-0001", ip=ip, user_agent=agent),
    )
    assert result.tokens is not None
    return result.tokens.login_risk


async def _fail(container: Container, email: str, times: int) -> None:
    for _ in range(times):
        with pytest.raises(AuthenticationError):
            await container.auth.login(
                email=email, password="wrong-password-123", org_id=None, meta=META
            )


async def _audit(conn: asyncpg.Connection, user_id: UUID, *actions: str) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        "SELECT action, metadata FROM audit_logs WHERE actor_id = $1 AND action = ANY($2)"
        " ORDER BY seq",
        user_id,
        list(actions),
    )
    return [{"action": row["action"], **json.loads(row["metadata"])} for row in rows]


class TestSignInRisk:
    async def test_familiar_places_are_quiet_and_new_ones_are_reported(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email, _ = await register(container)  # signed in from 203.0.113.10 with "pytest"
        user_id = await admin_conn.fetchval("SELECT id FROM users WHERE email = $1", email)

        assert await _login(container, email, ip="203.0.113.10", agent="pytest") is (
            LoginRisk.FAMILIAR
        )
        # A new address in the same network: a new DHCP lease, a colleague's desk.
        assert await _login(container, email, ip="203.0.113.77", agent="pytest") is (
            LoginRisk.FAMILIAR
        )
        assert await _login(container, email, ip="203.0.113.10", agent=CHROME) is (
            LoginRisk.UNFAMILIAR
        )
        assert await _login(container, email, ip="198.51.100.5", agent="curl/8.9.1") is (
            LoginRisk.SUSPICIOUS
        )

        reported = await _audit(
            admin_conn, user_id, "auth.login.new_device", "auth.login.suspicious"
        )
        assert reported == [
            {"action": "auth.login.new_device", "signals": ["new_device"]},
            {"action": "auth.login.suspicious", "signals": ["new_device", "new_network"]},
        ]
        rows = await admin_conn.fetch(
            "SELECT payload FROM outbox_messages"
            " WHERE task = 'security.send_email' AND payload->>'user_id' = $1",
            str(user_id),
        )
        mails = {p["template"]: p for p in (json.loads(r["payload"]) for r in rows)}
        assert mails["new_device_login"]["sign_in"]["client"] == "Chrome on Windows"
        assert mails["suspicious_login"]["sign_in"]["ip"] == "198.51.100.5"
        assert mails["suspicious_login"]["sign_in"]["client"] == "curl"

    async def test_a_success_after_repeated_failures(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email, _ = await register(container)
        user_id = await admin_conn.fetchval("SELECT id FROM users WHERE email = $1", email)
        assert META.ip is not None
        assert META.user_agent is not None

        await _fail(container, email, FAILURES_BEFORE_SUCCESS)
        # At home: the user mistyped. Recorded, but no alarm.
        assert await _login(container, email, ip=META.ip, agent=META.user_agent) is (
            LoginRisk.FAMILIAR
        )
        await _fail(container, email, FAILURES_BEFORE_SUCCESS)
        # From a new network right after several wrong passwords: a guess that worked?
        assert await _login(container, email, ip="192.0.2.44", agent=META.user_agent) is (
            LoginRisk.SUSPICIOUS
        )

        events = await _audit(admin_conn, user_id, "auth.login.succeeded", "auth.login.suspicious")
        succeeded = [e for e in events if e["action"] == "auth.login.succeeded"]
        assert [(e["risk"], e["signals"]) for e in succeeded] == [
            ("familiar", ["after_failures"]),
            ("suspicious", ["new_network", "after_failures"]),
        ]
        assert [e["signals"] for e in events if e["action"] == "auth.login.suspicious"] == [
            ["new_network", "after_failures"]
        ]

    async def test_the_email_gives_time_address_and_device_never_the_raw_agent(
        self, container: Container, admin_conn: asyncpg.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        email, _ = await register(container)
        user_id = await admin_conn.fetchval("SELECT id FROM users WHERE email = $1", email)
        sent: list[tuple[list[str], str, str]] = []

        class RecordingEmail:
            async def send_email(self, recipients: list[str], subject: str, body: str) -> None:
                sent.append((recipients, subject, body))

        monkeypatch.setattr(container.security_emails, "_email", RecordingEmail())
        sneaky = "Firefox/130.0 (Windows NT 10.0) URGENT: verify at https://evil.example/login"
        details = sign_in_details(
            at=datetime(2026, 9, 25, 8, 30, tzinfo=UTC), ip="198.51.100.5", user_agent=sneaky
        )
        assert await container.security_emails.send_notification(
            user_id=user_id, template="suspicious_login", sign_in=details
        )
        [(recipients, subject, body)] = sent
        assert recipients == [email]
        assert subject == "Unusual sign-in to your NexusFlow account"
        assert "When: 2026-09-25 08:30 UTC" in body
        assert "IP address: 198.51.100.5" in body
        assert "Device: Firefox on Windows" in body
        assert "evil" not in body
        assert "URGENT" not in body


class TestSignInMetrics:
    async def test_unfamiliar_sign_ins_are_counted(self, api: httpx2.AsyncClient) -> None:
        def counted() -> float:
            labels = {"event": "unfamiliar_login", "result": "detected"}
            return REGISTRY.get_sample_value("nexusflow_auth_events_total", labels) or 0.0

        owner = await signup(api)
        before = counted()
        response = await api.post(
            "/api/v1/auth/login",
            json={"email": owner.email, "password": PASSWORD},
            headers={"User-Agent": CHROME},  # a new device on the same network
        )
        assert response.status_code == 200, response.text
        assert "login_risk" not in response.json()  # monitoring only, never told to clients
        assert counted() == before + 1

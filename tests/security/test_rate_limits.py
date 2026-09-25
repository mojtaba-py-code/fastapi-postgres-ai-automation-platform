"""Rate limits of the HTTP-facing scopes, through the real apps (real PostgreSQL).

For every scope not covered elsewhere (login: ``test_api_security.py``; webhook
endpoint quota: ``test_business_api.py``) these tests prove that the limit is
enforced - ``429`` with ``Retry-After`` and the uniform error body - that it is
counted per principal, per client IP or per account as documented, and what a
Redis outage does: fail-closed scopes refuse with ``503``, fail-open scopes
keep serving, bounded by the in-process fallback.

The public and internal apps under test share the session container but each
request goes through a ``RateLimiter`` installed for the test in
``ApiState.limiter``: a fresh fake Redis whose server can be taken down and a
frozen clock, so budgets, ``Retry-After`` values and refills are exact. Limits
are lowered per test in the container's settings, keeping each scope's
configured failure policy.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import uuid4

import asyncpg
import fakeredis
import httpx2
import pytest
from asgi_lifespan import LifespanManager
from fastapi import FastAPI

from nexusflow.apps.api.main import create_app
from nexusflow.bootstrap.container import Container
from nexusflow.core.clock import FrozenClock
from nexusflow.core.config import RateLimitRule
from nexusflow.domain.authorization.principal import ServiceScope
from nexusflow.infrastructure.redis.rate_limit import RateLimiter
from tests.support.api import ApiSession, signup
from tests.support.business import create_dataset, create_project
from tests.support.fixtures import META, PASSWORD, SESSION, unique_email

pytestmark = [pytest.mark.security, pytest.mark.integration]

START = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
IP_A = "198.51.100.10"
IP_B = "198.51.100.20"
FORGED_TICKET = "a" * 64


@dataclass
class Limits:
    """The limiter the apps under test use, and the knobs a test turns."""

    limiter: RateLimiter
    clock: FrozenClock
    server: fakeredis.FakeServer
    rules: dict[str, RateLimitRule]
    monkeypatch: pytest.MonkeyPatch

    def set(self, scope: str, limit: int, period_seconds: int) -> None:
        """Lower ``scope`` for this test; its configured failure policy is kept."""
        rule = RateLimitRule(
            limit=limit,
            period_seconds=period_seconds,
            fail_closed=self.rules[scope].fail_closed,
        )
        self.monkeypatch.setitem(self.rules, scope, rule)

    def redis_down(self) -> None:
        self.server.connected = False

    def redis_up(self) -> None:
        self.server.connected = True


@asynccontextmanager
async def _running(
    container: Container, mode: Literal["public", "internal"]
) -> AsyncIterator[FastAPI]:
    app = create_app(container.settings, mode=mode, container=container, configure_logs=False)
    async with LifespanManager(app):
        yield app  # the FastAPI app itself, so the test can reach app.state.api


@pytest.fixture(scope="module")
async def public_app_under_test(container: Container) -> AsyncIterator[FastAPI]:
    async with _running(container, "public") as app:
        yield app


@pytest.fixture(scope="module")
async def internal_app_under_test(container: Container) -> AsyncIterator[FastAPI]:
    async with _running(container, "internal") as app:
        yield app


@pytest.fixture
async def limits(
    public_app_under_test: FastAPI,
    internal_app_under_test: FastAPI,
    container: Container,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[Limits]:
    server = fakeredis.FakeServer()
    redis = fakeredis.FakeAsyncRedis(server=server)
    clock = FrozenClock(START)
    limiter = RateLimiter(redis, prefix=container.settings.redis.key_prefix, clock=clock)
    for app in (public_app_under_test, internal_app_under_test):
        monkeypatch.setattr(app.state.api, "limiter", limiter)
    try:
        yield Limits(limiter, clock, server, container.settings.rate_limits.rules, monkeypatch)
    finally:
        server.connected = True
        await redis.aclose()


@asynccontextmanager
async def _client(app: FastAPI, ip: str) -> AsyncIterator[httpx2.AsyncClient]:
    transport = httpx2.ASGITransport(app=app, client=(ip, 40_000))
    async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.fixture
async def public(
    public_app_under_test: FastAPI, limits: Limits
) -> AsyncIterator[httpx2.AsyncClient]:
    async with _client(public_app_under_test, IP_A) as client:
        yield client


@pytest.fixture
async def public_b(
    public_app_under_test: FastAPI, limits: Limits
) -> AsyncIterator[httpx2.AsyncClient]:
    async with _client(public_app_under_test, IP_B) as client:
        yield client


@pytest.fixture
async def internal(
    internal_app_under_test: FastAPI, limits: Limits
) -> AsyncIterator[httpx2.AsyncClient]:
    async with _client(internal_app_under_test, IP_A) as client:
        yield client


@pytest.fixture
async def internal_b(
    internal_app_under_test: FastAPI, limits: Limits
) -> AsyncIterator[httpx2.AsyncClient]:
    async with _client(internal_app_under_test, IP_B) as client:
        yield client


def assert_rate_limited(response: httpx2.Response, retry_after: int) -> None:
    assert response.status_code == 429, response.text
    assert response.headers["retry-after"] == str(retry_after)
    assert response.json() == {
        "error": "rate_limited",
        "message": "Too many requests. Please retry later.",
        "request_id": response.headers["x-request-id"],
    }


def assert_unavailable(response: httpx2.Response) -> None:
    assert response.status_code == 503, response.text
    # The uniform body only: nothing about Redis or the limiter leaks.
    assert response.json() == {
        "error": "service_unavailable",
        "message": "The service is temporarily unavailable.",
        "request_id": response.headers["x-request-id"],
    }


def _as(client: httpx2.AsyncClient, session: ApiSession) -> ApiSession:
    """``session``'s credentials, sent from ``client``'s address."""
    return ApiSession(client, session.access_token, session.refresh_token, session.email)


def _registration(email: str) -> dict[str, str]:
    return {"email": email}


async def _service_token(container: Container, *scopes: ServiceScope) -> dict[str, str]:
    issued = await container.service_accounts.create(
        name=f"wf-{uuid4().hex[:8]}",
        workflow_key=f"wf-{uuid4().hex[:8]}",
        scopes=list(scopes),
        meta=META,
    )
    return {"Authorization": f"Bearer {issued.token}"}


def _sandbox_input() -> str:
    return f"/internal/v1/sandbox/orgs/{uuid4()}/runs/{uuid4()}/input"


class TestApiReadAndWrite:
    async def test_reads_are_limited_per_user_across_sessions(
        self, public: httpx2.AsyncClient, limits: Limits
    ) -> None:
        limits.set("api.read", 2, 60)
        alice = await signup(public)
        login = await public.post(
            "/api/v1/auth/login", json={"email": alice.email, "password": PASSWORD}
        )
        assert login.status_code == 200, login.text
        other_session = {"Authorization": f"Bearer {login.json()['access_token']}"}

        for _ in range(2):
            assert (await alice.get("/api/v1/projects")).status_code == 200
        assert_rate_limited(await alice.get("/api/v1/projects"), retry_after=30)
        # Per principal is per *user*: a second login does not bring a fresh budget.
        assert_rate_limited(await public.get("/api/v1/projects", headers=other_session), 30)
        # Another user is unaffected, and writes are a separate budget.
        assert (await (await signup(public)).get("/api/v1/projects")).status_code == 200
        assert (await alice.post("/api/v1/projects", json={"name": "W"})).status_code == 201

        limits.clock.advance(timedelta(seconds=30))  # one emission interval: one more read
        assert (await alice.get("/api/v1/projects")).status_code == 200
        assert_rate_limited(await alice.get("/api/v1/projects"), retry_after=30)

    async def test_writes_are_limited_per_principal(
        self, public: httpx2.AsyncClient, limits: Limits
    ) -> None:
        limits.set("api.write", 2, 60)
        alice, bob = await signup(public), await signup(public)
        for name in ("P1", "P2"):
            created = await alice.post("/api/v1/projects", json={"name": name})
            assert created.status_code == 201, created.text
        assert_rate_limited(await alice.post("/api/v1/projects", json={"name": "P3"}), 30)
        assert (await bob.post("/api/v1/projects", json={"name": "P1"})).status_code == 201
        assert (await alice.get("/api/v1/projects")).status_code == 200


class TestExportsAndAi:
    async def test_exports_and_report_downloads_share_one_budget_per_principal(
        self, public: httpx2.AsyncClient, limits: Limits
    ) -> None:
        limits.set("api.export", 1, 3600)
        alice = await signup(public)
        dataset_id = await create_dataset(alice, await create_project(alice))
        export = f"/api/v1/datasets/{dataset_id}/export"

        assert (await alice.get(export)).status_code == 200
        assert_rate_limited(await alice.get(export), retry_after=3600)
        # Report downloads draw on the same budget, refused before any lookup.
        assert_rate_limited(await alice.get(f"/api/v1/reports/{uuid4()}/download"), 3600)

        bob = await signup(public)
        bob_dataset = await create_dataset(bob, await create_project(bob))
        assert (await bob.get(f"/api/v1/datasets/{bob_dataset}/export")).status_code == 200

    async def test_ai_analyses_are_limited_per_principal(
        self, public: httpx2.AsyncClient, limits: Limits
    ) -> None:
        limits.set("api.ai", 1, 3600)
        alice = await signup(public)
        body = {"dataset_id": await create_dataset(alice, await create_project(alice))}

        queued = await alice.post("/api/v1/intelligence/analyses", json=body)
        assert queued.status_code == 202, queued.text
        assert_rate_limited(await alice.post("/api/v1/intelligence/analyses", json=body), 3600)

        bob = await signup(public)
        bob_body = {"dataset_id": await create_dataset(bob, await create_project(bob))}
        assert (await bob.post("/api/v1/intelligence/analyses", json=bob_body)).status_code == 202

    async def test_more_api_keys_do_not_buy_more_ai_budget(
        self, public: httpx2.AsyncClient, limits: Limits
    ) -> None:
        limits.set("api.ai", 1, 3600)
        alice = await signup(public)
        body = {"dataset_id": await create_dataset(alice, await create_project(alice))}
        keys = []
        for name in ("key-one", "key-two"):
            created = await alice.post(
                "/api/v1/api-keys",
                json={
                    "name": name,
                    "role": "analyst",
                    "scopes": ["insights:generate"],
                    "expires_in_days": 1,
                },
            )
            assert created.status_code == 201, created.text
            keys.append({"Authorization": f"Bearer {created.json()['token']}"})

        first = await public.post("/api/v1/intelligence/analyses", json=body, headers=keys[0])
        assert first.status_code == 202, first.text
        # The budget is the person's: a second key of the same user is refused.
        second = await public.post("/api/v1/intelligence/analyses", json=body, headers=keys[1])
        assert_rate_limited(second, 3600)


class TestAuthenticationScopes:
    async def test_registration_is_limited_per_client_ip(
        self, public: httpx2.AsyncClient, public_b: httpx2.AsyncClient, limits: Limits
    ) -> None:
        limits.set("auth.register", 1, 3600)
        first = await public.post("/api/v1/auth/register", json=_registration(unique_email()))
        assert first.status_code == 202, first.text
        again = await public.post("/api/v1/auth/register", json=_registration(unique_email()))
        assert_rate_limited(again, retry_after=3600)
        # X-Forwarded-For from an untrusted peer does not buy a fresh budget ...
        spoofed = await public.post(
            "/api/v1/auth/register",
            json=_registration(unique_email()),
            headers={"X-Forwarded-For": "203.0.113.99"},
        )
        assert_rate_limited(spoofed, retry_after=3600)
        # ... a different client address does.
        other = await public_b.post("/api/v1/auth/register", json=_registration(unique_email()))
        assert other.status_code == 202, other.text

    async def test_finishing_sign_ups_has_a_budget_of_its_own(
        self, public: httpx2.AsyncClient, public_b: httpx2.AsyncClient, limits: Limits
    ) -> None:
        # Starting is cheap to abuse (it sends mail); finishing needs a mailed
        # token, so a whole office behind one address can join in an hour.
        limits.set("auth.register", 1, 3600)
        limits.set("auth.register.complete", 1, 3600)
        await signup(public)  # finishing does not spend the starting budget ...
        first = await public.post("/api/v1/auth/register", json=_registration(unique_email()))
        assert first.status_code == 202, first.text
        assert_rate_limited(await _finish(public), retry_after=3600)
        other = await _finish(public_b)  # ... and every client address has its own
        assert other.status_code == 201, other.text

    async def test_sign_up_mail_is_limited_per_address(
        self, public: httpx2.AsyncClient, public_b: httpx2.AsyncClient, limits: Limits
    ) -> None:
        # Sign-up e-mails must not become a way to flood someone's mailbox: the
        # budget follows the address, whichever client asks.
        limits.set("auth.register.account", 1, 3600)
        target = unique_email()
        first = await public.post("/api/v1/auth/register", json=_registration(target))
        assert first.status_code == 202, first.text
        again = await public_b.post("/api/v1/auth/register", json=_registration(target.upper()))
        assert_rate_limited(again, retry_after=3600)
        other = await public_b.post("/api/v1/auth/register", json=_registration(unique_email()))
        assert other.status_code == 202, other.text

    async def test_token_refresh_is_limited_per_client_ip(
        self, public: httpx2.AsyncClient, public_b: httpx2.AsyncClient, limits: Limits
    ) -> None:
        session = await signup(public_b)
        limits.set("auth.refresh", 2, 60)
        for _ in range(2):  # guessed tokens spend the budget like real ones
            guessed = await public.post("/api/v1/auth/refresh", json={"refresh_token": "x" * 40})
            assert guessed.status_code == 401, guessed.text
        valid = {"refresh_token": session.refresh_token}
        assert_rate_limited(await public.post("/api/v1/auth/refresh", json=valid), 30)
        refreshed = await public_b.post("/api/v1/auth/refresh", json=valid)
        assert refreshed.status_code == 200, refreshed.text

    async def test_password_resets_are_limited_per_ip_and_per_account(
        self, public: httpx2.AsyncClient, public_b: httpx2.AsyncClient, limits: Limits
    ) -> None:
        limits.set("auth.password_reset", 2, 3600)  # one request per 1800 s once spent
        target = unique_email()  # no such account: the budget must not reveal that
        reset = "/api/v1/auth/password/reset-request"
        for _ in range(2):
            assert (await public.post(reset, json={"email": target})).status_code == 202
        # Per account: a fresh address cannot keep mailing the same inbox ...
        assert_rate_limited(await public_b.post(reset, json={"email": target}), 1800)
        # ... while that address can still ask for another account.
        assert (await public_b.post(reset, json={"email": unique_email()})).status_code == 202
        # Per IP: the first address has spent its budget, for any account ...
        assert_rate_limited(await public.post(reset, json={"email": unique_email()}), 1800)
        # ... and token guessing on the confirmation endpoint shares it.
        confirm = {"token": "x" * 43, "new_password": "An0ther-str0ng-passphrase!"}
        assert_rate_limited(await public.post("/api/v1/auth/password/reset", json=confirm), 1800)

    async def test_mfa_attempts_are_limited_per_client_ip(
        self, public: httpx2.AsyncClient, public_b: httpx2.AsyncClient, limits: Limits
    ) -> None:
        alice = await signup(public_b)
        limits.set("auth.mfa", 2, 300)
        forged = {"mfa_token": "forged.challenge.token", "code": "123456"}
        for _ in range(2):
            assert (await public.post("/api/v1/auth/mfa/verify", json=forged)).status_code == 401
        assert_rate_limited(await public.post("/api/v1/auth/mfa/verify", json=forged), 150)
        # Enrolment (a password check) from the same address shares the budget.
        enroll = await _as(public, alice).post(
            "/api/v1/auth/mfa/enroll", json={"password": PASSWORD}
        )
        assert_rate_limited(enroll, retry_after=150)
        assert (await public_b.post("/api/v1/auth/mfa/verify", json=forged)).status_code == 401

    async def test_password_change_guesses_are_throttled(
        self, public: httpx2.AsyncClient, limits: Limits
    ) -> None:
        alice = await signup(public)
        new_password = "An0ther-str0ng-passphrase!"
        statuses = {
            (
                await alice.post(
                    "/api/v1/auth/password/change",
                    json={
                        "current_password": f"guess-{i:02d}-wrong!",
                        "new_password": new_password,
                    },
                )
            ).status_code
            for i in range(25)
        }
        assert not statuses & {200, 422}  # every guess reached the password check
        confirmed = await alice.post(
            "/api/v1/auth/password/change",
            json={"current_password": PASSWORD, "new_password": new_password},
        )
        # The guesses were rate limited per user (and counted toward lockout), so
        # even the right password is refused for now.
        assert 429 in statuses
        assert confirmed.status_code != 200


class TestInternalScopes:
    async def test_automation_calls_are_limited_per_service_token(
        self, internal: httpx2.AsyncClient, container: Container, limits: Limits
    ) -> None:
        limits.set("automation.service", 2, 60)
        first = await _service_token(container, ServiceScope.DETECT)
        second = await _service_token(container, ServiceScope.DETECT)
        sweep = "/internal/v1/automation/detect/sweep"
        for _ in range(2):
            swept = await internal.post(sweep, json={"limit": 1}, headers=first)
            assert swept.status_code == 200, swept.text
        assert_rate_limited(await internal.post(sweep, json={"limit": 1}, headers=first), 30)
        assert (await internal.post(sweep, json={"limit": 1}, headers=second)).status_code == 200

    async def test_the_sandbox_gateway_is_limited_per_client_ip(
        self, internal: httpx2.AsyncClient, internal_b: httpx2.AsyncClient, limits: Limits
    ) -> None:
        limits.set("sandbox.gateway", 2, 60)
        ticket = {"X-Sandbox-Ticket": FORGED_TICKET}
        for _ in range(2):  # counted before the ticket is even looked at
            assert (await internal.get(_sandbox_input(), headers=ticket)).status_code == 401
        assert_rate_limited(await internal.get(_sandbox_input(), headers=ticket), 30)
        malformed = {"X-Sandbox-Ticket": "not-a-ticket"}
        assert_rate_limited(await internal.get(_sandbox_input(), headers=malformed), 30)
        assert (await internal_b.get(_sandbox_input(), headers=ticket)).status_code == 401


# --------------------------------------------------------------- Redis outage
#
# A probe sends one request of a scope as ``session`` (``dataset`` is one of its
# datasets) and returns the response.

type Probe = Callable[[httpx2.AsyncClient, ApiSession, str], Awaitable[httpx2.Response]]


async def _register(
    client: httpx2.AsyncClient, session: ApiSession, dataset: str
) -> httpx2.Response:
    return await client.post("/api/v1/auth/register", json=_registration(unique_email()))


async def _complete(
    client: httpx2.AsyncClient, session: ApiSession, dataset: str
) -> httpx2.Response:
    return await _finish(client)


async def _finish(client: httpx2.AsyncClient) -> httpx2.Response:
    """Finish a sign-up from a fresh link (the operator path stands in for the mail)."""
    token, _ = await SESSION["container"].auth.issue_signup_link(email=unique_email(), meta=META)
    body = {
        "token": token,
        "password": PASSWORD,
        "full_name": "Rate Tester",
        "organization_name": f"Rate {uuid4().hex[:6]}",
    }
    return await client.post("/api/v1/auth/register/complete", json=body)


async def _login(client: httpx2.AsyncClient, session: ApiSession, dataset: str) -> httpx2.Response:
    body = {"email": session.email, "password": PASSWORD}
    return await client.post("/api/v1/auth/login", json=body)


async def _refresh(
    client: httpx2.AsyncClient, session: ApiSession, dataset: str
) -> httpx2.Response:
    body = {"refresh_token": session.refresh_token}
    return await client.post("/api/v1/auth/refresh", json=body)


async def _reset(client: httpx2.AsyncClient, session: ApiSession, dataset: str) -> httpx2.Response:
    body = {"email": session.email}
    return await client.post("/api/v1/auth/password/reset-request", json=body)


async def _mfa(client: httpx2.AsyncClient, session: ApiSession, dataset: str) -> httpx2.Response:
    body = {"mfa_token": "forged.challenge.token", "code": "123456"}
    return await client.post("/api/v1/auth/mfa/verify", json=body)


async def _export(client: httpx2.AsyncClient, session: ApiSession, dataset: str) -> httpx2.Response:
    return await _as(client, session).get(f"/api/v1/datasets/{dataset}/export")


async def _analysis(
    client: httpx2.AsyncClient, session: ApiSession, dataset: str
) -> httpx2.Response:
    body = {"dataset_id": dataset}
    return await _as(client, session).post("/api/v1/intelligence/analyses", json=body)


async def _read(client: httpx2.AsyncClient, session: ApiSession, dataset: str) -> httpx2.Response:
    return await _as(client, session).get("/api/v1/projects")


async def _write(client: httpx2.AsyncClient, session: ApiSession, dataset: str) -> httpx2.Response:
    return await _as(client, session).post("/api/v1/projects", json={"name": "During outage"})


class TestRedisOutage:
    @pytest.mark.parametrize(
        ("scope", "probe", "recovered"),
        [
            pytest.param("auth.register", _register, 202, id="auth.register"),
            pytest.param("auth.register.complete", _complete, 201, id="auth.register.complete"),
            pytest.param("auth.login.ip", _login, 200, id="auth.login"),
            pytest.param("auth.refresh", _refresh, 200, id="auth.refresh"),
            pytest.param("auth.password_reset", _reset, 202, id="auth.password_reset"),
            pytest.param("auth.mfa", _mfa, 401, id="auth.mfa"),
            pytest.param("api.export", _export, 200, id="api.export"),
            pytest.param("api.ai", _analysis, 202, id="api.ai"),
        ],
    )
    async def test_fail_closed_scopes_refuse_while_redis_is_down(
        self,
        public: httpx2.AsyncClient,
        container: Container,
        limits: Limits,
        scope: str,
        probe: Probe,
        recovered: int,
    ) -> None:
        assert container.settings.rate_limits.rules[scope].fail_closed
        session = await signup(public)
        dataset = await create_dataset(session, await create_project(session))

        limits.redis_down()
        assert_unavailable(await probe(public, session, dataset))
        limits.redis_up()  # the very same request goes through again
        assert (await probe(public, session, dataset)).status_code == recovered

    async def test_nothing_is_created_behind_a_refused_registration(
        self, public: httpx2.AsyncClient, limits: Limits, admin_conn: asyncpg.Connection
    ) -> None:
        body = _registration(unique_email())
        requests = "SELECT count(*) FROM signup_requests WHERE email = $1"
        limits.redis_down()
        assert_unavailable(await public.post("/api/v1/auth/register", json=body))
        assert await admin_conn.fetchval(requests, body["email"]) == 0  # nothing mailed
        limits.redis_up()
        started = await public.post("/api/v1/auth/register", json=body)
        assert started.status_code == 202, started.text
        assert await admin_conn.fetchval(requests, body["email"]) == 1

    @pytest.mark.parametrize(
        ("scope", "probe", "status"),
        [("api.read", _read, 200), ("api.write", _write, 201)],
        ids=["api.read", "api.write"],
    )
    async def test_fail_open_scopes_keep_serving_while_redis_is_down(
        self,
        public: httpx2.AsyncClient,
        container: Container,
        limits: Limits,
        scope: str,
        probe: Probe,
        status: int,
    ) -> None:
        assert not container.settings.rate_limits.rules[scope].fail_closed
        session = await signup(public)
        limits.redis_down()
        assert (await probe(public, session, "")).status_code == status

    async def test_internal_fail_open_scopes_keep_serving_while_redis_is_down(
        self, internal: httpx2.AsyncClient, container: Container, limits: Limits
    ) -> None:
        rules = container.settings.rate_limits.rules
        assert not rules["automation.service"].fail_closed
        assert not rules["sandbox.gateway"].fail_closed
        token = await _service_token(container, ServiceScope.DETECT)
        limits.redis_down()
        swept = await internal.post(
            "/internal/v1/automation/detect/sweep", json={"limit": 1}, headers=token
        )
        assert swept.status_code == 200, swept.text
        # Past the limiter, the ticket check still answers.
        gateway = await internal.get(_sandbox_input(), headers={"X-Sandbox-Ticket": FORGED_TICKET})
        assert gateway.status_code == 401, gateway.text

    async def test_fail_open_scopes_stay_bounded_by_the_in_process_fallback(
        self, public: httpx2.AsyncClient, limits: Limits
    ) -> None:
        limits.set("api.read", 2, 60)
        alice = await signup(public)
        limits.redis_down()
        for _ in range(2):
            assert (await alice.get("/api/v1/projects")).status_code == 200
        assert_rate_limited(await alice.get("/api/v1/projects"), retry_after=30)

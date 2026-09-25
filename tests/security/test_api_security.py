"""HTTP-level security regression tests (authentication, authorization,
tenant isolation, input handling, error leakage, headers, rate limiting)."""

from __future__ import annotations

import base64
import json
from uuid import uuid4

import httpx2
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.infrastructure.security.jwt_tokens import (
    JwtKeyRing,
    JwtTokenCodec,
    generate_ed25519_private_key_pem,
)
from tests.support.api import signup
from tests.support.fixtures import PASSWORD, unique_email

pytestmark = [pytest.mark.security, pytest.mark.integration]

SECRET_FIELDS = ("password_hash", "key_hash", "token_hash", "mfa_secret", "secret_ciphertext")


def _assert_error_shape(response: httpx2.Response, status: int, code: str | None = None) -> None:
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body) >= {"error", "message", "request_id"}
    if code is not None:
        assert body["error"] == code
    serialized = json.dumps(body).lower()
    for marker in ("traceback", "sqlalchemy", "asyncpg", 'file "', ".py"):
        assert marker not in serialized


class TestAuthentication:
    async def test_protected_endpoint_requires_credentials(self, api: httpx2.AsyncClient) -> None:
        response = await api.get("/api/v1/users/me")
        _assert_error_shape(response, 401)
        assert response.headers["www-authenticate"].startswith("Bearer")

    @pytest.mark.parametrize(
        "header",
        [
            "Bearer",
            "Bearer    ",
            "Basic dXNlcjpwYXNz",
            "Bearer not.a.jwt",
            "Bearer nxf_garbage",
            "Bearer " + "a" * 5000,
        ],
    )
    async def test_malformed_credentials_rejected(
        self, api: httpx2.AsyncClient, header: str
    ) -> None:
        response = await api.get("/api/v1/users/me", headers={"Authorization": header})
        _assert_error_shape(response, 401)

    async def test_forged_tokens_rejected(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        session = await signup(api)
        me = (await session.get("/api/v1/users/me")).json()
        forger = JwtTokenCodec(
            JwtKeyRing.from_pem(generate_ed25519_private_key_pem(), "k1", {}),
            issuer=container.settings.security.jwt_issuer,
            audience=container.settings.security.jwt_audience,
            access_ttl_seconds=600,
            mfa_ttl_seconds=300,
        )
        forged = forger.issue_access_token(
            user_id=uuid4(),
            org_id=None,
            session_id=uuid4(),
            token_version=0,
            now=container.clock.now(),
        ).token
        header = base64.urlsafe_b64encode(b'{"alg":"none","kid":"k1"}').rstrip(b"=").decode()
        payload = (
            base64.urlsafe_b64encode(json.dumps({"sub": me["id"]}).encode()).rstrip(b"=").decode()
        )
        for token in (forged, f"{header}.{payload}."):
            response = await api.get(
                "/api/v1/users/me", headers={"Authorization": f"Bearer {token}"}
            )
            _assert_error_shape(response, 401)

    async def test_full_login_refresh_logout_cycle(self, api: httpx2.AsyncClient) -> None:
        session = await signup(api)
        login = await api.post(
            "/api/v1/auth/login", json={"email": session.email, "password": PASSWORD}
        )
        assert login.status_code == 200
        tokens = login.json()
        refreshed = await api.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert refreshed.status_code == 200
        headers = {"Authorization": f"Bearer {refreshed.json()['access_token']}"}
        assert (await api.post("/api/v1/auth/logout", headers=headers)).status_code == 204
        _assert_error_shape(await api.get("/api/v1/users/me", headers=headers), 401)

    async def test_oauth2_form_token_endpoint(self, api: httpx2.AsyncClient) -> None:
        session = await signup(api)
        response = await api.post(
            "/api/v1/auth/token",
            data={"grant_type": "password", "username": session.email, "password": PASSWORD},
        )
        assert response.status_code == 200
        assert response.json()["token_type"] == "bearer"

    async def test_login_brute_force_is_rate_limited(self, api: httpx2.AsyncClient) -> None:
        session = await signup(api)
        statuses = []
        for _ in range(8):
            response = await api.post(
                "/api/v1/auth/login",
                json={"email": session.email, "password": "definitely-wrong-1"},
            )
            statuses.append(response.status_code)
        assert 429 in statuses
        limited = next(r for r in [response] if r.status_code == 429)
        assert int(limited.headers["retry-after"]) >= 1

    async def test_password_reset_does_not_reveal_accounts(self, api: httpx2.AsyncClient) -> None:
        session = await signup(api)
        known = await api.post("/api/v1/auth/password/reset-request", json={"email": session.email})
        unknown = await api.post(
            "/api/v1/auth/password/reset-request", json={"email": unique_email()}
        )
        assert known.status_code == unknown.status_code == 202
        assert known.json() == unknown.json()

    async def test_sign_up_does_not_reveal_accounts(self, api: httpx2.AsyncClient) -> None:
        # It used to answer 409 email_taken: anyone could test who has an account.
        session = await signup(api)
        known = await api.post("/api/v1/auth/register", json={"email": session.email})
        unknown = await api.post("/api/v1/auth/register", json={"email": unique_email()})
        assert known.status_code == unknown.status_code == 202
        assert known.json() == unknown.json()
        assert set(known.headers) == set(unknown.headers)


class TestInputHandling:
    async def test_mass_assignment_is_rejected(self, api: httpx2.AsyncClient) -> None:
        response = await api.post(
            "/api/v1/auth/register/complete",
            json={
                "token": "a-sign-up-token",
                "password": PASSWORD,
                "full_name": "X",
                "organization_name": "Org",
                "is_platform_admin": True,
                "role": "owner",
            },
        )
        _assert_error_shape(response, 422, "validation_failed")
        started = await api.post(
            "/api/v1/auth/register", json={"email": unique_email(), "password": PASSWORD}
        )
        _assert_error_shape(started, 422, "validation_failed")  # the password comes later

    async def test_validation_errors_never_echo_input(self, api: httpx2.AsyncClient) -> None:
        secret = "super-secret-password-value"
        response = await api.post(
            "/api/v1/auth/login", json={"email": "not-an-email", "password": secret}
        )
        _assert_error_shape(response, 422)
        assert secret not in response.text
        assert "not-an-email" not in response.text

    async def test_oversized_body_rejected(self, api: httpx2.AsyncClient) -> None:
        response = await api.post(
            "/api/v1/auth/login",
            content=b'{"email": "' + b"a" * (2 * 1024 * 1024) + b'"}',
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 413

    async def test_invalid_host_header_rejected(self, api: httpx2.AsyncClient) -> None:
        response = await api.get("/health/live", headers={"host": "evil.example.com"})
        assert response.status_code == 400

    async def test_sql_injection_payloads_are_inert(self, api: httpx2.AsyncClient) -> None:
        session = await signup(api)
        for payload in ("' OR '1'='1", "1; DROP TABLE users;--", "-created_at; select pg_sleep(5)"):
            response = await session.get(
                "/api/v1/organizations/current/members", params={"sort": payload}
            )
            assert response.status_code == 422
            response = await session.get(
                "/api/v1/organizations/current/members", params={"cursor": payload}
            )
            assert response.status_code == 422

    async def test_unknown_routes_use_error_schema(self, api: httpx2.AsyncClient) -> None:
        _assert_error_shape(await api.get("/api/v1/../../etc/passwd"), 404)


class TestAuthorization:
    async def test_secrets_never_serialized(self, api: httpx2.AsyncClient) -> None:
        session = await signup(api)
        created = await session.post(
            "/api/v1/api-keys",
            json={"name": "ci", "role": "viewer", "scopes": ["sources:read"], "expires_in_days": 7},
        )
        assert created.status_code == 201
        listing = await session.get("/api/v1/api-keys")
        me = await session.get("/api/v1/users/me")
        for response in (created, listing, me):
            for field in SECRET_FIELDS:
                assert field not in response.text
        token = created.json()["token"]
        assert token not in listing.text

    async def test_api_key_scopes_are_enforced(self, api: httpx2.AsyncClient) -> None:
        session = await signup(api)
        created = await session.post(
            "/api/v1/api-keys",
            json={"name": "reader", "role": "viewer", "scopes": ["org:read"], "expires_in_days": 7},
        )
        key_headers = {"Authorization": f"Bearer {created.json()['token']}"}
        assert (
            await api.get("/api/v1/organizations/current", headers=key_headers)
        ).status_code == 200
        forbidden = await api.post(
            "/api/v1/api-keys",
            headers=key_headers,
            json={"name": "x", "role": "viewer", "scopes": ["org:read"], "expires_in_days": 1},
        )
        _assert_error_shape(forbidden, 403)

    async def test_role_escalation_through_api_key_is_blocked(
        self, api: httpx2.AsyncClient
    ) -> None:
        session = await signup(api)
        response = await session.post(
            "/api/v1/api-keys",
            json={
                "name": "x",
                "role": "viewer",
                "scopes": ["members:manage"],
                "expires_in_days": 1,
            },
        )
        _assert_error_shape(response, 422)

    async def test_cross_tenant_resources_are_invisible(self, api: httpx2.AsyncClient) -> None:
        alice = await signup(api)
        bob = await signup(api)
        bob_members = (await bob.get("/api/v1/organizations/current/members")).json()["items"]
        target = bob_members[0]["membership_id"]
        response = await alice.patch(
            f"/api/v1/organizations/current/members/{target}", json={"role": "viewer"}
        )
        _assert_error_shape(response, 404)
        response = await alice.delete(f"/api/v1/organizations/current/members/{target}")
        _assert_error_shape(response, 404)
        key = await bob.post(
            "/api/v1/api-keys",
            json={"name": "b", "role": "viewer", "scopes": ["org:read"], "expires_in_days": 1},
        )
        _assert_error_shape(await alice.delete(f"/api/v1/api-keys/{key.json()['id']}"), 404)

    async def test_audit_log_and_integrity_endpoint(self, api: httpx2.AsyncClient) -> None:
        session = await signup(api)
        entries = await session.get("/api/v1/audit")
        assert entries.status_code == 200
        actions = {e["action"] for e in entries.json()["items"]}
        assert "auth.registered" in actions
        verification = await session.get("/api/v1/audit/verify")
        assert verification.json()["ok"] is True


class TestResponseHardening:
    async def test_security_headers(self, api: httpx2.AsyncClient) -> None:
        response = await api.get("/health/live")
        headers = response.headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "no-referrer"
        assert "default-src 'none'" in headers["content-security-policy"]
        assert headers["cache-control"] == "no-store"
        assert "server" not in headers
        assert headers["x-request-id"]

    async def test_client_request_id_is_not_trusted_from_untrusted_peers(
        self, api: httpx2.AsyncClient
    ) -> None:
        response = await api.get("/health/live", headers={"x-request-id": "attacker-chosen-id"})
        assert response.headers["x-request-id"] != "attacker-chosen-id"

    async def test_spoofed_forwarded_for_is_ignored(
        self, api: httpx2.AsyncClient, admin_conn: object
    ) -> None:
        response = await api.post(
            "/api/v1/auth/login",
            json={"email": unique_email(), "password": "wrong-password-x"},
            headers={"x-forwarded-for": "1.2.3.4"},
        )
        assert response.status_code == 401

    async def test_readiness_reports_dependencies(self, api: httpx2.AsyncClient) -> None:
        response = await api.get("/health/ready")
        assert response.status_code == 200
        assert response.json()["checks"] == {"database": "ok", "redis": "ok"}

    async def test_jwks_exposes_only_public_keys(self, api: httpx2.AsyncClient) -> None:
        keys = (await api.get("/.well-known/jwks.json")).json()["keys"]
        assert keys and all(set(k) == {"kty", "crv", "kid", "use", "alg", "x"} for k in keys)

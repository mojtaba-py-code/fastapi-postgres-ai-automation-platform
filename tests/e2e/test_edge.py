"""Security properties of the deployed edge that unit tests cannot see: what nginx
exposes, the headers that reach a browser, and isolation between real tenants."""

from __future__ import annotations

import json
import secrets
import uuid

import httpx2
import pytest

from tests.e2e.conftest import LiveStack

API = "/api/v1"


def _owner(client: httpx2.Client) -> dict[str, str]:
    registered = client.post(
        f"{API}/auth/register",
        json={
            "email": f"e2e+{uuid.uuid4().hex[:10]}@nexusflow.example.com",
            "password": secrets.token_urlsafe(18),
            "full_name": "E2E Owner",
            "organization_name": f"E2E {uuid.uuid4().hex[:6]}",
        },
    )
    assert registered.status_code == 201, registered.text
    return {"Authorization": f"Bearer {registered.json()['access_token']}"}


def test_the_platform_reports_ready(client: httpx2.Client) -> None:
    assert client.get("/health/live").status_code == 200
    ready = client.get("/health/ready")
    assert ready.status_code == 200, ready.text
    assert set(ready.json()["checks"].values()) == {"ok"}
    assert client.get("/.well-known/jwks.json").json()["keys"]


@pytest.mark.parametrize(
    "path",
    ["/metrics", "/internal/v1/automation/health", "/docs", "/openapi.json"],
)
def test_internal_and_operational_endpoints_are_not_published(
    client: httpx2.Client, path: str
) -> None:
    assert client.get(path).status_code == 404


def test_responses_carry_the_security_headers(client: httpx2.Client, live: LiveStack) -> None:
    response = client.get(f"{API}/projects")
    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["cache-control"] == "no-store"
    assert headers.get("server", "nginx").lower() in ("nginx", "")  # no version disclosed
    if live.is_https:
        assert "max-age=" in headers["strict-transport-security"]


def test_the_api_requires_authentication(client: httpx2.Client) -> None:
    response = client.get(f"{API}/projects")
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")
    assert set(response.json()) >= {"error", "message", "request_id"}


def test_tenants_cannot_see_each_other(client: httpx2.Client) -> None:
    alice, mallory = _owner(client), _owner(client)
    project = client.post(f"{API}/projects", json={"name": "Secret"}, headers=alice)
    assert project.status_code == 201, project.text
    project_id = project.json()["id"]

    assert client.get(f"{API}/projects/{project_id}", headers=mallory).status_code == 404
    listed = client.get(f"{API}/projects", headers=mallory).json()["items"]
    assert project_id not in {p["id"] for p in listed}


def test_a_forged_webhook_is_rejected(client: httpx2.Client) -> None:
    body = json.dumps({"items": []}).encode()
    response = client.post(
        f"{API}/webhooks/{uuid.uuid4()}/{uuid.uuid4()}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-NexusFlow-Delivery": f"dlv-{uuid.uuid4().hex}",
            "X-NexusFlow-Signature": "t=1,v1=" + "0" * 64,
        },
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_signature"


def test_oversized_bodies_are_refused_at_the_edge(client: httpx2.Client) -> None:
    response = client.post(
        f"{API}/auth/login",
        content=b"{" + b" " * (2 * 1024 * 1024) + b"}",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413

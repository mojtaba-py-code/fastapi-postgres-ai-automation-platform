"""Security properties of the deployed edge that unit tests cannot see: what nginx
exposes, the headers that reach a browser, and isolation between real tenants."""

from __future__ import annotations

import json
import re
import uuid
from types import ModuleType

import httpx2
import pytest

from tests.e2e.conftest import LiveStack, sign_up

API = "/api/v1"


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


def test_responses_the_edge_generates_carry_the_security_headers(
    client: httpx2.Client,
) -> None:
    response = client.get("/metrics")  # answered by nginx itself, never proxied
    assert response.status_code == 404
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert "max-age=" in response.headers["strict-transport-security"]
    assert "camera=()" in response.headers["permissions-policy"]
    # The same JSON error schema as the application's own errors.
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["error"] == "not_found"
    uuid_shaped = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    assert re.fullmatch(uuid_shaped, response.json()["request_id"])
    proxied = client.get(f"{API}/projects")  # the application echoes the edge's id
    assert re.fullmatch(uuid_shaped, proxied.headers["x-request-id"])


def test_security_headers_are_never_sent_twice(client: httpx2.Client) -> None:
    response = client.get(f"{API}/projects")  # proxied: the application sets them
    for name in (
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "cache-control",
        "content-security-policy",
        "strict-transport-security",
        "permissions-policy",
    ):
        assert len(response.headers.get_list(name)) <= 1, name


def test_the_api_requires_authentication(client: httpx2.Client) -> None:
    response = client.get(f"{API}/projects")
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")
    assert set(response.json()) >= {"error", "message", "request_id"}


def test_tenants_cannot_see_each_other(
    client: httpx2.Client, live: LiveStack, demo: ModuleType
) -> None:
    alice, mallory = (
        sign_up(client, live, demo, "E2E Alice"),
        sign_up(client, live, demo, "E2E Mallory"),
    )
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
    assert response.json()["error"] == "payload_too_large"

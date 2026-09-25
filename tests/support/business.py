"""Shared helpers for business-API tests: payloads and resource factories."""

from __future__ import annotations

import time
from typing import Any
from uuid import UUID, uuid4

import httpx2

from nexusflow.domain.webhooks.signatures import build_signature_header
from tests.support.api import ApiSession

SCHEMA: dict[str, Any] = {
    "fields": [
        {"name": "sku", "type": "string", "required": True},
        {"name": "title", "type": "string"},
        {"name": "price", "type": "decimal"},
        {"name": "supplier_email", "type": "string", "sensitive": True},
    ],
    "key_field": "sku",
}
WEBHOOK_CONFIG = {
    "kind": "webhook",
    "items_path": "items",
    "field_mapping": {
        "sku": "sku",
        "title": "title",
        "price": "price",
        "supplier_email": "supplier.email",
    },
}
UPLOAD_CONFIG = {
    "kind": "file_upload",
    "format": "csv",
    "column_mapping": {"sku": "SKU", "title": "Title", "price": "Price", "supplier_email": "Email"},
}


def expect_error(response: httpx2.Response, status: int, code: str | None = None) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    assert set(body) >= {"error", "message", "request_id"}
    if code is not None:
        assert body["error"] == code, body
    return body


async def org_id_of(session: ApiSession) -> UUID:
    response = await session.get("/api/v1/organizations/current")
    return UUID(response.json()["id"])


async def create_project(session: ApiSession, name: str = "Pricing") -> str:
    response = await session.post(
        "/api/v1/projects", json={"name": name, "description": "Competitor prices"}
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def create_dataset(session: ApiSession, project_id: str) -> str:
    response = await session.post(
        "/api/v1/datasets",
        json={"project_id": project_id, "name": f"products-{uuid4().hex[:6]}", "schema": SCHEMA},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def create_source(
    session: ApiSession, project_id: str, dataset_id: str, config: dict[str, Any]
) -> str:
    response = await session.post(
        "/api/v1/sources",
        json={
            "project_id": project_id,
            "dataset_id": dataset_id,
            "name": f"src-{uuid4().hex[:6]}",
            "config": config,
        },
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def viewer_key(session: ApiSession, scopes: list[str]) -> dict[str, str]:
    response = await session.post(
        "/api/v1/api-keys",
        json={"name": "viewer", "role": "viewer", "scopes": scopes, "expires_in_days": 1},
    )
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def signed_headers(secret: str, body: bytes, delivery_id: str | None = None) -> dict[str, str]:
    delivery = delivery_id or f"dlv-{uuid4().hex}"
    header = build_signature_header(
        secret.encode(), timestamp=int(time.time()), delivery_id=delivery, body=body
    )
    return {
        "Content-Type": "application/json",
        "X-NexusFlow-Signature": header,
        "X-NexusFlow-Delivery": delivery,
    }

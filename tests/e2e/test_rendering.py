"""A JavaScript-rendered source on the live stack: the real headless Chromium, behind
its pinning egress proxy, renders a public page, and the pipeline stores what it
extracted. Needs internet access from the stack (CI runners have it)."""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Any

import httpx2
import pytest

API = "/api/v1"
PAGE = "https://example.com/"  # IANA's reserved example page: stable, public, no robots.txt


def _owner(client: httpx2.Client) -> dict[str, str]:
    registered = client.post(
        f"{API}/auth/register",
        json={
            "email": f"e2e+{uuid.uuid4().hex[:10]}@nexusflow.example.com",
            "password": secrets.token_urlsafe(18),
            "full_name": "E2E Renderer",
            "organization_name": f"E2E Rendering {uuid.uuid4().hex[:6]}",
        },
    )
    assert registered.status_code == 201, registered.text
    return {"Authorization": f"Bearer {registered.json()['access_token']}"}


def _created(response: httpx2.Response) -> dict[str, Any]:
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def test_a_javascript_source_is_rendered_by_the_real_browser(client: httpx2.Client) -> None:
    owner = _owner(client)
    project = _created(client.post(f"{API}/projects", json={"name": "Rendered"}, headers=owner))
    dataset = _created(
        client.post(
            f"{API}/datasets",
            json={
                "project_id": project["id"],
                "name": "Example pages",
                "schema": {
                    "fields": [{"name": "title", "type": "string", "required": True}],
                    "key_field": "title",
                },
                "classification": "internal",
                "retention_days": 30,
            },
            headers=owner,
        )
    )
    source = _created(
        client.post(
            f"{API}/sources",
            json={
                "project_id": project["id"],
                "dataset_id": dataset["id"],
                "name": "example.com, rendered",
                "config": {
                    "kind": "website",
                    "url": PAGE,
                    "item_selector": "body",
                    "fields": {"title": {"selector": "h1"}},
                    "render_javascript": True,
                },
            },
            headers=owner,
        )
    )

    queued = client.post(f"{API}/sources/{source['id']}/runs", headers=owner)
    assert queued.status_code == 202, queued.text
    run_id = queued.json()["id"]
    deadline = time.monotonic() + 180
    while True:
        run = client.get(f"{API}/runs/{run_id}", headers=owner).json()
        if run["status"] in ("succeeded", "failed", "cancelled"):
            break
        if time.monotonic() > deadline:
            pytest.fail(f"the rendered run did not finish in time: {run}")
        time.sleep(2)
    assert run["status"] == "succeeded", run

    records = client.get(f"{API}/datasets/{dataset['id']}/records", headers=owner).json()["items"]
    assert len(records) == 1, records
    assert "Example" in records[0]["data"]["title"]

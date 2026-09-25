"""IDOR sweep: another tenant's identifiers are invisible on every resource route.

Tenant A creates one of everything; tenant B - an owner with every permission
in its own organization - tries to read, change, run and delete each of them
by identifier. Every attempt must answer 404 (never 403, which would confirm
that the identifier exists) and change nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest

from tests.support.api import ApiSession, signup
from tests.support.business import (
    WEBHOOK_CONFIG,
    create_dataset,
    create_project,
    create_source,
)

pytestmark = [pytest.mark.integration, pytest.mark.security]

WEBSITE = {
    "kind": "website",
    "url": "https://shop.example.com/products",
    "item_selector": "div.product",
    "fields": {"sku": {"selector": ".sku"}},
}


async def _created(response: httpx2.Response) -> str:
    assert response.status_code in (201, 202), response.text
    return str(response.json()["id"])


async def _tenant_a_resources(owner: ApiSession) -> dict[str, str]:
    project = await create_project(owner)
    dataset = await create_dataset(owner, project)
    webhook_source = await create_source(owner, project, dataset, WEBHOOK_CONFIG)
    website_source = await create_source(owner, project, dataset, WEBSITE)
    now = datetime.now(UTC)
    return {
        "project": project,
        "dataset": dataset,
        "source": webhook_source,
        "run": await _created(await owner.post(f"/api/v1/sources/{website_source}/runs")),
        "integration": await _created(
            await owner.post(
                "/api/v1/integrations",
                json={"name": "crm", "kind": "http_bearer", "secret": "s3cr3t-token-value"},
            )
        ),
        "channel": await _created(
            await owner.post(
                "/api/v1/channels",
                json={"name": "ops", "config": {"kind": "email", "recipients": ["a@example.com"]}},
            )
        ),
        "rule": await _created(
            await owner.post(
                "/api/v1/alert-rules",
                json={"project_id": project, "name": "Broken", "condition": {"type": "run_failed"}},
            )
        ),
        "workflow": await _created(
            await owner.post(
                "/api/v1/workflows",
                json={
                    "project_id": project,
                    "name": "Nightly",
                    "trigger": "manual",
                    "source_ids": [website_source],
                },
            )
        ),
        "endpoint": await _created(
            await owner.post(
                "/api/v1/webhook-endpoints", json={"source_id": webhook_source, "name": "feed"}
            )
        ),
        "report": await _created(
            await owner.post(
                "/api/v1/reports",
                json={
                    "project_id": project,
                    "format": "json",
                    "period_start": (now - timedelta(days=1)).isoformat(),
                    "period_end": now.isoformat(),
                },
            )
        ),
        "insight": await _created(
            await owner.post("/api/v1/intelligence/analyses", json={"dataset_id": dataset})
        ),
    }


ATTEMPTS: list[tuple[str, str, dict[str, Any] | None]] = [
    ("GET", "/api/v1/projects/{project}", None),
    ("PATCH", "/api/v1/projects/{project}", {"description": "pwned"}),
    ("DELETE", "/api/v1/projects/{project}", None),
    ("GET", "/api/v1/datasets/{dataset}", None),
    ("GET", "/api/v1/datasets/{dataset}/records", None),
    ("GET", "/api/v1/datasets/{dataset}/export", None),
    ("PATCH", "/api/v1/datasets/{dataset}", {"description": "pwned"}),
    ("DELETE", "/api/v1/datasets/{dataset}", None),
    ("GET", "/api/v1/sources/{source}", None),
    ("GET", "/api/v1/sources/{source}/runs", None),
    ("POST", "/api/v1/sources/{source}/runs", None),
    ("DELETE", "/api/v1/sources/{source}", None),
    ("GET", "/api/v1/runs/{run}", None),
    ("GET", "/api/v1/integrations/{integration}", None),
    ("POST", "/api/v1/integrations/{integration}/rotate", {"secret": "attacker-value-1234"}),
    ("DELETE", "/api/v1/integrations/{integration}", None),
    ("PATCH", "/api/v1/channels/{channel}", {"enabled": False}),
    ("DELETE", "/api/v1/channels/{channel}", None),
    ("PATCH", "/api/v1/alert-rules/{rule}", {"enabled": False}),
    ("DELETE", "/api/v1/alert-rules/{rule}", None),
    ("GET", "/api/v1/workflows/{workflow}", None),
    ("GET", "/api/v1/workflows/{workflow}/runs", None),
    ("POST", "/api/v1/workflows/{workflow}/runs", None),
    ("POST", "/api/v1/workflows/{workflow}/status", {"status": "disabled", "reason": "pwned"}),
    ("DELETE", "/api/v1/workflows/{workflow}", None),
    ("POST", "/api/v1/webhook-endpoints/{endpoint}/rotate-secret", None),
    ("POST", "/api/v1/webhook-endpoints/{endpoint}/status", {"status": "disabled"}),
    ("GET", "/api/v1/reports/{report}", None),
    ("GET", "/api/v1/reports/{report}/download", None),
    ("GET", "/api/v1/intelligence/insights/{insight}", None),
    ("POST", "/api/v1/intelligence/analyses", {"dataset_id": "{dataset}"}),
]


async def test_no_route_reveals_or_touches_another_tenants_resources(
    api: httpx2.AsyncClient,
) -> None:
    alice, mallory = await signup(api), await signup(api)
    ids = await _tenant_a_resources(alice)

    answers: dict[str, int] = {}
    for method, template, body in ATTEMPTS:
        path = template.format(**ids)
        payload = (
            {k: (v.format(**ids) if isinstance(v, str) else v) for k, v in body.items()}
            if body is not None
            else None
        )
        response = await mallory.client.request(method, path, json=payload, headers=mallory.headers)
        answers[f"{method} {template}"] = response.status_code
    assert {route: status for route, status in answers.items() if status != 404} == {}

    # And nothing changed for the owner.
    for template in (
        "/api/v1/projects/{project}",
        "/api/v1/datasets/{dataset}",
        "/api/v1/workflows/{workflow}",
        "/api/v1/integrations/{integration}",
    ):
        assert (await alice.get(template.format(**ids))).status_code == 200
    workflow = (await alice.get(f"/api/v1/workflows/{ids['workflow']}")).json()
    assert workflow["status"] != "disabled"

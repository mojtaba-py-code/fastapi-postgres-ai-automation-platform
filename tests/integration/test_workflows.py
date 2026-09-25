"""Scheduled workflows through the API: validation, versioning, status, runs, audit."""

from __future__ import annotations

from typing import Any

import httpx2
import pytest

from tests.support.api import ApiSession, signup
from tests.support.business import (
    WEBHOOK_CONFIG,
    create_dataset,
    create_project,
    create_source,
    expect_error,
)

pytestmark = pytest.mark.integration

WEBSITE = {
    "kind": "website",
    "url": "https://shop.example.com/products",
    "item_selector": "div.product",
    "fields": {"sku": {"selector": ".sku"}},
}


async def _setup(api: httpx2.AsyncClient) -> tuple[ApiSession, str, str]:
    owner = await signup(api)
    project_id = await create_project(owner)
    dataset_id = await create_dataset(owner, project_id)
    return owner, project_id, await create_source(owner, project_id, dataset_id, WEBSITE)


async def _workflow(
    owner: ApiSession, project_id: str, source_id: str, **body: Any
) -> dict[str, Any]:
    created = await owner.post(
        "/api/v1/workflows",
        json={
            "project_id": project_id,
            "name": "Hourly prices",
            "schedule_interval_minutes": 60,
            "source_ids": [source_id],
            **body,
        },
    )
    assert created.status_code == 201, created.text
    workflow: dict[str, Any] = created.json()
    return workflow


async def _actions(owner: ApiSession) -> list[str]:
    response = await owner.get("/api/v1/audit", params={"resource_type": "workflow", "limit": "50"})
    return [entry["action"] for entry in response.json()["items"]]


async def test_a_scheduled_workflow_from_creation_to_emergency_stop(
    api: httpx2.AsyncClient,
) -> None:
    owner, project_id, source_id = await _setup(api)
    workflow = await _workflow(owner, project_id, source_id)
    path = f"/api/v1/workflows/{workflow['id']}"
    assert (workflow["status"], workflow["version"]) == ("active", 1)
    assert workflow["next_run_at"] is not None

    # Optimistic concurrency: an update based on a stale version is refused.
    renamed = await owner.patch(path, json={"name": "Prices", "expected_version": 1})
    assert (renamed.status_code, renamed.json()["version"]) == (200, 2)
    expect_error(
        await owner.patch(path, json={"name": "Lost update", "expected_version": 1}),
        409,
        "version_conflict",
    )

    paused = await owner.post(f"{path}/status", json={"status": "paused"})
    assert (paused.json()["status"], paused.json()["next_run_at"]) == ("paused", None)
    resumed = await owner.post(f"{path}/status", json={"status": "active"})
    assert resumed.json()["next_run_at"] is not None

    # Run now is idempotent per Idempotency-Key.
    key = {"Idempotency-Key": "run-2026-09-24-a"}
    first = await owner.post(f"{path}/runs", headers=key)
    again = await owner.post(f"{path}/runs", headers=key)
    assert (first.status_code, again.status_code) == (202, 200)
    assert first.json()["id"] == again.json()["id"]

    # The emergency stop cancels queued work and refuses new runs.
    disabled = await owner.post(
        f"{path}/status", json={"status": "disabled", "reason": "leaking credentials"}
    )
    assert (disabled.json()["status"], disabled.json()["disabled_reason"]) == (
        "disabled",
        "leaking credentials",
    )
    [run] = (await owner.get(f"{path}/runs")).json()["items"]
    assert (run["status"], run["error_code"]) == ("cancelled", "workflow_disabled")
    expect_error(await owner.post(f"{path}/runs"), 409, "workflow_not_runnable")

    assert set(await _actions(owner)) >= {
        "workflow.created",
        "workflow.updated",
        "workflow.enabled",
        "workflow.executed",
        "workflow.disabled",
    }


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"schedule_interval_minutes": None}, "invalid_interval"),  # scheduled needs one
        ({"trigger": "manual"}, "invalid_interval"),  # manual has none
    ],
)
async def test_schedules_are_validated(
    api: httpx2.AsyncClient, body: dict[str, Any], code: str
) -> None:
    owner, project_id, source_id = await _setup(api)
    response = await owner.post(
        "/api/v1/workflows",
        json={
            "project_id": project_id,
            "name": "Broken",
            "schedule_interval_minutes": 60,
            "source_ids": [source_id],
            **body,
        },
    )
    expect_error(response, 422, code)


async def test_only_pull_sources_of_the_same_project_can_be_scheduled(
    api: httpx2.AsyncClient,
) -> None:
    owner, project_id, _ = await _setup(api)
    dataset_id = await create_dataset(owner, project_id)
    webhook_source = await create_source(owner, project_id, dataset_id, WEBHOOK_CONFIG)
    expect_error(
        await owner.post(
            "/api/v1/workflows",
            json={
                "project_id": project_id,
                "name": "Push",
                "schedule_interval_minutes": 60,
                "source_ids": [webhook_source],
            },
        ),
        422,
        "not_pull_source",
    )
    other_project = await create_project(owner, name="Other")
    other_dataset = await create_dataset(owner, other_project)
    foreign = await create_source(owner, other_project, other_dataset, WEBSITE)
    response = await owner.post(
        "/api/v1/workflows",
        json={
            "project_id": project_id,
            "name": "Cross-project",
            "schedule_interval_minutes": 60,
            "source_ids": [foreign],
        },
    )
    assert response.status_code == 404


async def test_a_frozen_organization_cannot_run_workflows(api: httpx2.AsyncClient) -> None:
    owner, project_id, source_id = await _setup(api)
    workflow = await _workflow(owner, project_id, source_id)
    frozen = await owner.post(
        "/api/v1/organizations/current/automation-freeze",
        json={"frozen": True, "reason": "incident 42"},
    )
    assert frozen.status_code == 200, frozen.text
    expect_error(
        await owner.post(f"/api/v1/workflows/{workflow['id']}/runs"), 409, "automation_frozen"
    )

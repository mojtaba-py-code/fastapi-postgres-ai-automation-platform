"""Data lifecycle: retention, purges and deletions happen - and are audited."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import asyncpg
import httpx2
import pytest

from nexusflow.bootstrap.container import Container
from tests.support.api import ApiSession, signup
from tests.support.business import (
    WEBHOOK_CONFIG,
    create_dataset,
    create_project,
    create_source,
    org_id_of,
)

pytestmark = pytest.mark.integration

WEBSITE = {
    "kind": "website",
    "url": "https://shop.example.com/products",
    "item_selector": "div.product",
    "fields": {"sku": {"selector": ".sku"}},
}


async def _audit(owner: ApiSession, action: str) -> list[dict[str, Any]]:
    response = await owner.get("/api/v1/audit", params={"action": action, "limit": "50"})
    assert response.status_code == 200, response.text
    entries: list[dict[str, Any]] = response.json()["items"]
    return entries


async def test_sign_up_records_the_new_organization(api: httpx2.AsyncClient) -> None:
    owner = await signup(api)
    [created] = await _audit(owner, "org.created")
    assert created["resource_id"] == str(await org_id_of(owner))


async def test_retention_purges_old_operational_data_and_audits_it(
    api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
) -> None:
    owner = await signup(api)
    org_id = await org_id_of(owner)
    project_id = await create_project(owner)
    dataset_id = await create_dataset(owner, project_id)
    source_id = await create_source(owner, project_id, dataset_id, WEBSITE)
    run = await owner.post(f"/api/v1/sources/{source_id}/runs")
    assert run.status_code == 202, run.text
    run_id = UUID(run.json()["id"])
    await container.ingestion.fail_run(org_id=org_id, run_id=run_id, code="http_503", detail=None)
    await admin_conn.execute(
        "UPDATE collection_runs SET created_at = $2 WHERE id = $1",
        run_id,
        datetime.now(UTC) - timedelta(days=400),
    )

    report = await container.maintenance.apply_retention(org_id)

    assert report.purged["collection_runs"] == 1
    assert (
        await admin_conn.fetchval("SELECT count(*) FROM collection_runs WHERE id = $1", run_id) == 0
    )
    [purged] = await _audit(owner, "data.retention_purged")
    assert purged["metadata"] == {"collection_runs": 1}
    # A pass that deletes nothing leaves no audit noise.
    await container.maintenance.apply_retention(org_id)
    assert len(await _audit(owner, "data.retention_purged")) == 1


async def test_a_deleted_dataset_is_purged_and_audited(
    api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
) -> None:
    owner = await signup(api)
    org_id = await org_id_of(owner)
    project_id = await create_project(owner)
    dataset_id = await create_dataset(owner, project_id)
    await create_source(owner, project_id, dataset_id, WEBHOOK_CONFIG)
    assert not await container.maintenance.purge_dataset(org_id, UUID(dataset_id))  # still live

    deleted = await owner.delete(f"/api/v1/datasets/{dataset_id}")
    assert deleted.status_code == 204, deleted.text
    assert await container.maintenance.purge_dataset(org_id, UUID(dataset_id))

    assert (
        await admin_conn.fetchval("SELECT count(*) FROM datasets WHERE id = $1", UUID(dataset_id))
        == 0
    )
    [purged] = await _audit(owner, "dataset.purged")
    assert purged["resource_id"] == dataset_id


async def test_an_organization_is_purged_after_its_grace_period_and_its_audit_trail_remains(
    api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
) -> None:
    owner = await signup(api)
    org_id = await org_id_of(owner)
    slug = (await owner.get("/api/v1/organizations/current")).json()["slug"]
    requested = await owner.post(
        "/api/v1/organizations/current/deletion", json={"confirm_slug": slug}
    )
    assert requested.status_code in (200, 202, 204), requested.text
    assert org_id not in await container.maintenance.purge_due_organizations()  # grace period

    await admin_conn.execute(
        "UPDATE organizations SET deletion_requested_at = $2 WHERE id = $1",
        org_id,
        datetime.now(UTC) - timedelta(days=8),
    )
    assert org_id in await container.maintenance.purge_due_organizations()

    assert (
        await admin_conn.fetchval("SELECT count(*) FROM organizations WHERE id = $1", org_id) == 0
    )
    actions = {
        row["action"]
        for row in await admin_conn.fetch("SELECT action FROM audit_logs WHERE org_id = $1", org_id)
    }
    assert {"org.created", "org.deletion_requested", "org.purged"} <= actions


async def test_deleting_a_workflow_is_audited_as_a_deletion(api: httpx2.AsyncClient) -> None:
    owner = await signup(api)
    project_id = await create_project(owner)
    dataset_id = await create_dataset(owner, project_id)
    source_id = await create_source(owner, project_id, dataset_id, WEBSITE)  # a pull source
    created = await owner.post(
        "/api/v1/workflows",
        json={
            "project_id": project_id,
            "name": "Nightly",
            "trigger": "manual",
            "source_ids": [source_id],
        },
    )
    assert created.status_code == 201, created.text
    workflow_id = created.json()["id"]

    assert (await owner.delete(f"/api/v1/workflows/{workflow_id}")).status_code == 204
    [deleted] = await _audit(owner, "workflow.deleted")
    assert deleted["resource_id"] == workflow_id


async def test_old_dead_letters_are_purged_without_a_general_delete_right(
    api: httpx2.AsyncClient,
    container: Container,
    admin_conn: asyncpg.Connection,
    app_conn: asyncpg.Connection,
) -> None:
    owner = await signup(api)
    org_id = await org_id_of(owner)
    tenant_letter = await container.dead_letters.record(
        org_id=org_id,
        origin="celery",
        task_name="t",
        payload={},
        error_code="e",
        error_message=None,
        attempts=1,
        emit_event=False,
    )
    platform_letter = await container.dead_letters.record(
        org_id=None,
        origin="celery",
        task_name="t",
        payload={},
        error_code="e",
        error_message=None,
        attempts=1,
        emit_event=False,
    )
    await admin_conn.execute(
        "UPDATE dead_letters SET last_failed_at = $1 WHERE id = ANY($2::uuid[])",
        datetime.now(UTC) - timedelta(days=400),
        [tenant_letter.id, platform_letter.id],
    )

    assert (await container.maintenance.apply_retention(org_id)).purged["dead_letters"] == 1
    assert await container.maintenance.apply_platform_retention() >= 1
    remaining = await admin_conn.fetchval(
        "SELECT count(*) FROM dead_letters WHERE id = ANY($1::uuid[])",
        [tenant_letter.id, platform_letter.id],
    )
    assert remaining == 0
    # The runtime role still cannot delete dead letters itself.
    await app_conn.execute("SELECT set_config('app.current_org_id', $1, false)", str(org_id))
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("DELETE FROM dead_letters")

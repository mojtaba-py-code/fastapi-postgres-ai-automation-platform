"""Data lifecycle: retention, purges and deletions happen - and are audited."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import asyncpg
import httpx2
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.infrastructure.database.repositories.data import SqlMaintenanceRepository
from tests.support.api import ApiSession, signup
from tests.support.business import (
    SCHEMA,
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


PRICED = {**WEBSITE, "fields": {"sku": {"selector": ".sku"}, "price": {"selector": ".price"}}}


async def _priced_dataset(owner: ApiSession, **extra: Any) -> tuple[str, str]:
    project_id = await create_project(owner)
    created = await owner.post(
        "/api/v1/datasets",
        json={"project_id": project_id, "name": "prices", "schema": SCHEMA, **extra},
    )
    assert created.status_code == 201, created.text
    dataset_id = str(created.json()["id"])
    return dataset_id, await create_source(owner, project_id, dataset_id, PRICED)


async def _collect(
    owner: ApiSession, container: Container, source_id: str, items: list[dict[str, Any]]
) -> None:
    run = await owner.post(f"/api/v1/sources/{source_id}/runs")
    assert run.status_code == 202, run.text
    outcome = await container.ingestion.ingest(
        org_id=await org_id_of(owner), run_id=UUID(run.json()["id"]), items=items
    )
    assert outcome.status.value == "succeeded", outcome.stats


class TestRecordRetention:
    async def test_the_version_detection_still_needs_is_kept(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        dataset_id, source_id = await _priced_dataset(owner)
        await _collect(owner, container, source_id, [{"sku": "A-1", "price": "10"}])
        await container.detection.detect(org_id=org_id, dataset_id=UUID(dataset_id))
        # The record then stays unchanged for longer than the retention (180 days)...
        await admin_conn.execute(
            "UPDATE record_versions SET captured_at = now() - interval '400 days'"
            " WHERE dataset_id = $1",
            UUID(dataset_id),
        )
        # ...until a price change arrives that detection has not reached yet.
        await _collect(owner, container, source_id, [{"sku": "A-1", "price": "12"}])

        assert (await container.maintenance.apply_retention(org_id)).purged["record_versions"] == 0
        await container.detection.detect(org_id=org_id, dataset_id=UUID(dataset_id))

        changes = await admin_conn.fetch(
            "SELECT change_type, from_version, diff->'price' AS price FROM changes"
            " WHERE dataset_id = $1 ORDER BY to_version",
            UUID(dataset_id),
        )
        assert [c["change_type"] for c in changes] == ["created", "updated"]  # not "created"
        assert json.loads(changes[1]["price"])["old"] == "10"
        # Once version 2 is diffed, version 1 is no longer needed.
        assert (await container.maintenance.apply_retention(org_id)).purged["record_versions"] == 1

    async def test_retention_reaches_every_dataset_of_a_large_tenant(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        dataset_id, source_id = await _priced_dataset(owner, retention_days=7)
        for price in ("1.00", "2.00"):
            await _collect(owner, container, source_id, [{"sku": "A-1", "price": price}])
        await container.detection.detect(org_id=org_id, dataset_id=UUID(dataset_id))
        await admin_conn.execute(
            "UPDATE record_versions SET captured_at = now() - interval '30 days'"
            " WHERE dataset_id = $1",
            UUID(dataset_id),
        )
        # 200 newer datasets: the first page of the listing no longer holds the old one.
        project_id = await admin_conn.fetchval(
            "SELECT project_id FROM datasets WHERE id = $1", UUID(dataset_id)
        )
        await admin_conn.execute(
            "INSERT INTO datasets (id, org_id, project_id, name, schema, classification,"
            " retention_days, created_at, updated_at)"
            " SELECT gen_random_uuid(), $1, $2, 'bulk-' || n, $3::jsonb, 'internal', 7,"
            " now() + n * interval '1 second', now() FROM generate_series(1, 200) AS n",
            org_id,
            project_id,
            json.dumps(SCHEMA),
        )

        report = await container.maintenance.apply_retention(org_id)

        assert report.purged["record_versions"] == 1
        versions = await admin_conn.fetchval(
            "SELECT count(*) FROM record_versions WHERE dataset_id = $1", UUID(dataset_id)
        )
        assert versions == 1  # the newest stays

    async def test_old_changes_are_purged_once_their_alerts_are_evaluated(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        dataset_id, source_id = await _priced_dataset(owner, retention_days=30)
        for price in ("10", "12"):
            await _collect(owner, container, source_id, [{"sku": "A-1", "price": price}])
        await container.detection.detect(org_id=org_id, dataset_id=UUID(dataset_id))
        await admin_conn.execute(
            "UPDATE changes SET detected_at = now() - interval '60 days' WHERE dataset_id = $1",
            UUID(dataset_id),
        )

        before = await container.maintenance.apply_retention(org_id)
        await container.alerts.evaluate_changes(org_id=org_id)
        after = await container.maintenance.apply_retention(org_id)

        assert before.purged["changes"] == 0  # alerts were still to be evaluated
        assert after.purged["changes"] == 2
        left = await admin_conn.fetchval(
            "SELECT count(*) FROM changes WHERE dataset_id = $1", UUID(dataset_id)
        )
        assert left == 0
        [purged] = await _audit(owner, "data.retention_purged")
        assert purged["metadata"] == {"changes": 2}

    async def test_each_target_is_purged_in_batches_and_a_failing_one_spares_the_others(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        admin_conn: asyncpg.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, WEBSITE)
        for _ in range(5):
            run = await owner.post(f"/api/v1/sources/{source_id}/runs")
            await container.ingestion.fail_run(
                org_id=org_id, run_id=UUID(run.json()["id"]), code="http_503", detail=None
            )
        await admin_conn.execute(
            "UPDATE collection_runs SET created_at = now() - interval '400 days'"
            " WHERE source_id = $1",
            UUID(source_id),
        )
        monkeypatch.setattr(container.maintenance, "_batch", 2)
        batches: list[str] = []
        real_purge = SqlMaintenanceRepository.purge

        async def purge(self: Any, org: Any, target: str, before: Any, **kw: Any) -> int:
            batches.append(target)
            if target == "inbound_webhook_events":
                raise RuntimeError("statement timeout")
            return await real_purge(self, org, target, before, **kw)

        monkeypatch.setattr(SqlMaintenanceRepository, "purge", purge)

        with pytest.raises(RuntimeError, match="statement timeout"):
            await container.maintenance.apply_retention(org_id)

        # Three short batches (2 + 2 + 1), committed although a later target failed.
        assert batches.count("collection_runs") == 3
        assert "notification_deliveries" in batches  # the targets after it still ran
        remaining = await admin_conn.fetchval(
            "SELECT count(*) FROM collection_runs WHERE source_id = $1", UUID(source_id)
        )
        assert remaining == 0
        [purged] = await _audit(owner, "data.retention_purged")
        assert purged["metadata"] == {"collection_runs": 5}


class TestLargePurges:
    async def test_a_deleted_dataset_is_purged_in_short_batches(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        admin_conn: asyncpg.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        dataset_id, source_id = await _priced_dataset(owner)
        for price in ("1", "2"):
            await _collect(
                owner, container, source_id, [{"sku": f"S-{n}", "price": price} for n in range(5)]
            )
        await container.detection.detect(org_id=org_id, dataset_id=UUID(dataset_id))
        assert (await owner.delete(f"/api/v1/datasets/{dataset_id}")).status_code == 204
        monkeypatch.setattr(container.maintenance, "_batch", 2)
        batches: list[str] = []
        real_delete = SqlMaintenanceRepository.delete_batch

        async def delete_batch(self: Any, org: Any, target: str, **kw: Any) -> int:
            deleted = await real_delete(self, org, target, **kw)
            batches.append(target)
            assert deleted <= 2
            return int(deleted)

        monkeypatch.setattr(SqlMaintenanceRepository, "delete_batch", delete_batch)

        assert await container.maintenance.purge_dataset(org_id, UUID(dataset_id))

        # 10 versions, 10 changes and 5 records, two rows per statement at most.
        assert batches.count("record_versions") == 6
        assert batches.count("changes") == 6
        assert batches.count("records") == 3
        for table in ("datasets", "records", "record_versions", "changes"):
            column = "id" if table == "datasets" else "dataset_id"
            left = await admin_conn.fetchval(
                f"SELECT count(*) FROM {table} WHERE {column} = $1",  # noqa: S608 - fixed names
                UUID(dataset_id),
            )
            assert left == 0, table

    async def test_one_failing_organization_does_not_stop_the_purge_of_the_others(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        admin_conn: asyncpg.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        tenants = []
        for days_ago in (9, 8):  # the older request first
            owner = await signup(api)
            org_id = await org_id_of(owner)
            slug = (await owner.get("/api/v1/organizations/current")).json()["slug"]
            await owner.post("/api/v1/organizations/current/deletion", json={"confirm_slug": slug})
            await admin_conn.execute(
                "UPDATE organizations SET deletion_requested_at = now() - make_interval(days => $2)"
                " WHERE id = $1",
                org_id,
                days_ago,
            )
            tenants.append(org_id)
        broken, healthy = tenants
        attempts: list[UUID] = []
        real_purge = container.maintenance._purge_organization

        async def purge(org_id: UUID) -> None:
            attempts.append(org_id)
            if org_id == broken:
                raise RuntimeError("statement timeout")
            await real_purge(org_id)

        monkeypatch.setattr(container.maintenance, "_purge_organization", purge)
        failures: list[tuple[UUID, str]] = []

        purged = await container.maintenance.purge_due_organizations(
            on_error=lambda org_id, exc: failures.append((org_id, str(exc)))
        )

        assert [org for org in attempts if org in tenants] == [broken, healthy]
        assert healthy in purged and broken not in purged
        assert failures == [(broken, "statement timeout")]
        remaining = await admin_conn.fetch(
            "SELECT id FROM organizations WHERE id = ANY($1::uuid[])", tenants
        )
        assert [row["id"] for row in remaining] == [broken]  # retried by the next run


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

"""Ingestion keeps a dataset true to its sources: keys, ownership and snapshot order."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import asyncpg
import httpx2
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.domain.pipeline.ingestion import IngestionOutcome
from tests.support.api import ApiSession, signup
from tests.support.business import create_project, create_source, org_id_of

pytestmark = pytest.mark.integration

SCHEMA: dict[str, Any] = {
    "fields": [
        {"name": "sku", "type": "string", "required": True},
        {"name": "title", "type": "string"},
        {"name": "cost", "type": "decimal"},
        {"name": "link", "type": "url"},
    ],
    "key_field": "sku",
}
URL_KEYED: dict[str, Any] = {
    "fields": [
        {"name": "url", "type": "url", "required": True},
        {"name": "title", "type": "string"},
    ],
    "key_field": "url",
}


def _website(*fields: str) -> dict[str, Any]:
    return {
        "kind": "website",
        "url": "https://shop.example.com/products",
        "item_selector": "div.product",
        "fields": {name: {"selector": f".{name}"} for name in fields},
    }


async def _dataset(owner: ApiSession, project_id: str, schema: dict[str, Any]) -> str:
    created = await owner.post(
        "/api/v1/datasets",
        json={"project_id": project_id, "name": f"ds-{uuid4().hex[:6]}", "schema": schema},
    )
    assert created.status_code == 201, created.text
    return str(created.json()["id"])


async def _collect(
    owner: ApiSession, container: Container, source_id: str, items: list[dict[str, Any]]
) -> IngestionOutcome:
    run = await owner.post(f"/api/v1/sources/{source_id}/runs")
    assert run.status_code == 202, run.text
    return await container.ingestion.ingest(
        org_id=await org_id_of(owner), run_id=UUID(run.json()["id"]), items=items
    )


async def _live(conn: asyncpg.Connection, dataset_id: str) -> dict[str, dict[str, Any]]:
    rows = await conn.fetch(
        "SELECT record_key, data::text AS data, source_id FROM records"
        " WHERE dataset_id = $1 AND deleted_at IS NULL",
        UUID(dataset_id),
    )
    return {row["record_key"]: dict(row) for row in rows}


class TestItems:
    async def test_long_keys_sharing_a_prefix_are_two_stable_records(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await _dataset(owner, project_id, URL_KEYED)
        source_id = await create_source(owner, project_id, dataset_id, _website("url", "title"))
        base = "https://shop.example.com/catalogue/" + "c" * 600
        items = [{"url": base + "/red", "title": "Red"}, {"url": base + "/blue", "title": "Blue"}]

        first = await _collect(owner, container, source_id, items)  # was an IntegrityError
        again = await _collect(owner, container, source_id, items)

        assert (first.status.value, first.stats["created"]) == ("succeeded", 2)
        assert (again.stats["created"], again.stats["updated"], again.stats["unchanged"]) == (
            0,
            0,
            2,
        )
        versions = await admin_conn.fetchval(
            "SELECT count(*) FROM record_versions WHERE dataset_id = $1", UUID(dataset_id)
        )
        assert versions == 2  # no phantom version on an unchanged run

    async def test_an_item_with_an_unreadable_port_does_not_fail_the_run(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await _dataset(owner, project_id, SCHEMA)
        source_id = await create_source(owner, project_id, dataset_id, _website("sku", "link"))
        items = [{"sku": f"A-{i}", "link": f"https://shop.example.com/p/{i}"} for i in range(50)]
        items.append({"sku": "B-1", "link": "https://shop.example.com:99999/p/x"})

        outcome = await _collect(owner, container, source_id, items)  # raised ValueError

        assert outcome.status.value == "succeeded"
        assert (outcome.stats["created"], outcome.stats["invalid"]) == (50, 1)


class TestOwnership:
    async def test_records_of_a_replaced_source_are_deleted_by_its_successor(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await _dataset(owner, project_id, SCHEMA)
        first = await create_source(owner, project_id, dataset_id, _website("sku", "title"))
        items = [{"sku": f"A-{i}", "title": f"T{i}"} for i in range(4)]
        await _collect(owner, container, first, items)
        assert (await owner.delete(f"/api/v1/sources/{first}")).status_code == 204
        second = await create_source(owner, project_id, dataset_id, _website("sku", "title"))

        await _collect(owner, container, second, items)  # unchanged: the records are its own now
        outcome = await _collect(owner, container, second, items[:3])  # A-3 is gone

        assert outcome.stats["deleted"] == 1
        live = await _live(admin_conn, dataset_id)
        assert sorted(live) == ["A-0", "A-1", "A-2"]
        assert {row["source_id"] for row in live.values()} == {UUID(second)}

    async def test_a_record_moving_to_another_source_is_not_deleted_and_recreated(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await _dataset(owner, project_id, SCHEMA)
        shop_a = await create_source(owner, project_id, dataset_id, _website("sku", "title"))
        shop_b = await create_source(owner, project_id, dataset_id, _website("sku", "title"))
        moving, staying = {"sku": "X-1", "title": "Lamp"}, {"sku": "Y-1", "title": "Desk"}
        await _collect(owner, container, shop_a, [moving, staying])

        await _collect(owner, container, shop_b, [moving])  # the lamp is sold by B now
        by_a = await _collect(owner, container, shop_a, [staying])  # and no longer by A
        by_b = await _collect(owner, container, shop_b, [moving])

        assert by_a.stats["deleted"] == 0
        assert (by_b.stats["created"], by_b.stats["updated"], by_b.stats["unchanged"]) == (0, 0, 1)
        versions = await admin_conn.fetch(
            "SELECT v.version, v.is_deletion FROM record_versions v JOIN records r"
            " ON r.id = v.record_id WHERE r.dataset_id = $1 AND r.record_key = 'X-1'",
            UUID(dataset_id),
        )
        assert [(v["version"], v["is_deletion"]) for v in versions] == [(1, False)]


class TestSnapshotOrder:
    async def test_an_older_snapshot_finishing_last_is_superseded(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        project_id = await create_project(owner)
        dataset_id = await _dataset(owner, project_id, SCHEMA)
        source_id = await create_source(
            owner, project_id, dataset_id, _website("sku", "title", "cost")
        )
        base = [{"sku": f"A-{i}", "title": f"T{i}", "cost": "10"} for i in range(20)]
        first = await _collect(owner, container, source_id, base)
        await admin_conn.execute(
            "UPDATE collection_runs SET stats = stats || jsonb_build_object("
            "'collected_at', (now() - interval '3 minutes')::text) WHERE id = $1",
            first.run_id,
        )
        # Two runs start collecting one after the other (a scheduled and a manual
        # one): the first sees the older state, the second the newer one...
        older = UUID((await owner.post(f"/api/v1/sources/{source_id}/runs")).json()["id"])
        newer = UUID((await owner.post(f"/api/v1/sources/{source_id}/runs")).json()["id"])
        for run_id, minutes_ago in ((older, 2), (newer, 1)):
            plan = await container.collection.plan(org_id=org_id, run_id=run_id)
            assert plan.action.value == "sandbox_website"
            # Distinct start times whatever the clock's resolution (15 ms on Windows).
            await admin_conn.execute(
                "UPDATE collection_runs SET started_at = now() - make_interval(mins => $2)"
                " WHERE id = $1",
                run_id,
                minutes_ago,
            )
        newer_items = [dict(item, cost="12") for item in base]
        newer_items.append({"sku": "NEW", "title": "New", "cost": "5"})

        # ...but the newer one finishes first.
        applied = await container.ingestion.ingest(org_id=org_id, run_id=newer, items=newer_items)
        late = await container.ingestion.ingest(org_id=org_id, run_id=older, items=base)

        assert applied.stats["updated"] == 20
        assert late.status.value == "succeeded"
        assert late.stats["superseded"] is True
        assert (late.stats["updated"], late.stats["deleted"]) == (0, 0)
        live = await _live(admin_conn, dataset_id)
        assert "NEW" in live  # not deleted by the older snapshot
        assert '"cost": "12"' in live["A-0"]["data"]  # not reverted to 10

    async def test_snapshots_applied_in_order_are_all_applied(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await _dataset(owner, project_id, SCHEMA)
        source_id = await create_source(
            owner, project_id, dataset_id, _website("sku", "title", "cost")
        )
        outcomes = [
            await _collect(owner, container, source_id, [{"sku": "A-1", "cost": cost}])
            for cost in ("10", "11", "12")
        ]
        assert [o.stats.get("superseded", False) for o in outcomes] == [False, False, False]
        assert '"cost": "12"' in (await _live(admin_conn, dataset_id))["A-1"]["data"]

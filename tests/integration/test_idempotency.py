"""Idempotency keys name one request: never truncated, never another resource's, not eternal."""

from __future__ import annotations

import json
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
    expect_error,
    org_id_of,
    signed_headers,
)

pytestmark = pytest.mark.integration

WEBSITE = {
    "kind": "website",
    "url": "https://shop.example.com/products",
    "item_selector": "div.product",
    "fields": {"sku": {"selector": ".sku"}},
}
STEM = "nightly-analysis:" + "x" * 90  # longer than the 100 characters that were kept


def _key(suffix: str) -> dict[str, str]:
    return {"Idempotency-Key": f"{STEM}:{suffix}"}


async def _report(owner: ApiSession, project_id: str, days: int, key: str) -> httpx2.Response:
    end = datetime(2026, 9, 1, tzinfo=UTC)
    return await owner.post(
        "/api/v1/reports",
        json={
            "project_id": project_id,
            "format": "json",
            "period_start": (end - timedelta(days=days)).isoformat(),
            "period_end": end.isoformat(),
        },
        headers={"Idempotency-Key": key},
    )


class TestLongKeys:
    async def test_long_keys_with_a_common_prefix_are_two_requests(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        dataset_id = await create_dataset(owner, await create_project(owner))
        body = {"dataset_id": dataset_id}

        first = await owner.post("/api/v1/intelligence/analyses", json=body, headers=_key("a"))
        second = await owner.post("/api/v1/intelligence/analyses", json=body, headers=_key("b"))
        repeat = await owner.post("/api/v1/intelligence/analyses", json=body, headers=_key("b"))

        assert (first.status_code, second.status_code, repeat.status_code) == (202, 202, 200)
        assert first.json()["id"] != second.json()["id"] == repeat.json()["id"]
        stored = await admin_conn.fetchval(
            "SELECT idempotency_key FROM insights WHERE id = $1", UUID(first.json()["id"])
        )
        assert stored.startswith("req:") and len(stored) == 68  # a digest, not the key

    async def test_long_webhook_delivery_ids_with_a_common_prefix_are_two_deliveries(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, WEBHOOK_CONFIG)
        created = (
            await owner.post(
                "/api/v1/webhook-endpoints", json={"source_id": source_id, "name": "erp"}
            )
        ).json()
        path = created["url"].removeprefix("https://nexusflow.test.example")
        prefix = "erp.acme-corp.example:inventory-sync:2026-09-25T10:15:00Z:" + "p" * 60
        answers = []
        for delivery in (f"{prefix}:item-0001", f"{prefix}:item-0002", f"{prefix}:item-0002"):
            assert len(delivery) <= 128
            body = json.dumps({"items": [{"sku": delivery[-4:], "price": "1"}]}).encode()
            sent = await api.post(
                path, content=body, headers=signed_headers(created["secret"], body, delivery)
            )
            answers.append((sent.status_code, sent.json().get("status") or sent.json()["error"]))
        assert answers == [(202, "accepted"), (202, "accepted"), (200, "duplicate")]


class TestReusedKeys:
    async def test_an_analysis_key_reused_for_another_dataset_is_refused(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_x = await create_dataset(owner, project_id)
        dataset_y = await create_dataset(owner, project_id)
        key = {"Idempotency-Key": "nightly-analysis-0001"}
        first = await owner.post(
            "/api/v1/intelligence/analyses", json={"dataset_id": dataset_x}, headers=key
        )
        assert first.status_code == 202, first.text

        other = await owner.post(
            "/api/v1/intelligence/analyses", json={"dataset_id": dataset_y}, headers=key
        )

        expect_error(other, 409, "idempotency_key_reused")  # never dataset X's insight

    async def test_a_run_key_reused_for_another_source_is_refused(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        first = await create_source(owner, project_id, dataset_id, WEBSITE)
        second = await create_source(owner, project_id, dataset_id, WEBSITE)
        key = {"Idempotency-Key": "run-key-0001"}
        assert (await owner.post(f"/api/v1/sources/{first}/runs", headers=key)).status_code == 202
        repeat = await owner.post(f"/api/v1/sources/{first}/runs", headers=key)
        assert repeat.status_code == 200

        other = await owner.post(f"/api/v1/sources/{second}/runs", headers=key)

        expect_error(other, 409, "idempotency_key_reused")

    async def test_a_workflow_run_key_reused_for_another_workflow_is_refused(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, WEBSITE)
        workflows = []
        for name in ("Nightly", "Hourly"):
            created = await owner.post(
                "/api/v1/workflows",
                json={
                    "project_id": project_id,
                    "name": name,
                    "trigger": "manual",
                    "source_ids": [source_id],
                },
            )
            assert created.status_code == 201, created.text
            workflows.append(created.json()["id"])
        key = {"Idempotency-Key": "run-2026-09-25-a"}
        ran = await owner.post(f"/api/v1/workflows/{workflows[0]}/runs", headers=key)
        assert ran.status_code == 202, ran.text

        other = await owner.post(f"/api/v1/workflows/{workflows[1]}/runs", headers=key)

        expect_error(other, 409, "idempotency_key_reused")

    async def test_a_report_key_reused_for_another_period_is_refused(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        assert (await _report(owner, project_id, 7, "report-0001")).status_code == 202
        assert (await _report(owner, project_id, 7, "report-0001")).status_code == 200

        other = await _report(owner, project_id, 30, "report-0001")

        expect_error(other, 409, "idempotency_key_reused")


class TestExpiry:
    async def test_keys_are_released_after_the_retention_period(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, WEBSITE)
        key = {"Idempotency-Key": "run-key-0001"}
        runs: list[Any] = [await owner.post(f"/api/v1/sources/{source_id}/runs", headers=key)]
        insight = await owner.post(
            "/api/v1/intelligence/analyses", json={"dataset_id": dataset_id}, headers=key
        )
        report = await _report(owner, project_id, 7, "run-key-0001")
        for table, row in (
            ("collection_runs", runs[0]),
            ("insights", insight),
            ("reports", report),
        ):
            await admin_conn.execute(
                f"UPDATE {table} SET created_at = now() - interval '25 hours'"  # noqa: S608
                " WHERE id = $1",
                UUID(row.json()["id"]),
            )

        purged = (await container.maintenance.apply_retention(org_id)).purged

        assert purged["idempotency_keys"] == 3
        runs.append(await owner.post(f"/api/v1/sources/{source_id}/runs", headers=key))
        assert runs[1].status_code == 202  # a new run, not the day-old one
        assert runs[1].json()["id"] != runs[0].json()["id"]
        released = await admin_conn.fetchval(
            "SELECT idempotency_key FROM insights WHERE id = $1", UUID(insight.json()["id"])
        )
        assert released == f"expired:{insight.json()['id']}"
        assert (await container.maintenance.apply_retention(org_id)).purged["idempotency_keys"] == 0

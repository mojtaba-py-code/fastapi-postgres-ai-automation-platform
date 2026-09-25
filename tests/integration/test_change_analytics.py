"""Change analytics and report totals are computed from every change of a period."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import asyncpg
import httpx2
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.domain.reports import service as report_service
from tests.support.api import ApiSession, signup
from tests.support.bus import InProcessBus
from tests.support.business import (
    WEBHOOK_CONFIG,
    create_dataset,
    create_project,
    create_source,
    expect_error,
    org_id_of,
    signed_headers,
    viewer_key,
)

pytestmark = pytest.mark.integration

PERIOD = {"period_start": "2026-03-01T00:00:00Z", "period_end": "2026-03-08T00:00:00Z"}


def _item(sku: str, price: str) -> dict[str, Any]:
    return {
        "sku": sku,
        "title": f"Item {sku}",
        "price": price,
        "supplier": {"email": "s@x.example"},
    }


class Feed:
    """A dataset fed through a signed webhook, as a customer system would."""

    def __init__(self, api: httpx2.AsyncClient, bus: InProcessBus, owner: ApiSession) -> None:
        self.api, self.bus, self.owner = api, bus, owner

    async def open(self, project_id: str) -> Feed:
        self.dataset_id = await create_dataset(self.owner, project_id)
        source_id = await create_source(self.owner, project_id, self.dataset_id, WEBHOOK_CONFIG)
        endpoint = await self.owner.post(
            "/api/v1/webhook-endpoints", json={"source_id": source_id, "name": "feed"}
        )
        assert endpoint.status_code == 201, endpoint.text
        self.path = endpoint.json()["url"].removeprefix("https://nexusflow.test.example")
        self.secret = endpoint.json()["secret"]
        return self

    async def send(self, *items: dict[str, Any]) -> None:
        body = json.dumps({"items": list(items)}).encode()
        received = await self.api.post(
            self.path, content=body, headers=signed_headers(self.secret, body)
        )
        assert received.status_code == 202, received.text
        await self.bus.drain(await org_id_of(self.owner))


async def _backdate(
    conn: asyncpg.Connection, dataset_id: str, keys: list[str], moment: datetime
) -> None:
    """Arrange: move changes into the reported period (they were detected just now)."""
    await conn.execute(
        "UPDATE changes SET detected_at = $1 WHERE dataset_id = $2 AND record_key = ANY($3)",
        moment,
        UUID(dataset_id),
        keys,
    )


@pytest.fixture
async def project(
    api: httpx2.AsyncClient, bus: InProcessBus, admin_conn: asyncpg.Connection
) -> dict[str, Any]:
    """Two datasets of one project with 9 changes on known days of March 2026."""
    owner = await signup(api)
    project_id = await create_project(owner)
    prices = await Feed(api, bus, owner).open(project_id)
    await prices.send(*(_item(f"P-{n}", "10.00") for n in range(6)))  # 6 created
    await _backdate(admin_conn, prices.dataset_id, ["P-0", "P-1", "P-2"], _at(2, 10))
    await _backdate(admin_conn, prices.dataset_id, ["P-3", "P-4", "P-5"], _at(5, 10))
    await prices.send(*(_item(f"P-{n}", "10.00") for n in range(4)), _item("P-4", "95.00"))
    # P-4 moved; P-5 is missing from this delivery - whether that counts as a
    # deletion depends on the source, so only the updated keys are backdated.
    await admin_conn.execute(
        "UPDATE changes SET detected_at = $1 WHERE dataset_id = $2 AND change_type = 'updated'",
        _at(5, 23, 30),
        UUID(prices.dataset_id),
    )
    stock = await Feed(api, bus, owner).open(project_id)
    await stock.send(_item("S-1", "3.00"), _item("S-2", "4.00"))
    await _backdate(admin_conn, stock.dataset_id, ["S-1"], _at(3, 8))
    # Changes outside the period (its end is exclusive), and in another project, never count.
    await _backdate(admin_conn, stock.dataset_id, ["S-2"], _at(8, 0))
    other = await Feed(api, bus, owner).open(await create_project(owner, "Other"))
    await other.send(_item("O-1", "1.00"))
    await _backdate(admin_conn, other.dataset_id, ["O-1"], _at(4, 12))
    counted = await admin_conn.fetch(
        "SELECT change_type, count(*) AS n FROM changes WHERE dataset_id = ANY($1::uuid[])"
        " AND detected_at >= $2 AND detected_at < $3 GROUP BY change_type",
        [UUID(prices.dataset_id), UUID(stock.dataset_id)],
        _at(1, 0),
        _at(8, 0),
    )
    return {
        "owner": owner,
        "project_id": project_id,
        "prices": prices.dataset_id,
        "other_dataset": other.dataset_id,
        "expected": {row["change_type"]: row["n"] for row in counted},
    }


def _at(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 3, day, hour, minute, tzinfo=UTC)


class TestChangeAnalyticsApi:
    async def test_a_project_is_summarized_from_all_its_changes(
        self, project: dict[str, Any]
    ) -> None:
        owner: ApiSession = project["owner"]
        response = await owner.get(
            "/api/v1/analytics/changes", params={"project_id": project["project_id"], **PERIOD}
        )
        assert response.status_code == 200, response.text
        body = response.json()
        expected = project["expected"]
        assert expected == {"created": 7, "updated": 1}  # 6 prices + 1 stock; P-4 moved
        assert body["totals"] == {
            "changes": sum(expected.values()),
            "created": expected.get("created", 0),
            "updated": expected.get("updated", 0),
            "deleted": expected.get("deleted", 0),
        }
        assert sum(body["by_significance"].values()) == body["totals"]["changes"]
        assert set(body["by_significance"]) == {"low", "medium", "high", "critical"}
        daily = {day["date"]: day["changes"] for day in body["daily"]}
        assert list(daily) == [f"2026-03-0{d}" for d in range(1, 8)]  # quiet days included
        assert daily["2026-03-02"] == 3
        assert daily["2026-03-03"] == 1
        assert daily["2026-03-05"] == 3 + expected.get("updated", 0)
        assert daily["2026-03-04"] == 0  # the other project's change is not counted
        assert body["trend_note"]
        assert body["dataset_id"] is None

    async def test_one_dataset_can_be_summarized(self, project: dict[str, Any]) -> None:
        owner: ApiSession = project["owner"]
        response = await owner.get(
            "/api/v1/analytics/changes",
            params={"project_id": project["project_id"], "dataset_id": project["prices"], **PERIOD},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["dataset_id"] == project["prices"]
        assert body["totals"]["created"] == 6

    async def test_the_default_period_is_the_last_30_days(self, project: dict[str, Any]) -> None:
        owner: ApiSession = project["owner"]
        response = await owner.get(
            "/api/v1/analytics/changes", params={"project_id": project["project_id"]}
        )
        assert response.status_code == 200, response.text
        body = response.json()
        start = datetime.fromisoformat(body["period_start"])
        end = datetime.fromisoformat(body["period_end"])
        assert end - start == timedelta(days=30)
        assert len(body["daily"]) in (30, 31)

    async def test_scope_and_period_are_validated(
        self, api: httpx2.AsyncClient, project: dict[str, Any]
    ) -> None:
        owner: ApiSession = project["owner"]
        url = "/api/v1/analytics/changes"
        # A dataset of another project is not part of this one.
        expect_error(
            await owner.get(
                url,
                params={
                    "project_id": project["project_id"],
                    "dataset_id": project["other_dataset"],
                },
            ),
            404,
        )
        backwards = {"period_start": PERIOD["period_end"], "period_end": PERIOD["period_start"]}
        expect_error(
            await owner.get(url, params={"project_id": project["project_id"], **backwards}),
            422,
            "invalid_period",
        )
        too_long = {"period_start": "2025-01-01T00:00:00Z", "period_end": "2026-03-01T00:00:00Z"}
        expect_error(
            await owner.get(url, params={"project_id": project["project_id"], **too_long}),
            422,
            "invalid_period",
        )
        naive = {"period_start": "2026-03-01T00:00:00", "period_end": "2026-03-08T00:00:00"}
        expect_error(
            await owner.get(url, params={"project_id": project["project_id"], **naive}), 422
        )
        # Another tenant cannot tell the project exists.
        stranger = await signup(api)
        expect_error(
            await stranger.get(url, params={"project_id": project["project_id"], **PERIOD}), 404
        )

    async def test_reading_needs_the_changes_scope(
        self, api: httpx2.AsyncClient, project: dict[str, Any]
    ) -> None:
        owner: ApiSession = project["owner"]
        params = {"project_id": project["project_id"], **PERIOD}
        allowed = await viewer_key(owner, ["changes:read"])
        response = await api.get("/api/v1/analytics/changes", params=params, headers=allowed)
        assert response.status_code == 200, response.text
        denied = await viewer_key(owner, ["projects:read"])
        expect_error(await api.get("/api/v1/analytics/changes", params=params, headers=denied), 403)


class TestReportTotals:
    async def test_totals_count_every_change_not_only_the_listed_ones(
        self,
        project: dict[str, Any],
        container: Container,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner: ApiSession = project["owner"]
        monkeypatch.setattr(report_service, "_TOP_CHANGES", 2)  # list fewer than there are
        requested = await owner.post(
            "/api/v1/reports",
            json={"project_id": project["project_id"], "format": "json", **PERIOD},
        )
        assert requested.status_code == 202, requested.text
        report_id = UUID(requested.json()["id"])
        await container.reports.generate(org_id=await org_id_of(owner), report_id=report_id)
        download = await owner.get(f"/api/v1/reports/{report_id}/download")
        assert download.status_code == 200, download.text
        report = download.json()

        total = sum(project["expected"].values())
        assert report["totals"]["changes"] == total
        assert len(report["changes"]) == 2  # the two most significant...
        scores = [change["score"] for change in report["changes"]]
        assert scores == sorted(scores, reverse=True)
        assert sum(count for _, count in report["daily_trend"]) == total  # ...of all of them
        assert report["executive_summary"].startswith(f"{total} changes detected in 'Pricing'")
        notable = report["by_significance"]["high"] + report["by_significance"]["critical"]
        assert notable >= 1  # the price that moved almost tenfold
        assert len(report["anomalies"]) == notable
        assert {a["significance"] for a in report["anomalies"]} <= {"high", "critical"}

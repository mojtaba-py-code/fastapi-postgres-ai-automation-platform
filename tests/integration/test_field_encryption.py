"""Sensitive values are encrypted at rest; only those allowed ever see them.

A dataset's ``sensitive`` fields are sealed (AES-256-GCM, bound to tenant,
dataset, record and field) in records, their versions and the diffs of
changes. These tests read the database *as its superuser* - what a stolen
dump or backup would reveal - and through the API, as the owner (who may read
sensitive values) and as a viewer (who may not).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

import asyncpg
import fakeredis
import httpx2
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from nexusflow.bootstrap.container import Container, build_container
from nexusflow.core.jsonutil import content_hash
from nexusflow.core.pagination import PageRequest
from nexusflow.infrastructure.security.files import MAGIC
from tests.conftest import make_settings
from tests.support.api import ApiSession, signup
from tests.support.bus import InProcessBus
from tests.support.business import (
    UPLOAD_CONFIG,
    WEBHOOK_CONFIG,
    create_dataset,
    create_project,
    create_source,
    org_id_of,
    signed_headers,
    viewer_key,
)
from tests.support.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

# Values with characters outside the base64 alphabet ("@", "."), so that finding
# one inside a stored ciphertext by chance is impossible.
FIRST, SECOND, CHANGED = "alice@supplier.example", "bob@supplier.example", "carol@supplier.example"
COSTS = ("12.5", "99.25", "20.5")
SCHEMA = {
    "fields": [
        {"name": "sku", "type": "string", "required": True},
        {"name": "title", "type": "string"},
        {"name": "supplier_email", "type": "string", "sensitive": True},
        {"name": "cost", "type": "decimal", "sensitive": True},
    ],
    "key_field": "sku",
}
WEBSITE = {
    "kind": "website",
    "url": "https://shop.example.com/products",
    "item_selector": "div.product",
    "fields": {"sku": {"selector": ".key"}},
}


@dataclass(frozen=True)
class Tenant:
    owner: ApiSession
    org_id: UUID
    project_id: str
    dataset_id: str
    source_id: str

    async def collect(self, container: Container, items: list[dict[str, Any]]) -> None:
        """One full-snapshot collection run, then change detection."""
        run = await self.owner.post(f"/api/v1/sources/{self.source_id}/runs")
        assert run.status_code == 202, run.text
        outcome = await container.ingestion.ingest(
            org_id=self.org_id, run_id=UUID(run.json()["id"]), items=items
        )
        assert outcome.status.value == "succeeded", outcome.stats
        await container.detection.detect(org_id=self.org_id, dataset_id=UUID(self.dataset_id))


async def _tenant(api: httpx2.AsyncClient) -> Tenant:
    owner = await signup(api)
    project_id = await create_project(owner)
    created = await owner.post(
        "/api/v1/datasets",
        json={"project_id": project_id, "name": "suppliers", "schema": SCHEMA},
    )
    assert created.status_code == 201, created.text
    dataset_id = str(created.json()["id"])
    source_id = await create_source(owner, project_id, dataset_id, WEBSITE)
    return Tenant(owner, await org_id_of(owner), project_id, dataset_id, source_id)


async def _stored_text(conn: asyncpg.Connection, dataset_id: str) -> str:
    """Everything the database holds for the dataset's records, versions and changes."""
    rows = await conn.fetch(
        "SELECT data::text AS t FROM records WHERE dataset_id = $1"
        " UNION ALL SELECT data::text FROM record_versions WHERE dataset_id = $1"
        " UNION ALL SELECT diff::text FROM changes WHERE dataset_id = $1",
        UUID(dataset_id),
    )
    return "\n".join(row["t"] for row in rows)


class TestAtRest:
    async def test_the_database_never_holds_a_sensitive_value_in_plaintext(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        tenant = await _tenant(api)
        await tenant.collect(
            container,
            [
                {"sku": "A-1", "title": "Lamp", "supplier_email": FIRST, "cost": COSTS[0]},
                {"sku": "A-2", "title": "Desk", "supplier_email": SECOND, "cost": COSTS[1]},
            ],
        )
        # An update of both sensitive fields, and a deletion (A-2 is gone from
        # this full snapshot): every kind of stored row is exercised.
        await tenant.collect(
            container,
            [{"sku": "A-1", "title": "Lamp", "supplier_email": CHANGED, "cost": COSTS[2]}],
        )

        stored = await _stored_text(admin_conn, tenant.dataset_id)
        for secret in (FIRST, SECOND, CHANGED, *COSTS):
            assert secret not in stored
        assert stored.count('"$sealed"') >= 10
        assert "Lamp" in stored  # other fields stay plaintext, and queryable

        # The stored content hash is keyed: a dump cannot confirm a guessed value.
        [record] = (await tenant.owner.get(f"/api/v1/datasets/{tenant.dataset_id}/records")).json()[
            "items"
        ]
        stored_hash = await admin_conn.fetchval(
            "SELECT content_hash FROM records WHERE id = $1", UUID(record["id"])
        )
        assert stored_hash != content_hash(record["data"])

    async def test_the_owner_sees_values_and_a_viewer_sees_masks(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        tenant = await _tenant(api)
        await tenant.collect(
            container, [{"sku": "A-1", "title": "Lamp", "supplier_email": FIRST, "cost": "12.5"}]
        )
        await tenant.collect(
            container, [{"sku": "A-1", "title": "Lamp", "supplier_email": CHANGED, "cost": "20.5"}]
        )
        records_url = f"/api/v1/datasets/{tenant.dataset_id}/records"

        [record] = (await tenant.owner.get(records_url)).json()["items"]
        assert (record["data"]["supplier_email"], record["data"]["cost"]) == (CHANGED, "20.5")
        history = (await tenant.owner.get(f"/api/v1/records/{record['id']}/history")).json()
        assert [v["data"]["supplier_email"] for v in history["versions"]] == [CHANGED, FIRST]
        changes = (
            await tenant.owner.get("/api/v1/changes", params={"dataset_id": tenant.dataset_id})
        ).json()["items"]
        updated = next(c for c in changes if c["change_type"] == "updated")
        assert updated["diff"]["supplier_email"] == {"old": FIRST, "new": CHANGED}
        assert (updated["diff"]["cost"]["old"], updated["diff"]["cost"]["new"]) == ("12.5", "20.5")
        assert updated["diff"]["cost"]["pct"] == pytest.approx(64.0)  # sealed, and opened too

        viewer = await viewer_key(tenant.owner, ["records:read", "changes:read"])
        [masked] = (await api.get(records_url, headers=viewer)).json()["items"]
        assert masked["data"]["supplier_email"] == "[masked]"
        viewer_changes = (
            await api.get(
                "/api/v1/changes", params={"dataset_id": tenant.dataset_id}, headers=viewer
            )
        ).json()["items"]
        viewer_diff = next(c for c in viewer_changes if c["change_type"] == "updated")["diff"]
        assert viewer_diff["supplier_email"] == {"old": "[masked]", "new": "[masked]"}
        assert viewer_diff["cost"] == {"old": "[masked]", "new": "[masked]"}  # no percentage

        export = await tenant.owner.get(
            f"/api/v1/datasets/{tenant.dataset_id}/export", params={"format": "jsonl"}
        )
        assert export.status_code == 200, export.text
        assert json.loads(export.text.splitlines()[0])["supplier_email"] == CHANGED

    async def test_rules_on_sensitive_fields_still_fire_without_leaking(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        tenant = await _tenant(api)
        created = await tenant.owner.post(
            "/api/v1/alert-rules",
            json={
                "project_id": tenant.project_id,
                "dataset_id": tenant.dataset_id,
                "name": "Supplier changed",
                "condition": {"type": "field_changed", "field": "supplier_email"},
            },
        )
        assert created.status_code == 201, created.text
        await tenant.collect(container, [{"sku": "A-1", "supplier_email": FIRST}])
        await tenant.collect(container, [{"sku": "A-1", "supplier_email": CHANGED}])
        await container.alerts.evaluate_changes(org_id=tenant.org_id)

        alerts = (await tenant.owner.get("/api/v1/alerts")).json()["items"]
        [alert] = [a for a in alerts if "Supplier changed" in a["title"]]
        assert "supplier_email: [masked] -> [masked]" in alert["body"]
        assert FIRST not in json.dumps(alert)
        assert CHANGED not in json.dumps(alert)


class TestTampering:
    async def test_a_sealed_value_copied_to_another_record_does_not_open(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        tenant = await _tenant(api)
        await tenant.collect(
            container,
            [
                {"sku": "A-1", "supplier_email": FIRST},
                {"sku": "A-2", "supplier_email": SECOND},
            ],
        )
        # Someone with write access to the database moves A-1's ciphertext into
        # A-2, hoping the platform will decrypt it as A-2's value.
        await admin_conn.execute(
            "UPDATE records SET data = jsonb_set(data, '{supplier_email}',"
            " (SELECT data->'supplier_email' FROM records WHERE dataset_id = $1"
            " AND record_key = 'A-1')) WHERE dataset_id = $1 AND record_key = 'A-2'",
            UUID(tenant.dataset_id),
        )
        listing = await tenant.owner.get(f"/api/v1/datasets/{tenant.dataset_id}/records")
        assert listing.status_code >= 500  # fails closed: A-1's value is never shown as A-2's
        assert FIRST not in listing.text


class TestStagedPayloads:
    async def test_received_items_are_sealed_until_ingested(
        self, api: httpx2.AsyncClient, bus: InProcessBus, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, WEBHOOK_CONFIG)
        endpoint = await owner.post(
            "/api/v1/webhook-endpoints", json={"source_id": source_id, "name": "feed"}
        )
        assert endpoint.status_code == 201, endpoint.text
        path = endpoint.json()["url"].removeprefix("https://nexusflow.test.example")
        body = json.dumps(
            {"items": [{"sku": "A-1", "title": "Lamp", "supplier": {"email": FIRST}}]}
        ).encode()

        received = await api.post(
            path, content=body, headers=signed_headers(endpoint.json()["secret"], body)
        )
        assert received.status_code == 202, received.text
        run_id = UUID(received.json()["run_id"])
        # Raw source data waits for ingestion - encrypted as a whole.
        staged = await admin_conn.fetchval(
            "SELECT items::text FROM run_payloads WHERE run_id = $1", run_id
        )
        assert staged is not None
        assert '"$sealed"' in staged
        assert FIRST not in staged
        assert "Lamp" not in staged

        await bus.drain(await org_id_of(owner))
        assert not await admin_conn.fetchval(
            "SELECT count(*) FROM run_payloads WHERE run_id = $1", run_id
        )
        [record] = (await owner.get(f"/api/v1/datasets/{dataset_id}/records")).json()["items"]
        assert record["data"]["supplier_email"] == FIRST


def _platform(
    database: ProvisionedDatabase, root: Path, keys: dict[str, str], active: str
) -> Container:
    """Another instance of the platform on the same database, with its own keyring."""
    settings = make_settings(
        root,
        database={"url": database.app_url},
        app={"public_base_url": "https://nexusflow.test.example", "allowed_hosts": ["testserver"]},
        security={"encryption_keys": json.dumps(keys), "encryption_active_key_id": active},
    )
    engine = create_async_engine(database.app_url, pool_size=2, max_overflow=0)
    return build_container(
        settings,
        application_name="nexusflow-rotation-test",
        engine=engine,
        redis=fakeredis.FakeAsyncRedis(),
    )


class TestKeyRotation:
    async def test_rotation_rewraps_every_sealed_value_so_the_old_key_can_go(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        database: ProvisionedDatabase,
        admin_conn: asyncpg.Connection,
        tmp_path: Path,
    ) -> None:
        tenant = await _tenant(api)
        await tenant.collect(container, [{"sku": "A-1", "supplier_email": FIRST, "cost": "12.5"}])
        await tenant.collect(container, [{"sku": "A-1", "supplier_email": CHANGED, "cost": "20.5"}])
        current = json.loads(container.settings.security.encryption_keys.get_secret_value())
        assert set(current) == {"kek-1"}
        new_key = base64.b64encode(os.urandom(32)).decode()

        # Rotate: a new key becomes active, the old one stays for decryption only.
        rotated = _platform(database, tmp_path, {**current, "kek-2": new_key}, "kek-2")
        try:
            rewrapped = 0
            while count := await rotated.maintenance.rewrap_sealed(
                tenant.org_id, active_key_id="kek-2", batch=2
            ):
                rewrapped += count
        finally:
            await rotated.aclose()
        assert rewrapped >= 5  # the record, its two versions and two changes

        stored = await _stored_text(admin_conn, tenant.dataset_id)
        assert '"kid": "kek-1"' not in stored
        assert '"kid": "kek-2"' in stored

        # The old key is retired: an instance that no longer has it reads everything.
        retired = _platform(database, tmp_path, {"kek-2": new_key}, "kek-2")
        try:
            principal = await retired.authenticator.authenticate(tenant.owner.access_token)
            _, page = await retired.catalog.list_records(
                principal, UUID(tenant.dataset_id), PageRequest(), include_deleted=False
            )
            assert page.items[0].data["supplier_email"] == CHANGED
            changes = await retired.catalog.list_changes(
                principal, PageRequest(), {"dataset_id": UUID(tenant.dataset_id)}
            )
            updated = [c for c in changes.items if c.change_type.value == "updated"]
            assert updated[0].diff["supplier_email"] == {"old": FIRST, "new": CHANGED}
        finally:
            await retired.aclose()


class TestStoredFiles:
    async def test_uploads_and_reports_are_encrypted_on_disk(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, UPLOAD_CONFIG)
        csv_bytes = f"SKU,Title,Price,Email\r\nA-1,Lamp,9.99,{FIRST}\r\n".encode()

        uploaded = await owner.post(
            f"/api/v1/sources/{source_id}/uploads",
            files={"file": ("suppliers.csv", csv_bytes, "text/csv")},
        )
        assert uploaded.status_code == 201, uploaded.text
        key = f"uploads/{org_id}/{uploaded.json()['id']}.csv"
        on_disk = container.storage.local_path(key).read_bytes()
        assert on_disk.startswith(MAGIC)
        assert FIRST.encode() not in on_disk
        assert b"Lamp" not in on_disk
        # What the sandbox receives through the gateway is the original file.
        assert b"".join([c async for c in container.storage.stream(key)]) == csv_bytes

        report = await owner.post(
            "/api/v1/reports",
            json={
                "project_id": project_id,
                "format": "json",
                "period_start": "2026-01-01T00:00:00Z",
                "period_end": "2026-01-08T00:00:00Z",
            },
        )
        assert report.status_code == 202, report.text
        report_id = UUID(report.json()["id"])
        await container.reports.generate(org_id=org_id, report_id=report_id)
        report_key = f"reports/{org_id}/{report_id}.json"
        assert container.storage.local_path(report_key).read_bytes().startswith(MAGIC)
        download = await owner.get(f"/api/v1/reports/{report_id}/download")
        assert download.status_code == 200, download.text
        assert download.json()["project"] == "Pricing"  # decrypted, whole and verified
        digest = base64.b64encode(hashlib.sha256(download.content).digest()).decode()
        assert download.headers["repr-digest"] == f"sha-256=:{digest}:"

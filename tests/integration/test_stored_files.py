"""Stored files (uploads, reports) never outlive the rows that reference them."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import httpx2
import pytest
from asgi_lifespan import LifespanManager

from nexusflow.apps.api.main import create_app
from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import NotFoundError
from nexusflow.domain.shared.outbox import TaskName
from tests.support.api import ApiSession, signup
from tests.support.bus import InProcessBus
from tests.support.business import (
    UPLOAD_CONFIG,
    create_dataset,
    create_project,
    create_source,
    org_id_of,
)

pytestmark = pytest.mark.integration

CSV = b"SKU,Title,Price,Email\r\nA-1,Lamp,9.99,alice@supplier.example\r\n"


async def _upload(owner: ApiSession, source_id: str, org_id: UUID, content: bytes = CSV) -> str:
    uploaded = await owner.post(
        f"/api/v1/sources/{source_id}/uploads", files={"file": ("items.csv", content, "text/csv")}
    )
    assert uploaded.status_code == 201, uploaded.text
    return f"uploads/{org_id}/{uploaded.json()['id']}.csv"


async def _report(
    owner: ApiSession,
    container: Container,
    org_id: UUID,
    project_id: str,
    *,
    bus: InProcessBus | None = None,
    **scope: Any,
) -> str:
    now = datetime.now(UTC)
    created = await owner.post(
        "/api/v1/reports",
        json={
            "project_id": project_id,
            "format": "json",
            "period_start": (now - timedelta(days=1)).isoformat(),
            "period_end": (now + timedelta(minutes=5)).isoformat(),
            **scope,
        },
    )
    assert created.status_code == 202, created.text
    report_id = UUID(created.json()["id"])
    if bus is not None:
        await bus.drain(org_id)  # the queued generation job
    else:
        await container.reports.generate(org_id=org_id, report_id=report_id)
    key = f"reports/{org_id}/{report_id}.json"
    assert await container.storage.exists(key)
    return key


class TestDeletedWithTheirRows:
    async def test_purging_a_dataset_deletes_its_upload_and_report_files(
        self, api: httpx2.AsyncClient, container: Container, bus: InProcessBus
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, UPLOAD_CONFIG)
        upload_key = await _upload(owner, source_id, org_id)
        report_key = await _report(
            owner, container, org_id, project_id, bus=bus, dataset_id=dataset_id
        )
        kept_key = await _report(owner, container, org_id, project_id, bus=bus)  # the project's
        assert await container.storage.exists(upload_key)

        assert (await owner.delete(f"/api/v1/datasets/{dataset_id}")).status_code == 204
        await bus.drain(org_id)  # the purge, then the file deletion it queued

        assert not await container.storage.exists(upload_key)
        assert not await container.storage.exists(report_key)
        assert await container.storage.exists(kept_key)
        assert [m.payload["keys"] for m in bus.published(TaskName.DELETE_FILES, org_id)] == [
            sorted([report_key, upload_key])
        ]

    async def test_deleting_a_source_deletes_its_uploaded_files(
        self, api: httpx2.AsyncClient, container: Container, bus: InProcessBus
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, UPLOAD_CONFIG)
        keys = [
            await _upload(owner, source_id, org_id),
            await _upload(owner, source_id, org_id, CSV.replace(b"Lamp", b"Desk")),
        ]

        assert (await owner.delete(f"/api/v1/sources/{source_id}")).status_code == 204
        await bus.drain(org_id)

        assert [await container.storage.exists(key) for key in keys] == [False, False]

    async def test_deleting_a_project_deletes_its_report_files(
        self, api: httpx2.AsyncClient, container: Container, bus: InProcessBus
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        project_id = await create_project(owner)
        report_key = await _report(owner, container, org_id, project_id, bus=bus)

        assert (await owner.delete(f"/api/v1/projects/{project_id}")).status_code == 204
        await bus.drain(org_id)

        assert not await container.storage.exists(report_key)

    async def test_purging_an_organization_removes_every_file_it_had(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, UPLOAD_CONFIG)
        upload_key = await _upload(owner, source_id, org_id)
        report_key = await _report(owner, container, org_id, project_id)
        # A file no row points to any more (a crash between a delete and its job).
        orphan = f"uploads/{org_id}/{uuid4()}.csv"
        await container.storage.save_bytes(orphan, b"left behind")
        slug = (await owner.get("/api/v1/organizations/current")).json()["slug"]
        await owner.post("/api/v1/organizations/current/deletion", json={"confirm_slug": slug})
        await admin_conn.execute(
            "UPDATE organizations SET deletion_requested_at = now() - interval '8 days'"
            " WHERE id = $1",
            org_id,
        )

        assert org_id in await container.maintenance.purge_due_organizations()

        for key in (upload_key, report_key, orphan):
            assert not await container.storage.exists(key), key
        root = container.storage.local_path(upload_key).parents[2]
        for area in ("uploads", "reports"):
            assert not (root / area / str(org_id)).exists()
        [purged] = await admin_conn.fetch(
            "SELECT metadata FROM audit_logs WHERE org_id = $1 AND action = 'org.purged'", org_id
        )
        assert '"files": 3' in purged["metadata"]


class TestNoFileWithoutARow:
    async def test_a_report_deleted_while_it_renders_leaves_no_file(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        admin_conn: asyncpg.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner = await signup(api)
        org_id = await org_id_of(owner)
        project_id = await create_project(owner)
        now = datetime.now(UTC)
        created = await owner.post(
            "/api/v1/reports",
            json={
                "project_id": project_id,
                "format": "json",
                "period_start": (now - timedelta(days=1)).isoformat(),
                "period_end": now.isoformat(),
            },
        )
        report_id = UUID(created.json()["id"])
        real_save = container.storage.save_bytes

        async def save_after_deletion(key: str, data: bytes) -> Any:
            # The project is deleted while the report renders.
            await admin_conn.execute("DELETE FROM reports WHERE id = $1", report_id)
            return await real_save(key, data)

        monkeypatch.setattr(container.storage, "save_bytes", save_after_deletion)

        with pytest.raises(NotFoundError):
            await container.reports.generate(org_id=org_id, report_id=report_id)

        assert not await container.storage.exists(f"reports/{org_id}/{report_id}.json")

    async def test_the_deletion_job_spares_referenced_files_and_other_tenants(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner, other = await signup(api), await signup(api)
        org_id, other_org = await org_id_of(owner), await org_id_of(other)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, UPLOAD_CONFIG)
        live = await _upload(owner, source_id, org_id)
        foreign = f"uploads/{other_org}/{uuid4()}.csv"
        await container.storage.save_bytes(foreign, b"another tenant's file")

        removed = await container.maintenance.delete_files(org_id, [live, foreign])

        assert removed == 0
        assert await container.storage.exists(live)  # its upload row still exists
        assert await container.storage.exists(foreign)  # not this tenant's


async def test_the_api_removes_plaintext_copies_left_by_a_killed_process(
    container: Container,
) -> None:
    root = container.storage.local_path(f"uploads/{uuid4()}/{uuid4()}.csv").parents[2]
    left_behind = root / ".scratch" / "left-behind.csv"
    left_behind.parent.mkdir(parents=True, exist_ok=True)
    left_behind.write_bytes(b"SKU\r\nplaintext\r\n")
    hours_ago = time.time() - 2 * 3600
    os.utime(left_behind, (hours_ago, hours_ago))

    app = create_app(container.settings, container=container, configure_logs=False)
    async with LifespanManager(app):
        pass

    assert not left_behind.exists()

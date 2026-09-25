"""End-to-end API tests for the business resources (real app, real PostgreSQL).

Each test drives the public HTTP API and, where a background worker would run
in production, calls the same domain service the worker calls.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

import httpx2
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import RateLimitedError
from nexusflow.core.pagination import encode_cursor
from nexusflow.domain.automation.maintenance import MAX_RUN_ATTEMPTS, STUCK_RUN_AFTER
from nexusflow.domain.shared.unit_of_work import TenantScope
from nexusflow.domain.webhooks import service as webhook_service
from nexusflow.domain.webhooks.signatures import ParsedSignature, verify_signature
from tests.support.api import ApiSession, signup
from tests.support.business import (
    SCHEMA,
    UPLOAD_CONFIG,
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


class TestCatalog:
    async def test_project_and_dataset_lifecycle(self, api: httpx2.AsyncClient) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)

        projects = (await owner.get("/api/v1/projects")).json()
        assert [p["id"] for p in projects["items"]] == [project_id]
        dataset = (await owner.get(f"/api/v1/datasets/{dataset_id}")).json()
        assert dataset["schema"]["key_field"] == "sku"
        listed = (await owner.get("/api/v1/datasets", params={"project_id": project_id})).json()
        assert [d["id"] for d in listed["items"]] == [dataset_id]

        renamed = await owner.patch(f"/api/v1/projects/{project_id}", json={"name": "Pricing EU"})
        assert renamed.json()["name"] == "Pricing EU"
        assert (await owner.delete(f"/api/v1/datasets/{dataset_id}")).status_code == 204
        expect_error(await owner.get(f"/api/v1/datasets/{dataset_id}"), 404)

    async def test_projects_are_deleted_only_when_empty_and_audited(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        expect_error(await owner.delete(f"/api/v1/projects/{project_id}"), 409, "project_not_empty")
        assert (await owner.delete(f"/api/v1/datasets/{dataset_id}")).status_code == 204
        assert (await owner.delete(f"/api/v1/projects/{project_id}")).status_code == 204
        expect_error(await owner.get(f"/api/v1/projects/{project_id}"), 404)
        expect_error(await owner.delete(f"/api/v1/projects/{project_id}"), 404)
        trail = (await owner.get("/api/v1/audit", params={"action": "project.deleted"})).json()
        assert [e["resource_id"] for e in trail["items"]] == [project_id]
        # Other tenants cannot even see the project, let alone delete it.
        other = await signup(api)
        foreign = await create_project(other)
        expect_error(await owner.delete(f"/api/v1/projects/{foreign}"), 404)

    async def test_users_of_the_organization_are_listed(self, api: httpx2.AsyncClient) -> None:
        owner = await signup(api)
        listed = (await owner.get("/api/v1/users")).json()["items"]
        assert [u["role"] for u in listed] == ["owner"]
        members = (await owner.get("/api/v1/organizations/current/members")).json()["items"]
        assert listed == members
        viewer = await viewer_key(owner, ["projects:read"])
        expect_error(await api.get("/api/v1/users", headers=viewer), 403)

    async def test_invalid_schema_and_mass_assignment_rejected(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        bad_key = {**SCHEMA, "fields": [{"name": "sku", "type": "string"}]}  # key not required
        expect_error(
            await owner.post(
                "/api/v1/datasets", json={"project_id": project_id, "name": "x", "schema": bad_key}
            ),
            422,
        )
        smuggled = await owner.post(
            "/api/v1/projects", json={"name": "p", "org_id": str(uuid4()), "status": "archived"}
        )
        expect_error(smuggled, 422)

    async def test_viewer_is_read_only(self, api: httpx2.AsyncClient) -> None:
        owner = await signup(api)
        await create_project(owner)
        viewer = await viewer_key(owner, ["projects:read"])
        assert (await api.get("/api/v1/projects", headers=viewer)).status_code == 200
        expect_error(await api.post("/api/v1/projects", headers=viewer, json={"name": "nope"}), 403)
        expect_error(
            await api.get("/api/v1/sources", headers=viewer), 403
        )  # scope not granted to the key

    async def test_resources_of_other_tenants_are_invisible(self, api: httpx2.AsyncClient) -> None:
        alice = await signup(api)
        bob = await signup(api)
        project_id = await create_project(alice)
        dataset_id = await create_dataset(alice, project_id)
        expect_error(await bob.get(f"/api/v1/projects/{project_id}"), 404)
        expect_error(await bob.patch(f"/api/v1/projects/{project_id}", json={"name": "mine"}), 404)
        expect_error(await bob.get(f"/api/v1/datasets/{dataset_id}/records"), 404)
        expect_error(
            await bob.post(
                "/api/v1/datasets", json={"project_id": project_id, "name": "x", "schema": SCHEMA}
            ),
            404,
        )
        assert (await bob.get("/api/v1/projects")).json()["items"] == []

    async def test_cursor_from_another_sort_is_a_client_error(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        for name in ("alpha", "beta", "gamma"):
            await create_project(owner, name)
        by_name = (await owner.get("/api/v1/projects", params={"limit": 1, "sort": "name"})).json()
        assert by_name["next_cursor"]
        replayed = await owner.get(
            "/api/v1/projects",
            params={"limit": 1, "sort": "-created_at", "cursor": by_name["next_cursor"]},
        )
        expect_error(replayed, 422, "invalid_cursor")
        expect_error(await owner.get("/api/v1/projects", params={"sort": "password_hash"}), 422)

    @pytest.mark.parametrize(
        ("path", "sort", "value"),
        [
            ("/api/v1/changes", "-score", 40_000),  # beyond SMALLINT
            ("/api/v1/changes", "-score", 2**70),  # beyond any integer column
            ("/api/v1/projects", "name", "a\x00b"),  # PostgreSQL text cannot hold NUL
            ("/api/v1/projects", "name", "\ud800"),  # lone surrogate: not encodable
            ("/api/v1/projects", "-created_at", "0001-01-01T00:00:00+05:00"),  # UTC underflow
            ("/api/v1/projects", "-created_at", "9999-12-31T23:00:00-05:00"),  # UTC overflow
        ],
    )
    async def test_crafted_cursors_are_client_errors_not_crashes(
        self, api: httpx2.AsyncClient, path: str, sort: str, value: str | int
    ) -> None:
        owner = await signup(api)
        crafted = encode_cursor(value, uuid4())
        response = await owner.get(path, params={"sort": sort, "cursor": crafted})
        expect_error(response, 422, "invalid_cursor")


class TestOrganizationSettings:
    async def test_settings_patch_merges_and_never_lifts_a_freeze(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        await owner.patch(
            "/api/v1/organizations/current",
            json={"settings": {"allowed_source_domains": ["example.com"]}},
        )
        await owner.post(
            "/api/v1/organizations/current/automation-freeze",
            json={"frozen": True, "reason": "incident 7"},
        )
        patched = await owner.patch(
            "/api/v1/organizations/current", json={"settings": {"ai_external_processing": True}}
        )
        assert patched.status_code == 200, patched.text
        settings = patched.json()["settings"]
        assert settings["ai_external_processing"] is True
        assert settings["automation_frozen"] is True  # untouched by an unrelated change
        assert settings["allowed_source_domains"] == ["example.com"]
        smuggled = await owner.patch(
            "/api/v1/organizations/current", json={"settings": {"automation_frozen": False}}
        )
        expect_error(smuggled, 422)
        cleared = await owner.patch(
            "/api/v1/organizations/current", json={"settings": {"allowed_source_domains": None}}
        )
        assert cleared.json()["settings"]["allowed_source_domains"] is None


class TestWebhookIngestion:
    async def _endpoint(self, owner: ApiSession) -> tuple[str, str, str, str]:
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, WEBHOOK_CONFIG)
        created = await owner.post(
            "/api/v1/webhook-endpoints", json={"source_id": source_id, "name": "shop"}
        )
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["url"].startswith("https://nexusflow.test.example/api/v1/webhooks/")
        path = body["url"].removeprefix("https://nexusflow.test.example")
        return path, body["secret"], dataset_id, project_id

    async def test_signed_delivery_is_ingested_masked_and_exported_safely(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        path, secret, dataset_id, _ = await self._endpoint(owner)
        payload = json.dumps(
            {
                "items": [
                    {
                        "sku": "A-1",
                        "title": '=HYPERLINK("http://evil.example")',
                        "price": "10.50",
                        "supplier": {"email": "buyer@supplier.example"},
                    },
                    {
                        "sku": "A-2",
                        "title": "Plain",
                        "price": "3",
                        "supplier": {"email": "x@supplier.example"},
                    },
                ]
            }
        ).encode()
        headers = signed_headers(secret, payload, "dlv-0001-first")
        accepted = await api.post(path, content=payload, headers=headers)
        assert accepted.status_code == 202, accepted.text
        run_id = UUID(accepted.json()["run_id"])

        duplicate = await api.post(path, content=payload, headers=headers)
        assert duplicate.status_code == 200
        assert duplicate.json() == {"status": "duplicate", "run_id": None}

        outcome = await container.ingestion.ingest(
            org_id=await org_id_of(owner), run_id=run_id, items=None
        )
        assert outcome.status.value == "succeeded", outcome.stats

        records = (await owner.get(f"/api/v1/datasets/{dataset_id}/records")).json()["items"]
        assert {r["data"]["supplier_email"] for r in records} == {
            "buyer@supplier.example",
            "x@supplier.example",
        }
        viewer = await viewer_key(owner, ["records:read"])
        masked = (await api.get(f"/api/v1/datasets/{dataset_id}/records", headers=viewer)).json()[
            "items"
        ]
        assert {r["data"]["supplier_email"] for r in masked} == {"[masked]"}

        export = await owner.get(f"/api/v1/datasets/{dataset_id}/export", params={"format": "csv"})
        assert export.status_code == 200
        assert export.headers["content-disposition"].startswith("attachment;")
        assert export.headers["cache-control"] == "no-store"
        assert "'=HYPERLINK" in export.text  # formula neutralised for spreadsheet apps
        assert ",=HYPERLINK" not in export.text

    async def test_rejections_are_uniform_and_reveal_nothing(self, api: httpx2.AsyncClient) -> None:
        owner = await signup(api)
        path, secret, _, _ = await self._endpoint(owner)
        body = b'{"items": []}'
        unsigned = expect_error(
            await api.post(path, content=body, headers={"Content-Type": "application/json"}), 401
        )
        wrong = expect_error(
            await api.post(path, content=body, headers=signed_headers("whsec_wrong", body)), 401
        )
        org_part = path.split("/")[4]
        unknown_path = f"/api/v1/webhooks/{org_part}/{uuid4()}"
        unknown = expect_error(
            await api.post(unknown_path, content=body, headers=signed_headers(secret, body)), 401
        )
        other_org = expect_error(
            await api.post(
                f"/api/v1/webhooks/{uuid4()}/{path.split('/')[5]}",
                content=body,
                headers=signed_headers(secret, body),
            ),
            401,
        )
        for rejection in (unsigned, wrong, unknown, other_org):
            assert (rejection["error"], rejection["message"]) == (
                "invalid_signature",
                "Webhook signature verification failed.",
            )
        expect_error(
            await api.post(
                path, content=b"a=1", headers={"Content-Type": "application/x-www-form-urlencoded"}
            ),
            415,
        )

    async def test_a_failed_delivery_stays_retryable_under_the_same_id(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        path, secret, _, _ = await self._endpoint(owner)
        broken = b'{"items": [}'  # signed correctly, but fails while being stored
        failed = await api.post(
            path, content=broken, headers=signed_headers(secret, broken, "dlv-retry-0001")
        )
        assert failed.status_code == 422, failed.text
        # The sender fixes the payload and retries the same delivery: it must be
        # stored, not acknowledged as a "duplicate" of the attempt that failed.
        fixed = b'{"items": [{"sku": "A-1"}]}'
        retried = await api.post(
            path, content=fixed, headers=signed_headers(secret, fixed, "dlv-retry-0001")
        )
        assert retried.status_code == 202, retried.text
        replayed = await api.post(
            path, content=fixed, headers=signed_headers(secret, fixed, "dlv-retry-0001")
        )
        assert (replayed.status_code, replayed.json()["status"]) == (200, "duplicate")

    async def test_a_claimed_but_unstored_delivery_is_never_called_a_duplicate(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        path, secret, _, _ = await self._endpoint(owner)
        namespace = f"webhook:{path.split('/')[5]}"
        # An earlier attempt claimed the fast-path nonce but never committed.
        assert await container.replay_guard.first_use(namespace, "dlv-claimed-01", ttl_seconds=600)
        body = b'{"items": [{"sku": "A-1"}]}'
        in_flight = await api.post(
            path, content=body, headers=signed_headers(secret, body, "dlv-claimed-01")
        )
        expect_error(in_flight, 409, "delivery_in_progress")
        await container.replay_guard.release(namespace, "dlv-claimed-01")
        stored = await api.post(
            path, content=body, headers=signed_headers(secret, body, "dlv-claimed-01")
        )
        assert stored.status_code == 202, stored.text

    async def test_only_authenticated_deliveries_spend_the_endpoint_quota(
        self, api: httpx2.AsyncClient, container: Container, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        charged: list[UUID] = []

        class ExhaustedAfterOne:
            async def consume(self, endpoint_id: UUID) -> None:
                charged.append(endpoint_id)
                if len(charged) > 1:
                    raise RateLimitedError(retry_after_seconds=30)

        monkeypatch.setattr(container.webhooks, "_quota", ExhaustedAfterOne())
        owner = await signup(api)
        path, secret, _, _ = await self._endpoint(owner)
        body = b'{"items": [{"sku": "A-1"}]}'
        for _ in range(3):  # forged traffic is rejected before the quota is touched
            forged = await api.post(
                path, content=body, headers=signed_headers("whsec_forged", body)
            )
            expect_error(forged, 401, "invalid_signature")
        assert charged == []
        accepted = await api.post(path, content=body, headers=signed_headers(secret, body))
        assert accepted.status_code == 202, accepted.text
        throttled = await api.post(path, content=body, headers=signed_headers(secret, body))
        expect_error(throttled, 429, "rate_limited")
        assert throttled.headers["retry-after"] == "30"
        assert charged == [UUID(path.split("/")[5])] * 2

    async def test_unknown_endpoints_cost_the_same_signature_work(
        self, api: httpx2.AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        verifications: list[int] = []

        def counting(**kwargs: Any) -> ParsedSignature:
            verifications.append(len(kwargs["secrets"]))
            return verify_signature(**kwargs)

        monkeypatch.setattr(webhook_service, "verify_signature", counting)
        owner = await signup(api)
        path, secret, _, _ = await self._endpoint(owner)
        body = b'{"items": []}'
        unknown = f"/api/v1/webhooks/{path.split('/')[4]}/{uuid4()}"
        expect_error(
            await api.post(unknown, content=body, headers=signed_headers(secret, body)), 401
        )
        expect_error(
            await api.post(path, content=body, headers=signed_headers("whsec_x", body)), 401
        )
        assert verifications == [1, 1]  # a decoy HMAC for the unknown endpoint, too

    async def test_frozen_organization_refuses_deliveries(self, api: httpx2.AsyncClient) -> None:
        owner = await signup(api)
        path, secret, _, _ = await self._endpoint(owner)
        frozen = await owner.post(
            "/api/v1/organizations/current/automation-freeze",
            json={"frozen": True, "reason": "incident drill"},
        )
        assert frozen.status_code == 200, frozen.text
        body = b'{"items": [{"sku": "A-1"}]}'
        expect_error(
            await api.post(path, content=body, headers=signed_headers(secret, body)),
            409,
            "source_inactive",
        )


class TestUploadsAndRuns:
    async def test_csv_upload_is_accepted_once_and_bad_files_rejected(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, UPLOAD_CONFIG)
        url = f"/api/v1/sources/{source_id}/uploads"
        csv_bytes = b"SKU,Title,Price,Email\r\nA-1,Widget,9.99,a@b.example\r\n"

        first = await owner.post(
            url, files={"file": ("../../etc/passwd.csv", csv_bytes, "text/csv")}
        )
        assert first.status_code == 201, first.text
        assert "/" not in first.json()["original_filename"]
        again = await owner.post(url, files={"file": ("prices.csv", csv_bytes, "text/csv")})
        assert again.status_code == 200
        assert again.json()["id"] == first.json()["id"]

        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        expect_error(await owner.post(url, files={"file": ("image.csv", png, "text/csv")}), 422)
        expect_error(await owner.post(url, json={"file": "x"}), 415)
        two_files = [
            ("file", ("a.csv", csv_bytes, "text/csv")),
            ("file", ("b.csv", csv_bytes, "text/csv")),
        ]
        expect_error(await owner.post(url, files=two_files), 400)

        kept = container.storage.local_path(
            f"uploads/{await org_id_of(owner)}/{first.json()['id']}.csv"
        )
        stored = [p for p in kept.parent.iterdir() if p.is_file()]
        assert len(stored) == 1  # rejected and duplicate uploads leave nothing behind

    async def test_a_snapshot_missing_most_records_deletes_nothing(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        website = {
            "kind": "website",
            "url": "https://shop.example.com/products",
            "item_selector": "div.product",
            "fields": {"sku": {"selector": ".sku"}},
        }
        source_id = await create_source(owner, project_id, dataset_id, website)
        org_id = await org_id_of(owner)

        async def snapshot(skus: list[str]) -> dict[str, Any]:
            run = await owner.post(f"/api/v1/sources/{source_id}/runs")
            assert run.status_code == 202, run.text
            outcome = await container.ingestion.ingest(
                org_id=org_id, run_id=UUID(run.json()["id"]), items=[{"sku": s} for s in skus]
            )
            assert outcome.status.value == "succeeded", outcome.stats
            return outcome.stats

        catalogue = [f"P-{i:03d}" for i in range(30)]
        assert (await snapshot(catalogue))["created"] == 30
        # The page suddenly lists 5 of 30 products (layout change, hostile site):
        broken = await snapshot(catalogue[:5])
        assert (broken["deleted"], broken["deletions_withheld"]) == (0, 25)
        records = f"/api/v1/datasets/{dataset_id}/records"
        assert len((await owner.get(records, params={"limit": 200})).json()["items"]) == 30
        # A handful of genuinely discontinued products are still deleted.
        normal = await snapshot(catalogue[:27])
        assert normal["deleted"] == 3
        assert "deletions_withheld" not in normal
        assert len((await owner.get(records, params={"limit": 200})).json()["items"]) == 27

    @pytest.mark.parametrize("ending", ["failed", "cancelled", "reaped"])
    async def test_a_file_whose_run_never_stored_it_can_be_uploaded_again(
        self, api: httpx2.AsyncClient, container: Container, ending: str
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, UPLOAD_CONFIG)
        url = f"/api/v1/sources/{source_id}/uploads"
        csv_file = {"file": ("prices.csv", b"SKU,Title\r\nA-1,Widget\r\n", "text/csv")}
        first = (await owner.post(url, files=csv_file)).json()
        org_id, run_id = await org_id_of(owner), UUID(first["run_id"])
        if ending == "failed":  # e.g. the worker gave up after its retries
            await container.ingestion.fail_run(
                org_id=org_id, run_id=run_id, code="parser_crashed", detail=None
            )
        elif ending == "cancelled":  # e.g. the organization was frozen before the run started
            await container.ingestion.cancel_run(
                org_id=org_id, run_id=run_id, code="automation_frozen"
            )
        else:  # its workers kept dying: the reaper gives up after the last attempt
            async with container.uow_factory(TenantScope.system(org_id)) as uow:
                run = await uow.data.runs.get_for_update(org_id, run_id)
                assert run is not None
                run.start(container.clock.now() - STUCK_RUN_AFTER * 2)
                run.attempt = MAX_RUN_ATTEMPTS
                await uow.commit()
            assert (await container.maintenance.reap(org_id)).failed_runs == 1

        listed = (await owner.get(url)).json()["items"]
        assert [(u["id"], u["status"]) for u in listed] == [(first["id"], "failed")]
        # No longer deduplicated against an upload that will never finish ...
        retry = await owner.post(url, files=csv_file)
        assert retry.status_code == 201, retry.text
        assert retry.json()["id"] != first["id"]
        # ... while the new, live upload is deduplicated as usual.
        again = await owner.post(url, files=csv_file)
        assert (again.status_code, again.json()["id"]) == (200, retry.json()["id"])

    async def test_run_now_is_idempotent_and_respects_the_freeze(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        website = {
            "kind": "website",
            "url": "https://shop.example.com/products",
            "item_selector": "div.product",
            "fields": {"sku": {"selector": ".sku"}, "title": {"selector": "h2"}},
        }
        source_id = await create_source(owner, project_id, dataset_id, website)
        url = f"/api/v1/sources/{source_id}/runs"
        first = await owner.post(url, headers={"Idempotency-Key": "run-key-0001"})
        assert first.status_code == 202, first.text
        repeat = await owner.post(url, headers={"Idempotency-Key": "run-key-0001"})
        assert repeat.status_code == 200
        assert repeat.json()["id"] == first.json()["id"]
        expect_error(await owner.post(url, headers={"Idempotency-Key": "bad key!"}), 422)

        await owner.post(
            "/api/v1/organizations/current/automation-freeze",
            json={"frozen": True, "reason": "drill"},
        )
        expect_error(await owner.post(url), 409, "automation_frozen")

    @pytest.mark.parametrize(
        "target",
        [
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:10.0.0.1]/",
            "file:///etc/passwd",
            "http://localhost:8080/",
        ],
    )
    async def test_sources_cannot_target_internal_addresses(
        self, api: httpx2.AsyncClient, target: str
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        config = {
            "kind": "website",
            "url": target,
            "item_selector": "div",
            "fields": {"sku": {"selector": "a"}},
        }
        response = await owner.post(
            "/api/v1/sources",
            json={
                "project_id": project_id,
                "dataset_id": dataset_id,
                "name": "x",
                "config": config,
            },
        )
        expect_error(response, 422)


class TestReports:
    async def test_report_generation_and_download(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        requested = await owner.post(
            "/api/v1/reports",
            json={
                "project_id": project_id,
                "format": "csv",
                "title": "Weekly <b>report</b>",
                "period_start": "2026-01-01T00:00:00Z",
                "period_end": "2026-01-08T00:00:00Z",
            },
            headers={"Idempotency-Key": "report-0001"},
        )
        assert requested.status_code == 202, requested.text
        report_id = UUID(requested.json()["id"])
        expect_error(
            await owner.get(f"/api/v1/reports/{report_id}/download"), 409, "report_not_ready"
        )

        await container.reports.generate(org_id=await org_id_of(owner), report_id=report_id)
        download = await owner.get(f"/api/v1/reports/{report_id}/download")
        assert download.status_code == 200, download.text
        assert download.headers["content-type"].startswith("text/csv")
        assert download.headers["content-disposition"].startswith("attachment;")
        digest = base64.b64encode(hashlib.sha256(download.content).digest()).decode()
        assert download.headers["repr-digest"] == f"sha-256=:{digest}:"

    async def test_naive_datetimes_are_rejected(self, api: httpx2.AsyncClient) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        response = await owner.post(
            "/api/v1/reports",
            json={
                "project_id": project_id,
                "format": "pdf",
                "period_start": "2026-01-01T00:00:00",
                "period_end": "2026-01-08T00:00:00",
            },
        )
        expect_error(response, 422)


class TestInternalAutomationApi:
    async def test_failed_n8n_executions_retry_with_backoff_then_dead_letter(
        self, internal_api: httpx2.AsyncClient, container: Container
    ) -> None:
        token = await self._token(container, "automation:recover")
        chain = [f"exec-{uuid4().hex[:10]}" for _ in range(4)]
        decisions = []
        for index, execution_id in enumerate(chain):
            report = {
                "workflow": "NexusFlow 2 - Change Detection",
                "node": "Detect changes",
                "execution_id": execution_id,
                "retry_of": chain[index - 1] if index else None,
                "error_message": "HTTP 503",
                "idempotent": True,
            }
            response = await internal_api.post(
                "/internal/v1/automation/failures", json=report, headers=token
            )
            assert response.status_code == 200, response.text
            decisions.append(response.json())
            if index == 0:
                # n8n retrying the same report (lost response) must not count twice.
                again = await internal_api.post(
                    "/internal/v1/automation/failures", json=report, headers=token
                )
                assert again.json()["retry"] is True
        retries, final = decisions[:3], decisions[3]
        assert all(d["retry"] for d in retries)
        delays = [d["delay_seconds"] for d in retries]
        assert 0 < delays[0] < delays[1] < delays[2] <= 900  # exponential backoff
        assert final["retry"] is False
        assert final["dead_letter_id"] is not None

    async def test_automation_steps_are_audited_to_the_service_account(
        self, api: httpx2.AsyncClient, internal_api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        dataset_id = await create_dataset(owner, await create_project(owner))
        step = {"org_id": str(await org_id_of(owner)), "dataset_id": dataset_id}
        token = await self._token(container, "automation:detect", "automation:alert")
        for path, body in (
            ("/internal/v1/automation/detect", step),
            ("/internal/v1/automation/alerts/evaluate", {"org_id": step["org_id"]}),
        ):
            response = await internal_api.post(path, json=body, headers=token)
            assert response.status_code == 200, response.text
        entries = (await owner.get("/api/v1/audit", params={"action": "automation.step"})).json()
        steps = sorted((e["actor_type"], e["metadata"]["step"]) for e in entries["items"])
        assert steps == [("service", "detect"), ("service", "evaluate_alerts")]

    async def test_callers_cannot_supply_their_own_attempt_count(
        self, internal_api: httpx2.AsyncClient, container: Container
    ) -> None:
        token = await self._token(container, "automation:recover")
        forged = {"workflow": "w", "node": "n", "execution_id": "e1", "attempt": 0}
        expect_error(
            await internal_api.post("/internal/v1/automation/failures", json=forged, headers=token),
            422,
        )

    async def _token(self, container: Container, *scopes: str) -> dict[str, str]:
        from nexusflow.domain.authorization.principal import ServiceScope
        from tests.support.fixtures import META

        issued = await container.service_accounts.create(
            name=f"wf-{uuid4().hex[:8]}",
            workflow_key=f"wf-{uuid4().hex[:8]}",
            scopes=[ServiceScope(s) for s in scopes],
            meta=META,
        )
        return {"Authorization": f"Bearer {issued.token}"}

    async def test_only_scoped_service_tokens_are_accepted(
        self, api: httpx2.AsyncClient, internal_api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        step = {"org_id": str(await org_id_of(owner)), "dataset_id": dataset_id}

        expect_error(
            await internal_api.post(
                "/internal/v1/automation/detect", json=step, headers=owner.headers
            ),
            401,
        )
        detect_token = await self._token(container, "automation:detect")
        detected = await internal_api.post(
            "/internal/v1/automation/detect", json=step, headers=detect_token
        )
        assert detected.status_code == 200, detected.text
        assert detected.json()["changes_created"] == 0
        expect_error(
            await internal_api.post(
                "/internal/v1/automation/analyze", json=step, headers=detect_token
            ),
            403,
        )
        # Service tokens are useless against the tenant API.
        expect_error(await api.get("/api/v1/projects", headers=detect_token), 401)

    async def test_kill_switches(
        self, api: httpx2.AsyncClient, internal_api: httpx2.AsyncClient, container: Container
    ) -> None:
        from nexusflow.infrastructure.redis.client import FeatureFlags

        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        step = {"org_id": str(await org_id_of(owner)), "dataset_id": dataset_id}
        token = await self._token(container, "automation:detect", "automation:recover")

        await owner.post(
            "/api/v1/organizations/current/automation-freeze",
            json={"frozen": True, "reason": "drill"},
        )
        expect_error(
            await internal_api.post("/internal/v1/automation/detect", json=step, headers=token),
            409,
            "automation_frozen",
        )

        await container.flags.set(FeatureFlags.AUTOMATION_KILL_SWITCH, enabled=True)
        try:
            expect_error(
                await internal_api.post("/internal/v1/automation/detect", json=step, headers=token),
                503,
                "automation_disabled",
            )
            failure = await internal_api.post(
                "/internal/v1/automation/failures",
                headers=token,
                json={
                    "org_id": step["org_id"],
                    "workflow": "data-collection",
                    "node": "Call API",
                    "execution_id": "exec-42",
                    "error_message": (
                        "GET https://api.example.com/x?token=supersecret failed: "
                        "Bearer abcdefghijklmnop123"
                    ),
                    "idempotent": True,
                },
            )
            assert failure.status_code == 200, failure.text
            # Nothing is retried while automation is stopped: straight to a dead letter.
            assert failure.json()["retry"] is False
        finally:
            await container.flags.set(FeatureFlags.AUTOMATION_KILL_SWITCH, enabled=False)

        letters = (await owner.get("/api/v1/dead-letters")).json()["items"]
        assert len(letters) == 1
        message = letters[0]["error_message"]
        assert "supersecret" not in message
        assert "abcdefghijklmnop123" not in message

"""Worker flows against the real database: the sandbox trust boundary, staged
ingestion and event routing (internal orchestration mode)."""

from __future__ import annotations

import io
import json
import math
import time
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import httpx2
import openpyxl
import pytest
from fastapi import FastAPI

from nexusflow.apps.api.routers import sandbox_gateway
from nexusflow.apps.workers.handlers import (
    WorkerDeps,
    analyze_changes,
    collect_dispatch,
    collect_rest_api,
    detect_changes,
    dispatch_due_workflows,
    evaluate_alerts,
    route_event,
    sweep_detection,
)
from nexusflow.apps.workers.messages import (
    DatasetMessage,
    Empty,
    EventMessage,
    InsightMessage,
    OrgMessage,
    RunMessage,
)
from nexusflow.apps.workers.sandbox import UploadJob, parse_uploaded_file
from nexusflow.bootstrap.container import Container
from nexusflow.bootstrap.sandbox import SandboxComponents, build_sandbox
from nexusflow.core.config import SandboxSettings
from nexusflow.core.errors import PermanentError, TransientError
from nexusflow.domain.shared.unit_of_work import TenantScope
from nexusflow.domain.webhooks.signatures import build_signature_header
from nexusflow.infrastructure.messaging.celery_app import (
    SANDBOX,
    SANDBOX_UPLOAD_TASK,
    SANDBOX_WEBSITE_TASK,
)
from nexusflow.infrastructure.redis.client import FeatureFlags
from nexusflow.infrastructure.sandbox.gateway import SandboxGatewayClient
from tests.support.api import ApiSession, signup
from tests.support.business import (
    UPLOAD_CONFIG,
    WEBHOOK_CONFIG,
    create_dataset,
    create_project,
    create_source,
    org_id_of,
)

pytestmark = pytest.mark.integration

WEBSITE_CONFIG = {
    "kind": "website",
    "url": "https://shop.example.com/products",
    "item_selector": "div.product",
    "fields": {"sku": {"selector": ".sku"}, "title": {"selector": "h2"}},
}
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


class RecordingDispatcher:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any], str]] = []

    def send_task(self, name: str, *, kwargs: dict[str, Any], queue: str) -> None:
        self.sent.append((name, kwargs, queue))


def _deps(container: Container) -> tuple[WorkerDeps, RecordingDispatcher]:
    dispatcher = RecordingDispatcher()
    return WorkerDeps(container=container, dispatcher=dispatcher), dispatcher  # type: ignore[arg-type]


async def _website_run(owner: ApiSession) -> tuple[UUID, UUID, str]:
    project_id = await create_project(owner)
    dataset_id = await create_dataset(owner, project_id)
    source_id = await create_source(owner, project_id, dataset_id, WEBSITE_CONFIG)
    run = await owner.post(f"/api/v1/sources/{source_id}/runs")
    assert run.status_code == 202, run.text
    return await org_id_of(owner), UUID(run.json()["id"]), dataset_id


def _result_url(org_id: UUID, run_id: UUID) -> str:
    return f"/internal/v1/sandbox/orgs/{org_id}/runs/{run_id}/result"


def _sandbox(internal_app: FastAPI) -> SandboxComponents:
    """The sandbox's components, talking to the in-process internal app."""
    sandbox = build_sandbox(SandboxSettings())
    sandbox.gateway = SandboxGatewayClient(
        "http://testserver", timeout_seconds=10, transport=httpx2.ASGITransport(app=internal_app)
    )
    sandbox.closers.append(sandbox.gateway.aclose)
    return sandbox


def _xlsx() -> bytes:
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    assert sheet is not None
    sheet.append(["SKU", "Title", "Price", "Email"])
    sheet.append(["X-1", "Crate", 12.5, "x@example.com"])
    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


async def _upload_source(
    api: httpx2.AsyncClient, config: dict[str, Any] = UPLOAD_CONFIG
) -> tuple[ApiSession, str, str]:
    owner = await signup(api)
    project_id = await create_project(owner)
    dataset_id = await create_dataset(owner, project_id)
    return owner, await create_source(owner, project_id, dataset_id, config), dataset_id


async def _upload_job(
    owner: ApiSession,
    container: Container,
    source_id: str,
    content: bytes,
    content_type: str = "text/csv",
) -> tuple[UUID, UUID, UploadJob]:
    """Upload ``content`` and dispatch its run: the job the sandbox receives."""
    name = "parts.xlsx" if content_type == XLSX else "parts.csv"
    uploaded = await owner.post(
        f"/api/v1/sources/{source_id}/uploads", files={"file": (name, content, content_type)}
    )
    assert uploaded.status_code == 201, uploaded.text
    org_id, run_id = await org_id_of(owner), UUID(uploaded.json()["run_id"])
    deps, dispatcher = _deps(container)
    await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
    [(task, kwargs, _)] = dispatcher.sent
    assert task == SANDBOX_UPLOAD_TASK
    return org_id, run_id, UploadJob.model_validate(kwargs)


class TestSandboxBoundary:
    async def test_website_run_round_trip_through_the_gateway(
        self, api: httpx2.AsyncClient, internal_api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        org_id, run_id, dataset_id = await _website_run(owner)
        deps, dispatcher = _deps(container)

        await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
        [(task, kwargs, queue)] = dispatcher.sent
        assert (task, queue) == (SANDBOX_WEBSITE_TASK, SANDBOX)
        assert kwargs["config"]["url"] == WEBSITE_CONFIG["url"]
        ticket = kwargs["ticket"]

        # A duplicate delivery of the same dispatch must not start a second fetch.
        await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
        assert len(dispatcher.sent) == 1

        body = {
            "items": [{"sku": "A-1", "title": "Widget"}, {"sku": "A-2", "title": "Gadget"}],
            "truncated": False,
            "detail": {"http_status": 200, "host": "shop.example.com", "injected": "<script>"},
        }
        forged = "0" * 64
        rejected = await internal_api.post(
            _result_url(org_id, run_id), json=body, headers={"X-Sandbox-Ticket": forged}
        )
        assert rejected.status_code == 401
        other_run = await internal_api.post(
            _result_url(org_id, uuid4()), json=body, headers={"X-Sandbox-Ticket": ticket}
        )
        assert other_run.status_code == 401  # a ticket is bound to exactly one run
        other_org = await internal_api.post(
            _result_url(uuid4(), run_id), json=body, headers={"X-Sandbox-Ticket": ticket}
        )
        assert other_org.status_code == 401
        malformed = await internal_api.post(
            _result_url(org_id, run_id), json=body, headers={"X-Sandbox-Ticket": "x"}
        )
        assert malformed.status_code == 422

        accepted = await internal_api.post(
            _result_url(org_id, run_id), json=body, headers={"X-Sandbox-Ticket": ticket}
        )
        assert accepted.status_code == 202, accepted.text
        again = await internal_api.post(
            _result_url(org_id, run_id), json=body, headers={"X-Sandbox-Ticket": ticket}
        )
        assert again.status_code == 202  # idempotent re-submission

        await collect_dispatch(
            deps, RunMessage(org_id=org_id, run_id=run_id)
        )  # ingests the staged items
        run = (await owner.get(f"/api/v1/runs/{run_id}")).json()
        assert run["status"] == "succeeded"
        assert run["stats"]["http_status"] == 200
        assert "injected" not in run["stats"]
        records = (await owner.get(f"/api/v1/datasets/{dataset_id}/records")).json()["items"]
        assert {r["record_key"] for r in records} == {"A-1", "A-2"}

        late = await internal_api.post(
            _result_url(org_id, run_id), json=body, headers={"X-Sandbox-Ticket": ticket}
        )
        assert late.status_code == 409  # the run is closed; replays are refused

    async def test_oversized_or_malformed_results_are_refused(
        self, api: httpx2.AsyncClient, internal_api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        org_id, run_id, _ = await _website_run(owner)
        deps, dispatcher = _deps(container)
        await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
        ticket = dispatcher.sent[0][1]["ticket"]
        headers = {"X-Sandbox-Ticket": ticket}
        nested = {"items": [{"sku": {"nested": {"deep": [1, 2, 3]}}}]}
        assert (
            await internal_api.post(_result_url(org_id, run_id), json=nested, headers=headers)
        ).status_code == 422
        too_many = {
            "items": [
                {"sku": str(i)} for i in range(container.settings.scraping.max_items_per_run + 1)
            ]
        }
        assert (
            await internal_api.post(_result_url(org_id, run_id), json=too_many, headers=headers)
        ).status_code == 422
        bad_code = {"error_code": "DROP TABLE"}
        assert (
            await internal_api.post(_result_url(org_id, run_id), json=bad_code, headers=headers)
        ).status_code == 422
        failed = await internal_api.post(
            _result_url(org_id, run_id), json={"error_code": "robots_disallowed"}, headers=headers
        )
        assert failed.status_code == 202
        run = (await owner.get(f"/api/v1/runs/{run_id}")).json()
        assert (run["status"], run["error_code"]) == ("failed", "robots_disallowed")

    async def test_the_ticket_is_checked_before_the_body_is_read(
        self, api: httpx2.AsyncClient, internal_api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        org_id, run_id, _ = await _website_run(owner)
        await collect_dispatch(_deps(container)[0], RunMessage(org_id=org_id, run_id=run_id))
        # Two megabytes of garbage with a forged ticket: refused as unauthorized,
        # i.e. before any of it was buffered or parsed.
        garbage = await internal_api.post(
            _result_url(org_id, run_id),
            content=b"[" * (2 * 1024 * 1024),
            headers={"X-Sandbox-Ticket": "e" * 64, "Content-Type": "application/json"},
        )
        assert garbage.status_code == 401

    async def test_large_results_are_staged_one_at_a_time(
        self,
        api: httpx2.AsyncClient,
        internal_api: httpx2.AsyncClient,
        container: Container,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner = await signup(api)
        org_id, run_id, _ = await _website_run(owner)
        deps, dispatcher = _deps(container)
        await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
        headers = {"X-Sandbox-Ticket": dispatcher.sent[0][1]["ticket"]}
        monkeypatch.setattr(sandbox_gateway, "_SMALL_BODY", 0)  # every body counts as large
        monkeypatch.setattr(sandbox_gateway, "_SLOT_WAIT_SECONDS", 0.05)
        body = {"items": [{"sku": "A-1"}], "truncated": False}

        await sandbox_gateway._LARGE_RESULTS.acquire()  # another large result is in flight
        try:
            busy = await internal_api.post(_result_url(org_id, run_id), json=body, headers=headers)
        finally:
            sandbox_gateway._LARGE_RESULTS.release()
        assert (busy.status_code, busy.json()["error"]) == (503, "gateway_busy")
        accepted = await internal_api.post(_result_url(org_id, run_id), json=body, headers=headers)
        assert accepted.status_code == 202, accepted.text

    async def test_upload_input_is_the_attempts_and_a_sandbox_failure_frees_the_file(
        self, api: httpx2.AsyncClient, internal_api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, UPLOAD_CONFIG)
        uploads_url = f"/api/v1/sources/{source_id}/uploads"
        csv_bytes = b"SKU,Title\r\nB-1,Bolt\r\n"
        csv_file = {"file": ("parts.csv", csv_bytes, "text/csv")}
        uploaded = await owner.post(uploads_url, files=csv_file)
        assert uploaded.status_code == 201, uploaded.text
        org_id, run_id = await org_id_of(owner), UUID(uploaded.json()["run_id"])
        deps, dispatcher = _deps(container)
        await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
        [(_, kwargs, _)] = dispatcher.sent
        headers = {"X-Sandbox-Ticket": kwargs["ticket"]}
        input_url = f"/internal/v1/sandbox/orgs/{org_id}/runs/{run_id}/input"

        downloaded = await internal_api.get(input_url, headers=headers)
        assert (downloaded.status_code, downloaded.content) == (200, csv_bytes)
        # The attempt's job, retried, needs its input again (until its result is in).
        again = await internal_api.get(input_url, headers=headers)
        assert (again.status_code, again.content) == (200, csv_bytes)

        failed = await internal_api.post(
            _result_url(org_id, run_id), json={"error_code": "parse_failed"}, headers=headers
        )
        assert failed.status_code == 202
        closed = await internal_api.get(input_url, headers=headers)
        assert (closed.status_code, closed.json()["error"]) == (409, "run_closed")
        [upload] = (await owner.get(uploads_url)).json()["items"]
        assert (upload["status"], upload["rejection_reason"]) == ("failed", "parse_failed")
        run = (await owner.get(f"/api/v1/runs/{run_id}")).json()
        assert (run["status"], run["error_code"]) == ("failed", "parse_failed")
        retry = await owner.post(uploads_url, files=csv_file)
        assert retry.status_code == 201, retry.text  # the failed file may be uploaded again

    async def test_an_upload_job_retried_after_its_download_completes_the_run(
        self,
        api: httpx2.AsyncClient,
        internal_app: FastAPI,
        container: Container,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner, source_id, dataset_id = await _upload_source(api)
        csv_bytes = b"SKU,Title,Price,Email\r\nB-1,Bolt,1.25,a@example.com\r\n"
        org_id, run_id, job = await _upload_job(owner, container, source_id, csv_bytes)
        # The gateway is busy with another large result: the first attempt of the
        # job downloads and parses the file, then its submission gets a 503.
        monkeypatch.setattr(sandbox_gateway, "_SMALL_BODY", 0)
        monkeypatch.setattr(sandbox_gateway, "_SLOT_WAIT_SECONDS", 0.05)
        sandbox = _sandbox(internal_app)
        try:
            await sandbox_gateway._LARGE_RESULTS.acquire()
            try:
                with pytest.raises(TransientError):
                    await parse_uploaded_file(sandbox, job)
            finally:
                sandbox_gateway._LARGE_RESULTS.release()
            await parse_uploaded_file(sandbox, job)  # the Celery retry: same job, same ticket
            # Its result is in: the input is gone for that ticket, and the job is moot.
            with pytest.raises(PermanentError) as moot:
                await parse_uploaded_file(sandbox, job)
            assert moot.value.code == "no_input"
        finally:
            await sandbox.aclose()

        await collect_dispatch(_deps(container)[0], RunMessage(org_id=org_id, run_id=run_id))
        run = (await owner.get(f"/api/v1/runs/{run_id}")).json()
        assert run["status"] == "succeeded", run
        records = (await owner.get(f"/api/v1/datasets/{dataset_id}/records")).json()["items"]
        assert [r["record_key"] for r in records] == ["B-1"]

    async def test_an_xlsx_upload_is_parsed_end_to_end(
        self, api: httpx2.AsyncClient, internal_app: FastAPI, container: Container
    ) -> None:
        config = {**UPLOAD_CONFIG, "format": "xlsx"}
        owner, source_id, dataset_id = await _upload_source(api, config)
        org_id, run_id, job = await _upload_job(owner, container, source_id, _xlsx(), XLSX)
        sandbox = _sandbox(internal_app)
        try:
            await parse_uploaded_file(sandbox, job)
        finally:
            await sandbox.aclose()
        async with container.uow_factory(TenantScope.system(org_id)) as uow:
            staged = await uow.data.payloads.exists(org_id, run_id)
            upload = await uow.data.uploads.get_by_run(org_id, run_id)
            run = await uow.data.runs.get(org_id, run_id)
        assert staged
        assert upload is not None and (upload.status.value, upload.row_count) == ("processed", 1)
        assert run is not None and run.status.value == "running"  # its ingestion is queued

        await collect_dispatch(_deps(container)[0], RunMessage(org_id=org_id, run_id=run_id))
        assert (await owner.get(f"/api/v1/runs/{run_id}")).json()["status"] == "succeeded"
        records = (await owner.get(f"/api/v1/datasets/{dataset_id}/records")).json()["items"]
        assert [(r["record_key"], r["data"]["title"]) for r in records] == [("X-1", "Crate")]

    async def test_items_holding_braces_in_their_text_are_accepted(
        self, api: httpx2.AsyncClient, internal_api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        org_id, run_id, _ = await _website_run(owner)
        deps, dispatcher = _deps(container)
        await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
        headers = {"X-Sandbox-Ticket": dispatcher.sent[0][1]["ticket"]}
        cap = container.settings.scraping.max_items_per_run * 4 + 16  # objects in a result
        # Flat items whose text holds more "{" than the result may hold objects.
        items = [{"sku": f"S-{n}", "title": "{" * 40} for n in range(cap // 40 + 1)]
        accepted = await internal_api.post(
            _result_url(org_id, run_id), json={"items": items}, headers=headers
        )
        assert accepted.status_code == 202, accepted.text

        owner = await signup(api)
        org_id, run_id, _ = await _website_run(owner)
        await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
        headers = {"X-Sandbox-Ticket": dispatcher.sent[-1][1]["ticket"]}
        objects = {"items": [{"sku": "S-1"}], "detail": {"pad": [{} for _ in range(cap)]}}
        refused = await internal_api.post(
            _result_url(org_id, run_id), json=objects, headers=headers
        )
        assert (refused.status_code, refused.json()["error"]) == (422, "invalid_result")

    async def test_a_non_finite_number_never_leaves_the_sandbox(
        self, api: httpx2.AsyncClient, internal_app: FastAPI, container: Container
    ) -> None:
        owner = await signup(api)
        org_id, run_id, _ = await _website_run(owner)
        deps, dispatcher = _deps(container)
        await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
        sandbox = _sandbox(internal_app)
        try:
            with pytest.raises(PermanentError) as refused:
                await sandbox.gateway.submit(
                    org_id,
                    run_id,
                    ticket=dispatcher.sent[0][1]["ticket"],
                    items=[{"sku": math.inf}],
                )
        finally:
            await sandbox.aclose()
        assert refused.value.code == "invalid_result"  # reported as the run's failure

    async def test_upload_is_parsed_by_the_sandbox_via_its_ticket(
        self,
        api: httpx2.AsyncClient,
        internal_api: httpx2.AsyncClient,
        internal_app: FastAPI,
        container: Container,
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, UPLOAD_CONFIG)
        csv_bytes = (
            b"SKU,Title,Price,Email\r\nB-1,Bolt,1.25,a@example.com\r\nB-2,Nut,0.5,b@example.com\r\n"
        )
        uploaded = await owner.post(
            f"/api/v1/sources/{source_id}/uploads",
            files={"file": ("parts.csv", csv_bytes, "text/csv")},
        )
        assert uploaded.status_code == 201, uploaded.text
        org_id, run_id = await org_id_of(owner), UUID(uploaded.json()["run_id"])
        deps, dispatcher = _deps(container)

        await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
        [(task, kwargs, _)] = dispatcher.sent
        assert task == SANDBOX_UPLOAD_TASK

        denied = await internal_api.get(
            f"/internal/v1/sandbox/orgs/{org_id}/runs/{run_id}/input",
            headers={"X-Sandbox-Ticket": "f" * 64},
        )
        assert denied.status_code == 401

        sandbox = build_sandbox(SandboxSettings())
        sandbox.gateway = SandboxGatewayClient(
            "http://testserver",
            timeout_seconds=10,
            transport=httpx2.ASGITransport(app=internal_app),
        )
        sandbox.closers.append(sandbox.gateway.aclose)
        try:
            await parse_uploaded_file(sandbox, UploadJob.model_validate(kwargs))
        finally:
            await sandbox.aclose()

        await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
        records = (await owner.get(f"/api/v1/datasets/{dataset_id}/records")).json()["items"]
        assert {r["record_key"] for r in records} == {"B-1", "B-2"}
        upload = (await owner.get(f"/api/v1/sources/{source_id}/uploads")).json()["items"][0]
        assert (upload["status"], upload["row_count"]) == ("processed", 2)


REST_CONFIG = {
    "kind": "rest_api",
    "url": "https://api.example.com/items",
    "items_path": "items",
    "field_mapping": {"sku": "sku", "title": "title"},
}


class TestRestApiRuns:
    async def test_an_unexpected_error_hands_the_run_back_to_the_task_retry(
        self, api: httpx2.AsyncClient, container: Container, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        owner = await signup(api)
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, REST_CONFIG)
        run = await owner.post(f"/api/v1/sources/{source_id}/runs")
        assert run.status_code == 202, run.text
        run_path = f"/api/v1/runs/{run.json()['id']}"
        message = RunMessage(org_id=await org_id_of(owner), run_id=UUID(run.json()["id"]))
        deps, _ = _deps(container)

        async def broken(*args: Any, **kwargs: Any) -> Any:
            raise ValueError("a bug, or a library error that nobody mapped")

        monkeypatch.setattr(container.rest_collector, "collect", broken)
        with pytest.raises(ValueError):  # the task logs it and retries
            await collect_rest_api(deps, message)
        assert (await owner.get(run_path)).json()["status"] == "queued"  # not left RUNNING

        async def working(*args: Any, **kwargs: Any) -> Any:
            items = [{"sku": "R-1", "title": "Relay"}]
            return SimpleNamespace(items=items, truncated=False, detail={})

        monkeypatch.setattr(container.rest_collector, "collect", working)
        await collect_rest_api(deps, message)  # the task's retry starts the run again
        finished = (await owner.get(run_path)).json()
        assert (finished["status"], finished["attempt"]) == ("succeeded", 2)


class _Spy:
    """Records calls instead of doing the work (what matters is *whether*)."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        # Quacks like every outcome the handlers inspect afterwards.
        return SimpleNamespace(usage={}, changes_created=0, max_significance=None)


class TestAutomationPauses:
    """Internal orchestration honours the kill switch and tenant freezes too."""

    @pytest.fixture
    def spies(self, container: Container, monkeypatch: pytest.MonkeyPatch) -> dict[str, _Spy]:
        targets = {
            "dispatch_due": container.automation,
            "sweep_detection": container.automation,
            "detect": container.detection,
            "analyze": container.intelligence,
            "mark_failed": container.intelligence,
            "evaluate_changes": container.alerts,
        }
        spies = {name: _Spy() for name in targets}
        for name, owner in targets.items():
            monkeypatch.setattr(owner, name, spies[name])
        return spies

    async def _run_everything(self, container: Container, org_id: UUID) -> None:
        deps, _ = _deps(container)
        await dispatch_due_workflows(deps, Empty())
        await sweep_detection(deps, Empty())
        await detect_changes(deps, DatasetMessage(org_id=org_id, dataset_id=uuid4()))
        await evaluate_alerts(deps, OrgMessage(org_id=org_id))
        await analyze_changes(deps, InsightMessage(org_id=org_id, insight_id=uuid4()))

    async def test_the_global_kill_switch_stops_all_automated_work(
        self, api: httpx2.AsyncClient, container: Container, spies: dict[str, _Spy]
    ) -> None:
        assert container.settings.n8n.orchestration == "internal"
        org_id = await org_id_of(await signup(api))
        await container.flags.set(FeatureFlags.AUTOMATION_KILL_SWITCH, enabled=True)
        try:
            await self._run_everything(container, org_id)
        finally:
            await container.flags.set(FeatureFlags.AUTOMATION_KILL_SWITCH, enabled=False)
        worked = {name for name, spy in spies.items() if spy.calls and name != "mark_failed"}
        assert worked == set()
        # A queued analysis is closed out - never sent to the AI provider.
        assert [call["code"] for call in spies["mark_failed"].calls] == ["automation_disabled"]

        await self._run_everything(container, org_id)  # released: everything runs again
        assert all(spies[name].calls for name in spies if name != "mark_failed")

    async def test_a_frozen_tenant_is_skipped_while_others_keep_running(
        self, api: httpx2.AsyncClient, container: Container, spies: dict[str, _Spy]
    ) -> None:
        owner = await signup(api)
        frozen = await owner.post(
            "/api/v1/organizations/current/automation-freeze",
            json={"frozen": True, "reason": "incident drill"},
        )
        assert frozen.status_code == 200, frozen.text
        deps, _ = _deps(container)
        org_id = await org_id_of(owner)
        await detect_changes(deps, DatasetMessage(org_id=org_id, dataset_id=uuid4()))
        await evaluate_alerts(deps, OrgMessage(org_id=org_id))
        await analyze_changes(deps, InsightMessage(org_id=org_id, insight_id=uuid4()))
        assert not (spies["detect"].calls or spies["evaluate_changes"].calls)
        assert not spies["analyze"].calls
        assert [call["code"] for call in spies["mark_failed"].calls] == ["automation_frozen"]

        other = await org_id_of(await signup(api))
        await evaluate_alerts(deps, OrgMessage(org_id=other))
        assert [call["org_id"] for call in spies["evaluate_changes"].calls] == [other]

    async def test_domain_events_have_no_consequences_while_paused(
        self,
        api: httpx2.AsyncClient,
        container: Container,
        spies: dict[str, _Spy],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        requested = _Spy()  # AI analysis requests raised by changes.detected
        monkeypatch.setattr(container.intelligence, "request_automatic", requested)
        owner = await signup(api)
        org_id = await org_id_of(owner)
        events = [
            EventMessage.model_validate(
                {
                    "event": "collection.completed",
                    "org_id": str(org_id),
                    "run_id": str(uuid4()),
                    "source_id": str(uuid4()),
                    "dataset_id": str(uuid4()),
                    "status": "succeeded",
                    "workflow_run_id": None,
                }
            ),
            EventMessage.model_validate(
                {
                    "event": "changes.detected",
                    "org_id": str(org_id),
                    "dataset_id": str(uuid4()),
                    "changes": 3,
                    "max_significance": "high",
                    "analyze": True,
                }
            ),
        ]
        deps, _ = _deps(container)

        await container.flags.set(FeatureFlags.AUTOMATION_KILL_SWITCH, enabled=True)
        try:
            for event in events:
                await route_event(deps, event)
        finally:
            await container.flags.set(FeatureFlags.AUTOMATION_KILL_SWITCH, enabled=False)
        frozen = await owner.post(
            "/api/v1/organizations/current/automation-freeze",
            json={"frozen": True, "reason": "incident drill"},
        )
        assert frozen.status_code == 200, frozen.text
        for event in events:
            await route_event(deps, event)

        consequences = (spies["detect"], spies["evaluate_changes"], requested)
        assert not any(spy.calls for spy in consequences)


class TestEventRouting:
    async def _ingested_webhook(
        self, owner: ApiSession, container: Container, api: httpx2.AsyncClient
    ) -> tuple[UUID, str, str, UUID]:
        project_id = await create_project(owner)
        dataset_id = await create_dataset(owner, project_id)
        source_id = await create_source(owner, project_id, dataset_id, WEBHOOK_CONFIG)
        endpoint = (
            await owner.post(
                "/api/v1/webhook-endpoints", json={"source_id": source_id, "name": "e"}
            )
        ).json()
        body = json.dumps({"items": [{"sku": "C-1", "title": "Cable", "price": "4"}]}).encode()
        delivery = f"dlv-{uuid4().hex}"
        headers = {
            "Content-Type": "application/json",
            "X-NexusFlow-Delivery": delivery,
            "X-NexusFlow-Signature": build_signature_header(
                endpoint["secret"].encode(),
                timestamp=int(time.time()),
                delivery_id=delivery,
                body=body,
            ),
        }
        path = endpoint["url"].removeprefix("https://nexusflow.test.example")
        accepted = await api.post(path, content=body, headers=headers)
        assert accepted.status_code == 202, accepted.text
        org_id = await org_id_of(owner)
        run_id = UUID(accepted.json()["run_id"])
        deps, _ = _deps(container)
        await collect_dispatch(deps, RunMessage(org_id=org_id, run_id=run_id))
        return org_id, project_id, dataset_id, run_id

    async def test_internal_orchestration_detects_and_alerts(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        org_id, project_id, dataset_id, run_id = await self._ingested_webhook(owner, container, api)
        rule = await owner.post(
            "/api/v1/alert-rules",
            json={
                "project_id": project_id,
                "dataset_id": dataset_id,
                "name": "New products",
                "condition": {"type": "change_type", "change_types": ["created"]},
            },
        )
        assert rule.status_code == 201, rule.text
        deps, _ = _deps(container)
        completed = EventMessage.model_validate(
            {
                "event": "collection.completed",
                "org_id": str(org_id),
                "run_id": str(run_id),
                "source_id": str(uuid4()),
                "dataset_id": dataset_id,
                "status": "succeeded",
                "workflow_run_id": None,
            }
        )
        await route_event(deps, completed)
        changes = (await owner.get("/api/v1/changes", params={"dataset_id": dataset_id})).json()[
            "items"
        ]
        assert [c["change_type"] for c in changes] == ["created"]

        detected = EventMessage.model_validate(
            {
                "event": "changes.detected",
                "org_id": str(org_id),
                "dataset_id": dataset_id,
                "changes": 1,
                "max_significance": "low",
                "analyze": False,
            }
        )
        await route_event(deps, detected)
        await route_event(deps, detected)  # redelivery: alerts are de-duplicated
        alerts = (await owner.get("/api/v1/alerts")).json()["items"]
        assert len(alerts) == 1
        assert alerts[0]["title"].startswith("[WARNING] New products")

    async def test_failed_runs_raise_run_failed_alerts(
        self, api: httpx2.AsyncClient, container: Container
    ) -> None:
        owner = await signup(api)
        org_id, run_id, dataset_id = await _website_run(owner)
        project_id = (await owner.get(f"/api/v1/datasets/{dataset_id}")).json()["project_id"]
        await owner.post(
            "/api/v1/alert-rules",
            json={
                "project_id": project_id,
                "name": "Broken sources",
                "condition": {"type": "run_failed"},
                "severity": "critical",
            },
        )
        await container.ingestion.fail_run(
            org_id=org_id, run_id=run_id, code="http_404", detail=None
        )
        deps, _ = _deps(container)
        await route_event(
            deps,
            EventMessage.model_validate(
                {
                    "event": "collection.completed",
                    "org_id": str(org_id),
                    "run_id": str(run_id),
                    "source_id": str(uuid4()),
                    "dataset_id": dataset_id,
                    "status": "failed",
                    "workflow_run_id": None,
                }
            ),
        )
        alerts = (await owner.get("/api/v1/alerts")).json()["items"]
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "critical"
        assert "http_404" in alerts[0]["body"]

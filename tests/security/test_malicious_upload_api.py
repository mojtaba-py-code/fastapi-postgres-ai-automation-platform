"""Hostile uploads through the real API (real app, real PostgreSQL, fake Redis).

``POST /api/v1/sources/{id}/uploads`` must refuse every hostile file *at intake*
with its ``upload_*`` code and leave nothing behind: no stored bytes (not even
a temporary part), no upload record, no queued run - only an ``upload.rejected``
audit entry naming the reason. The declared file name and MIME type are never
trusted, the size cap holds while streaming, and a configured malware scanner
is authoritative (fail closed). Hostile archives are built in
``tests.security.hostile_files``; no real malware is used.
"""

from __future__ import annotations

import asyncio
import codecs
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import httpx2
import pytest
from fastapi import FastAPI

from nexusflow.apps.workers.handlers import WorkerDeps, collect_dispatch
from nexusflow.apps.workers.messages import RunMessage
from nexusflow.apps.workers.sandbox import UploadJob, parse_uploaded_file
from nexusflow.bootstrap.container import Container
from nexusflow.bootstrap.sandbox import build_sandbox
from nexusflow.core.config import SandboxSettings
from nexusflow.core.errors import ServiceUnavailableError
from nexusflow.domain.shared.ports import ScanVerdict
from nexusflow.infrastructure.sandbox.gateway import SandboxGatewayClient
from tests.security.hostile_files import (
    MARKER,
    cfb_document,
    csv_bytes,
    empty_file,
    encrypted_sheet,
    ratio_bomb,
    too_many_entries,
    total_size_bomb,
    truncated_workbook,
    vba_project,
    with_member,
    workbook,
)
from tests.support.api import ApiSession, signup
from tests.support.business import (
    UPLOAD_CONFIG,
    create_dataset,
    create_project,
    create_source,
    expect_error,
    org_id_of,
)

pytestmark = [pytest.mark.security, pytest.mark.integration]

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
XLSX_CONFIG = {**UPLOAD_CONFIG, "format": "xlsx"}
CSV_ROW = b"SKU,Title,Price,Email\r\nA-1,Widget,9.99,a@b.example\r\n"
RLO, ZWSP = chr(0x202E), chr(0x200B)  # right-to-left override, zero-width space


@dataclass
class UploadTarget:
    owner: ApiSession
    source_id: str
    org_id: UUID

    @property
    def url(self) -> str:
        return f"/api/v1/sources/{self.source_id}/uploads"

    async def upload(
        self, data: bytes, *, filename: str = "prices.csv", content_type: str = "text/csv"
    ) -> httpx2.Response:
        return await self.owner.post(self.url, files={"file": (filename, data, content_type)})

    async def workbook(self, data: bytes) -> httpx2.Response:
        return await self.upload(data, filename="prices.xlsx", content_type=XLSX_MIME)


@dataclass
class FakeScanner:
    """Stands in for clamd: "detects" the harmless MARKER, or is unreachable."""

    down: bool = False
    scanned: list[bytes] = field(default_factory=list)

    async def scan(self, path: Path) -> ScanVerdict:
        data = await asyncio.to_thread(path.read_bytes)
        self.scanned.append(data)
        if self.down:
            raise ServiceUnavailableError(internal_detail="clamd unavailable: test outage")
        if MARKER in data:
            return ScanVerdict(clean=False, signature="NexusFlow.Test.Marker")
        return ScanVerdict(clean=True)


class RecordingDispatcher:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any], str]] = []

    def send_task(self, name: str, *, kwargs: dict[str, Any], queue: str) -> None:
        self.sent.append((name, kwargs, queue))


async def _target(api: httpx2.AsyncClient, config: dict[str, Any]) -> UploadTarget:
    owner = await signup(api)
    project_id = await create_project(owner)
    dataset_id = await create_dataset(owner, project_id)
    source_id = await create_source(owner, project_id, dataset_id, config)
    return UploadTarget(owner, source_id, await org_id_of(owner))


@pytest.fixture
async def csv_target(api: httpx2.AsyncClient) -> UploadTarget:
    return await _target(api, UPLOAD_CONFIG)


@pytest.fixture
async def xlsx_target(api: httpx2.AsyncClient) -> UploadTarget:
    return await _target(api, XLSX_CONFIG)


@pytest.fixture
def scanner(container: Container, monkeypatch: pytest.MonkeyPatch) -> FakeScanner:
    fake = FakeScanner()
    monkeypatch.setattr(container.uploads, "_scanner", fake)
    return fake


def _stored(container: Container, org_id: UUID) -> list[str]:
    """Every file in the tenant's upload directory, temporary ``.part`` files included."""
    directory = container.storage.local_path(f"uploads/{org_id}/{uuid4()}.csv").parent
    return sorted(p.name for p in directory.iterdir()) if directory.exists() else []


async def _assert_nothing_left(
    target: UploadTarget, container: Container, rejected: str | None
) -> None:
    assert _stored(container, target.org_id) == []
    assert (await target.owner.get(target.url)).json()["items"] == []
    runs = await target.owner.get(f"/api/v1/sources/{target.source_id}/runs")
    assert runs.json()["items"] == []
    audit = await target.owner.get("/api/v1/audit", params={"action": "upload.rejected"})
    reasons = [entry["metadata"]["reason"] for entry in audit.json()["items"]]
    assert reasons == ([rejected] if rejected else [])


class TestHostileWorkbooks:
    @pytest.mark.parametrize(
        ("build", "code"),
        [
            pytest.param(ratio_bomb, "upload_zip_bomb", id="1000-to-1-member"),
            pytest.param(total_size_bomb, "upload_zip_bomb", id="over-200-MiB-in-total"),
            pytest.param(too_many_entries, "upload_too_many_entries", id="entry-flood"),
            pytest.param(encrypted_sheet, "upload_encrypted", id="encrypted-member"),
            pytest.param(vba_project, "upload_macro", id="vba-project"),
            pytest.param(
                lambda: with_member("..\\..\\..\\etc\\cron.d\\evil"),
                "upload_path_traversal",
                id="traversal-member",
            ),
            pytest.param(cfb_document, "upload_type_mismatch", id="ole-document"),
            pytest.param(csv_bytes, "upload_type_mismatch", id="csv-text"),
            pytest.param(truncated_workbook, "upload_corrupt", id="truncated"),
            pytest.param(empty_file, "upload_type_mismatch", id="empty"),
        ],
    )
    async def test_hostile_workbooks_are_refused_at_intake_leaving_nothing_behind(
        self,
        xlsx_target: UploadTarget,
        container: Container,
        scanner: FakeScanner,
        build: Callable[[], bytes],
        code: str,
    ) -> None:
        expect_error(await xlsx_target.workbook(build()), 422, code)
        await _assert_nothing_left(xlsx_target, container, code)
        assert scanner.scanned == []  # hostile archives never even reach the scanner

    async def test_a_genuine_workbook_is_accepted(
        self, xlsx_target: UploadTarget, scanner: FakeScanner
    ) -> None:
        # The control for the table above: the same route takes a real workbook.
        data = workbook()
        accepted = await xlsx_target.workbook(data)
        assert accepted.status_code == 201, accepted.text
        assert accepted.json()["content_type"] == XLSX_MIME
        assert scanner.scanned == [data]


class TestHostileCsv:
    @pytest.mark.parametrize(
        ("data", "code"),
        [
            pytest.param(b"SKU,Title\r\nA-1,\x00x\r\n", "upload_binary", id="nul-byte"),
            pytest.param(cfb_document(), "upload_binary", id="ole-document"),
            pytest.param(b"SKU,Title\r\nA-1,caf\xe9\r\n", "upload_encoding", id="latin-1"),
            pytest.param(b"SKU,Title\r\nA-1,\xed\xa0\x80\r\n", "upload_encoding", id="surrogate"),
            pytest.param(b"\x7fELF\x02\x01\x01\x00", "upload_type_mismatch", id="elf"),
            pytest.param(b"%PDF-1.7\n", "upload_type_mismatch", id="pdf"),
            pytest.param(workbook(), "upload_type_mismatch", id="xlsx-workbook"),
        ],
    )
    async def test_hostile_csv_files_are_refused_at_intake_leaving_nothing_behind(
        self, csv_target: UploadTarget, container: Container, data: bytes, code: str
    ) -> None:
        expect_error(await csv_target.upload(data), 422, code)
        await _assert_nothing_left(csv_target, container, code)

    async def test_a_utf8_bom_is_accepted_and_stored_byte_for_byte(
        self, csv_target: UploadTarget, container: Container
    ) -> None:
        data = b"\xef\xbb\xbf" + CSV_ROW
        accepted = await csv_target.upload(data)
        assert accepted.status_code == 201, accepted.text
        upload = accepted.json()
        assert (upload["size_bytes"], upload["sha256"]) == (
            len(data),
            hashlib.sha256(data).hexdigest(),
        )
        assert _stored(container, csv_target.org_id) == [f"{upload['id']}.csv"]


class TestDeclaredTypeIsNeverTrusted:
    async def test_a_workbook_declared_as_csv_is_refused(
        self, csv_target: UploadTarget, container: Container
    ) -> None:
        response = await csv_target.upload(workbook(), filename="prices.csv")
        expect_error(response, 422, "upload_type_mismatch")
        await _assert_nothing_left(csv_target, container, "upload_type_mismatch")

    async def test_csv_text_declared_as_a_workbook_is_refused(
        self, xlsx_target: UploadTarget, container: Container
    ) -> None:
        expect_error(await xlsx_target.workbook(CSV_ROW), 422, "upload_type_mismatch")
        await _assert_nothing_left(xlsx_target, container, "upload_type_mismatch")

    async def test_the_content_decides_not_the_declared_name_or_mime_type(
        self, csv_target: UploadTarget, container: Container
    ) -> None:
        accepted = await csv_target.upload(
            CSV_ROW, filename="invoice.pdf.exe", content_type="application/x-msdownload"
        )
        assert accepted.status_code == 201, accepted.text
        upload = accepted.json()
        # Stored under a server-generated key in the source's format; the client's
        # name is kept for display only and its MIME type is discarded.
        assert upload["content_type"] == "text/csv"
        assert upload["original_filename"] == "invoice.pdf.exe"
        assert _stored(container, csv_target.org_id) == [f"{upload['id']}.csv"]

    async def test_hostile_file_names_are_only_ever_displayed_sanitised(
        self, csv_target: UploadTarget, container: Container
    ) -> None:
        # A traversal prefix, an over-long name, a right-to-left override that would
        # display "...csv.png" as "...gnp.csv", and a zero-width space.
        name = "..\\..\\" + "a" * 300 + RLO + "gnp.csv" + ZWSP
        accepted = await csv_target.upload(CSV_ROW, filename=name)
        assert accepted.status_code == 201, accepted.text
        shown = accepted.json()["original_filename"]
        assert len(shown) <= 200
        assert not {"/", "\\", RLO, ZWSP} & set(shown)
        assert _stored(container, csv_target.org_id) == [f"{accepted.json()['id']}.csv"]

    async def test_a_text_part_named_file_is_not_a_file(
        self, csv_target: UploadTarget, container: Container
    ) -> None:
        # A multipart part without a filename is a plain form field, not an UploadFile.
        response = await csv_target.owner.post(csv_target.url, files={"file": (None, CSV_ROW)})
        expect_error(response, 422, "file_required")
        await _assert_nothing_left(csv_target, container, None)


class TestSizeAndEmptiness:
    async def test_one_byte_over_the_cap_is_refused_while_streaming(
        self, csv_target: UploadTarget, container: Container
    ) -> None:
        cap = container.settings.storage.max_upload_bytes
        body = CSV_ROW + b"B-2,Bolt,1.00,b@b.example\r\n" * (cap // 27 + 1)
        oversized = body[: cap + 1]
        assert len(oversized) == cap + 1  # inside the route's body limit (cap + 64 KiB)
        expect_error(await csv_target.upload(oversized), 413, "payload_too_large")
        await _assert_nothing_left(csv_target, container, None)

    async def test_an_empty_csv_is_refused_at_intake(self, csv_target: UploadTarget) -> None:
        expect_error(await csv_target.upload(b""), 422, "upload_empty")

    async def test_a_csv_without_rows_is_refused_by_the_sandbox_parser(
        self,
        csv_target: UploadTarget,
        container: Container,
        internal_app: FastAPI,
    ) -> None:
        # A byte-order mark alone is valid UTF-8 text, so intake accepts the file;
        # the sandbox parser is what refuses it - no record is ever written.
        accepted = await csv_target.upload(codecs.BOM_UTF8)
        assert accepted.status_code == 201, accepted.text
        run_id = UUID(accepted.json()["run_id"])
        dispatcher = RecordingDispatcher()
        deps = WorkerDeps(container=container, dispatcher=cast(Any, dispatcher))
        await collect_dispatch(deps, RunMessage(org_id=csv_target.org_id, run_id=run_id))
        [(_, kwargs, _)] = dispatcher.sent

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

        run = (await csv_target.owner.get(f"/api/v1/runs/{run_id}")).json()
        assert (run["status"], run["error_code"]) == ("failed", "upload_empty")
        [upload] = (await csv_target.owner.get(csv_target.url)).json()["items"]
        assert (upload["status"], upload["rejection_reason"]) == ("failed", "upload_empty")


class TestMalwareScanning:
    async def test_a_file_the_scanner_flags_is_refused_and_never_stored(
        self, csv_target: UploadTarget, container: Container, scanner: FakeScanner
    ) -> None:
        infected = CSV_ROW + b"B-2," + MARKER + b",1.00,b@b.example\r\n"
        expect_error(await csv_target.upload(infected), 422, "upload_malware")
        assert scanner.scanned == [infected]  # the scanner saw exactly the uploaded bytes
        await _assert_nothing_left(csv_target, container, "upload_malware")

    async def test_a_scanner_outage_fails_closed(
        self, csv_target: UploadTarget, container: Container, scanner: FakeScanner
    ) -> None:
        scanner.down = True
        response = await csv_target.upload(CSV_ROW)
        body = expect_error(response, 503, "service_unavailable")
        assert "clamd" not in response.text
        assert body["message"] == "The service is temporarily unavailable."
        await _assert_nothing_left(csv_target, container, None)
        scanner.down = False  # once the scanner is back, the same file goes through
        assert (await csv_target.upload(CSV_ROW)).status_code == 201

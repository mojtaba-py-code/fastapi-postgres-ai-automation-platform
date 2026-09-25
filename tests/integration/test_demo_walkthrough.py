"""The presenter's walkthrough (scripts/demo.py) against the real API over HTTP.

The public API is served by uvicorn on a local port inside the test's event loop,
backed by the embedded PostgreSQL. The worker pools are replaced by the
in-process bus, which runs every committed outbox message the way the workers
would - the sign-up link too: its e-mail is recorded instead of sent, and the
owner "opens" it from there. Only Mailpit, n8n and the network edge (nginx,
TLS) are absent; the end-to-end suite (tests/e2e) covers those against a
running stack.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import re
import socket
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path
from types import ModuleType

import httpx2
import pytest
import uvicorn
from fastapi import FastAPI

from nexusflow.apps.workers import handlers
from nexusflow.bootstrap.container import Container
from tests.support.bus import InProcessBus

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]


def _demo_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("nexusflow_demo", ROOT / "scripts" / "demo.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


@contextlib.asynccontextmanager
async def _serving(app: FastAPI, bus: InProcessBus) -> AsyncIterator[str]:
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, lifespan="off", log_level="warning")
    )
    serving = asyncio.create_task(server.serve())
    stop = asyncio.Event()

    async def workers() -> None:
        while not stop.is_set():
            await bus.work()
            await asyncio.sleep(0.05)

    working = asyncio.create_task(workers())
    try:
        async with asyncio.timeout(10):
            while not server.started:  # noqa: ASYNC110 - uvicorn exposes no startup event
                await asyncio.sleep(0.02)
        yield f"http://localhost:{port}"
    finally:
        stop.set()
        await working
        server.should_exit = True
        await serving


class Inbox:
    """The mail the security e-mail service sends, kept for the test to read."""

    def __init__(self) -> None:
        self.sent: list[tuple[list[str], str, str]] = []

    async def send_email(self, recipients: list[str], subject: str, body: str) -> None:
        self.sent.append((recipients, subject, body))

    def signup_token(self, email: str) -> str:
        """Called from the walkthrough's thread while the bus works in the loop."""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            for recipients, _, body in list(self.sent):
                match = re.search(r"/complete-signup#token=([A-Za-z0-9_-]+)", body)
                if recipients == [email] and match:
                    return match[1]
            time.sleep(0.05)
        raise AssertionError(f"no sign-up e-mail for {email}")


async def test_the_demo_walkthrough_runs_end_to_end(
    api_app: FastAPI,
    container: Container,
    bus: InProcessBus,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await container.redis.flushall()
    inbox = Inbox()
    monkeypatch.setattr(container.security_emails, "_email", inbox)
    monkeypatch.setattr(handlers, "_mail_disabled", lambda deps, kind: False)
    demo = _demo_module()
    narration: list[str] = []
    async with _serving(api_app, bus) as base_url:
        client = httpx2.Client(base_url=base_url, headers={"Host": "testserver"}, timeout=30.0)
        walkthrough = demo.Walkthrough(
            base_url,
            output_dir=tmp_path,
            mailpit_url=None,
            timeout=60,
            echo=narration.append,
            client=client,  # the test app only accepts its own host name
            signup_token=inbox.signup_token,
        )
        result = await asyncio.to_thread(walkthrough.run)

    assert bus.errors == []
    assert result.run_statuses == ["succeeded", "succeeded"]
    second = {c["record_key"]: c for c in demo.second_run(result.changes)}
    assert set(second) == demo.EXPECTED_SECOND_RUN  # NX-103's tracking parameter is not a change
    assert second["NX-102"]["significance"] == "critical"  # +30 % against a 25 % threshold
    assert second["NX-106"]["change_type"] == "created"
    titles = sorted(alert["title"] for alert in result.alerts)
    assert titles == [
        "[CRITICAL] Price up 10 % or more: updated NX-100",
        "[CRITICAL] Price up 10 % or more: updated NX-102",
        "[WARNING] Availability changed: updated NX-104",
    ]
    assert result.insight["status"] == "completed"
    assert result.insight["provider"] == "offline"  # the tenant did not opt in to external AI
    assert result.analytics["totals"]["changes"] == len(result.changes)
    assert result.analytics["totals"]["created"] == 7  # six products, then NX-106
    assert result.reports["pdf"].read_bytes().startswith(b"%PDF")
    assert result.reports["xlsx"].read_bytes().startswith(b"PK")
    assert result.audit_ok and result.audit_checked > 0
    assert {
        "dataset.created",
        "webhook.endpoint_created",
        "alert_rule.created",
        "report.requested",
        "report.downloaded",
    } <= set(result.audit_actions)
    assert result.emails is None  # no Mailpit here
    assert any("hash chain: intact" in line for line in narration)
    assert (
        "     last 30 days: 11 changes (7 new, 4 updated, 0 removed); "
        "All detected changes fall in the second half of the period."
    ) in narration

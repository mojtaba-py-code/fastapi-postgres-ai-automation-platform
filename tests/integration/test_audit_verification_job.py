"""The daily job verifies every audit chain; an edited history pages the operators."""

from __future__ import annotations

from typing import Any, cast

import asyncpg
import pytest
from prometheus_client import REGISTRY

from nexusflow.apps.workers import messages as m
from nexusflow.apps.workers.handlers import WorkerDeps, verify_audit_chains
from nexusflow.bootstrap.container import Container
from tests.support.fixtures import register

pytestmark = pytest.mark.integration


def _broken_count() -> float:
    labels = {"result": "broken"}
    return REGISTRY.get_sample_value("nexusflow_audit_chain_verifications_total", labels) or 0.0


class _Pages:
    def __init__(self) -> None:
        self.summaries: list[str] = []

    async def __call__(self, *, severity: str, summary: str) -> bool:
        assert severity == "critical"
        self.summaries.append(summary)
        return True


async def test_an_edited_audit_history_is_found_counted_and_paged(
    container: Container, admin_conn: asyncpg.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    await register(container)
    org_id = await admin_conn.fetchval(
        "SELECT org_id FROM audit_logs WHERE org_id IS NOT NULL ORDER BY occurred_at DESC LIMIT 1"
    )
    pages = _Pages()
    monkeypatch.setattr(container.automation, "page_operators", pages)

    async def only_this_tenant() -> list[Any]:
        return [org_id]  # other tests leave their own edited chains behind

    monkeypatch.setattr(container.maintenance, "tenants", only_this_tenant)
    deps = WorkerDeps(container=container, dispatcher=cast(Any, None))

    # Someone with superuser access edits history, trigger disabled.
    await admin_conn.execute("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only")
    try:
        await admin_conn.execute(
            "UPDATE audit_logs SET ip = '198.51.100.99' WHERE org_id = $1 AND seq = 1", org_id
        )
    finally:
        await admin_conn.execute("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_append_only")

    before = _broken_count()
    await verify_audit_chains(deps, m.Empty())

    assert _broken_count() > before
    [summary] = pages.summaries
    assert str(org_id) in summary  # the page names the chain to investigate
    assert "INCIDENT_RESPONSE.md" in summary

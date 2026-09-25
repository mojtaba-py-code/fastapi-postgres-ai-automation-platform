"""Operator CLI commands against the real database."""

from __future__ import annotations

from uuid import uuid4

import httpx2
import pytest

from nexusflow.apps.cli.main import build_parser
from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import AuthenticationError
from tests.support.api import signup
from tests.support.fixtures import META

pytestmark = pytest.mark.integration


async def _run(container: Container, *argv: str) -> dict[str, object]:
    args = build_parser().parse_args(argv)
    result: dict[str, object] = await args.handler(container, args)
    return result


async def test_service_account_lifecycle(
    container: Container, internal_api: httpx2.AsyncClient
) -> None:
    key = f"wf-{uuid4().hex[:8]}"
    created = await _run(
        container,
        "service-account",
        "create",
        "--name",
        key,
        "--workflow-key",
        key,
        "--scope",
        "automation:detect",
    )
    token = str(created["token"])
    assert token.startswith("nxs_")
    headers = {"Authorization": f"Bearer {token}"}
    sweep = await internal_api.post(
        "/internal/v1/automation/detect/sweep", json={}, headers=headers
    )
    assert sweep.status_code == 200, sweep.text

    rotated = await _run(container, "service-account", "rotate", "--workflow-key", key)
    stale = await internal_api.post(
        "/internal/v1/automation/detect/sweep", json={}, headers=headers
    )
    assert stale.status_code == 401  # the old token died with the rotation
    headers = {"Authorization": f"Bearer {rotated['token']}"}

    await _run(
        container,
        "service-account",
        "disable",
        "--workflow-key",
        key,
        "--reason",
        "compromise drill",
    )
    disabled = await internal_api.post(
        "/internal/v1/automation/detect/sweep", json={}, headers=headers
    )
    assert disabled.status_code == 403
    listed = await _run(container, "service-account", "list")
    assert any(a["workflow_key"] == key and not a["enabled"] for a in listed["service_accounts"])  # type: ignore[index, union-attr]


async def test_kill_switch_commands(container: Container, internal_api: httpx2.AsyncClient) -> None:
    key = f"wf-{uuid4().hex[:8]}"
    created = await _run(
        container,
        "service-account",
        "create",
        "--name",
        key,
        "--workflow-key",
        key,
        "--scope",
        "automation:detect",
    )
    headers = {"Authorization": f"Bearer {created['token']}"}
    assert (await _run(container, "kill-switch", "engage", "--reason", "incident 42")) == {
        "ok": True,
        "kill_switch": "engaged",
        "n8n_workflows_deactivated": [],
    }
    try:
        assert (await _run(container, "kill-switch", "status"))["kill_switch"] == "engaged"
        blocked = await internal_api.post(
            "/internal/v1/automation/detect/sweep", json={}, headers=headers
        )
        assert blocked.status_code == 503
    finally:
        await _run(container, "kill-switch", "release", "--reason", "resolved")
    assert (await _run(container, "kill-switch", "status"))["kill_switch"] == "released"


async def test_kill_switch_engages_even_when_n8n_cannot_be_reached(container: Container) -> None:
    assert container.n8n is None  # the test stack has no n8n
    try:
        result = await _run(
            container, "kill-switch", "engage", "--reason", "drill", "--deactivate-n8n", "wf1"
        )
        # The switch itself is on, and the failed part is reported, not swallowed.
        assert result == {
            "ok": False,
            "kill_switch": "engaged",
            "n8n_workflows_deactivated": [],
            "n8n_workflows_failed": {"wf1": "n8n_not_configured"},
        }
        assert (await _run(container, "kill-switch", "status"))["kill_switch"] == "engaged"
    finally:
        await _run(container, "kill-switch", "release", "--reason", "drill over")


async def test_rewrap_and_audit_verification(container: Container, api: httpx2.AsyncClient) -> None:
    owner = await signup(api)
    created = await owner.post(
        "/api/v1/integrations",
        json={"name": "crm", "kind": "http_bearer", "secret": "s3cr3t-token-value"},
    )
    assert created.status_code == 201, created.text
    org_id = (await owner.get("/api/v1/organizations/current")).json()["id"]
    rewrap = await _run(container, "keys", "rewrap")
    assert rewrap["active_key_id"] == container.settings.security.encryption_active_key_id
    verified = await _run(container, "audit", "verify", "--org", org_id)
    assert verified["ok"] is True


async def test_audit_verification_covers_the_platform_chain(container: Container) -> None:
    with pytest.raises(AuthenticationError):  # an event without a tenant
        await container.auth.login(
            email="nobody@example.com", password="not-the-password", org_id=None, meta=META
        )
    verified = await _run(container, "audit", "verify")
    [platform] = [chain for chain in verified["chains"] if chain["chain"] == "platform"]
    assert platform["ok"] is True
    assert platform["checked"] >= 1

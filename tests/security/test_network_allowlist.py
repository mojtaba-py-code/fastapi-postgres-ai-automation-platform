"""An organization's network allowlist, end to end.

Members' sessions and API keys reach the organization only from its listed
networks; a valid credential used from elsewhere is refused, and the
organization's audit trail shows it. Administrators cannot lock themselves
out, and operators can lift a list that locked an organization out anyway.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from uuid import uuid4

import httpx2
import pytest
from fastapi import FastAPI

from nexusflow.apps.cli.main import build_parser
from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import InvalidInputError, NotFoundError
from tests.support.api import ApiSession, signup
from tests.support.business import expect_error, org_id_of, viewer_key
from tests.support.fixtures import PASSWORD

pytestmark = [pytest.mark.security, pytest.mark.integration]

OFFICE = "203.0.113.10"
OFFICE_NETWORK = "203.0.113.0/24"
HOME = "198.51.100.20"
SETTINGS = "/api/v1/organizations/current"


async def _client(app: FastAPI, ip: str) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, client=(ip, 40_000)), base_url="http://testserver"
    )


@pytest.fixture
async def office(api_app: FastAPI, container: Container) -> AsyncIterator[httpx2.AsyncClient]:
    await container.redis.flushall()
    async with await _client(api_app, OFFICE) as client:
        yield client


@pytest.fixture
async def home(api_app: FastAPI) -> AsyncIterator[httpx2.AsyncClient]:
    async with await _client(api_app, HOME) as client:
        yield client


def _from(client: httpx2.AsyncClient, session: ApiSession) -> ApiSession:
    """The same credentials, used from another network."""
    return ApiSession(client, session.access_token, session.refresh_token, session.email)


async def _restrict(owner: ApiSession, *networks: str) -> httpx2.Response:
    """Set the organization's allowlist; no networks lifts it."""
    ranges = list(networks) or None
    return await owner.patch(SETTINGS, json={"settings": {"allowed_ip_ranges": ranges}})


async def _audit(owner: ApiSession, action: str) -> list[dict[str, Any]]:
    response = await owner.get("/api/v1/audit", params={"action": action})
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


async def test_members_and_api_keys_reach_the_organization_only_from_its_networks(
    office: httpx2.AsyncClient, home: httpx2.AsyncClient
) -> None:
    owner = await signup(office)
    key = await viewer_key(owner, ["projects:read"])

    applied = await _restrict(owner, "2001:db8::/32", OFFICE_NETWORK)
    assert applied.status_code == 200, applied.text
    assert applied.json()["settings"]["allowed_ip_ranges"] == [OFFICE_NETWORK, "2001:db8::/32"]

    away = _from(home, owner)
    expect_error(await away.get(SETTINGS), 403, "ip_not_allowed")
    expect_error(await away.get("/api/v1/projects"), 403, "ip_not_allowed")
    expect_error(await home.get("/api/v1/projects", headers=key), 403, "ip_not_allowed")
    # Claiming to be in the office is not enough: X-Forwarded-For is believed
    # only from a trusted proxy, and none is configured here.
    spoofed = {**key, "X-Forwarded-For": OFFICE}
    expect_error(await home.get("/api/v1/projects", headers=spoofed), 403, "ip_not_allowed")

    assert (await owner.get(SETTINGS)).status_code == 200
    assert (await office.get("/api/v1/projects", headers=key)).status_code == 200


async def test_an_administrator_cannot_lock_the_organization_out(
    office: httpx2.AsyncClient,
) -> None:
    owner = await signup(office)

    expect_error(await _restrict(owner, "198.51.100.0/24"), 422, "would_lock_you_out")
    expect_error(await _restrict(owner, "0.0.0.0/0"), 422, "invalid_settings")
    expect_error(await _restrict(owner, "the office"), 422, "invalid_settings")
    assert (await owner.get(SETTINGS)).json()["settings"]["allowed_ip_ranges"] is None

    assert (await _restrict(owner, OFFICE_NETWORK)).status_code == 200
    # Other settings still change under the list, and the list can be lifted.
    changed = await owner.patch(SETTINGS, json={"settings": {"default_retention_days": 90}})
    assert changed.status_code == 200, changed.text
    assert changed.json()["settings"]["allowed_ip_ranges"] == [OFFICE_NETWORK]
    lifted = await _restrict(owner)
    assert lifted.status_code == 200, lifted.text
    assert lifted.json()["settings"]["allowed_ip_ranges"] is None

    changes = [e["metadata"].get("settings", {}) for e in await _audit(owner, "org.updated")]
    assert {"allowed_ip_ranges": [OFFICE_NETWORK]} in changes
    assert {"allowed_ip_ranges": None} in changes


async def test_signing_in_from_elsewhere_reaches_the_account_but_not_the_organization(
    office: httpx2.AsyncClient, home: httpx2.AsyncClient
) -> None:
    owner = await signup(office)
    org_id = await org_id_of(owner)
    assert (await _restrict(owner, OFFICE_NETWORK)).status_code == 200
    credentials = {"email": owner.email, "password": PASSWORD}

    # Signing in to the organization by name, from elsewhere, is refused ...
    named = await home.post(
        "/api/v1/auth/login", json={**credentials, "organization_id": str(org_id)}
    )
    expect_error(named, 403, "ip_not_allowed")

    # ... and when it is only the default, the session opens without it.
    signed_in = await home.post("/api/v1/auth/login", json=credentials)
    assert signed_in.status_code == 200, signed_in.text
    body = signed_in.json()
    assert body["organization_id"] is None
    away = ApiSession(home, body["access_token"], body["refresh_token"], owner.email)
    assert (await away.get("/api/v1/users/me")).status_code == 200
    expect_error(await away.get(SETTINGS), 403, "permission_denied")  # no organization, no role
    switched = await away.post(
        "/api/v1/auth/switch-organization", json={"organization_id": str(org_id)}
    )
    expect_error(switched, 403, "ip_not_allowed")

    # The organization sees that valid credentials were used from outside.
    denied = await _audit(owner, "auth.network_denied")
    assert sorted(e["metadata"]["via"] for e in denied) == ["sign_in", "sign_in", "switch"]
    assert {(e["ip"], e["result"]) for e in denied} == {(HOME, "denied")}

    # From the office everything works as before.
    back = await office.post("/api/v1/auth/login", json=credentials)
    assert back.json()["organization_id"] == str(org_id)


async def _operator(container: Container, *argv: str) -> dict[str, Any]:
    args = build_parser().parse_args(argv)
    result: dict[str, Any] = await args.handler(container, args)
    return result


async def test_an_operator_can_lift_an_allowlist_that_locked_an_organization_out(
    container: Container, office: httpx2.AsyncClient, home: httpx2.AsyncClient
) -> None:
    owner = await signup(office)
    org_id = await org_id_of(owner)
    assert (await _restrict(owner, OFFICE_NETWORK)).status_code == 200
    away = _from(home, owner)  # the office changed ISP: nobody is "in the office" any more
    expect_error(await away.get(SETTINGS), 403, "ip_not_allowed")

    clear = ("org", "clear-network-allowlist", "--org")
    with pytest.raises(InvalidInputError):
        await _operator(container, *clear, str(org_id), "--reason", " ")
    with pytest.raises(NotFoundError):
        await _operator(container, *clear, str(uuid4()), "--reason", "Office moved")
    result = await _operator(container, *clear, str(org_id), "--reason", "Office changed ISP")
    assert result == {"organization_id": org_id, "allowed_ip_ranges": None}

    assert (await away.get(SETTINGS)).status_code == 200
    [entry] = await _audit(owner, "org.network_allowlist_cleared")
    assert entry["actor_type"] == "system"
    assert entry["metadata"] == {"reason": "Office changed ISP", "removed": [OFFICE_NETWORK]}

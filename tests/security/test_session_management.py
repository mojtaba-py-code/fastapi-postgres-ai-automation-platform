"""Users see their sign-in sessions and can end any one of them at once."""

from __future__ import annotations

import httpx2
import pytest

from tests.support.api import ApiSession, signup
from tests.support.business import expect_error, viewer_key
from tests.support.fixtures import PASSWORD

pytestmark = [pytest.mark.security, pytest.mark.integration]

FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"


async def _second_device(api: httpx2.AsyncClient, owner: ApiSession) -> ApiSession:
    signed_in = await api.post(
        "/api/v1/auth/login",
        json={"email": owner.email, "password": PASSWORD},
        headers={"User-Agent": FIREFOX},
    )
    assert signed_in.status_code == 200, signed_in.text
    body = signed_in.json()
    return ApiSession(api, body["access_token"], body["refresh_token"], owner.email)


async def test_the_session_list_names_every_device_and_marks_this_one(
    api: httpx2.AsyncClient,
) -> None:
    owner = await signup(api)
    laptop = await _second_device(api, owner)

    listed = await owner.get("/api/v1/users/me/sessions")
    assert listed.status_code == 200, listed.text
    sessions = listed.json()
    assert len(sessions) == 2
    assert [s["current"] for s in sessions].count(True) == 1
    assert {s["device"] for s in sessions} >= {"Firefox on Linux"}
    assert all(set(s) >= {"id", "ip", "created_at", "last_used_at", "expires_at"} for s in sessions)
    # Nothing that could be replayed is ever listed.
    assert laptop.refresh_token not in listed.text
    assert laptop.access_token not in listed.text


async def test_ending_a_session_cuts_its_tokens_off_at_once(api: httpx2.AsyncClient) -> None:
    owner = await signup(api)
    laptop = await _second_device(api, owner)
    [other] = [s for s in (await owner.get("/api/v1/users/me/sessions")).json() if not s["current"]]

    ended = await owner.delete(f"/api/v1/users/me/sessions/{other['id']}")
    assert ended.status_code == 204, ended.text

    expect_error(await laptop.get("/api/v1/users/me"), 401)
    refreshed = await api.post("/api/v1/auth/refresh", json={"refresh_token": laptop.refresh_token})
    assert refreshed.status_code == 401
    assert (await owner.get("/api/v1/users/me")).status_code == 200  # this one lives on
    audit = (await owner.get("/api/v1/audit", params={"action": "auth.session.revoked"})).json()
    assert [entry["resource_id"] for entry in audit["items"]] == [other["id"]]


async def test_nobody_can_end_or_see_another_users_sessions(api: httpx2.AsyncClient) -> None:
    owner = await signup(api)
    stranger = await signup(api)
    [theirs] = (await stranger.get("/api/v1/users/me/sessions")).json()

    expect_error(await owner.delete(f"/api/v1/users/me/sessions/{theirs['id']}"), 404)
    assert (await stranger.get("/api/v1/users/me")).status_code == 200


async def test_an_api_key_cannot_manage_its_creators_sessions(api: httpx2.AsyncClient) -> None:
    owner = await signup(api)
    key = await viewer_key(owner, ["projects:read"])
    [mine] = (await owner.get("/api/v1/users/me/sessions")).json()

    expect_error(await api.get("/api/v1/users/me/sessions", headers=key), 403, "session_required")
    expect_error(
        await api.delete(f"/api/v1/users/me/sessions/{mine['id']}", headers=key),
        403,
        "session_required",
    )
    assert (await owner.get("/api/v1/users/me")).status_code == 200

"""An organization that requires MFA never shuts its members out (review A-2).

Every request with a session that has not passed MFA is refused in such an
organization - and that used to include the MFA enrolment endpoints, so a
member without MFA (or an owner who turned the policy on before setting it up)
could never recover. They can now set MFA up, and confirming it with a code
opens the organization in the same session.
"""

from __future__ import annotations

import httpx2
import pyotp
import pytest

from tests.support.api import signup
from tests.support.business import expect_error, viewer_key
from tests.support.fixtures import PASSWORD

pytestmark = [pytest.mark.security, pytest.mark.integration]

ORG = "/api/v1/organizations/current"


async def test_a_member_without_mfa_sets_it_up_and_gets_in(api: httpx2.AsyncClient) -> None:
    owner = await signup(api)
    enforced = await owner.patch(ORG, json={"settings": {"require_mfa": True}})
    assert enforced.status_code == 200, enforced.text

    # The organization's data stays closed ...
    refused = expect_error(await owner.get(ORG), 403, "mfa_required")
    assert "/auth/mfa/enroll" in refused["message"]
    expect_error(await owner.get("/api/v1/projects"), 403, "mfa_required")

    # ... but setting MFA up is possible, and needs the password as always.
    expect_error(
        await owner.post("/api/v1/auth/mfa/enroll", json={"password": "not-the-password!"}),
        403,
        "invalid_password",
    )
    enrolled = await owner.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD})
    assert enrolled.status_code == 200, enrolled.text
    expect_error(await owner.get(ORG), 403, "mfa_required")  # not before it is confirmed
    code = pyotp.TOTP(enrolled.json()["secret"]).now()
    confirmed = await owner.post("/api/v1/auth/mfa/confirm", json={"code": code})
    assert confirmed.status_code == 200, confirmed.text

    # The code proved the second factor: this session now opens the organization.
    assert (await owner.get(ORG)).status_code == 200
    assert (await owner.get("/api/v1/projects")).status_code == 200


async def test_set_up_mode_opens_nothing_but_the_enrolment(api: httpx2.AsyncClient) -> None:
    owner = await signup(api)
    key = await viewer_key(owner, ["projects:read"])
    assert (await owner.patch(ORG, json={"settings": {"require_mfa": True}})).status_code == 200

    # Every other endpoint still refuses the session ...
    for path in ("/api/v1/users/me/sessions", "/api/v1/audit", "/api/v1/api-keys"):
        assert (await owner.get(path)).status_code == 403, path
    # ... and an API key cannot enrol its creator (it has no session).
    response = await api.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD}, headers=key)
    expect_error(response, 403, "session_required")

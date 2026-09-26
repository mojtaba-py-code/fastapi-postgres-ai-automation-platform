"""Every action that asks for the account password treats a wrong one like a
failed sign-in (review finding A-1).

Enabling or disabling MFA and erasing the account each check the password.
They used to answer "wrong" and "right" without counting failures or honouring
a lockout, so a stolen access token - or a leaked API key, which acts for its
creator - was an unlimited oracle for the account password.
"""

from __future__ import annotations

from typing import Any

import httpx2
import pytest

from tests.support.api import ApiSession, signup
from tests.support.business import expect_error, viewer_key
from tests.support.fixtures import PASSWORD

pytestmark = [pytest.mark.security, pytest.mark.integration]

THRESHOLD = 5  # security.lockout_threshold


def _wrong(i: int) -> str:
    return f"not-the-password-{i:02d}"


async def _audit(owner: ApiSession, action: str) -> list[dict[str, Any]]:
    response = await owner.get("/api/v1/audit", params={"action": action})
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


@pytest.mark.parametrize(
    ("path", "body", "purpose"),
    [
        ("/api/v1/auth/mfa/enroll", lambda pw: {"password": pw}, "mfa_enrollment"),
        ("/api/v1/users/me/delete", lambda pw: {"password": pw}, "account_deletion"),
        (
            "/api/v1/auth/webauthn/register/begin",
            lambda pw: {"password": pw},
            "passkey_registration",
        ),
    ],
)
async def test_wrong_passwords_lock_the_account_as_at_sign_in(
    api: httpx2.AsyncClient, path: str, body: Any, purpose: str
) -> None:
    owner = await signup(api)
    for i in range(THRESHOLD):
        wrong = await owner.post(path, json=body(_wrong(i)))
        # 403, not 401: the caller's token is fine; only the password is wrong.
        expect_error(wrong, 403, "invalid_password")
        assert "www-authenticate" not in wrong.headers

    # Locked now: even the right password is refused, here and at sign-in.
    expect_error(await owner.post(path, json=body(PASSWORD)), 403, "account_locked")
    signed_in = await api.post(
        "/api/v1/auth/login", json={"email": owner.email, "password": PASSWORD}
    )
    assert signed_in.status_code == 401
    failures = await _audit(owner, "auth.password.confirmation_failed")
    assert [f["metadata"]["purpose"] for f in failures] == [purpose] * THRESHOLD


async def test_disabling_mfa_counts_wrong_passwords_and_wrong_codes(
    api: httpx2.AsyncClient,
) -> None:
    owner = await signup(api)
    enrolled = await owner.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD})
    assert enrolled.status_code == 200, enrolled.text
    import pyotp

    totp = pyotp.TOTP(enrolled.json()["secret"])
    confirmed = await owner.post("/api/v1/auth/mfa/confirm", json={"code": totp.now()})
    assert confirmed.status_code == 200, confirmed.text

    attempts = [
        {"password": _wrong(0), "code": "000000"},
        {"password": PASSWORD, "code": "000000"},  # right password, wrong code
        {"password": _wrong(1), "code": "000000"},
        {"password": PASSWORD, "code": "999999"},
        {"password": _wrong(2), "code": "000000"},
    ]
    for attempt in attempts:
        response = await owner.post("/api/v1/auth/mfa/disable", json=attempt)
        assert response.status_code in (403, 422), response.text
    expect_error(
        await owner.post(
            "/api/v1/auth/mfa/disable", json={"password": PASSWORD, "code": totp.now()}
        ),
        403,
        "account_locked",
    )


async def test_an_api_key_cannot_confirm_its_creators_password(api: httpx2.AsyncClient) -> None:
    owner = await signup(api)
    key = await viewer_key(owner, ["projects:read"])

    for path in (
        "/api/v1/auth/mfa/enroll",
        "/api/v1/users/me/delete",
        "/api/v1/auth/webauthn/register/begin",
    ):
        response = await api.post(path, json={"password": PASSWORD}, headers=key)
        expect_error(response, 403, "session_required")
    assert (await owner.get("/api/v1/users/me")).status_code == 200  # nothing happened


async def test_a_wrong_current_password_is_403_when_changing_it(api: httpx2.AsyncClient) -> None:
    owner = await signup(api)
    response = await owner.post(
        "/api/v1/auth/password/change",
        json={"current_password": _wrong(0), "new_password": "An0ther-str0ng-passphrase!"},
    )
    expect_error(response, 403, "invalid_password")
    assert "www-authenticate" not in response.headers

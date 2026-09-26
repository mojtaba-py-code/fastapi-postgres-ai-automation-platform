"""Passkeys (WebAuthn) as a second factor, end to end through the API.

A software authenticator (tests/support/webauthn.py) answers real ceremonies
with P-256, Ed25519 and RSA keys, so every test runs the platform's own
verification: registration, sign-in, management, organizations that require
MFA, recovery codes, erasure - and the ways a response can be wrong, each
refused for its own reason (what the person registering is told, or what the
audit trail records for a sign-in, whose answer stays generic).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import httpx2
import pyotp
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.core.clock import FrozenClock
from nexusflow.domain.authorization.roles import Role
from tests.support.api import ApiSession, signup
from tests.support.business import expect_error, viewer_key
from tests.support.fixtures import META, PASSWORD, unique_email
from tests.support.webauthn import (
    AT,
    EDDSA,
    ES256,
    RP_ID,
    RS256,
    UP,
    UV,
    SoftwareAuthenticator,
    b64url,
    b64url_decode,
    rp_id_hash,
)

pytestmark = [pytest.mark.security, pytest.mark.integration]

REGISTER_BEGIN = "/api/v1/auth/webauthn/register/begin"
REGISTER_FINISH = "/api/v1/auth/webauthn/register/finish"
PASSKEYS = "/api/v1/auth/webauthn/credentials"
SIGN_IN_BEGIN = "/api/v1/auth/mfa/webauthn/begin"
SIGN_IN_VERIFY = "/api/v1/auth/mfa/webauthn/verify"
LOGIN = "/api/v1/auth/login"
THRESHOLD = 5  # security.lockout_threshold


# ------------------------------------------------------------------ helpers


async def begin_registration(session: ApiSession) -> dict[str, Any]:
    response = await session.post(REGISTER_BEGIN, json={"password": PASSWORD})
    assert response.status_code == 200, response.text
    assert response.json()["expires_in"] == 300
    options: dict[str, Any] = response.json()["options"]
    return options


async def finish_registration(
    session: ApiSession,
    authenticator: SoftwareAuthenticator,
    options: dict[str, Any],
    *,
    name: str | None = "Laptop",
    **overrides: Any,
) -> httpx2.Response:
    credential = authenticator.attestation(options, **overrides)
    return await session.post(REGISTER_FINISH, json={"name": name, "credential": credential})


async def register_passkey(
    session: ApiSession, authenticator: SoftwareAuthenticator | None = None, **overrides: Any
) -> tuple[SoftwareAuthenticator, dict[str, Any]]:
    authenticator = authenticator or SoftwareAuthenticator()
    response = await finish_registration(
        session, authenticator, await begin_registration(session), **overrides
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return authenticator, body


async def refused_registration(
    session: ApiSession, reason: str, **overrides: Any
) -> dict[str, Any]:
    authenticator = overrides.pop("authenticator", None) or SoftwareAuthenticator()
    options = await begin_registration(session)
    response = await finish_registration(session, authenticator, options, **overrides)
    body = expect_error(response, 422, "passkey_rejected")
    assert [detail["code"] for detail in body["details"]] == [reason], body
    return body


async def password_step(api: httpx2.AsyncClient, email: str) -> dict[str, Any]:
    response = await api.post(LOGIN, json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    assert body["mfa_required"] is True, body
    return body


async def sign_in_options(api: httpx2.AsyncClient, mfa_token: str) -> dict[str, Any]:
    response = await api.post(SIGN_IN_BEGIN, json={"mfa_token": mfa_token})
    assert response.status_code == 200, response.text
    options: dict[str, Any] = response.json()["options"]
    return options


async def verify(
    api: httpx2.AsyncClient, mfa_token: str, credential: dict[str, Any]
) -> httpx2.Response:
    return await api.post(SIGN_IN_VERIFY, json={"mfa_token": mfa_token, "credential": credential})


async def sign_in(
    api: httpx2.AsyncClient, email: str, authenticator: SoftwareAuthenticator, **overrides: Any
) -> httpx2.Response:
    token = (await password_step(api, email))["mfa_token"]
    options = await sign_in_options(api, token)
    return await verify(api, token, authenticator.assertion(options, **overrides))


def session_from(api: httpx2.AsyncClient, response: httpx2.Response, email: str) -> ApiSession:
    assert response.status_code == 200, response.text
    body = response.json()
    return ApiSession(api, body["access_token"], body["refresh_token"], email)


async def user_id_of(admin_conn: asyncpg.Connection, email: str) -> UUID:
    user_id: UUID = await admin_conn.fetchval("SELECT id FROM users WHERE email = $1", email)
    return user_id


async def audit_metadata(
    admin_conn: asyncpg.Connection, email: str, action: str
) -> list[dict[str, Any]]:
    rows = await admin_conn.fetch(
        "SELECT metadata FROM audit_logs WHERE action = $1 AND actor_id = "
        "(SELECT id FROM users WHERE email = $2) ORDER BY occurred_at",
        action,
        email,
    )
    return [json.loads(row["metadata"]) for row in rows]


async def sign_in_refusals(admin_conn: asyncpg.Connection, email: str) -> list[str]:
    """The reasons recorded for refused passkey sign-ins, oldest first."""
    return [
        entry["reason"]
        for entry in await audit_metadata(admin_conn, email, "auth.mfa.failed")
        if entry.get("method") == "webauthn"
    ]


async def security_emails(admin_conn: asyncpg.Connection, email: str) -> list[str]:
    rows = await admin_conn.fetch(
        "SELECT payload FROM outbox_messages WHERE task = 'security.send_email' "
        "AND payload->>'user_id' = $1 ORDER BY created_at",
        str(await user_id_of(admin_conn, email)),
    )
    return [json.loads(row["payload"])["template"] for row in rows]


async def stored_passkeys(admin_conn: asyncpg.Connection, email: str) -> list[asyncpg.Record]:
    rows: list[asyncpg.Record] = await admin_conn.fetch(
        "SELECT * FROM webauthn_credentials WHERE user_id = "
        "(SELECT id FROM users WHERE email = $1) ORDER BY created_at",
        email,
    )
    return rows


@pytest.fixture
def frozen_now(container: Container, monkeypatch: pytest.MonkeyPatch) -> FrozenClock:
    """One clock for sign-in and passkey management, starting now."""
    clock = FrozenClock(datetime.now(UTC))
    monkeypatch.setattr(container.auth, "_clock", clock)
    monkeypatch.setattr(container.passkeys, "_clock", clock)
    return clock


# ------------------------------------------------------------- registration


class TestRegistration:
    @pytest.mark.parametrize("algorithm", [ES256, EDDSA, RS256], ids=["ES256", "EdDSA", "RS256"])
    async def test_each_algorithm_registers_and_signs_in(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection, algorithm: int
    ) -> None:
        owner = await signup(api)
        authenticator, registered = await register_passkey(owner, SoftwareAuthenticator(algorithm))
        # The first second factor turns MFA on, with recovery codes shown once.
        assert len(registered["recovery_codes"]) == 10
        passkey = registered["passkey"]
        assert passkey["name"] == "Laptop"
        assert passkey["algorithm"] == {ES256: "ES256", EDDSA: "EdDSA", RS256: "RS256"}[algorithm]
        assert passkey["transports"] == ["hybrid", "internal"]
        assert (await owner.get("/api/v1/users/me")).json()["mfa_enabled"] is True

        challenge = await password_step(api, owner.email)
        assert challenge["methods"] == ["webauthn", "recovery_code"]
        options = await sign_in_options(api, challenge["mfa_token"])
        answered = await verify(api, challenge["mfa_token"], authenticator.assertion(options))
        signed_in = session_from(api, answered, owner.email)

        sessions = (await signed_in.get("/api/v1/users/me/sessions")).json()
        assert [s["mfa_verified"] for s in sessions if s["current"]] == [True]
        [stored] = await stored_passkeys(admin_conn, owner.email)
        assert (stored["sign_count"], stored["algorithm"]) == (1, algorithm)
        assert stored["last_used_at"] is not None
        logins = await audit_metadata(admin_conn, owner.email, "auth.login.succeeded")
        assert logins[-1]["mfa"] is True
        assert logins[-1]["mfa_method"] == "webauthn"
        assert "passkey_added" in await security_emails(admin_conn, owner.email)

    async def test_the_creation_options_follow_the_policy(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        options = await begin_registration(owner)
        assert options["rp"] == {"id": RP_ID, "name": "NexusFlow AI"}
        assert options["attestation"] == "none"
        assert options["authenticatorSelection"] == {
            "residentKey": "preferred",
            "requireResidentKey": False,
            "userVerification": "required",
        }
        assert [p["alg"] for p in options["pubKeyCredParams"]] == [-7, -8, -257]
        assert {p["type"] for p in options["pubKeyCredParams"]} == {"public-key"}
        assert options["timeout"] == 300_000
        assert len(b64url_decode(options["challenge"])) == 32
        assert options["excludeCredentials"] == []
        # The user handle is random: neither the account's ID nor its address.
        user = options["user"]
        handle = b64url_decode(user["id"])
        user_id = await user_id_of(admin_conn, owner.email)
        assert len(handle) == 64
        assert user_id.bytes not in handle
        assert owner.email.encode() not in handle
        assert (user["name"], user["displayName"]) == (owner.email, "Api Tester")

        authenticator, _ = await register_passkey(owner)  # a fresh begin, a fresh handle
        assert authenticator.user_handle is not None
        again = await begin_registration(owner)
        # A second passkey keeps the account's handle; the first one is excluded.
        assert again["user"]["id"] == b64url(authenticator.user_handle)
        assert again["excludeCredentials"] == [
            {
                "type": "public-key",
                "id": b64url(authenticator.credential_id),
                "transports": ["hybrid", "internal"],
            }
        ]
        assert again["challenge"] != options["challenge"]

    async def test_a_second_passkey_brings_no_new_recovery_codes(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        first, _ = await register_passkey(owner)
        _, second = await register_passkey(owner, name="Security key")
        assert second["recovery_codes"] is None
        assert second["passkey"]["name"] == "Security key"
        stored = await stored_passkeys(admin_conn, owner.email)
        assert len(stored) == 2
        # One random handle per account, stored with each of its passkeys.
        assert {bytes(row["user_handle"]) for row in stored} == {first.user_handle}
        assert (
            await admin_conn.fetchval(
                "SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1",
                await user_id_of(admin_conn, owner.email),
            )
            == 10
        )

    async def test_names_and_transports_are_cleaned(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        _, named = await register_passkey(
            owner,
            name="Work\u202e laptop\x00  ",
            transports=["usb", "nfc", "carrier-pigeon", "usb"],
        )
        assert named["passkey"]["name"] == "Work laptop"
        assert named["passkey"]["transports"] == ["usb", "nfc"]
        _, unnamed = await register_passkey(owner, name=None)
        assert unnamed["passkey"]["name"] == "Passkey"

    async def test_backup_flags_are_recorded(self, api: httpx2.AsyncClient) -> None:
        owner = await signup(api)
        _, synced = await register_passkey(
            owner, SoftwareAuthenticator(backup_eligible=True, backed_up=True)
        )
        assert (synced["passkey"]["backup_eligible"], synced["passkey"]["backed_up"]) == (
            True,
            True,
        )


# The defects a registration is refused for, each with the reason given back.
REFUSED_REGISTRATIONS: list[tuple[str, dict[str, Any]]] = [
    ("type_mismatch", {"kind": "webauthn.get"}),
    ("challenge_mismatch", {"challenge": b64url(os.urandom(32))}),
    ("origin_not_allowed", {"origin": "https://nexusflow.test.example.evil.example"}),
    ("origin_not_allowed", {"origin": f"http://{RP_ID}"}),
    ("cross_origin", {"client_members": {"crossOrigin": True}}),
    ("token_binding_unsupported", {"client_members": {"tokenBinding": {"status": "present"}}}),
    ("rp_id_mismatch", {"rp_hash": rp_id_hash("evil.example")}),
    ("user_not_present", {"flags": UV | AT}),
    ("user_not_verified", {"flags": UP | AT}),
    ("credential_data_missing", {"flags": UP | UV}),
    ("attestation_format_unsupported", {"fmt": "packed", "att_stmt": {"alg": -7, "sig": b"s"}}),
    ("attestation_format_unsupported", {"fmt": "none", "att_stmt": {"x5c": [b"cert"]}}),
    ("algorithm_not_allowed", {"public_key": {1: 2, 3: -35, -1: 2, -2: b"x" * 48}}),
    (
        "public_key_invalid",  # an OKP key type with ES256
        {"public_key": {1: 1, 3: -7, -1: 1, -2: b"x" * 32, -3: b"y" * 32}},
    ),
    ("credential_id_invalid", {"raw_id": os.urandom(32)}),
]


class TestRefusedRegistrations:
    @pytest.mark.parametrize(
        ("reason", "overrides"),
        REFUSED_REGISTRATIONS,
        ids=[f"{reason}-{i}" for i, (reason, _) in enumerate(REFUSED_REGISTRATIONS)],
    )
    async def test_a_defective_attestation_stores_nothing(
        self,
        api: httpx2.AsyncClient,
        admin_conn: asyncpg.Connection,
        reason: str,
        overrides: dict[str, Any],
    ) -> None:
        owner = await signup(api)
        await refused_registration(owner, reason, **overrides)
        assert await stored_passkeys(admin_conn, owner.email) == []
        assert (await owner.get("/api/v1/users/me")).json()["mfa_enabled"] is False
        refusals = await audit_metadata(
            admin_conn, owner.email, "auth.webauthn.registration_failed"
        )
        assert refusals == [{"reason": reason}]

    async def test_a_challenge_is_answered_once(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        authenticator = SoftwareAuthenticator()
        options = await begin_registration(owner)
        credential = authenticator.attestation(options)
        first = await owner.post(REGISTER_FINISH, json={"credential": credential})
        assert first.status_code == 201, first.text
        replayed = await owner.post(REGISTER_FINISH, json={"credential": credential})
        body = expect_error(replayed, 422, "passkey_rejected")
        assert body["details"][0]["code"] == "challenge_missing"
        other = SoftwareAuthenticator().attestation(options)
        body = expect_error(
            await owner.post(REGISTER_FINISH, json={"credential": other}), 422, "passkey_rejected"
        )
        assert body["details"][0]["code"] == "challenge_missing"
        assert len(await stored_passkeys(admin_conn, owner.email)) == 1

    async def test_a_challenge_expires_after_five_minutes(
        self, api: httpx2.AsyncClient, frozen_now: FrozenClock
    ) -> None:
        owner = await signup(api)
        options = await begin_registration(owner)
        frozen_now.advance(timedelta(seconds=301))
        response = await finish_registration(owner, SoftwareAuthenticator(), options)
        body = expect_error(response, 422, "passkey_rejected")
        assert body["details"][0]["code"] == "challenge_expired"

    async def test_a_challenge_belongs_to_the_session_that_asked(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        laptop = session_from(
            api,
            await api.post(LOGIN, json={"email": owner.email, "password": PASSWORD}),
            owner.email,
        )
        options = await begin_registration(owner)
        response = await finish_registration(laptop, SoftwareAuthenticator(), options)
        body = expect_error(response, 422, "passkey_rejected")
        assert body["details"][0]["code"] == "challenge_missing"

    async def test_a_credential_registered_to_another_account_is_refused(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        first = await signup(api)
        authenticator, _ = await register_passkey(first)
        second = await signup(api)
        response = await finish_registration(
            second, authenticator, await begin_registration(second)
        )
        expect_error(response, 409, "passkey_exists")
        assert await stored_passkeys(admin_conn, second.email) == []
        refusals = await audit_metadata(
            admin_conn, second.email, "auth.webauthn.registration_failed"
        )
        assert refusals == [{"reason": "credential_exists"}]
        # ... and registering it twice to the same account is refused as well.
        response = await finish_registration(first, authenticator, await begin_registration(first))
        expect_error(response, 409, "passkey_exists")

    async def test_ten_passkeys_at_most(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        for _ in range(10):
            await register_passkey(owner)
        refused = await owner.post(REGISTER_BEGIN, json={"password": PASSWORD})
        expect_error(refused, 409, "too_many_passkeys")
        assert len(await stored_passkeys(admin_conn, owner.email)) == 10

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            pytest.param(("response", "clientDataJSON"), b64url(b"{" * 4097), id="client-data"),
            pytest.param(
                ("response", "attestationObject"), b64url(os.urandom(65537)), id="attestation"
            ),
            pytest.param(
                ("response", "authenticatorData"), b64url(os.urandom(4097)), id="auth-data"
            ),
            pytest.param(("response", "publicKey"), b64url(os.urandom(2049)), id="public-key"),
            pytest.param(("response", "transports"), ["usb"] * 9, id="transports"),
            pytest.param(("response", "transports"), ["USB!"], id="transport-name"),
            pytest.param(("rawId",), b64url(os.urandom(1024)), id="credential-id"),
            pytest.param(("clientExtensionResults",), {str(i): i for i in range(17)}, id="exts"),
            pytest.param(("type",), "password", id="type"),
            pytest.param(("response", "clientDataJSON"), "e30=", id="padded"),
            pytest.param(("response", "clientDataJSON"), "e3+=", id="standard-alphabet"),
            pytest.param(("response", "clientDataJSON"), "", id="empty"),
            pytest.param(("response", "clientDataJSON"), 42, id="not-a-string"),
            pytest.param(("response", "extra"), "x", id="unknown-member"),
            pytest.param(("id",), "not-the-raw-id", id="id-is-not-raw-id"),
        ],
    )
    async def test_oversized_or_malformed_members_are_refused_before_verification(
        self, api: httpx2.AsyncClient, path: tuple[str, ...], value: Any
    ) -> None:
        owner = await signup(api)
        options = await begin_registration(owner)
        credential = SoftwareAuthenticator().attestation(options)
        target = credential
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        response = await owner.post(REGISTER_FINISH, json={"credential": credential})
        body = expect_error(response, 422, "validation_failed")
        assert body["details"]
        if isinstance(value, str) and len(value) > 8:
            assert value not in response.text  # never echoed
        # The challenge is still pending: a well-formed answer goes through.
        good = await finish_registration(owner, SoftwareAuthenticator(), options)
        assert good.status_code == 201, good.text

    async def test_an_overlong_name_is_refused(self, api: httpx2.AsyncClient) -> None:
        owner = await signup(api)
        response = await finish_registration(
            owner, SoftwareAuthenticator(), await begin_registration(owner), name="n" * 65
        )
        expect_error(response, 422, "validation_failed")

    async def test_an_api_key_cannot_register_or_list_passkeys(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        key = await viewer_key(owner, ["projects:read"])
        expect_error(
            await api.post(REGISTER_BEGIN, json={"password": PASSWORD}, headers=key),
            403,
            "session_required",
        )
        expect_error(await api.get(PASSKEYS, headers=key), 403, "session_required")


# ------------------------------------------------------------------ sign-in


async def _passkey_owner(
    api: httpx2.AsyncClient, authenticator: SoftwareAuthenticator | None = None
) -> tuple[ApiSession, SoftwareAuthenticator]:
    owner = await signup(api)
    registered, _ = await register_passkey(owner, authenticator)
    return owner, registered


REFUSED_SIGN_INS: list[tuple[str, dict[str, Any]]] = [
    ("type_mismatch", {"kind": "webauthn.create"}),
    ("challenge_mismatch", {"challenge": b64url(os.urandom(32))}),
    ("origin_not_allowed", {"origin": "https://evil.example"}),
    ("cross_origin", {"client_members": {"crossOrigin": True}}),
    ("rp_id_mismatch", {"rp_hash": rp_id_hash("evil.example")}),
    ("user_not_present", {"flags": UV}),
    ("user_not_verified", {"flags": UP}),
    (
        "credential_data_unexpected",
        {"flags": UP | UV | AT, "attested": bytes(16) + (16).to_bytes(2, "big") + bytes(16)},
    ),
    ("signature_invalid", {"tamper": "authenticator_data"}),
    ("signature_invalid", {"tamper": "client_data"}),
    ("signature_invalid", {"tamper": "signature"}),
    ("user_handle_mismatch", {"user_handle": os.urandom(64)}),
    ("credential_unknown", {"raw_id": os.urandom(32)}),
]


class TestSignIn:
    async def test_a_passkey_that_never_counts_signs_in_again_and_again(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner, authenticator = await _passkey_owner(api, SoftwareAuthenticator(counting=False))
        for _ in range(2):
            assert (await sign_in(api, owner.email, authenticator)).status_code == 200

    async def test_the_request_options_name_only_the_accounts_passkeys(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner, first = await _passkey_owner(api)
        second, _ = await register_passkey(owner, SoftwareAuthenticator(EDDSA))
        stranger, _ = await _passkey_owner(api)
        options = await sign_in_options(api, (await password_step(api, owner.email))["mfa_token"])
        assert options["rpId"] == RP_ID
        assert options["userVerification"] == "required"
        assert options["timeout"] <= 300_000
        assert len(b64url_decode(options["challenge"])) == 32
        assert {c["id"] for c in options["allowCredentials"]} == {
            b64url(first.credential_id),
            b64url(second.credential_id),
        }
        assert stranger.email not in json.dumps(options)

    async def test_a_passkey_answer_is_accepted_once(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, authenticator = await _passkey_owner(api)
        token = (await password_step(api, owner.email))["mfa_token"]
        credential = authenticator.assertion(await sign_in_options(api, token))
        assert (await verify(api, token, credential)).status_code == 200
        replayed = await verify(api, token, credential)
        expect_error(replayed, 401, "mfa_failed")
        assert await sign_in_refusals(admin_conn, owner.email) == ["challenge_missing"]

    async def test_a_verify_without_a_begin_is_refused(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, authenticator = await _passkey_owner(api)
        token = (await password_step(api, owner.email))["mfa_token"]
        forged = authenticator.assertion({"challenge": b64url(os.urandom(32))})
        expect_error(await verify(api, token, forged), 401, "mfa_failed")
        assert await sign_in_refusals(admin_conn, owner.email) == ["challenge_missing"]

    async def test_a_challenge_expires(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection, frozen_now: FrozenClock
    ) -> None:
        owner, authenticator = await _passkey_owner(api)
        token = (await password_step(api, owner.email))["mfa_token"]
        options = await sign_in_options(api, token)
        # Past the challenge, still within the sign-in token's 30-second leeway.
        frozen_now.advance(timedelta(seconds=301))
        expect_error(await verify(api, token, authenticator.assertion(options)), 401)
        assert await sign_in_refusals(admin_conn, owner.email) == ["challenge_expired"]

    async def test_the_challenge_is_bound_to_the_password_step(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, authenticator = await _passkey_owner(api)
        first = (await password_step(api, owner.email))["mfa_token"]
        options = await sign_in_options(api, first)
        second = (await password_step(api, owner.email))["mfa_token"]
        expect_error(await verify(api, second, authenticator.assertion(options)), 401)
        assert await sign_in_refusals(admin_conn, owner.email) == ["challenge_missing"]

    @pytest.mark.parametrize(
        ("reason", "overrides"),
        REFUSED_SIGN_INS,
        ids=[f"{reason}-{i}" for i, (reason, _) in enumerate(REFUSED_SIGN_INS)],
    )
    async def test_a_defective_assertion_is_refused_and_counted(
        self,
        api: httpx2.AsyncClient,
        admin_conn: asyncpg.Connection,
        reason: str,
        overrides: dict[str, Any],
    ) -> None:
        owner, authenticator = await _passkey_owner(api)
        response = await sign_in(api, owner.email, authenticator, **overrides)
        body = expect_error(response, 401, "mfa_failed")
        assert body["message"] == "Verification failed."  # the reason is not given away
        assert await sign_in_refusals(admin_conn, owner.email) == [reason]
        failures = await admin_conn.fetchval(
            "SELECT failed_login_attempts FROM users WHERE email = $1", owner.email
        )
        assert failures == 1
        [stored] = await stored_passkeys(admin_conn, owner.email)
        assert stored["sign_count"] == 0  # nothing moved
        assert stored["last_used_at"] is None

    async def test_only_a_passkey_the_options_allowed_answers_them(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, _ = await _passkey_owner(api)
        token = (await password_step(api, owner.email))["mfa_token"]
        options = await sign_in_options(api, token)
        # Registered after the options were issued: the account's, but not allowed.
        newer, _ = await register_passkey(owner, name="Newer")
        expect_error(await verify(api, token, newer.assertion(options)), 401, "mfa_failed")
        assert await sign_in_refusals(admin_conn, owner.email) == ["credential_unknown"]

    async def test_another_accounts_passkey_is_unknown_here(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, _ = await _passkey_owner(api)
        _, strangers = await _passkey_owner(api)
        response = await sign_in(api, owner.email, strangers)
        expect_error(response, 401, "mfa_failed")
        assert await sign_in_refusals(admin_conn, owner.email) == ["credential_unknown"]

    async def test_a_counter_that_goes_back_is_refused_as_a_possible_clone(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, authenticator = await _passkey_owner(api)
        assert (await sign_in(api, owner.email, authenticator)).status_code == 200  # count 1
        assert (await sign_in(api, owner.email, authenticator)).status_code == 200  # count 2
        for presented in (2, 1):  # the same count again, then a lower one
            response = await sign_in(api, owner.email, authenticator, sign_count=presented)
            expect_error(response, 401, "mfa_failed")
        assert await sign_in_refusals(admin_conn, owner.email) == [
            "counter_regression",
            "counter_regression",
        ]
        clones = await audit_metadata(admin_conn, owner.email, "auth.webauthn.clone_suspected")
        assert clones == [
            {"stored_counter": 2, "presented_counter": 2},
            {"stored_counter": 2, "presented_counter": 1},
        ]
        assert (await security_emails(admin_conn, owner.email)).count(
            "passkey_clone_suspected"
        ) == 2
        [stored] = await stored_passkeys(admin_conn, owner.email)
        assert stored["sign_count"] == 2

    async def test_a_passkey_cannot_become_backup_eligible_later(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, authenticator = await _passkey_owner(api)
        authenticator.backup_eligible = True
        expect_error(await sign_in(api, owner.email, authenticator), 401, "mfa_failed")
        assert await sign_in_refusals(admin_conn, owner.email) == ["backup_eligibility_changed"]

    async def test_the_backup_state_is_kept_up_to_date(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, authenticator = await _passkey_owner(
            api, SoftwareAuthenticator(backup_eligible=True)
        )
        authenticator.backed_up = True
        assert (await sign_in(api, owner.email, authenticator)).status_code == 200
        [stored] = await stored_passkeys(admin_conn, owner.email)
        assert (stored["backup_eligible"], stored["backed_up"]) == (True, True)

    async def test_refused_passkeys_lock_the_account_like_wrong_codes(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, authenticator = await _passkey_owner(api)
        token = (await password_step(api, owner.email))["mfa_token"]
        for _ in range(THRESHOLD):
            options = await sign_in_options(api, token)
            wrong = authenticator.assertion(options, tamper="signature")
            expect_error(await verify(api, token, wrong), 401, "mfa_failed")
        # Locked: a valid passkey is refused too, and so is the password step.
        expect_error(await api.post(SIGN_IN_BEGIN, json={"mfa_token": token}), 401, "mfa_failed")
        expect_error(await api.post(LOGIN, json={"email": owner.email, "password": PASSWORD}), 401)
        locked = await admin_conn.fetchval(
            "SELECT locked_until FROM users WHERE email = $1", owner.email
        )
        assert locked is not None
        assert await audit_metadata(admin_conn, owner.email, "auth.login.locked")
        assert "account_locked" in await security_emails(admin_conn, owner.email)

    async def test_a_code_for_an_account_with_passkeys_only_is_just_wrong(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner, _ = await _passkey_owner(api)
        token = (await password_step(api, owner.email))["mfa_token"]
        response = await api.post(
            "/api/v1/auth/mfa/verify", json={"mfa_token": token, "code": "123456"}
        )
        expect_error(response, 401, "mfa_failed")

    async def test_an_account_without_passkeys_gets_no_passkey_challenge(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        enrolled = await owner.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD})
        totp = pyotp.TOTP(enrolled.json()["secret"])
        confirmed = await owner.post("/api/v1/auth/mfa/confirm", json={"code": totp.now()})
        assert confirmed.status_code == 200, confirmed.text
        challenge = await password_step(api, owner.email)
        assert challenge["methods"] == ["totp", "recovery_code"]
        response = await api.post(SIGN_IN_BEGIN, json={"mfa_token": challenge["mfa_token"]})
        expect_error(response, 409, "no_passkeys")

    async def test_a_forged_or_wrong_kind_of_token_gets_no_challenge(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner, _ = await _passkey_owner(api)
        expect_error(await api.post(SIGN_IN_BEGIN, json={"mfa_token": "forged"}), 401)
        # An access token is no MFA challenge token (token_use).
        expect_error(await api.post(SIGN_IN_BEGIN, json={"mfa_token": owner.access_token}), 401)

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            pytest.param(("response", "signature"), b64url(os.urandom(513)), id="signature"),
            pytest.param(("response", "userHandle"), b64url(os.urandom(65)), id="user-handle"),
            pytest.param(
                ("response", "authenticatorData"), b64url(os.urandom(4097)), id="auth-data"
            ),
            pytest.param(("response", "clientDataJSON"), b64url(b" " * 4097), id="client-data"),
            pytest.param(("response", "attestationObject"), "AAAA", id="unknown-member"),
        ],
    )
    async def test_oversized_members_are_refused_before_verification(
        self, api: httpx2.AsyncClient, path: tuple[str, ...], value: Any
    ) -> None:
        owner, authenticator = await _passkey_owner(api)
        token = (await password_step(api, owner.email))["mfa_token"]
        credential = authenticator.assertion(await sign_in_options(api, token))
        target = credential
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        expect_error(await verify(api, token, credential), 422, "validation_failed")


# --------------------------------------------------------------- management


class TestManagement:
    async def test_the_list_shows_no_key_material(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, authenticator = await _passkey_owner(api)
        response = await owner.get(PASSKEYS)
        assert response.status_code == 200, response.text
        [listed] = response.json()
        assert set(listed) == {
            "id",
            "name",
            "algorithm",
            "transports",
            "backup_eligible",
            "backed_up",
            "created_at",
            "last_used_at",
        }
        [stored] = await stored_passkeys(admin_conn, owner.email)
        for secretless in (stored["public_key"], stored["credential_id"], stored["user_handle"]):
            assert b64url(bytes(secretless)) not in response.text
        assert b64url(authenticator.credential_id) not in response.text

    async def test_rename(self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection) -> None:
        owner, _ = await _passkey_owner(api)
        [listed] = (await owner.get(PASSKEYS)).json()
        renamed = await owner.patch(f"{PASSKEYS}/{listed['id']}", json={"name": " Phone\u200b "})
        assert renamed.status_code == 200, renamed.text
        assert renamed.json()["name"] == "Phone"
        expect_error(
            await owner.patch(f"{PASSKEYS}/{listed['id']}", json={"name": "\u200b"}),
            422,
            "name_required",
        )
        assert await audit_metadata(admin_conn, owner.email, "auth.webauthn.renamed") == [{}]

    async def test_another_accounts_passkey_does_not_exist_for_you(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner, _ = await _passkey_owner(api)
        stranger, _ = await _passkey_owner(api)
        [theirs] = (await stranger.get(PASSKEYS)).json()
        expect_error(await owner.patch(f"{PASSKEYS}/{theirs['id']}", json={"name": "x"}), 404)
        expect_error(
            await owner.post(f"{PASSKEYS}/{theirs['id']}/delete", json={"password": PASSWORD}),
            404,
        )
        expect_error(
            await owner.post(f"{PASSKEYS}/{uuid4()}/delete", json={"password": PASSWORD}), 404
        )
        assert len((await stranger.get(PASSKEYS)).json()) == 1

    async def test_removing_a_passkey_needs_the_password_and_is_announced(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, first = await _passkey_owner(api)
        await register_passkey(owner, name="Spare")
        [kept, spare] = (await owner.get(PASSKEYS)).json()
        path = f"{PASSKEYS}/{spare['id']}/delete"
        expect_error(
            await owner.post(path, json={"password": "not-the-password!"}), 403, "invalid_password"
        )
        assert (await owner.post(path, json={"password": PASSWORD})).status_code == 204
        assert [p["id"] for p in (await owner.get(PASSKEYS)).json()] == [kept["id"]]
        assert await audit_metadata(admin_conn, owner.email, "auth.webauthn.removed") == [
            {"remaining": 1}
        ]
        assert "passkey_removed" in await security_emails(admin_conn, owner.email)
        assert (await sign_in(api, owner.email, first)).status_code == 200

    async def test_a_removed_passkey_no_longer_signs_in(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, _first = await _passkey_owner(api)
        spare, _ = await register_passkey(owner, name="Spare")
        [_, listed] = (await owner.get(PASSKEYS)).json()
        removed = await owner.post(f"{PASSKEYS}/{listed['id']}/delete", json={"password": PASSWORD})
        assert removed.status_code == 204
        expect_error(await sign_in(api, owner.email, spare), 401, "mfa_failed")
        assert await sign_in_refusals(admin_conn, owner.email) == ["credential_unknown"]

    async def test_the_last_second_factor_cannot_be_removed(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, _ = await _passkey_owner(api)
        [only] = (await owner.get(PASSKEYS)).json()
        refused = await owner.post(f"{PASSKEYS}/{only['id']}/delete", json={"password": PASSWORD})
        body = expect_error(refused, 409, "last_second_factor")
        assert "/auth/mfa/disable" in body["message"]
        assert len(await stored_passkeys(admin_conn, owner.email)) == 1
        assert (await owner.get("/api/v1/users/me")).json()["mfa_enabled"] is True

    async def test_with_an_authenticator_app_the_last_passkey_can_go(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner, _ = await _passkey_owner(api)
        enrolled = await owner.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD})
        assert enrolled.status_code == 200, enrolled.text
        totp = pyotp.TOTP(enrolled.json()["secret"])
        confirmed = await owner.post("/api/v1/auth/mfa/confirm", json={"code": totp.now()})
        assert confirmed.status_code == 200, confirmed.text
        challenge = await password_step(api, owner.email)
        assert challenge["methods"] == ["totp", "webauthn", "recovery_code"]

        [only] = (await owner.get(PASSKEYS)).json()
        removed = await owner.post(f"{PASSKEYS}/{only['id']}/delete", json={"password": PASSWORD})
        assert removed.status_code == 204, removed.text
        assert (await owner.get("/api/v1/users/me")).json()["mfa_enabled"] is True
        assert (await password_step(api, owner.email))["methods"] == ["totp", "recovery_code"]

    async def test_second_factors_change_only_from_a_session_that_passed_one(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        # Signed in on a second device before MFA was on: that session never passed it.
        laptop = session_from(
            api,
            await api.post(LOGIN, json={"email": owner.email, "password": PASSWORD}),
            owner.email,
        )
        await register_passkey(owner)
        await register_passkey(owner, name="Spare")
        [listed, _] = (await owner.get(PASSKEYS)).json()

        for response in (
            await laptop.post(REGISTER_BEGIN, json={"password": PASSWORD}),
            await laptop.post(f"{PASSKEYS}/{listed['id']}/delete", json={"password": PASSWORD}),
            await laptop.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD}),
        ):
            expect_error(response, 403, "mfa_session_required")
        assert len((await owner.get(PASSKEYS)).json()) == 2

    async def test_turning_mfa_off_removes_every_passkey_and_ends_every_session(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        _, registered = await register_passkey(owner)
        codes = registered["recovery_codes"]
        await register_passkey(owner, name="Spare")
        # Passkeys only: a six-digit code is simply wrong (no authenticator app).
        wrong = await owner.post(
            "/api/v1/auth/mfa/disable", json={"password": PASSWORD, "code": "123456"}
        )
        expect_error(wrong, 422, "invalid_code")
        disabled = await owner.post(
            "/api/v1/auth/mfa/disable", json={"password": PASSWORD, "code": codes[0]}
        )
        assert disabled.status_code == 204, disabled.text
        assert await stored_passkeys(admin_conn, owner.email) == []
        user_id = await user_id_of(admin_conn, owner.email)
        assert not await admin_conn.fetchval(
            "SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1", user_id
        )
        expect_error(await owner.get("/api/v1/users/me"), 401)  # signed out everywhere
        signed_in = await api.post(LOGIN, json={"email": owner.email, "password": PASSWORD})
        assert "access_token" in signed_in.json()  # no second factor any more
        [disabled_event] = await audit_metadata(admin_conn, owner.email, "auth.mfa.disabled")
        assert disabled_event == {"webauthn_removed": 2}


# ------------------------------------------- organizations, recovery, erasure


class TestAroundTheAccount:
    async def test_a_passkey_satisfies_an_organization_that_requires_mfa(
        self, api: httpx2.AsyncClient
    ) -> None:
        owner = await signup(api)
        org = "/api/v1/organizations/current"
        assert (await owner.patch(org, json={"settings": {"require_mfa": True}})).status_code == 200
        refused = expect_error(await owner.get(org), 403, "mfa_required")
        assert "/auth/webauthn/register/begin" in refused["message"]

        # Set-up mode: registering the first passkey opens the organization at once.
        authenticator, _ = await register_passkey(owner)
        assert (await owner.get(org)).status_code == 200

        # So does a new sign-in with password and passkey.
        signed_in = session_from(api, await sign_in(api, owner.email, authenticator), owner.email)
        assert (await signed_in.get(org)).status_code == 200
        [member] = (await signed_in.get("/api/v1/organizations/current/members")).json()["items"]
        assert member["mfa_enabled"] is True
        # A password alone gets no further than the second factor.
        assert (await password_step(api, owner.email))["mfa_required"] is True

    async def test_recovery_codes_still_sign_in_once_each(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        _, registered = await register_passkey(owner)
        code = registered["recovery_codes"][0]
        token = (await password_step(api, owner.email))["mfa_token"]
        used = await api.post("/api/v1/auth/mfa/verify", json={"mfa_token": token, "code": code})
        assert used.status_code == 200, used.text
        again = (await password_step(api, owner.email))["mfa_token"]
        reused = await api.post("/api/v1/auth/mfa/verify", json={"mfa_token": again, "code": code})
        expect_error(reused, 401, "mfa_failed")
        logins = await audit_metadata(admin_conn, owner.email, "auth.login.succeeded")
        assert logins[-1]["mfa_method"] == "recovery_code"

    async def test_erasing_an_account_deletes_its_passkeys(
        self, api: httpx2.AsyncClient, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        inviter = await container.authenticator.authenticate(owner.access_token)
        email = unique_email("leaver")
        invitation = await container.organizations.invite(
            inviter, email=email, role=Role.ANALYST, meta=META
        )
        raw = "invite-" + uuid4().hex
        await admin_conn.execute(
            "UPDATE invitations SET token_hash = $1 WHERE id = $2",
            container.token_hasher.hash(raw),
            invitation.id,
        )
        tokens = await container.auth.register_invited(
            token=raw, password=PASSWORD, full_name="Leaving Member", meta=META
        )
        member = ApiSession(api, tokens.access_token, tokens.refresh_token, email)
        await register_passkey(member)
        user_id = await user_id_of(admin_conn, email)
        assert len(await stored_passkeys(admin_conn, email)) == 1

        erased = await member.post("/api/v1/users/me/delete", json={"password": PASSWORD})
        assert erased.status_code == 204, erased.text
        assert not await admin_conn.fetchval(
            "SELECT count(*) FROM webauthn_credentials WHERE user_id = $1", user_id
        )
        assert not await admin_conn.fetchval("SELECT mfa_enabled FROM users WHERE id = $1", user_id)

    async def test_the_personal_data_export_lists_passkeys_without_keys(
        self, api: httpx2.AsyncClient, admin_conn: asyncpg.Connection
    ) -> None:
        owner, _ = await _passkey_owner(api)
        response = await owner.get("/api/v1/users/me/export")
        assert response.status_code == 200, response.text
        [exported] = response.json()["passkeys"]
        assert exported["name"] == "Laptop"
        assert set(exported) == {
            "id",
            "name",
            "created_at",
            "last_used_at",
            "transports",
            "backed_up",
        }
        [stored] = await stored_passkeys(admin_conn, owner.email)
        assert b64url(bytes(stored["public_key"])) not in response.text

    async def test_passkey_rows_are_visible_to_their_owner_only(
        self, api: httpx2.AsyncClient, app_conn: asyncpg.Connection, admin_conn: asyncpg.Connection
    ) -> None:
        owner, _ = await _passkey_owner(api)
        stranger, _ = await _passkey_owner(api)
        owner_id = await user_id_of(admin_conn, owner.email)
        stranger_id = await user_id_of(admin_conn, stranger.email)
        count = "SELECT count(*) FROM webauthn_credentials"
        await app_conn.execute(
            "SELECT set_config('app.current_user_id', '', false), "
            "set_config('app.current_org_id', '', false), "
            "set_config('app.auth_context', 'off', false)"
        )
        assert await app_conn.fetchval(count) == 0  # no context, no rows
        await app_conn.execute("SELECT set_config('app.current_user_id', $1, false)", str(owner_id))
        assert await app_conn.fetchval(count) == 1
        assert (
            await app_conn.fetchval(
                "SELECT count(*) FROM webauthn_credentials WHERE user_id = $1", stranger_id
            )
            == 0
        )
        # Nor can one be written for, or moved to, another account.
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app_conn.execute(
                "INSERT INTO webauthn_credentials (id, user_id, credential_id, user_handle, "
                "public_key, algorithm, sign_count, transports, name, backup_eligible, "
                "backed_up, created_at) VALUES ($1, $2, $3, $4, $5, -7, 0, '{}', 'x', false, "
                "false, now())",
                uuid4(),
                stranger_id,
                os.urandom(32),
                os.urandom(64),
                os.urandom(91),
            )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app_conn.execute("UPDATE webauthn_credentials SET user_id = $1", stranger_id)
        rls = await admin_conn.fetchrow(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE relname = 'webauthn_credentials'"
        )
        assert (rls["relrowsecurity"], rls["relforcerowsecurity"]) == (True, True)

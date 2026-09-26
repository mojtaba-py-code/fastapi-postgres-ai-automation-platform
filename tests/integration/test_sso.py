"""Single sign-on through an organization's OpenID Connect provider, end to end.

The API and the database are real; the identity provider is the in-process
fake of tests/support/oidc.py, reached through the platform's own OIDC client.
Covered: configuration (the secret never comes back, discovery must name the
issuer, only public HTTPS, viewer or analyst only, administrators' sessions
only), domain verification, just-in-time accounts and memberships, linking an
existing account and matching it by its subject later, every refusal of the
callback (state, binding, nonce, signature, algorithm, audience, times,
unverified or foreign addresses, a subject conflict), MFA from the provider or
the platform, the network allowlist, and the audit trail of all of it.
"""

from __future__ import annotations

import base64
import json
import os
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import httpx2
import pyotp
import pytest
import structlog
from fakeredis import FakeAsyncRedis
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine

from nexusflow.apps.cli.main import build_parser
from nexusflow.bootstrap.container import Container, build_container
from nexusflow.domain.shared.unit_of_work import TenantScope
from tests.conftest import make_settings
from tests.support.api import ApiSession, signup
from tests.support.business import expect_error, org_id_of, viewer_key
from tests.support.database import ProvisionedDatabase
from tests.support.fixtures import META, PASSWORD
from tests.support.oidc import (
    SSO,
    FakeIdp,
    FakeNetwork,
    configure,
    finish,
    fresh_domain,
    hmac_token,
    public_pem,
    ready,
    session_of,
    sign_in,
    start,
    unsigned_token,
    verify,
)

pytestmark = [pytest.mark.integration, pytest.mark.security]


def _platform(
    database: ProvisionedDatabase, root: Path, keys: dict[str, str], active: str
) -> Container:
    """Another instance of the platform on the same database, with its own keyring."""
    settings = make_settings(
        root,
        database={"url": database.app_url},
        app={"public_base_url": "https://nexusflow.test.example", "allowed_hosts": ["testserver"]},
        security={"encryption_keys": json.dumps(keys), "encryption_active_key_id": active},
    )
    engine = create_async_engine(database.app_url, pool_size=2, max_overflow=0)
    return build_container(
        settings, application_name="nexusflow-sso-rotation", engine=engine, redis=FakeAsyncRedis()
    )


async def _audit(owner: ApiSession, action: str) -> list[dict[str, Any]]:
    response = await owner.get("/api/v1/audit", params={"action": action})
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


async def _failures(owner: ApiSession) -> list[str]:
    """The reasons of the organization's failed single sign-ons, oldest first."""
    entries = await _audit(owner, "auth.sso.failed")
    return [entry["metadata"]["reason"] for entry in reversed(entries)]


async def _member_role(owner: ApiSession, email: str) -> str | None:
    members = (await owner.get("/api/v1/organizations/current/members")).json()["items"]
    return next((m["role"] for m in members if m["email"] == email), None)


# =============================================================== configuration


class TestConfiguration:
    async def test_the_secret_is_write_only_and_sealed(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        idp = network.add(FakeIdp())
        domain = fresh_domain()
        with structlog.testing.capture_logs() as logs:
            configured = await configure(owner, idp, [domain], default_role="analyst")
            read = await owner.get(SSO)
        assert configured.status_code == 200, configured.text
        body = configured.json()
        assert body["client_secret_set"] is True
        assert "client_secret" not in body
        assert body["redirect_uri"] == "https://nexusflow.test.example/sso/callback"
        assert body["default_role"] == "analyst"
        [status] = body["domains"]
        assert (status["domain"], status["verified"]) == (domain, False)
        assert status["txt_record_name"] == f"_nexusflow-verification.{domain}"
        assert status["txt_record_value"].startswith("nexusflow-verification=")
        for text in (configured.text, read.text, repr(logs)):
            assert idp.client_secret not in text
        # Stored sealed (AES-256-GCM, bound to the organization and row).
        stored = await admin_conn.fetchval(
            "SELECT client_secret_ciphertext FROM sso_connections WHERE client_id = $1",
            idp.client_id,
        )
        assert stored.startswith(b"NF") and idp.client_secret.encode() not in stored
        [event] = await _audit(owner, "sso.configured")
        assert event["metadata"]["secret_rotated"] is True
        assert idp.client_secret not in json.dumps(event)

    async def test_an_update_keeps_the_secret_unless_a_new_one_is_given(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        owner = await signup(api)
        domain = fresh_domain()
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        body = {"issuer": idp.issuer, "client_id": idp.client_id, "allowed_domains": [domain]}
        updated = await owner.client.put(SSO, json=body, headers=owner.headers)
        assert updated.status_code == 200, updated.text
        assert updated.json()["domains"][0]["verified"] is True  # same domain: still verified
        # Signing in still works: the stored secret was kept.
        response = await sign_in(api, idp, slug, email=f"keep@{domain}")
        assert response.status_code == 200, response.text
        [event] = await _audit(owner, "sso.updated")
        assert event["metadata"]["secret_rotated"] is False

    async def test_the_discovery_document_must_name_exactly_the_issuer(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        owner = await signup(api)
        idp = network.add(FakeIdp())
        idp.discovery_overrides["issuer"] = "https://login.attacker.example.com"
        expect_error(await configure(owner, idp, [fresh_domain()]), 422, "sso_discovery_failed")
        expect_error(await owner.get(SSO), 404, "sso_not_configured")

    @pytest.mark.parametrize(
        "issuer",
        [
            "http://idp.example.com",
            "https://10.1.2.3",
            "https://localhost",
            "https://idp.example.com:8443",
            "https://idp.example.com/?tenant=1",
        ],
    )
    async def test_the_issuer_must_be_a_public_https_url(
        self, api: httpx2.AsyncClient, network: FakeNetwork, issuer: str
    ) -> None:
        owner = await signup(api)
        idp = network.add(FakeIdp())
        body = {
            "issuer": issuer,
            "client_id": idp.client_id,
            "client_secret": idp.client_secret,
            "allowed_domains": [fresh_domain()],
        }
        expect_error(await owner.client.put(SSO, json=body, headers=owner.headers), 422)
        assert network.requests == []  # refused before any request

    @pytest.mark.parametrize("role", ["owner", "admin", "operator"])
    async def test_an_identity_provider_grants_viewer_or_analyst_only(
        self, api: httpx2.AsyncClient, network: FakeNetwork, role: str
    ) -> None:
        owner = await signup(api)
        idp = network.add(FakeIdp())
        response = await configure(owner, idp, [fresh_domain()], default_role=role)
        expect_error(response, 422, "invalid_default_role")

    async def test_only_an_administrators_session_configures_it(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        owner = await signup(api)
        idp = network.add(FakeIdp())
        body = {
            "issuer": idp.issuer,
            "client_id": idp.client_id,
            "client_secret": idp.client_secret,
            "allowed_domains": [fresh_domain()],
        }
        key = await api.post(
            "/api/v1/api-keys",
            json={"name": "k", "role": "admin", "scopes": ["org:update"], "expires_in_days": 1},
            headers=owner.headers,
        )
        headers = {"Authorization": f"Bearer {key.json()['token']}"}
        expect_error(await api.put(SSO, json=body, headers=headers), 403, "session_required")
        viewer = await viewer_key(owner, ["org:read"])
        expect_error(await api.put(SSO, json=body, headers=viewer), 403, "permission_denied")
        expect_error(await api.get(SSO, headers=viewer), 403, "permission_denied")

    async def test_domains_are_verified_by_their_txt_record(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        owner = await signup(api)
        idp = network.add(FakeIdp())
        verified, pending = fresh_domain(), fresh_domain()
        assert (await configure(owner, idp, [verified, pending])).status_code == 200
        checked = await owner.post(f"{SSO}/domains/verify")
        assert {c["result"] for c in checked.json()["checks"]} == {"record_not_found"}
        network.publish_txt(f"_nexusflow-verification.{verified}", "nexusflow-verification=forged")
        result = await verify(owner, network, verified)
        assert {c["domain"]: c["result"] for c in result["checks"]} == {
            verified: "verified",
            pending: "record_not_found",
        }
        again = (await owner.post(f"{SSO}/domains/verify")).json()
        assert {c["domain"]: c["result"] for c in again["checks"]}[verified] == "already_verified"
        [event] = await _audit(owner, "sso.domain_verified")
        assert event["metadata"] == {"domain": verified, "method": "dns"}
        network.resolver_down = True
        down = (await owner.post(f"{SSO}/domains/verify")).json()
        assert {c["domain"]: c["result"] for c in down["checks"]}[pending] == "lookup_failed"

    async def test_an_operator_can_confirm_a_domain(
        self, api: httpx2.AsyncClient, network: FakeNetwork, container: Container
    ) -> None:
        owner = await signup(api)
        idp = network.add(FakeIdp())
        domain = fresh_domain()
        assert (await configure(owner, idp, [domain])).status_code == 200
        org_id = await org_id_of(owner)
        args = build_parser().parse_args(
            [
                "sso",
                "verify-domain",
                "--org",
                str(org_id),
                "--domain",
                domain,
                "--reason",
                "DNS by phone",
            ]
        )
        result = await args.handler(container, args)
        assert result["verified_domains"] == [domain]
        [event] = await _audit(owner, "sso.domain_verified")
        assert event["actor_type"] == "system"
        assert event["metadata"] == {
            "domain": domain,
            "method": "operator",
            "reason": "DNS by phone",
        }

    async def test_requiring_sso_needs_a_verified_domain_and_cannot_lock_the_caller_out(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        owner = await signup(api)
        idp = network.add(FakeIdp())
        domain = fresh_domain()
        response = await configure(owner, idp, [domain], sso_required=True)
        expect_error(response, 422, "sso_domain_not_verified")
        assert (await configure(owner, idp, [domain])).status_code == 200
        await verify(owner, network, domain)
        # A password session without MFA would be shut out by its own change.
        response = await configure(owner, idp, [domain], sso_required=True)
        expect_error(response, 422, "would_lock_you_out")
        settings = (await owner.get("/api/v1/organizations/current")).json()["settings"]
        assert settings["sso_required"] is False

    async def test_sso_required_is_not_an_ordinary_setting(self, api: httpx2.AsyncClient) -> None:
        owner = await signup(api)
        response = await owner.patch(
            "/api/v1/organizations/current", json={"settings": {"sso_required": True}}
        )
        expect_error(response, 422, "validation_failed")

    async def test_key_rotation_rewraps_the_client_secret(
        self,
        api: httpx2.AsyncClient,
        network: FakeNetwork,
        container: Container,
        database: ProvisionedDatabase,
        tmp_path: Path,
    ) -> None:
        owner = await signup(api)
        idp = network.add(FakeIdp())
        assert (await configure(owner, idp, [fresh_domain()])).status_code == 200
        org_id = await org_id_of(owner)
        current = json.loads(container.settings.security.encryption_keys.get_secret_value())
        new_key = base64.b64encode(os.urandom(32)).decode()

        rotated = _platform(database, tmp_path, {**current, "kek-2": new_key}, "kek-2")
        try:
            before = await rotated.maintenance.still_under_old_keys(org_id, active_key_id="kek-2")
            assert before["sso_connections"] == 1
            assert await rotated.sso.rewrap(org_id, active_key_id="kek-2") == 1
            after = await rotated.maintenance.still_under_old_keys(org_id, active_key_id="kek-2")
            assert "sso_connections" not in after
        finally:
            await rotated.aclose()
        retired = _platform(database, tmp_path, {"kek-2": new_key}, "kek-2")
        try:  # the old key is gone: the secret still opens
            async with retired.uow_factory(TenantScope.system(org_id)) as uow:
                connection = await uow.sso_connections.get_for_org(org_id)
            assert connection is not None
            secret = retired.cipher.decrypt(
                connection.client_secret_ciphertext, context=connection.secret_context
            )
            assert secret == idp.client_secret
        finally:
            await retired.aclose()

    async def test_removing_the_provider_ends_its_sessions(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        owner = await signup(api)
        domain = fresh_domain()
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        member = session_of(api, await sign_in(api, idp, slug, email=f"m@{domain}"), f"m@{domain}")
        assert (await member.get("/api/v1/organizations/current")).status_code == 200
        removed = await owner.delete(SSO)
        assert removed.status_code == 204, removed.text
        expect_error(await member.get("/api/v1/organizations/current"), 401)
        refreshed = await api.post(
            "/api/v1/auth/refresh", json={"refresh_token": member.refresh_token}
        )
        expect_error(refreshed, 401, "invalid_refresh_token")
        [event] = await _audit(owner, "sso.removed")
        assert (
            event["metadata"]["sessions_revoked"],
            event["metadata"]["identities_unlinked"],
        ) == (
            1,
            1,
        )
        expect_error(await api.post("/api/v1/auth/sso/start", json={"organization": slug}), 404)


# ==================================================================== sign-in


class TestSignIn:
    async def test_a_new_person_gets_an_account_and_the_default_role_just_in_time(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        domain = fresh_domain()
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain, default_role="analyst")
        email = f"new.person@{domain}"
        response = await sign_in(api, idp, slug, email=email.upper(), name="New Person")
        member = session_of(api, response, email)
        org_id = await org_id_of(owner)
        assert response.json()["organization_id"] == str(org_id)
        me = (await member.get("/api/v1/users/me")).json()
        assert (me["email"], me["full_name"]) == (email, "New Person")
        assert await _member_role(owner, email) == "analyst"
        assert (await member.get("/api/v1/projects")).status_code == 200

        account = await admin_conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
        assert account["password_hash"] == "!"  # no password: nothing can verify against it
        assert account["email_verified_at"] is not None
        link = await admin_conn.fetchrow(
            "SELECT issuer, subject FROM sso_identities WHERE user_id = $1", account["id"]
        )
        assert link["issuer"] == idp.issuer
        session = await admin_conn.fetchrow(
            "SELECT sso_org_id, mfa_verified FROM user_sessions WHERE user_id = $1", account["id"]
        )
        assert (session["sso_org_id"], session["mfa_verified"]) == (org_id, False)
        # No password sign-in for such an account (until a reset sets one).
        login = await api.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        expect_error(login, 401, "invalid_credentials")

        for action in (
            "auth.sso.jit_user_created",
            "auth.sso.jit_membership_created",
            "auth.sso.identity_linked",
        ):
            assert len(await _audit(owner, action)) == 1, action
        [success] = await _audit(owner, "auth.sso.succeeded")
        assert success["metadata"] == {"mfa": False, "idp_mfa": False, "new_account": True}
        assert success["actor_id"] == str(account["id"])

    async def test_a_just_in_time_account_sets_a_password_with_a_reset(
        self,
        api: httpx2.AsyncClient,
        network: FakeNetwork,
        container: Container,
        admin_conn: asyncpg.Connection,
    ) -> None:
        owner = await signup(api)
        domain = fresh_domain()
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        email = f"no.password@{domain}"
        session_of(api, await sign_in(api, idp, slug, email=email), email)

        await container.auth.request_password_reset(email=email, meta=META)
        reset_id = await admin_conn.fetchval(
            "SELECT id FROM password_reset_tokens "
            "WHERE user_id = (SELECT id FROM users WHERE email = $1) AND used_at IS NULL",
            email,
        )
        assert reset_id is not None
        # As the mail worker does: the token itself is mailed, only its hash stored.
        raw_token = "reset-token-" + uuid4().hex
        await admin_conn.execute(
            "UPDATE password_reset_tokens SET token_hash = $1 WHERE id = $2",
            container.token_hasher.hash(raw_token),
            reset_id,
        )
        await container.auth.reset_password(token=raw_token, new_password=PASSWORD, meta=META)
        login = await api.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert login.status_code == 200, login.text

    async def test_an_existing_account_is_linked_then_found_by_its_subject(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        domain = fresh_domain()
        alice = await signup(api, email=f"alice@{domain}")  # owner of her own organization
        alice_id = (await alice.get("/api/v1/users/me")).json()["id"]
        owner = await signup(api)
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)

        first = await sign_in(api, idp, slug, email=f"alice@{domain}", sub="alice-subject")
        linked = session_of(api, first, alice.email)
        assert (await linked.get("/api/v1/users/me")).json()["id"] == alice_id
        assert await _member_role(owner, alice.email) == "viewer"
        [event] = await _audit(owner, "auth.sso.identity_linked")
        assert event["metadata"] == {"new_account": False}

        # The provider changed her address: the subject still finds the account.
        second = await sign_in(api, idp, slug, email=f"alice.new@{domain}", sub="alice-subject")
        again = session_of(api, second, alice.email)
        assert (await again.get("/api/v1/users/me")).json()["id"] == alice_id
        assert len(await _audit(owner, "auth.sso.identity_linked")) == 1

    async def test_an_existing_member_keeps_their_role(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        domain = fresh_domain()
        owner = await signup(api, email=f"owner@{domain}")
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        session = session_of(api, await sign_in(api, idp, slug, email=owner.email), owner.email)
        assert (await session.get("/api/v1/organizations/current")).status_code == 200
        assert await _member_role(owner, owner.email) == "owner"
        assert await _audit(owner, "auth.sso.jit_membership_created") == []

    async def test_the_session_reaches_its_organization_only(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        domain = fresh_domain()
        alice = await signup(api, email=f"alice@{domain}")
        own_org = await org_id_of(alice)
        owner = await signup(api)
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        sso = session_of(api, await sign_in(api, idp, slug, email=alice.email), alice.email)
        sso_org = await org_id_of(owner)

        organizations = (await sso.get("/api/v1/organizations")).json()
        assert [o["id"] for o in organizations] == [str(sso_org)]
        switched = await sso.post(
            "/api/v1/auth/switch-organization", json={"organization_id": str(own_org)}
        )
        expect_error(switched, 403, "sso_session_bound")
        renewed = await api.post("/api/v1/auth/refresh", json={"refresh_token": sso.refresh_token})
        assert renewed.json()["organization_id"] == str(sso_org)
        # Her password session is not confined.
        assert len((await alice.get("/api/v1/organizations")).json()) == 2

    async def test_an_address_linked_to_another_subject_is_not_taken_over(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        owner = await signup(api)
        domain = fresh_domain()
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        email = f"bob@{domain}"
        assert (await sign_in(api, idp, slug, email=email, sub="bob-1")).status_code == 200
        response = await sign_in(api, idp, slug, email=email, sub="impostor-2")
        expect_error(response, 401, "sso_failed")
        assert await _failures(owner) == ["identity_conflict"]

    @pytest.mark.parametrize(
        ("forge", "reason"),
        [
            (lambda idp, claims: unsigned_token(claims), "algorithm_not_allowed"),
            (
                lambda idp, claims: hmac_token(claims, public_pem(idp.keys["rsa-1"][0]), "rsa-1"),
                "algorithm_not_allowed",
            ),
            (lambda idp, claims: idp.sign({**claims, "aud": "other-client"}), "audience_mismatch"),
            (
                lambda idp, claims: idp.sign({**claims, "aud": [idp.client_id, "x"], "azp": "x"}),
                "authorized_party_mismatch",
            ),
            (
                lambda idp, claims: idp.sign({**claims, "exp": int(time.time()) - 600}),
                "id_token_expired",
            ),
            (lambda idp, claims: idp.sign({**claims, "nonce": "replayed"}), "nonce_mismatch"),
            (
                lambda idp, claims: idp.sign({**claims, "iss": "https://evil.example.com"}),
                "issuer_mismatch",
            ),
            (lambda idp, claims: FakeIdp().sign(claims), "invalid_signature"),
        ],
        ids=[
            "alg-none",
            "hs256-public-key",
            "audience",
            "azp",
            "expired",
            "nonce",
            "issuer",
            "signature",
        ],
    )
    async def test_an_id_token_that_does_not_verify_opens_nothing(
        self,
        api: httpx2.AsyncClient,
        network: FakeNetwork,
        admin_conn: asyncpg.Connection,
        forge: Any,
        reason: str,
    ) -> None:
        owner = await signup(api)
        domain = fresh_domain()
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        email = f"victim@{domain}"
        response = await sign_in(api, idp, slug, email=email, id_token=lambda c: forge(idp, c))
        body = expect_error(response, 401, "sso_failed")
        assert body["message"] == "Single sign-on failed. Start again."  # nothing more
        assert await _failures(owner) == [reason]
        assert await admin_conn.fetchval("SELECT count(*) FROM users WHERE email = $1", email) == 0

    async def test_an_unverified_address_is_refused(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        owner = await signup(api)
        domain = fresh_domain()
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        response = await sign_in(api, idp, slug, email=f"x@{domain}", email_verified=False)
        expect_error(response, 403, "sso_email_not_verified")
        assert await _failures(owner) == ["email_not_verified"]

    async def test_only_the_organizations_verified_domains_are_accepted(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        domain, pending = fresh_domain(), fresh_domain()
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        body = {
            "issuer": idp.issuer,
            "client_id": idp.client_id,
            "allowed_domains": [domain, pending],
        }
        assert (await owner.client.put(SSO, json=body, headers=owner.headers)).status_code == 200
        for email in (f"x@{pending}", "someone@gmail.com", f"x@sub.{domain}"):
            response = await sign_in(api, idp, slug, email=email)
            expect_error(response, 403, "sso_domain_not_allowed")
        assert await _failures(owner) == ["domain_not_allowed"] * 3
        assert (
            await admin_conn.fetchval(
                "SELECT count(*) FROM users WHERE email = ANY($1)",
                [f"x@{pending}", f"x@sub.{domain}"],
            )
            == 0
        )

    async def test_a_state_is_single_use_and_bound_to_the_client_that_started_it(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        domain = fresh_domain()
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        started = await start(api, slug)
        code = idp.authorize(started.authorization_url, email=f"c@{domain}")
        # Someone who saw the redirect (code and state) but not the binding.
        stolen = await finish(api, started, code, binding="x" * 43)
        expect_error(stolen, 401, "sso_failed")
        assert idp.token_requests == []  # refused before the provider was asked
        # The state was not spent: its client finishes the sign-in.
        assert (await finish(api, started, code)).status_code == 200
        replay = await finish(
            api, started, idp.authorize(started.authorization_url, email=f"c@{domain}")
        )
        expect_error(replay, 401, "sso_failed")
        assert await _failures(owner) == ["binding_mismatch", "state_reused"]
        unknown = await api.post(
            "/api/v1/auth/sso/callback",
            json={"code": "c", "state": "s" * 43, "binding": "b" * 43},
        )
        expect_error(unknown, 401, "sso_failed")
        platform = await admin_conn.fetchval(
            "SELECT count(*) FROM audit_logs WHERE org_id IS NULL AND action = 'auth.sso.failed'"
            " AND metadata->>'reason' = 'unknown_state'"
        )
        assert platform >= 1

    async def test_an_expired_state_is_refused(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        domain = fresh_domain()
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        started = await start(api, slug)
        await admin_conn.execute(
            "UPDATE sso_login_states SET expires_at = now() - interval '1 minute'"
            " WHERE org_id = $1",
            await org_id_of(owner),
        )
        response = await finish(api, started, idp.authorize(started.authorization_url))
        expect_error(response, 401, "sso_failed")
        assert await _failures(owner) == ["state_expired"]

    async def test_what_is_stored_for_a_started_sign_in(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        idp = FakeIdp()
        slug = await ready(owner, network, idp, fresh_domain())
        started = await start(api, slug)
        row = await admin_conn.fetchrow(
            "SELECT * FROM sso_login_states WHERE org_id = $1", await org_id_of(owner)
        )
        stored = json.dumps({k: str(v) for k, v in dict(row).items()})
        assert started.state not in stored and started.binding not in stored  # keyed hashes
        assert row["code_verifier_ciphertext"].startswith(b"NF")  # sealed
        assert (row["expires_at"] - row["created_at"]).total_seconds() == 600

    async def test_started_sign_ins_are_deleted_a_week_after_they_expire(
        self,
        api: httpx2.AsyncClient,
        network: FakeNetwork,
        container: Container,
        admin_conn: asyncpg.Connection,
    ) -> None:
        owner = await signup(api)
        slug = await ready(owner, network, FakeIdp(), fresh_domain())
        await start(api, slug)
        await start(api, slug)
        org_id = await org_id_of(owner)
        [old, recent] = [
            r["id"]
            for r in await admin_conn.fetch(
                "SELECT id FROM sso_login_states WHERE org_id = $1 ORDER BY id", org_id
            )
        ]
        await admin_conn.execute(
            "UPDATE sso_login_states SET expires_at = now() - interval '8 days' WHERE id = $1",
            old,
        )
        purged = await container.maintenance.apply_identity_retention()
        assert purged["sso_login_states"] >= 1
        left = await admin_conn.fetch("SELECT id FROM sso_login_states WHERE org_id = $1", org_id)
        assert [r["id"] for r in left] == [recent]

    async def test_start_answers_alike_for_every_organization_without_sso(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        plain = await signup(api)
        pending = await signup(api)
        assert (
            await configure(pending, network.add(FakeIdp()), [fresh_domain()])
        ).status_code == 200
        answers = []
        for slug in (
            "no-such-organization-here",
            (await plain.get("/api/v1/organizations/current")).json()["slug"],
            (await pending.get("/api/v1/organizations/current")).json()["slug"],  # none verified
            "Not A Slug!",
        ):
            response = await api.post("/api/v1/auth/sso/start", json={"organization": slug})
            answers.append(
                (response.status_code, response.json()["error"], response.json()["message"])
            )
        assert len(set(answers)) == 1
        assert answers[0][:2] == (404, "sso_not_available")

    async def test_an_identity_provider_outage_is_temporary(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        owner = await signup(api)
        idp = FakeIdp()
        slug = await ready(owner, network, idp, fresh_domain())
        idp.token_status = 503
        expect_error(await sign_in(api, idp, slug), 503, "sso_unavailable")
        assert await _failures(owner) == ["provider_unavailable"]

    async def test_the_start_and_callback_are_rate_limited_per_address(
        self, api: httpx2.AsyncClient, network: FakeNetwork, container: Container
    ) -> None:
        owner = await signup(api)
        slug = await ready(owner, network, FakeIdp(), fresh_domain())
        rules = container.settings.rate_limits.rules
        for scope in ("auth.sso.start", "auth.sso.callback"):
            assert rules[scope].fail_closed
            for _ in range(rules[scope].limit):
                await container.limiter.hit(scope, "127.0.0.1", rules[scope])
        expect_error(await api.post("/api/v1/auth/sso/start", json={"organization": slug}), 429)
        callback = {"code": "c", "state": "s" * 43, "binding": "b" * 43}
        expect_error(await api.post("/api/v1/auth/sso/callback", json=callback), 429)


# ========================================================================= MFA


class TestMfa:
    async def test_the_providers_mfa_counts_only_when_trusted_and_reported(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        owner = await signup(api)
        domain = fresh_domain()
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        await owner.patch("/api/v1/organizations/current", json={"settings": {"require_mfa": True}})
        # The owner's own session now needs MFA too; switch to trusting the provider
        # through the service (the owner has no MFA to reach the API with).
        email = f"mfa@{domain}"
        refused = await sign_in(api, idp, slug, email=email, amr=["pwd", "mfa"])
        expect_error(refused, 403, "mfa_required")  # reported, but not trusted
        assert await admin_conn.fetchval("SELECT count(*) FROM users WHERE email = $1", email) == 0

        org_id = await org_id_of_admin(admin_conn, slug)
        await admin_conn.execute(
            "UPDATE sso_connections SET trust_idp_mfa = true WHERE org_id = $1", org_id
        )
        expect_error(await sign_in(api, idp, slug, email=email, amr=["pwd"]), 403, "mfa_required")
        trusted = session_of(
            api, await sign_in(api, idp, slug, email=email, amr=["pwd", "hwk"]), email
        )
        assert (await trusted.get("/api/v1/projects")).status_code == 200
        [session] = (await trusted.get("/api/v1/users/me/sessions")).json()
        assert session["mfa_verified"] is True

    async def test_the_platforms_own_second_factor_completes_a_sso_sign_in(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        domain = fresh_domain()
        alice = await signup(api, email=f"alice@{domain}")
        enrolled = await alice.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD})
        confirmed = await alice.post(
            "/api/v1/auth/mfa/confirm",
            json={"code": pyotp.TOTP(enrolled.json()["secret"]).now()},
        )
        recovery = confirmed.json()["recovery_codes"][0]
        owner = await signup(api)
        idp = FakeIdp()
        slug = await ready(owner, network, idp, domain)
        await owner.patch("/api/v1/organizations/current", json={"settings": {"require_mfa": True}})

        challenge = await sign_in(api, idp, slug, email=alice.email)
        assert challenge.status_code == 200, challenge.text
        body = challenge.json()
        assert body["mfa_required"] is True and "access_token" not in body
        verified = await api.post(
            "/api/v1/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "code": recovery}
        )
        session = session_of(api, verified, alice.email)
        assert (await session.get("/api/v1/projects")).status_code == 200
        # A single sign-on session, bound to the organization - not a password one.
        own_org = await org_id_of(alice)
        switched = await session.post(
            "/api/v1/auth/switch-organization", json={"organization_id": str(own_org)}
        )
        expect_error(switched, 403, "sso_session_bound")
        stored = await admin_conn.fetchval(
            "SELECT sso_org_id FROM user_sessions WHERE id = ("
            " SELECT session_id FROM refresh_tokens WHERE user_id ="
            " (SELECT id FROM users WHERE email = $1) ORDER BY issued_at DESC LIMIT 1)",
            alice.email,
        )
        assert stored == UUID(verified.json()["organization_id"])


async def org_id_of_admin(admin_conn: asyncpg.Connection, slug: str) -> UUID:
    org_id: UUID = await admin_conn.fetchval("SELECT id FROM organizations WHERE slug = $1", slug)
    return org_id


# ============================================================ network allowlist


OFFICE, HOME = "203.0.113.10", "198.51.100.20"


@pytest.fixture
async def office(api_app: FastAPI, container: Container) -> AsyncIterator[httpx2.AsyncClient]:
    await container.redis.flushall()
    transport = httpx2.ASGITransport(app=api_app, client=(OFFICE, 40_000))
    async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.fixture
async def home(api_app: FastAPI) -> AsyncIterator[httpx2.AsyncClient]:
    transport = httpx2.ASGITransport(app=api_app, client=(HOME, 40_000))
    async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


async def test_the_network_allowlist_applies_to_single_sign_on(
    office: httpx2.AsyncClient, home: httpx2.AsyncClient, network: FakeNetwork
) -> None:
    owner = await signup(office)
    domain = fresh_domain()
    idp = FakeIdp()
    slug = await ready(owner, network, idp, domain)
    restricted = await owner.patch(
        "/api/v1/organizations/current",
        json={"settings": {"allowed_ip_ranges": ["203.0.113.0/24"]}},
    )
    assert restricted.status_code == 200, restricted.text
    email = f"far@{domain}"
    expect_error(await sign_in(home, idp, slug, email=email), 403, "ip_not_allowed")
    [failed] = await _audit(owner, "auth.sso.failed")
    assert (failed["metadata"]["reason"], failed["ip"]) == ("network_not_allowed", HOME)
    members = (await owner.get("/api/v1/organizations/current/members")).json()["items"]
    assert email not in {m["email"] for m in members}  # refused before anything was created
    assert (await sign_in(office, idp, slug, email=f"near@{domain}")).status_code == 200

"""SCIM 2.0 provisioning (RFC 7643/7644) of an organization's members.

Tokens (owners only, shown once, keyed hashes, revocable, never valid on the
rest of the API), the discovery endpoints, provisioning (accounts without
passwords, memberships with the default role, existing accounts linked),
filters and pagination, replace and patch (Okta and Microsoft Entra ID
shapes), deprovisioning (membership removed, API keys revoked, sessions for
the organization unusable, the account never deleted, owners never touched),
malformed and oversized requests, the rate limit and tenant isolation.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import httpx2
import pytest

from nexusflow.bootstrap.container import Container
from tests.support.api import ApiSession, signup
from tests.support.business import expect_error, org_id_of
from tests.support.fixtures import META
from tests.support.oidc import FakeIdp, FakeNetwork, fresh_domain, ready, session_of, sign_in

pytestmark = [pytest.mark.integration, pytest.mark.security]

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
TOKENS = "/api/v1/organizations/current/scim-tokens"
USERS = "/scim/v2/Users"
ORG = "/api/v1/organizations/current"


class Scim:
    """A SCIM client with one organization's token."""

    def __init__(self, client: httpx2.AsyncClient, token: str) -> None:
        self.client = client
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/scim+json",
            "Accept": "application/scim+json",
        }

    async def get(self, path: str, **params: Any) -> httpx2.Response:
        return await self.client.get(path, params=params or None, headers=self.headers)

    async def post(self, path: str, body: Any) -> httpx2.Response:
        return await self.client.post(path, content=json.dumps(body), headers=self.headers)

    async def put(self, path: str, body: Any) -> httpx2.Response:
        return await self.client.put(path, content=json.dumps(body), headers=self.headers)

    async def patch(self, path: str, *operations: dict[str, Any]) -> httpx2.Response:
        body = {"schemas": [PATCH_SCHEMA], "Operations": list(operations)}
        return await self.client.patch(path, content=json.dumps(body), headers=self.headers)

    async def delete(self, path: str) -> httpx2.Response:
        return await self.client.delete(path, headers=self.headers)


def user(email: str, **extra: Any) -> dict[str, Any]:
    return {
        "schemas": [USER_SCHEMA],
        "userName": email,
        "name": {"givenName": "Grace", "familyName": "Hopper"},
        "displayName": "Grace Hopper",
        "emails": [{"value": email, "type": "work", "primary": True}],
        "active": True,
        **extra,
    }


def scim_error(response: httpx2.Response, status: int, scim_type: str | None = None) -> dict:
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith("application/scim+json")
    body: dict[str, Any] = response.json()
    assert body["schemas"] == [ERROR_SCHEMA]
    assert body["status"] == str(status)
    assert body.get("scimType") == scim_type, body
    return body


class Directory:
    def __init__(self, owner: ApiSession, scim: Scim, domain: str, idp: FakeIdp, slug: str) -> None:
        self.owner, self.scim, self.domain, self.idp, self.slug = owner, scim, domain, idp, slug

    def email(self, name: str) -> str:
        return f"{name}@{self.domain}"

    async def provision(self, name: str, **extra: Any) -> dict[str, Any]:
        response = await self.scim.post(USERS, user(self.email(name), **extra))
        assert response.status_code == 201, response.text
        body: dict[str, Any] = response.json()
        return body

    async def role_of(self, email: str) -> str | None:
        members = (await self.owner.get(f"{ORG}/members")).json()["items"]
        return next((m["role"] for m in members if m["email"] == email), None)

    async def audit(self, action: str) -> list[dict[str, Any]]:
        response = await self.owner.get("/api/v1/audit", params={"action": action})
        items: list[dict[str, Any]] = response.json()["items"]
        return items


async def _directory(api: httpx2.AsyncClient, network: FakeNetwork) -> Directory:
    domain = fresh_domain()
    owner = await signup(api, email=f"owner@{domain}")
    idp = FakeIdp()
    slug = await ready(owner, network, idp, domain, default_role="analyst")
    created = await owner.post(TOKENS, json={"name": "Okta", "expires_in_days": 30})
    assert created.status_code == 201, created.text
    return Directory(owner, Scim(api, created.json()["token"]), domain, idp, slug)


# ======================================================================= tokens


class TestTokens:
    async def test_an_owner_creates_a_token_shown_once_and_stored_as_a_keyed_hash(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        directory = await _directory(api, network)
        token = directory.scim.token
        assert token.startswith("nxp_") and len(token) == 66  # nxp_ + prefix_ + secret + crc
        [listed] = (await directory.owner.get(TOKENS)).json()
        assert "token" not in listed and token[4:16] == listed["prefix"]
        stored = await admin_conn.fetchrow(
            "SELECT token_hash, token_prefix FROM scim_tokens WHERE token_prefix = $1",
            listed["prefix"],
        )
        assert len(stored["token_hash"]) == 64 and token not in stored["token_hash"]
        [event] = await directory.audit("scim.token_created")
        assert event["metadata"] == {
            "name": "Okta",
            "prefix": listed["prefix"],
            "expires_in_days": 30,
        }
        assert token not in json.dumps(event)
        assert (await directory.scim.get("/scim/v2/ServiceProviderConfig")).status_code == 200

    async def test_only_an_owners_signed_in_session_manages_tokens(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        email = directory.email("admin")
        admin = session_of(
            api, await sign_in(api, directory.idp, directory.slug, email=email), email
        )
        members = (await directory.owner.get(f"{ORG}/members")).json()["items"]
        [membership] = [m for m in members if m["email"] == email]
        await directory.owner.patch(
            f"{ORG}/members/{membership['membership_id']}", json={"role": "admin"}
        )
        expect_error(await admin.post(TOKENS, json={"name": "x"}), 403, "owner_required")
        expect_error(await admin.get(TOKENS), 403, "owner_required")
        key = await directory.owner.post(
            "/api/v1/api-keys",
            json={"name": "k", "role": "owner", "scopes": ["org:update"], "expires_in_days": 1},
        )
        headers = {"Authorization": f"Bearer {key.json()['token']}"}
        response = await api.post(TOKENS, json={"name": "x"}, headers=headers)
        expect_error(response, 403, "session_required")

    async def test_a_revoked_or_expired_token_stops_working(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        directory = await _directory(api, network)
        second = await directory.owner.post(TOKENS, json={"name": "Entra"})
        entra = Scim(api, second.json()["token"])
        [okta, _] = sorted(
            (await directory.owner.get(TOKENS)).json(), key=lambda t: t["name"] != "Okta"
        )
        assert (await directory.owner.delete(f"{TOKENS}/{okta['id']}")).status_code == 204
        response = await directory.scim.get(USERS)
        scim_error(response, 401)
        assert response.headers["www-authenticate"].startswith("Bearer")
        assert len(await directory.audit("scim.token_revoked")) == 1
        await admin_conn.execute(
            "UPDATE scim_tokens SET expires_at = now() - interval '1 second' WHERE id = $1",
            UUID(second.json()["id"]),
        )
        scim_error(await entra.get(USERS), 401)

    async def test_tokens_and_the_rest_of_the_api_never_mix(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        scim_headers = {"Authorization": f"Bearer {directory.scim.token}"}
        for path in ("/api/v1/projects", "/api/v1/users/me", ORG):
            expect_error(await api.get(path, headers=scim_headers), 401)
        # ... and neither a user's access token nor an API key works on SCIM.
        key = await directory.owner.post(
            "/api/v1/api-keys",
            json={"name": "k", "role": "viewer", "scopes": ["projects:read"], "expires_in_days": 1},
        )
        for credential in (directory.owner.access_token, key.json()["token"], "garbage"):
            response = await api.get(USERS, headers={"Authorization": f"Bearer {credential}"})
            scim_error(response, 401)
        scim_error(await api.get(USERS), 401)

    async def test_an_organization_has_at_most_ten_live_tokens(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        for index in range(9):
            created = await directory.owner.post(TOKENS, json={"name": f"t{index}"})
            assert created.status_code == 201, created.text
        expect_error(
            await directory.owner.post(TOKENS, json={"name": "t10"}), 409, "too_many_tokens"
        )


# ==================================================================== discovery


async def test_the_discovery_endpoints_describe_the_service(
    api: httpx2.AsyncClient, network: FakeNetwork
) -> None:
    directory = await _directory(api, network)
    config = await directory.scim.get("/scim/v2/ServiceProviderConfig")
    assert config.headers["content-type"].startswith("application/scim+json")
    body = config.json()
    assert (body["patch"], body["bulk"]["supported"], body["filter"]) == (
        {"supported": True},
        False,
        {"supported": True, "maxResults": 200},
    )
    assert body["authenticationSchemes"][0]["type"] == "oauthbearertoken"
    types = (await directory.scim.get("/scim/v2/ResourceTypes")).json()
    assert (types["totalResults"], types["Resources"][0]["schema"]) == (1, USER_SCHEMA)
    assert (await directory.scim.get("/scim/v2/ResourceTypes/User")).json()["endpoint"] == "/Users"
    schemas = (await directory.scim.get("/scim/v2/Schemas")).json()
    names = {a["name"] for a in schemas["Resources"][0]["attributes"]}
    assert names == {"userName", "name", "displayName", "emails", "active", "externalId"}
    schema = (await directory.scim.get(f"/scim/v2/Schemas/{USER_SCHEMA}")).json()
    assert schema["id"] == USER_SCHEMA
    scim_error(await directory.scim.get("/scim/v2/Schemas/urn:other"), 404)
    scim_error(await directory.scim.get("/scim/v2/ResourceTypes/Group"), 404)


# ================================================================= provisioning


class TestProvisioning:
    async def test_a_new_person_gets_an_account_without_password_and_the_default_role(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        directory = await _directory(api, network)
        email = directory.email("grace")
        response = await directory.scim.post(USERS, user(email.upper(), externalId="okta-1"))
        assert response.status_code == 201, response.text
        body = response.json()
        assert response.headers["location"] == body["meta"]["location"]
        assert body["meta"]["location"].endswith(f"/scim/v2/Users/{body['id']}")
        assert (body["userName"], body["externalId"], body["active"]) == (email, "okta-1", True)
        assert body["name"] == {"givenName": "Grace", "familyName": "Hopper"}
        assert body["emails"] == [{"value": email, "type": "work", "primary": True}]
        assert await directory.role_of(email) == "analyst"
        account = await admin_conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
        assert (account["password_hash"], account["full_name"]) == ("!", "Grace Hopper")
        [created] = await directory.audit("scim.user_created")
        assert created["actor_type"] == "scim"
        assert created["metadata"]["account_created"] is True
        [joined] = await directory.audit("member.joined")
        assert joined["metadata"] == {
            "user_id": str(account["id"]),
            "role": "analyst",
            "via": "scim",
        }
        # The person signs in through the organization's provider into this account.
        signed_in = session_of(
            api, await sign_in(api, directory.idp, directory.slug, email=email), email
        )
        assert (await signed_in.get("/api/v1/users/me")).json()["id"] == str(account["id"])
        fetched = await directory.scim.get(f"{USERS}/{body['id']}")
        assert fetched.json() == body

    async def test_an_existing_account_is_linked_and_a_member_keeps_their_role(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        outsider = await signup(api, email=directory.email("outsider"))
        owner = await directory.provision("owner")
        assert owner["userName"] == directory.owner.email
        assert await directory.role_of(directory.owner.email) == "owner"
        await directory.provision("outsider")
        assert await directory.role_of(outsider.email) == "analyst"
        [_, linked] = await directory.audit("scim.user_created")
        assert linked["metadata"]["account_created"] is False

    async def test_a_second_entry_for_one_person_or_one_external_id_is_a_conflict(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        await directory.provision("ada", externalId="ext-7")
        again = await directory.scim.post(USERS, user(directory.email("ADA")))
        scim_error(again, 409, "uniqueness")
        taken = await directory.scim.post(USERS, user(directory.email("bob"), externalId="ext-7"))
        scim_error(taken, 409, "uniqueness")

    async def test_addresses_outside_the_verified_domains_are_refused(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        directory = await _directory(api, network)
        for email in ("ceo@victim.example.com", f"x@sub.{directory.domain}", "not-an-address"):
            response = await directory.scim.post(USERS, user(email))
            scim_error(response, 400, "invalidValue")
        assert (
            await admin_conn.fetchval(
                "SELECT count(*) FROM users WHERE email = 'ceo@victim.example.com'"
            )
            == 0
        )
        refused = await directory.audit("scim.request_refused")
        assert [e["metadata"]["reason"] for e in refused] == ["domain_not_verified"] * 2
        assert {e["result"] for e in refused} == {"denied"}

    async def test_passwords_are_refused_and_server_attributes_are_never_taken(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        email = directory.email("eve")
        with_password = await directory.scim.post(USERS, user(email, password="Hunter2!Hunter2!"))
        scim_error(with_password, 400, "invalidValue")
        forced_id = str(uuid4())
        smuggled = user(
            email,
            id=forced_id,
            meta={"created": "1999-01-01T00:00:00Z"},
            roles=[{"value": "owner", "primary": True}],
            groups=[{"value": "admins"}],
            is_platform_admin=True,
            org_id=str(uuid4()),
            **{
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                    "department": "Security"
                }
            },
        )
        created = await directory.scim.post(USERS, smuggled)
        assert created.status_code == 201, created.text
        assert created.json()["id"] != forced_id
        assert await directory.role_of(email) == "analyst"


# ============================================================ filters and paging


class TestListing:
    async def test_filters_on_user_name_external_id_and_email(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        ada = await directory.provision("ada", externalId="Ext-Ada")
        await directory.provision("bob")
        scim = directory.scim
        for expression in (
            f'userName eq "{directory.email("ADA")}"',
            'externalId eq "Ext-Ada"',
            f'emails.value eq "{directory.email("ada")}"',
            f'{USER_SCHEMA}:userName eq "{directory.email("ada")}"',
        ):
            found = (await scim.get(USERS, filter=expression)).json()
            assert (found["totalResults"], found["Resources"][0]["id"]) == (1, ada["id"]), (
                expression
            )
        assert (await scim.get(USERS, filter='externalId eq "ext-ada"')).json()["totalResults"] == 0
        nobody = (await scim.get(USERS, filter='userName eq "nobody@example.com"')).json()
        assert (nobody["totalResults"], nobody["Resources"]) == (0, [])
        assert (await scim.get(USERS)).json()["totalResults"] == 2

    @pytest.mark.parametrize(
        "expression",
        [
            'userName co "ada"',
            'userName sw "a"',
            'title eq "boss"',
            'name.givenName eq "Ada"',
            'userName eq "a" or userName eq "b"',
            "userName eq ada",
            'userName eq "unterminated',
            "userName pr",
            'active eq "true"',
        ],
    )
    async def test_every_other_filter_is_refused(
        self, api: httpx2.AsyncClient, network: FakeNetwork, expression: str
    ) -> None:
        directory = await _directory(api, network)
        scim_error(await directory.scim.get(USERS, filter=expression), 400, "invalidFilter")

    async def test_pagination_is_by_start_index_and_capped_count(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        ids = [(await directory.provision(name))["id"] for name in ("a1", "a2", "a3")]
        scim = directory.scim
        first = (await scim.get(USERS, startIndex=1, count=2)).json()
        assert (first["totalResults"], first["startIndex"], first["itemsPerPage"]) == (3, 1, 2)
        last = (await scim.get(USERS, startIndex=3, count=2)).json()
        assert [r["id"] for r in first["Resources"] + last["Resources"]] == ids
        counted = (await scim.get(USERS, count=0)).json()
        assert (counted["totalResults"], counted["Resources"]) == (3, [])
        assert (await scim.get(USERS, startIndex=-5, count=1)).json()["startIndex"] == 1
        beyond = (await scim.get(USERS, startIndex=10**12)).json()
        assert (beyond["totalResults"], beyond["Resources"]) == (3, [])
        capped = (await scim.get(USERS, count=10_000)).json()
        assert capped["itemsPerPage"] == 3
        scim_error(await scim.get(USERS, count="many"), 400, "invalidValue")


# ================================================================ replace, patch


class TestChanges:
    async def test_replace_and_patch_change_the_directory_entry(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        entry = await directory.provision("ada")
        path = f"{USERS}/{entry['id']}"
        scim = directory.scim
        replaced = await scim.put(
            path,
            {
                "schemas": [USER_SCHEMA],
                "userName": directory.email("ada"),
                "externalId": "00u1",
                "name": {"formatted": "Ada King", "givenName": "Ada"},
                "active": True,
            },
        )
        assert replaced.status_code == 200, replaced.text
        body = replaced.json()
        assert (body["externalId"], body["name"]) == (
            "00u1",
            {"formatted": "Ada King", "givenName": "Ada"},
        )
        assert "displayName" not in body  # a replace clears what it leaves out
        # Okta: no path, a value object.
        okta = await scim.patch(
            path,
            {"op": "replace", "value": {"displayName": "Ada L.", "name.familyName": "Lovelace"}},
        )
        assert (okta.json()["displayName"], okta.json()["name"]["familyName"]) == (
            "Ada L.",
            "Lovelace",
        )
        # Microsoft Entra ID: capitalised ops, paths, filtered e-mail paths.
        entra = await scim.patch(
            path,
            {"op": "Replace", "path": "name.givenName", "value": "Augusta"},
            {"op": "Add", "path": 'emails[type eq "work"].value', "value": directory.email("ada")},
            {"op": "Replace", "path": "title", "value": "Countess"},  # not kept: ignored
        )
        assert entra.status_code == 200, entra.text
        assert entra.json()["name"]["givenName"] == "Augusta"
        [update, *_] = await directory.audit("scim.user_updated")
        assert update["metadata"]["changed"] == ["name.givenName"]

    async def test_the_address_cannot_be_changed_by_scim(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        entry = await directory.provision("ada")
        path = f"{USERS}/{entry['id']}"
        moved = await directory.scim.put(path, user(directory.email("someone-else")))
        scim_error(moved, 400, "mutability")
        patched = await directory.scim.patch(
            path, {"op": "replace", "path": "userName", "value": directory.email("x")}
        )
        scim_error(patched, 400, "mutability")

    @pytest.mark.parametrize(
        ("operation", "scim_type"),
        [
            ({"op": "remove", "path": "displayName"}, "invalidValue"),
            ({"op": "replace", "path": "password", "value": "Hunter2!Hunter2!"}, "invalidValue"),
            ({"op": "replace", "path": "nosuchattribute", "value": 1}, "invalidPath"),
            ({"op": "replace", "path": "active", "value": "maybe"}, "invalidValue"),
            ({"op": "replace", "path": "displayName", "value": {"nested": 1}}, "invalidValue"),
            ({"op": "replace", "value": "not-an-object"}, "invalidValue"),
        ],
    )
    async def test_unsupported_or_invalid_operations_are_refused(
        self,
        api: httpx2.AsyncClient,
        network: FakeNetwork,
        operation: dict[str, Any],
        scim_type: str,
    ) -> None:
        directory = await _directory(api, network)
        entry = await directory.provision("ada")
        scim_error(await directory.scim.patch(f"{USERS}/{entry['id']}", operation), 400, scim_type)


# ============================================================== deprovisioning


class TestDeprovisioning:
    async def test_deactivation_removes_the_membership_revokes_keys_and_ends_access(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        directory = await _directory(api, network)
        entry = await directory.provision("ada")
        email = directory.email("ada")
        member = session_of(
            api, await sign_in(api, directory.idp, directory.slug, email=email), email
        )
        members = (await directory.owner.get(f"{ORG}/members")).json()["items"]
        [membership] = [m for m in members if m["email"] == email]
        await directory.owner.patch(
            f"{ORG}/members/{membership['membership_id']}", json={"role": "admin"}
        )
        key = await member.post(
            "/api/v1/api-keys",
            json={"name": "k", "role": "viewer", "scopes": ["projects:read"], "expires_in_days": 1},
        )
        key_headers = {"Authorization": f"Bearer {key.json()['token']}"}
        assert (await api.get("/api/v1/projects", headers=key_headers)).status_code == 200

        # Microsoft Entra ID sends booleans as strings.
        deactivated = await directory.scim.patch(
            f"{USERS}/{entry['id']}", {"op": "Replace", "path": "active", "value": "False"}
        )
        assert deactivated.status_code == 200, deactivated.text
        assert deactivated.json()["active"] is False
        assert await directory.role_of(email) is None
        expect_error(await api.get("/api/v1/projects", headers=key_headers), 401)
        assert await admin_conn.fetchval(
            "SELECT revoked_at IS NOT NULL FROM api_keys WHERE name = 'k' AND created_by ="
            " (SELECT id FROM users WHERE email = $1)",
            email,
        )
        expect_error(await member.get(ORG), 401)  # the organization's session is unusable
        refreshed = await api.post(
            "/api/v1/auth/refresh", json={"refresh_token": member.refresh_token}
        )
        expect_error(refreshed, 401, "invalid_refresh_token")
        # Signing in through the provider does not undo the directory.
        again = await sign_in(api, directory.idp, directory.slug, email=email)
        expect_error(again, 403, "sso_access_revoked")
        [removed] = await directory.audit("member.removed")
        assert removed["metadata"]["via"] == "scim"
        assert removed["metadata"]["api_keys_revoked"] == 1
        assert len(await directory.audit("scim.user_deactivated")) == 1

        # Reactivated: a member again, with the default role (roles live in the app).
        reactivated = await directory.scim.patch(
            f"{USERS}/{entry['id']}", {"op": "replace", "value": {"active": True}}
        )
        assert reactivated.json()["active"] is True
        assert await directory.role_of(email) == "analyst"
        assert len(await directory.audit("scim.user_reactivated")) == 1

    async def test_delete_removes_the_entry_and_membership_never_the_account(
        self, api: httpx2.AsyncClient, network: FakeNetwork, admin_conn: asyncpg.Connection
    ) -> None:
        directory = await _directory(api, network)
        person = await signup(api, email=directory.email("carol"))  # also owns her own org
        entry = await directory.provision("carol")
        assert (await directory.scim.delete(f"{USERS}/{entry['id']}")).status_code == 204
        scim_error(await directory.scim.get(f"{USERS}/{entry['id']}"), 404)
        scim_error(await directory.scim.delete(f"{USERS}/{entry['id']}"), 404)
        assert await directory.role_of(person.email) is None
        assert (
            await admin_conn.fetchval("SELECT status FROM users WHERE email = $1", person.email)
            == "active"
        )
        assert (await person.get(ORG)).status_code == 200  # her own organization is untouched
        assert len(await directory.audit("scim.user_deleted")) == 1

    async def test_owners_are_never_deactivated_or_removed_by_scim(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        entry = await directory.provision("owner")
        path = f"{USERS}/{entry['id']}"
        scim_error(
            await directory.scim.patch(path, {"op": "replace", "path": "active", "value": False}),
            403,
        )
        scim_error(await directory.scim.delete(path), 403)
        assert await directory.role_of(directory.owner.email) == "owner"
        refused = await directory.audit("scim.request_refused")
        assert [e["metadata"]["reason"] for e in refused] == ["owner_protected"] * 2
        assert (await directory.scim.get(path)).json()["active"] is True

    async def test_a_member_removed_in_the_application_shows_as_inactive(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        entry = await directory.provision("ada")
        members = (await directory.owner.get(f"{ORG}/members")).json()["items"]
        [membership] = [m for m in members if m["email"] == directory.email("ada")]
        await directory.owner.delete(f"{ORG}/members/{membership['membership_id']}")
        assert (await directory.scim.get(f"{USERS}/{entry['id']}")).json()["active"] is False
        # ... and the provider's sign-in does not quietly bring the person back.
        again = await sign_in(api, directory.idp, directory.slug, email=directory.email("ada"))
        expect_error(again, 403, "sso_access_revoked")


# ================================================================= bad requests


class TestMalformedRequests:
    async def test_malformed_bodies_are_refused_in_the_scim_error_schema(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        scim = directory.scim
        headers = scim.headers
        raw = await api.post(USERS, content=b"{not json", headers=headers)
        scim_error(raw, 400, "invalidSyntax")
        scim_error(await scim.post(USERS, {"userName": directory.email("x")}), 400, "invalidSyntax")
        scim_error(await scim.post(USERS, ["not", "an", "object"]), 400, "invalidSyntax")
        scim_error(await scim.post(USERS, {"schemas": [USER_SCHEMA]}), 400, "invalidValue")
        twice = {
            "schemas": [USER_SCHEMA],
            "userName": "a@b.example.com",
            "USERNAME": "c@d.example.com",
        }
        scim_error(await scim.post(USERS, twice), 400, "invalidSyntax")
        deep: Any = "x"
        for _ in range(40):
            deep = {"a": deep}
        scim_error(
            await scim.post(USERS, user(directory.email("d"), extra=deep)), 400, "invalidSyntax"
        )
        plain = await api.post(
            USERS,
            content=json.dumps(user(directory.email("p"))),
            headers={**headers, "Content-Type": "text/plain"},
        )
        scim_error(plain, 415)
        json_type = await api.post(
            USERS,
            content=json.dumps(user(directory.email("j"))),
            headers={**headers, "Content-Type": "application/json"},
        )
        assert json_type.status_code == 201, json_type.text
        scim_error(await scim.get(f"{USERS}/not-a-uuid"), 404)
        operations = {"schemas": [PATCH_SCHEMA], "Operations": "replace everything"}
        entry = json_type.json()["id"]
        scim_error(
            await api.patch(f"{USERS}/{entry}", content=json.dumps(operations), headers=headers),
            400,
            "invalidSyntax",
        )
        many = [{"op": "replace", "path": "displayName", "value": "x"}] * 51
        scim_error(await scim.patch(f"{USERS}/{entry}", *many), 400, "tooMany")

    async def test_a_huge_body_is_refused_before_it_is_read(
        self, api: httpx2.AsyncClient, network: FakeNetwork
    ) -> None:
        directory = await _directory(api, network)
        huge = user(directory.email("h"), displayName="x" * (70 * 1024))
        response = await directory.scim.post(USERS, huge)
        assert response.status_code == 413, response.text
        assert await directory.role_of(directory.email("h")) is None

    async def test_each_token_has_its_rate_limit(
        self,
        api: httpx2.AsyncClient,
        network: FakeNetwork,
        container: Container,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        directory = await _directory(api, network)
        rules = container.settings.rate_limits.rules
        assert rules["scim.token"].fail_closed
        # A tiny budget for this test: the real one (600 a minute) refills while
        # a test spends it.
        tiny = rules["scim.token"].model_copy(update={"limit": 2, "period_seconds": 3600})
        monkeypatch.setitem(rules, "scim.token", tiny)
        for _ in range(2):
            assert (await directory.scim.get(USERS)).status_code == 200
        limited = await directory.scim.get(USERS)
        scim_error(limited, 429)
        assert int(limited.headers["retry-after"]) >= 1
        other = await directory.owner.post(TOKENS, json={"name": "second"})
        assert (await Scim(api, other.json()["token"]).get(USERS)).status_code == 200


# ================================================================ personal data


async def test_a_persons_links_and_directory_entries_are_exported_and_erased(
    api: httpx2.AsyncClient,
    network: FakeNetwork,
    container: Container,
    admin_conn: asyncpg.Connection,
) -> None:
    directory = await _directory(api, network)
    await directory.provision("ada", externalId="00u-ada")
    email = directory.email("ada")
    assert (await sign_in(api, directory.idp, directory.slug, email=email)).status_code == 200

    document = await container.privacy.export_for(email, META)
    [link] = document["identity_provider_links"]
    assert (link["issuer"], link["email"]) == (directory.idp.issuer, email)
    [entry] = document["directory_entries"]
    assert (entry["user_name"], entry["external_id"], entry["active"]) == (email, "00u-ada", True)
    [session] = document["sessions"]
    assert session["single_sign_on_organization_id"] == str(await org_id_of(directory.owner))

    user_id = await admin_conn.fetchval("SELECT id FROM users WHERE email = $1", email)
    await container.privacy.erase_for(email, reason="Request by e-mail", meta=META)
    for table in ("sso_identities", "scim_users"):
        count = await admin_conn.fetchval(
            f"SELECT count(*) FROM {table} WHERE user_id = $1",  # noqa: S608 - fixed names
            user_id,
        )
        assert count == 0, table
    assert await directory.role_of(email) is None


# ==================================================================== isolation


async def test_a_token_sees_and_changes_its_own_organization_only(
    api: httpx2.AsyncClient, network: FakeNetwork
) -> None:
    a = await _directory(api, network)
    b = await _directory(api, network)
    victim = await b.provision("victim", externalId="b-1")
    path = f"{USERS}/{victim['id']}"
    scim_error(await a.scim.get(path), 404)
    scim_error(await a.scim.put(path, user(b.email("victim"))), 404)
    scim_error(await a.scim.patch(path, {"op": "replace", "path": "active", "value": False}), 404)
    scim_error(await a.scim.delete(path), 404)
    for expression in (f'userName eq "{b.email("victim")}"', 'externalId eq "b-1"'):
        assert (await a.scim.get(USERS, filter=expression)).json()["totalResults"] == 0
    # Organization B's domain is not A's to provision.
    scim_error(await a.scim.post(USERS, user(b.email("another"))), 400, "invalidValue")
    assert (await b.scim.get(path)).json()["active"] is True
    assert await b.role_of(b.email("victim")) == "analyst"
    assert await org_id_of(a.owner) != await org_id_of(b.owner)

"""API keys never outlive or outrank the member who created them (joiner-mover-leaver)."""

from __future__ import annotations

from uuid import uuid4

import asyncpg
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import AuthenticationError
from nexusflow.core.pagination import PageRequest
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission, Role, permissions_for
from nexusflow.domain.identity.auth_service import TokenPair
from tests.support.fixtures import META, PASSWORD, register, unique_email

pytestmark = [pytest.mark.integration, pytest.mark.security]

ADMIN_SCOPES = sorted(p.value for p in permissions_for(Role.ADMIN))


async def _principal(container: Container, tokens: TokenPair) -> Principal:
    return await container.authenticator.authenticate(tokens.access_token)


async def _join_as(
    container: Container, owner: Principal, admin_conn: asyncpg.Connection, role: Role
) -> Principal:
    email = unique_email(role.value)
    invitation = await container.organizations.invite(owner, email=email, role=role, meta=META)
    raw = "invite-" + uuid4().hex
    await admin_conn.execute(
        "UPDATE invitations SET token_hash = $1 WHERE id = $2",
        container.token_hasher.hash(raw),
        invitation.id,
    )
    tokens = await container.auth.register(
        email=email,
        password=PASSWORD,
        full_name="Key Maker",
        organization_name=None,
        invitation_token=raw,
        meta=META,
    )
    return await _principal(container, tokens)


async def _membership_id(container: Container, owner: Principal, user: Principal) -> object:
    members = await container.organizations.list_members(owner, PageRequest())
    return next(m.membership_id for m in members.items if m.user_id == user.user_id)


async def test_a_demoted_members_keys_are_demoted_and_a_leavers_keys_die(
    container: Container, admin_conn: asyncpg.Connection
) -> None:
    _, owner_tokens = await register(container)
    owner = await _principal(container, owner_tokens)
    admin = await _join_as(container, owner, admin_conn, Role.ADMIN)
    created = await container.accounts.create_api_key(
        admin, name="ci", role=Role.ADMIN, scopes=ADMIN_SCOPES, expires_in_days=30, meta=META
    )
    as_admin = await container.authenticator.authenticate(created.token)
    assert as_admin.role is Role.ADMIN
    assert Permission.MEMBERS_MANAGE in as_admin.permissions

    membership_id = await _membership_id(container, owner, admin)
    await container.organizations.change_role(
        owner,
        membership_id=membership_id,  # type: ignore[arg-type]
        role=Role.VIEWER,
        meta=META,
    )
    # Demotion applies to the key on its very next use - no admin powers left.
    demoted = await container.authenticator.authenticate(created.token)
    assert demoted.role is Role.VIEWER
    assert demoted.permissions <= permissions_for(Role.VIEWER)
    assert Permission.MEMBERS_MANAGE not in demoted.permissions

    await container.organizations.remove_member(
        owner,
        membership_id=membership_id,  # type: ignore[arg-type]
        meta=META,
    )
    # The leaver's key stops working at once and is recorded as revoked.
    with pytest.raises(AuthenticationError):
        await container.authenticator.authenticate(created.token)
    keys = await container.accounts.list_api_keys(owner, PageRequest())
    [key] = [k for k in keys.items if k.id == created.key.id]
    assert key.revoked_at is not None


async def test_keys_of_other_members_are_unaffected_by_a_removal(
    container: Container, admin_conn: asyncpg.Connection
) -> None:
    _, owner_tokens = await register(container)
    owner = await _principal(container, owner_tokens)
    leaver = await _join_as(container, owner, admin_conn, Role.ADMIN)
    stayer = await _join_as(container, owner, admin_conn, Role.ADMIN)
    scopes = ["projects:read"]
    leaver_key = await container.accounts.create_api_key(
        leaver, name="l", role=Role.VIEWER, scopes=scopes, expires_in_days=7, meta=META
    )
    stayer_key = await container.accounts.create_api_key(
        stayer, name="s", role=Role.VIEWER, scopes=scopes, expires_in_days=7, meta=META
    )
    await container.organizations.remove_member(
        owner,
        membership_id=await _membership_id(container, owner, leaver),  # type: ignore[arg-type]
        meta=META,
    )
    with pytest.raises(AuthenticationError):
        await container.authenticator.authenticate(leaver_key.token)
    still = await container.authenticator.authenticate(stayer_key.token)
    assert still.permissions == frozenset({Permission.PROJECTS_READ})


async def test_deleting_an_account_revokes_its_keys(
    container: Container, admin_conn: asyncpg.Connection
) -> None:
    _, owner_tokens = await register(container)
    owner = await _principal(container, owner_tokens)
    member = await _join_as(container, owner, admin_conn, Role.ADMIN)
    created = await container.accounts.create_api_key(
        member, name="m", role=Role.VIEWER, scopes=["projects:read"], expires_in_days=7, meta=META
    )
    await container.accounts.delete_account(member, password=PASSWORD, meta=META)
    with pytest.raises(AuthenticationError):
        await container.authenticator.authenticate(created.token)
    keys = await container.accounts.list_api_keys(owner, PageRequest())
    [key] = [k for k in keys.items if k.id == created.key.id]
    assert key.revoked_at is not None

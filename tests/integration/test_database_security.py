"""Database-level security: RLS tenant isolation, grants, append-only audit."""

from __future__ import annotations

from uuid import uuid4

import asyncpg
import httpx2
import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy.ext.asyncio import create_async_engine

from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import AuthenticationError
from nexusflow.domain.audit.model import PLATFORM_CHAIN, verify_chain
from nexusflow.domain.shared.unit_of_work import TenantScope
from nexusflow.infrastructure.database.metadata import metadata
from nexusflow.infrastructure.database.tables import load_all_tables
from tests.support.api import signup
from tests.support.business import (
    WEBHOOK_CONFIG,
    create_dataset,
    create_project,
    create_source,
)
from tests.support.database import ProvisionedDatabase
from tests.support.fixtures import META, register, unique_email

pytestmark = pytest.mark.security


async def _set_context(
    conn: asyncpg.Connection, *, org: str = "", user: str = "", auth: str = "off"
) -> None:
    await conn.execute(
        "SELECT set_config('app.current_org_id', $1, false), "
        "set_config('app.current_user_id', $2, false), set_config('app.auth_context', $3, false)",
        org,
        user,
        auth,
    )


async def test_migrations_match_orm_metadata(database: ProvisionedDatabase) -> None:
    load_all_tables()
    engine = create_async_engine(database.migrator_url)
    try:
        async with engine.connect() as conn:
            differences = await conn.run_sync(
                lambda sync_conn: compare_metadata(
                    MigrationContext.configure(sync_conn, opts={"compare_type": False}), metadata
                )
            )
    finally:
        await engine.dispose()
    assert differences == [], f"ORM metadata and migrations diverged: {differences}"


async def test_no_rows_visible_without_tenant_context(
    container: Container, app_conn: asyncpg.Connection
) -> None:
    await register(container)
    await _set_context(app_conn)
    for table in (
        "organizations",
        "users",
        "memberships",
        "api_keys",
        "user_sessions",
        "audit_logs",
    ):
        assert await app_conn.fetchval(f"SELECT count(*) FROM {table}") == 0, table  # noqa: S608


_TENANT_TABLES = """
    SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
           (SELECT count(*) FROM pg_policies p
             WHERE p.schemaname = 'public' AND p.tablename = c.relname) AS policies
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'r'
       AND EXISTS (SELECT 1 FROM pg_attribute a
                    WHERE a.attrelid = c.oid AND a.attname = 'org_id' AND NOT a.attisdropped)
     ORDER BY c.relname
"""


# Deliberate, documented exceptions to "RLS enabled + forced + a policy":
_RLS_EXCEPTIONS = {
    # RLS on, not forced: rows are appended only by the SECURITY DEFINER function
    # nf_append_audit (the table owner); tenants read their chain through a policy.
    "audit_logs": "enabled",
    # Task identifiers only (no tenant content), drained across every tenant by the
    # outbox relay - see THREAT_MODEL.md, "Data stores and messaging".
    "outbox_messages": "none",
}


async def test_every_tenant_table_forces_row_level_security(
    admin_conn: asyncpg.Connection,
) -> None:
    # Any table that holds tenant data (it has an org_id column) must have RLS
    # enabled AND forced, and at least one policy - a new table that forgets
    # this fails here, not in production.
    rows = await admin_conn.fetch(_TENANT_TABLES)
    assert len(rows) >= 25, [r["relname"] for r in rows]  # not vacuously true
    unprotected = [
        r["relname"]
        for r in rows
        if r["relname"] not in _RLS_EXCEPTIONS
        and not (r["relrowsecurity"] and r["relforcerowsecurity"] and r["policies"] > 0)
    ]
    assert unprotected == []
    audit = next(r for r in rows if r["relname"] == "audit_logs")
    assert audit["relrowsecurity"]
    assert audit["policies"] > 0


async def test_no_tenant_table_leaks_rows_without_a_tenant_context(
    container: Container,
    api: httpx2.AsyncClient,
    app_conn: asyncpg.Connection,
    admin_conn: asyncpg.Connection,
) -> None:
    # Put rows into the business tables first, so an empty result means "hidden".
    owner = await signup(api)
    project_id = await create_project(owner)
    dataset_id = await create_dataset(owner, project_id)
    await create_source(owner, project_id, dataset_id, WEBHOOK_CONFIG)
    tables = [
        r["relname"]
        for r in await admin_conn.fetch(_TENANT_TABLES)
        if _RLS_EXCEPTIONS.get(r["relname"]) != "none"
    ]
    populated = [t for t in tables if await admin_conn.fetchval(f"SELECT count(*) FROM {t}")]  # noqa: S608
    assert {"projects", "datasets", "sources", "memberships"} <= set(populated)
    await _set_context(app_conn)
    leaking = [t for t in tables if await app_conn.fetchval(f"SELECT count(*) FROM {t}")]  # noqa: S608
    assert leaking == []


async def test_tenant_cannot_read_or_write_other_tenant(
    container: Container, app_conn: asyncpg.Connection, admin_conn: asyncpg.Connection
) -> None:
    await register(container)
    await register(container)
    orgs = await admin_conn.fetch("SELECT id FROM organizations ORDER BY created_at DESC LIMIT 2")
    org_a, org_b = orgs[0]["id"], orgs[1]["id"]
    await _set_context(app_conn, org=str(org_a))
    visible = {r["id"] for r in await app_conn.fetch("SELECT id FROM organizations")}
    assert visible == {org_a}
    members = await app_conn.fetch("SELECT org_id FROM memberships")
    assert {r["org_id"] for r in members} == {org_a}
    # Writing a row for another tenant violates the policy's WITH CHECK clause.
    other_user = await admin_conn.fetchval(
        "SELECT user_id FROM memberships WHERE org_id = $1", org_b
    )
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute(
            "INSERT INTO memberships (id, org_id, user_id, role, created_at, updated_at) "
            "VALUES ($1, $2, $3, 'owner', now(), now())",
            uuid4(),
            org_b,
            other_user,
        )
    # Updates and deletes against invisible rows affect nothing.
    assert (
        await app_conn.execute("UPDATE organizations SET name = 'pwned' WHERE id = $1", org_b)
        == "UPDATE 0"
    )
    assert await app_conn.execute("DELETE FROM memberships WHERE org_id = $1", org_b) == "DELETE 0"


async def test_app_role_cannot_escalate_to_platform_admin(
    container: Container, app_conn: asyncpg.Connection, admin_conn: asyncpg.Connection
) -> None:
    email, _ = await register(container)
    user_id = await admin_conn.fetchval("SELECT id FROM users WHERE email = $1", email)
    await _set_context(app_conn, user=str(user_id))
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("UPDATE users SET is_platform_admin = true WHERE id = $1", user_id)


async def test_audit_log_is_append_only(
    container: Container, app_conn: asyncpg.Connection, admin_conn: asyncpg.Connection
) -> None:
    await register(container)
    org_id = await admin_conn.fetchval(
        "SELECT org_id FROM audit_logs WHERE org_id IS NOT NULL LIMIT 1"
    )
    await _set_context(app_conn, org=str(org_id))
    assert await app_conn.fetchval("SELECT count(*) FROM audit_logs") >= 1
    for statement in (
        "UPDATE audit_logs SET action = 'x'",
        "DELETE FROM audit_logs",
        "INSERT INTO audit_logs (id) VALUES (gen_random_uuid())",
        "TRUNCATE audit_logs",
    ):
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app_conn.execute(statement)
    # Even a superuser is stopped by the append-only trigger.
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await admin_conn.execute(
            "UPDATE audit_logs SET action = 'tampered' WHERE org_id = $1", org_id
        )


async def test_audit_append_rejects_cross_tenant_events(
    container: Container, app_conn: asyncpg.Connection, admin_conn: asyncpg.Connection
) -> None:
    await register(container)
    await register(container)
    orgs = await admin_conn.fetch("SELECT id FROM organizations ORDER BY created_at DESC LIMIT 2")
    await _set_context(app_conn, org=str(orgs[0]["id"]))
    event_id = uuid4()
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute(
            "SELECT nf_append_audit($1, $2, now(), 'system', NULL, 'org.updated', NULL, NULL, "
            "'success', NULL, NULL, NULL, '{}'::jsonb, $3)",
            event_id,
            orgs[1]["id"],
            f'{{"id":"{event_id}"}}',
        )


async def test_audit_chain_verifies_and_detects_tampering(
    container: Container, admin_conn: asyncpg.Connection
) -> None:
    await register(container)
    org_id = await admin_conn.fetchval(
        "SELECT org_id FROM audit_logs WHERE org_id IS NOT NULL ORDER BY occurred_at DESC LIMIT 1"
    )
    async with container.uow_factory(TenantScope(org_id=org_id)) as uow:
        entries = await uow.audit.chain(org_id, from_seq=1, limit=100)
    assert entries
    assert verify_chain(entries).ok
    # Simulate a privileged attacker editing history with the trigger disabled.
    await admin_conn.execute("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only")
    try:
        await admin_conn.execute(
            "UPDATE audit_logs SET ip = '198.51.100.99' WHERE org_id = $1 AND seq = 1", org_id
        )
    finally:
        await admin_conn.execute("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_append_only")
    async with container.uow_factory(TenantScope(org_id=org_id)) as uow:
        tampered = await uow.audit.chain(org_id, from_seq=1, limit=100)
    result = verify_chain(tampered)
    assert not result.ok
    assert result.first_invalid_seq == 1
    assert result.reason == "row_modified"


async def _failed_sign_in(container: Container) -> None:
    """A sign-in for an unknown account: an audit event without a tenant."""
    with pytest.raises(AuthenticationError):
        await container.auth.login(
            email=unique_email("nobody"), password="not-the-password", org_id=None, meta=META
        )


async def test_the_platform_chain_is_readable_only_through_its_functions(
    container: Container, app_conn: asyncpg.Connection
) -> None:
    await _failed_sign_in(container)
    await _set_context(app_conn)
    # Row-level security hides events without a tenant from the runtime role ...
    assert await app_conn.fetchval("SELECT count(*) FROM audit_logs WHERE org_id IS NULL") == 0
    # ... except through the platform-chain functions, which return nothing else.
    rows = await app_conn.fetch("SELECT chain_key, org_id FROM nf_platform_audit_page(1, 5000)")
    assert rows
    assert len(rows) <= 1000  # a bounded page, whatever the caller asks for
    assert {(row["chain_key"], row["org_id"]) for row in rows} == {(PLATFORM_CHAIN, None)}


async def test_the_platform_chain_verifies_anchors_and_detects_tampering(
    container: Container, admin_conn: asyncpg.Connection
) -> None:
    await _failed_sign_in(container)
    intact = await container.audit_log.verify_platform_chain()
    assert intact.ok and intact.checked >= 1
    seq, digest = await container.audit_log.anchor(None) or (0, "")
    head = await admin_conn.fetchrow(
        "SELECT seq, hash, ip FROM audit_logs WHERE chain_key = $1 ORDER BY seq DESC LIMIT 1",
        PLATFORM_CHAIN,
    )
    assert (seq, digest) == (head["seq"], bytes(head["hash"]).hex())

    # A privileged attacker edits a platform event (restored afterwards: the
    # chain is shared by every test in this database).
    await admin_conn.execute("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only")
    try:
        await admin_conn.execute(
            "UPDATE audit_logs SET ip = '198.51.100.99' WHERE chain_key = $1 AND seq = $2",
            PLATFORM_CHAIN,
            head["seq"],
        )
        tampered = await container.audit_log.verify_platform_chain()
        assert (tampered.ok, tampered.first_invalid_seq, tampered.reason) == (
            False,
            head["seq"],
            "row_modified",
        )
    finally:
        await admin_conn.execute(
            "UPDATE audit_logs SET ip = $3 WHERE chain_key = $1 AND seq = $2",
            PLATFORM_CHAIN,
            head["seq"],
            head["ip"],
        )
        await admin_conn.execute("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_append_only")
    assert (await container.audit_log.verify_platform_chain()).ok

"""Migration 0012 (the second factor a session passed) goes down and up again.

A fresh database of its own, at 0012: ``user_sessions.mfa_method`` is there, and
its check constraints refuse an unknown factor and a factor on a session that
did not pass MFA. Going down to 0011 is refused while an organization requires
passkeys (the policy would end silently); once none does, the column goes, and
``require_passkey`` leaves the organizations' settings (0011's code would
refuse the unknown key). Then forward again.
"""

from __future__ import annotations

import asyncio
import json
from uuid import UUID, uuid4

import asyncpg
import pytest

from tests.support.database import (
    ProvisionedDatabase,
    admin_url_or_none,
    create_database,
    downgrade,
    drop_database,
    run_migrations,
)

pytestmark = pytest.mark.integration

CONSTRAINTS = {"ck_user_sessions_mfa_method", "ck_user_sessions_mfa_method_verified"}


async def _state(conn: asyncpg.Connection) -> tuple[bool, set[str], str]:
    column = await conn.fetchval(
        "SELECT count(*) FROM information_schema.columns"
        " WHERE table_name = 'user_sessions' AND column_name = 'mfa_method'"
    )
    constraints = {
        row["conname"]
        for row in await conn.fetch(
            "SELECT conname FROM pg_constraint WHERE conname LIKE 'ck_user_sessions_mfa_method%'"
        )
    }
    version = await conn.fetchval("SELECT version_num FROM alembic_version")
    return bool(column), constraints, str(version)


async def _organization(conn: asyncpg.Connection, settings: dict[str, bool]) -> UUID:
    org_id = uuid4()
    await conn.execute(
        "INSERT INTO organizations (id, name, slug, status, settings, created_at, updated_at)"
        " VALUES ($1, 'Org', $2, 'active', $3::jsonb, now(), now())",
        org_id,
        f"org-{org_id.hex[:12]}",
        json.dumps(settings),
    )
    return org_id


async def _session(conn: asyncpg.Connection, user_id: UUID, *, verified: bool, method: str) -> None:
    await conn.execute(
        "INSERT INTO user_sessions (id, user_id, created_at, last_used_at, expires_at,"
        " mfa_verified, mfa_method) VALUES ($1, $2, now(), now(), now() + interval '1 day',"
        " $3, $4)",
        uuid4(),
        user_id,
        verified,
        method,
    )


async def _down_and_up(db: ProvisionedDatabase, conn: asyncpg.Connection) -> None:
    assert await _state(conn) == (True, CONSTRAINTS, "0012")
    user_id = uuid4()
    await conn.execute(
        "INSERT INTO users (id, email, password_hash, full_name, status, is_platform_admin,"
        " mfa_enabled, failed_login_attempts, lockout_count, password_changed_at,"
        " token_version, created_at, updated_at) VALUES ($1, $2, '!', 'Person', 'active',"
        " false, true, 0, 0, now(), 0, now(), now())",
        user_id,
        f"person-{user_id.hex[:8]}@example.com",
    )
    await _session(conn, user_id, verified=True, method="webauthn")
    with pytest.raises(asyncpg.CheckViolationError):
        await _session(conn, user_id, verified=True, method="sms")
    with pytest.raises(asyncpg.CheckViolationError):
        await _session(conn, user_id, verified=False, method="totp")
    requiring = await _organization(conn, {"require_mfa": True, "require_passkey": True})
    lifted = await _organization(conn, {"require_mfa": False, "require_passkey": False})

    with pytest.raises(RuntimeError, match="require passkeys"):
        await asyncio.to_thread(downgrade, db, "0011")
    assert await _state(conn) == (True, CONSTRAINTS, "0012")  # nothing changed

    await conn.execute(
        "UPDATE organizations SET settings = jsonb_set(settings, '{require_passkey}', 'false')"
        " WHERE id = $1",
        requiring,
    )
    await asyncio.to_thread(downgrade, db, "0011")
    assert await _state(conn) == (False, set(), "0011")
    for org_id in (requiring, lifted):
        stored = await conn.fetchval("SELECT settings FROM organizations WHERE id = $1", org_id)
        assert json.loads(stored) == {"require_mfa": org_id == requiring}

    await asyncio.to_thread(run_migrations, db, "0012")
    assert await _state(conn) == (True, CONSTRAINTS, "0012")
    methods = await conn.fetch("SELECT mfa_method FROM user_sessions WHERE user_id = $1", user_id)
    assert [row["mfa_method"] for row in methods] == [None]  # recorded from now on only


async def test_migration_0012_goes_down_and_up_again() -> None:
    admin_url = admin_url_or_none()
    if admin_url is None:
        pytest.skip("PostgreSQL not available")
    db = await create_database(admin_url)
    try:
        await asyncio.to_thread(downgrade, db, "0012")  # below any later migration
        conn = await asyncpg.connect(db.admin_url.rsplit("/", 1)[0] + f"/{db.name}")
        try:
            await _down_and_up(db, conn)
        finally:
            await conn.close()
    finally:
        await drop_database(db)

"""Migration 0010 (single sign-on and SCIM) goes down and up again cleanly.

A fresh database of its own: migrated to the head, taken back to 0009 (the
new tables, the session column and the widened audit actor check are gone)
and forward again.
"""

from __future__ import annotations

import asyncio

import asyncpg
import pytest

from tests.support.database import (
    admin_url_or_none,
    create_database,
    downgrade,
    drop_database,
    run_migrations,
)

pytestmark = pytest.mark.integration

NEW_TABLES = {"sso_connections", "sso_login_states", "sso_identities", "scim_tokens", "scim_users"}


async def _state(url: str) -> tuple[set[str], bool, str]:
    conn = await asyncpg.connect(url)
    try:
        tables = {
            r["tablename"]
            for r in await conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        }
        column = await conn.fetchval(
            "SELECT count(*) FROM information_schema.columns"
            " WHERE table_name = 'user_sessions' AND column_name = 'sso_org_id'"
        )
        check = await conn.fetchval(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint"
            " WHERE conname = 'ck_audit_logs_actor_type'"
        )
        return tables & NEW_TABLES, bool(column), str(check)
    finally:
        await conn.close()


async def test_migration_0010_goes_down_and_up_again() -> None:
    admin_url = admin_url_or_none()
    if admin_url is None:
        pytest.skip("PostgreSQL not available")
    db = await create_database(admin_url)
    url = db.admin_url.rsplit("/", 1)[0] + f"/{db.name}"
    try:
        tables, column, check = await _state(url)
        assert (tables, column) == (NEW_TABLES, True)
        assert "'scim'" in check

        await asyncio.to_thread(downgrade, db, "0009")
        tables, column, check = await _state(url)
        assert (tables, column) == (set(), False)
        assert "'scim'" not in check

        await asyncio.to_thread(run_migrations, db, "head")
        tables, column, check = await _state(url)
        assert (tables, column) == (NEW_TABLES, True)
        assert "'scim'" in check
    finally:
        await drop_database(db)

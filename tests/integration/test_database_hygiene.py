"""Schema-wide properties that a new table, function or foreign key could lose.

Review round 12 (database): row-level security was only checked for tables
with an ``org_id`` column, nothing pinned the hygiene of the SECURITY DEFINER
functions, foreign keys without an index made deletes scan whole tables (E-1),
and the audit purge could cut a chain in the middle (E-5).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import asyncpg
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.domain.audit.model import (
    ActorType,
    AuditAction,
    AuditEvent,
    AuditResult,
    verify_chain,
)
from nexusflow.domain.shared.unit_of_work import TenantScope

pytestmark = [pytest.mark.security, pytest.mark.integration]

# Tables outside *forced* row-level security, each for a documented reason.
NOT_FORCED = {
    "alembic_version": "migration bookkeeping; no tenant data",
    "audit_chain_heads": "owner-only; written by nf_append_audit, no grant to the app role",
    "audit_logs": "written only through nf_append_audit; tenants read it under a policy",
    "outbox_messages": "the platform's job queue; rows carry identifiers only",
}
APPEND = (
    "SELECT nf_append_audit($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14)"
)


async def test_row_level_security_is_forced_on_every_table_but_the_documented_ones(
    admin_conn: asyncpg.Connection,
) -> None:
    rows = await admin_conn.fetch(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND c.relkind = 'r' "
        "AND NOT (c.relrowsecurity AND c.relforcerowsecurity)"
    )
    assert {r["relname"] for r in rows} == set(NOT_FORCED)


async def test_security_definer_functions_pin_their_search_path_and_are_not_public(
    admin_conn: asyncpg.Connection,
) -> None:
    rows = await admin_conn.fetch(
        "SELECT p.proname, p.proconfig, has_function_privilege('public', p.oid, 'EXECUTE') "
        "AS anyone FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'public' AND p.prosecdef"
    )
    assert len(rows) >= 9
    for row in rows:
        assert "search_path=pg_catalog, public" in (row["proconfig"] or []), row["proname"]
        assert not row["anyone"], row["proname"]


async def test_every_foreign_key_whose_parent_is_deleted_has_an_index(
    admin_conn: asyncpg.Connection,
) -> None:
    # Without one, each deleted parent row scans the whole child table, across
    # all tenants, inside the application's statement timeout (review E-1).
    rows = await admin_conn.fetch(
        "SELECT con.conrelid::regclass::text AS child, a.attname AS column, "
        "con.confrelid::regclass::text AS parent FROM pg_constraint con "
        "JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = con.conkey[1] "
        "WHERE con.contype = 'f' AND array_length(con.conkey, 1) = 1 AND NOT EXISTS ("
        "SELECT 1 FROM pg_index i WHERE i.indrelid = con.conrelid "
        "AND i.indkey[0] = con.conkey[1])"
    )
    # Users are anonymised, never deleted: their foreign keys never fire.
    unindexed = sorted(f"{r['child']}.{r['column']}" for r in rows if r["parent"] != "users")
    assert unindexed == []


def _event(org_id: UUID, at: datetime) -> AuditEvent:
    return AuditEvent(
        id=uuid4(),
        org_id=org_id,
        occurred_at=at,
        actor_type=ActorType.SYSTEM,
        actor_id=None,
        action=AuditAction.AUTOMATION_STEP,
        resource_type="workflow",
        resource_id="w",
        result=AuditResult.SUCCESS,
        ip=None,
        user_agent=None,
        request_id=None,
        metadata={},
    )


async def test_the_audit_purge_removes_only_a_prefix_of_each_chain(
    container: Container, app_conn: asyncpg.Connection, admin_conn: asyncpg.Connection
) -> None:
    org_id = uuid4()
    await admin_conn.execute(
        "INSERT INTO organizations (id, name, slug, status, settings, created_at, updated_at) "
        "VALUES ($1, 'Purge', $2, 'active', '{}', now(), now())",
        org_id,
        f"purge-{org_id.hex[:12]}",
    )
    t0 = datetime(2020, 1, 1, 12, 0, tzinfo=UTC)
    # Events are stamped when built and ordered when appended: built at +2 s,
    # +1 s and +3 s, appended in that order - seq 1, 2 and 3.
    async with app_conn.transaction():
        await app_conn.execute("SELECT set_config('app.current_org_id', $1, true)", str(org_id))
        for offset in (2, 1, 3):
            event = _event(org_id, t0 + timedelta(seconds=offset))
            await app_conn.fetchval(
                APPEND,
                event.id,
                event.org_id,
                event.occurred_at,
                event.actor_type.value,
                event.actor_id,
                event.action.value,
                event.resource_type,
                event.resource_id,
                event.result.value,
                event.ip,
                event.user_agent,
                event.request_id,
                json.dumps(event.metadata),
                event.canonical(),
            )

    # A cutoff between the first two entries: purging by time alone deleted
    # seq 2 and kept seq 1 - a gap reported as tampering for ever after.
    assert (
        await admin_conn.fetchval(
            "SELECT nf_purge_audit_logs($1)", t0 + timedelta(milliseconds=1500)
        )
        == 0
    )
    # A cutoff after both: the chain's prefix goes, the rest stays verifiable.
    assert (
        await admin_conn.fetchval(
            "SELECT nf_purge_audit_logs($1)", t0 + timedelta(milliseconds=2500)
        )
        == 2
    )
    async with container.uow_factory(TenantScope(org_id=org_id)) as uow:
        remaining = await uow.audit.chain(org_id, from_seq=1, limit=10)
    assert [entry.seq for entry in remaining] == [3]
    assert verify_chain(remaining).ok

"""Dead-letter retention: a narrow purge function instead of a DELETE grant.

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-24

The runtime role may insert and update dead letters but, deliberately, not
delete them - so the retention job failed on them and rolled back every other
purge of the same pass. ``nf_purge_dead_letters`` deletes only rows older
than the given cutoff, and only those of the current tenant context (or,
outside any tenant, the platform-level ones): retention works without handing
out a general DELETE right.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from nexusflow.infrastructure.database.rls import app_role, split_sql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SIGNATURE = "nf_purge_dead_letters(timestamptz)"

_FUNCTION = """
CREATE OR REPLACE FUNCTION nf_purge_dead_letters(p_before timestamptz)
RETURNS bigint
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
DECLARE
    v_org uuid := public.nf_current_org();
    v_count bigint;
BEGIN
    DELETE FROM public.dead_letters
     WHERE last_failed_at < p_before
       AND org_id IS NOT DISTINCT FROM v_org;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;
"""


def upgrade() -> None:
    role = app_role()
    for statement in [
        *split_sql(_FUNCTION),
        f"REVOKE ALL ON FUNCTION {_SIGNATURE} FROM PUBLIC",
        f"GRANT EXECUTE ON FUNCTION {_SIGNATURE} TO {role}",
    ]:
        op.execute(statement)


def downgrade() -> None:
    op.execute(f"DROP FUNCTION IF EXISTS {_SIGNATURE}")

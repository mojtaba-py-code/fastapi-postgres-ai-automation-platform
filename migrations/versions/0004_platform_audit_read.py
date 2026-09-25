"""Platform audit chain: read access for verification and anchoring.

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-24

Events without a tenant (failed sign-ins for unknown accounts, operator CLI
actions such as the kill switch) are chained under the nil UUID. Row-level
security shows the runtime role only its current tenant's rows, so nothing
could read - and therefore verify or anchor - that chain.

Two narrow SECURITY DEFINER functions expose exactly the platform chain: a page
of it by sequence number (at most 1000 rows per call) and its head. They
cannot reach any tenant's rows, and writes still go only through
``nf_append_audit``.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from nexusflow.infrastructure.database.rls import app_role, split_sql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PAGE = "nf_platform_audit_page(bigint, integer)"
_HEAD = "nf_platform_audit_head()"

_FUNCTIONS = """
CREATE OR REPLACE FUNCTION nf_platform_audit_page(p_from_seq bigint, p_limit integer)
RETURNS SETOF public.audit_logs
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT * FROM public.audit_logs
     WHERE chain_key = '00000000-0000-0000-0000-000000000000'::uuid
       AND seq >= p_from_seq
     ORDER BY seq
     LIMIT LEAST(GREATEST(p_limit, 0), 1000)
$$;

CREATE OR REPLACE FUNCTION nf_platform_audit_head()
RETURNS SETOF public.audit_logs
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT * FROM public.audit_logs
     WHERE chain_key = '00000000-0000-0000-0000-000000000000'::uuid
     ORDER BY seq DESC
     LIMIT 1
$$;
"""


def upgrade() -> None:
    role = app_role()
    for statement in [
        *split_sql(_FUNCTIONS),
        f"REVOKE ALL ON FUNCTION {_PAGE} FROM PUBLIC",
        f"REVOKE ALL ON FUNCTION {_HEAD} FROM PUBLIC",
        f"GRANT EXECUTE ON FUNCTION {_PAGE} TO {role}",
        f"GRANT EXECUTE ON FUNCTION {_HEAD} TO {role}",
    ]:
        op.execute(statement)


def downgrade() -> None:
    op.execute(f"DROP FUNCTION IF EXISTS {_HEAD}")
    op.execute(f"DROP FUNCTION IF EXISTS {_PAGE}")

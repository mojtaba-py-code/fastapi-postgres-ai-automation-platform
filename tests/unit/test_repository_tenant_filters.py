"""Every query of tenant data names its tenant (THREAT_MODEL.md, section 4.7).

Row-level security isolates tenants inside PostgreSQL; on top of it every
repository query of business data filters by ``org_id``, so a mistake in
how a transaction's tenant is set cannot become a cross-tenant read or write.
Review D-n1 found eleven queries that relied on row-level security alone.
This check keeps new ones from appearing.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPOSITORIES = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "nexusflow"
    / "infrastructure"
    / "database"
    / "repositories"
    / "data.py"
)
_QUERY_MARKERS = ("select(", "update(", "delete(", "insert(", "self._s.get(", ".execute(")

# Deliberate: no tenant rows are read or written by name here.
EXCEPTIONS = {
    "SqlSourceRepository.lock": "a transaction-scoped advisory lock; no rows",
    "SqlMaintenanceRepository.purge_outbox": (
        "outbox_messages hold identifiers only and are drained across tenants"
    ),
    "SqlSystemQueries.tenant_ids": "a SECURITY DEFINER function that lists tenant ids",
    "SqlSystemQueries.orgs_due_for_purge": "the same, for tenants due for deletion",
}


def _unfiltered() -> set[str]:
    source = REPOSITORIES.read_text(encoding="utf-8")
    found = set()
    for node in ast.parse(source).body:
        if not isinstance(node, ast.ClassDef):
            continue
        for method in node.body:
            if not isinstance(method, ast.AsyncFunctionDef):
                continue
            body = ast.get_source_segment(source, method) or ""
            if any(marker in body for marker in _QUERY_MARKERS) and "org_id" not in body:
                found.add(f"{node.name}.{method.name}")
    return found


def test_every_tenant_query_filters_by_its_tenant() -> None:
    unfiltered = _unfiltered()
    assert unfiltered - set(EXCEPTIONS) == set(), "add an org_id filter"
    assert set(EXCEPTIONS) <= unfiltered, "a documented exception is gone: remove it here"

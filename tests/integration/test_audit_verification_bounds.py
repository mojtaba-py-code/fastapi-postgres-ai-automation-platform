"""Audit verification never passes a partial check off as a complete one (review E-4).

Verification stopped after a fixed number of entries and answered ok=True:
beyond it - on the platform chain after a few weeks of failed sign-ins, on a
busy tenant after a few months - rows could be edited without detection, by
the daily job as much as by the API. The job and the CLI now check whole
chains; the API's bounded check says when it stopped early.
"""

from __future__ import annotations

import asyncpg
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.audit.service import AuditService
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.shared.unit_of_work import TenantScope
from tests.support.fixtures import META, register

pytestmark = pytest.mark.integration

BOUND = 5


async def _longer_chain(container: Container, admin_conn: asyncpg.Connection) -> tuple[object, int]:
    await register(container)
    org_id = await admin_conn.fetchval(
        "SELECT org_id FROM audit_logs WHERE org_id IS NOT NULL ORDER BY occurred_at DESC LIMIT 1"
    )
    for n in range(BOUND * 2):
        async with container.uow_factory(TenantScope.system(org_id)) as uow:
            await container.audit.record(
                uow.audit,
                action=AuditAction.ORG_UPDATED,
                principal=Principal.system(),
                meta=META,
                org_id=org_id,
                resource_type="organization",
                resource_id=org_id,
                metadata={"n": n},
            )
            await uow.commit()
    total = await admin_conn.fetchval("SELECT max(seq) FROM audit_logs WHERE org_id = $1", org_id)
    return org_id, int(total)


async def test_a_bounded_check_says_so_and_the_full_check_sees_every_entry(
    container: Container, admin_conn: asyncpg.Connection
) -> None:
    org_id, total = await _longer_chain(container, admin_conn)
    service = AuditService(uow_factory=container.uow_factory, max_verify_entries=BOUND)
    principal = Principal.system(org_id)  # type: ignore[arg-type]

    bounded = await service.verify_integrity(principal)
    assert (bounded.ok, bounded.checked, bounded.complete) == (True, BOUND, False)
    full = await service.verify_integrity(principal, complete=True)
    assert (full.ok, full.checked, full.complete) == (True, total, True)

    # An edit beyond the bound: the bounded check cannot see it - and says it
    # did not look - while the full check (the daily job's) finds it.
    await admin_conn.execute("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only")
    try:
        await admin_conn.execute(
            "UPDATE audit_logs SET ip = '198.51.100.7' WHERE org_id = $1 AND seq = $2",
            org_id,
            total,
        )
    finally:
        await admin_conn.execute("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_append_only")
    assert (await service.verify_integrity(principal)).complete is False
    broken = await service.verify_integrity(principal, complete=True)
    assert (broken.ok, broken.first_invalid_seq, broken.reason) == (False, total, "row_modified")


async def test_a_chain_exactly_as_long_as_the_bound_is_complete(
    container: Container, admin_conn: asyncpg.Connection
) -> None:
    org_id, total = await _longer_chain(container, admin_conn)
    service = AuditService(uow_factory=container.uow_factory, max_verify_entries=total)

    result = await service.verify_integrity(Principal.system(org_id))  # type: ignore[arg-type]

    assert (result.ok, result.checked, result.complete) == (True, total, True)

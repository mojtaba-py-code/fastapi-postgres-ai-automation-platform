"""A backup restores into a working platform.

The procedure of ``scripts/backup.sh`` and ``scripts/restore.sh`` - ``pg_dump``
in custom format without owners, ``pg_restore --clean --if-exists --no-owner
--role=nexusflow_migrator`` - run against PostgreSQL with the production roles.
The restored database must restore without a single error, hold the same rows,
still isolate tenants, verify its audit chains, and let users sign in.
(The e2e CI job runs the scripts themselves against the Compose stack.)
"""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import asyncpg
import fakeredis
import httpx2
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from nexusflow.bootstrap.container import Container, build_container
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.shared.context import RequestMeta
from tests.conftest import make_settings
from tests.support.api import signup
from tests.support.business import create_dataset, create_project, org_id_of
from tests.support.database import (
    APP_ROLE,
    MIGRATOR_ROLE,
    ROLE_PASSWORD,
    ProvisionedDatabase,
)
from tests.support.fixtures import PASSWORD

pytestmark = pytest.mark.integration


def _tool(name: str) -> str | None:
    """``pg_dump`` / ``pg_restore`` from PATH, or the embedded server's own."""
    found = shutil.which(name)
    if found:
        return found
    try:
        import pgserver
    except ImportError:
        return None
    suffix = ".exe" if os.name == "nt" else ""
    bundled = Path(pgserver.__file__).parent / "pginstall" / "bin" / f"{name}{suffix}"
    return str(bundled) if bundled.exists() else None


def _major(tool: str) -> int:
    # A PostgreSQL client tool found above, not user input.
    output = subprocess.run([tool, "--version"], capture_output=True, text=True, check=True)  # noqa: S603
    match = re.search(r"(\d+)(?:\.\d+)?", output.stdout)
    assert match, output.stdout
    return int(match.group(1))


def _url(base: str, *, database: str, user: str | None = None, driver: str = "postgresql") -> str:
    """``base`` pointing at another database (and optionally another user)."""
    parts = urlsplit(base.replace("postgresql+asyncpg://", "postgresql://"))
    netloc = parts.netloc
    if user is not None:
        host = parts.hostname or "localhost"
        netloc = f"{user}:{ROLE_PASSWORD}@{host}" + (f":{parts.port}" if parts.port else "")
    return urlunsplit((driver, netloc, f"/{database}", parts.query, ""))


async def _row_counts(conn: asyncpg.Connection) -> dict[str, int]:
    tables = await conn.fetch(
        "SELECT relname FROM pg_class WHERE relkind = 'r'"
        " AND relnamespace = 'public'::regnamespace ORDER BY relname"
    )
    # Table names come from the catalog of the test database.
    return {
        row["relname"]: await conn.fetchval(f'SELECT count(*) FROM "{row["relname"]}"')  # noqa: S608
        for row in tables
    }


async def _forced_rls(conn: asyncpg.Connection) -> set[str]:
    rows = await conn.fetch(
        "SELECT relname FROM pg_class WHERE relkind = 'r' AND relforcerowsecurity"
        " AND relnamespace = 'public'::regnamespace"
    )
    return {row["relname"] for row in rows}


async def _run(*command: str) -> subprocess.CompletedProcess[str]:
    return await asyncio.to_thread(
        subprocess.run, list(command), capture_output=True, text=True, timeout=300
    )


async def test_a_restored_backup_is_a_working_platform(
    api: httpx2.AsyncClient,
    container: Container,
    database: ProvisionedDatabase,
    admin_conn: asyncpg.Connection,
    tmp_path: Path,
) -> None:
    pg_dump, pg_restore = _tool("pg_dump"), _tool("pg_restore")
    if pg_dump is None or pg_restore is None:
        pytest.skip("pg_dump / pg_restore not available")
    server_major = int(await admin_conn.fetchval("SHOW server_version_num")) // 10000
    if min(_major(pg_dump), _major(pg_restore)) < server_major:
        pytest.skip("the PostgreSQL client tools are older than the server")

    # Something worth restoring: a tenant with data, sessions and audit entries.
    owner = await signup(api)
    org_id = await org_id_of(owner)
    await create_dataset(owner, await create_project(owner))
    source_counts = await _row_counts(admin_conn)

    # backup.sh: pg_dump --format=custom --no-owner, as the superuser.
    archive = tmp_path / "nexusflow.dump"
    source = _url(database.admin_url, database=database.name)
    dumped = await _run(pg_dump, "--format=custom", "--no-owner", "--file", str(archive), source)
    assert dumped.returncode == 0, dumped.stderr

    # restore.sh, into an empty database of the same cluster.
    restored_name = f"nf_restored_{secrets.token_hex(4)}"
    await admin_conn.execute(f"CREATE DATABASE {restored_name} OWNER {MIGRATOR_ROLE}")
    try:
        restored = await _run(
            pg_restore,
            "--clean",
            "--if-exists",
            "--no-owner",
            f"--role={MIGRATOR_ROLE}",
            "--dbname",
            _url(database.admin_url, database=restored_name),
            str(archive),
        )
        # Not one ignored error: restore.sh runs under `set -e`.
        assert restored.returncode == 0, restored.stderr
        assert "error" not in restored.stderr.lower(), restored.stderr

        conn = await asyncpg.connect(_url(database.admin_url, database=restored_name))
        try:
            assert await _row_counts(conn) == source_counts
            assert await _forced_rls(conn) == await _forced_rls(admin_conn)
            assert await _forced_rls(conn)  # tenant tables really are protected
        finally:
            await conn.close()

        # The application role, restricted by row-level security, sees no tenant
        # data without a tenant - exactly as before the restore.
        app = await asyncpg.connect(_url(database.admin_url, database=restored_name, user=APP_ROLE))
        try:
            assert await app.fetchval("SELECT count(*) FROM projects") == 0
        finally:
            await app.close()

        await _check_the_restored_platform(container, database, restored_name, org_id, owner.email)
    finally:
        await admin_conn.execute(f"DROP DATABASE IF EXISTS {restored_name} WITH (FORCE)")


async def _check_the_restored_platform(
    original: Container, database: ProvisionedDatabase, name: str, org_id: UUID, email: str
) -> None:
    """The platform, pointed at the restored database, verifies and signs in."""
    url = _url(database.app_url, database=name, driver="postgresql+asyncpg")
    settings = make_settings(
        Path(original.settings.storage.root),
        database={"url": url},
        app={"public_base_url": "https://nexusflow.test.example", "allowed_hosts": ["testserver"]},
    )
    engine = create_async_engine(url, pool_size=2, max_overflow=0)
    restored = build_container(
        settings,
        application_name="nexusflow-restore-test",
        engine=engine,
        redis=fakeredis.FakeAsyncRedis(),
    )
    try:
        tenant = await restored.audit_log.verify_integrity(Principal.system(org_id))
        assert tenant.ok, tenant
        assert tenant.checked > 0
        platform = await restored.audit_log.verify_platform_chain()
        assert platform.ok, platform
        signed_in = await restored.auth.login(
            email=email,
            password=PASSWORD,
            org_id=None,
            meta=RequestMeta(request_id="req-restore-01", ip="203.0.113.10", user_agent="pytest"),
        )
        assert signed_in.tokens is not None
    finally:
        await restored.aclose()

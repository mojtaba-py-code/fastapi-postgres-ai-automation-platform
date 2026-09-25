"""Provision a throw-away PostgreSQL database with production-like roles.

* ``NEXUSFLOW_TEST_DATABASE_URL`` - superuser URL of an existing server (CI uses
  the ``postgres`` service container);
* otherwise an embedded server is started with ``pgserver`` (``--group localdb``);
* otherwise integration tests are skipped.

Two roles are created exactly as in production: a migrator (schema owner,
``BYPASSRLS``) that runs Alembic, and the application role (``NOBYPASSRLS``)
that every test connects as - so row-level security is really exercised.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
from alembic import command
from alembic.config import Config

APP_ROLE = "nexusflow_app"
MIGRATOR_ROLE = "nexusflow_migrator"
ROLE_PASSWORD = "integration-test-only"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class ProvisionedDatabase:
    name: str
    admin_url: str
    migrator_url: str
    app_url: str


def admin_url_or_none() -> str | None:
    configured = os.environ.get("NEXUSFLOW_TEST_DATABASE_URL")
    if configured:
        return configured
    try:
        import pgserver
    except ImportError:
        return None
    data_dir = Path(tempfile.gettempdir()) / "nexusflow-test-pg"
    server = pgserver.get_server(data_dir, cleanup_mode=None)
    uri: str = server.get_uri()
    return uri


def _with_credentials(url: str, *, user: str, password: str, database: str, driver: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or "localhost"
    port = f":{parts.port}" if parts.port else ""
    netloc = f"{user}:{password}@{host}{port}"
    return urlunsplit((driver, netloc, f"/{database}", "", ""))


async def create_database(admin_url: str) -> ProvisionedDatabase:
    name = f"nf_test_{secrets.token_hex(4)}"
    plain_admin = admin_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(plain_admin)
    try:
        for role, attrs in ((MIGRATOR_ROLE, "BYPASSRLS"), (APP_ROLE, "NOBYPASSRLS")):
            exists = await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", role)
            if not exists:
                await conn.execute(f"CREATE ROLE {role} LOGIN {attrs} PASSWORD '{ROLE_PASSWORD}'")
        await conn.execute(f"CREATE DATABASE {name} OWNER {MIGRATOR_ROLE}")
        # As in deploy/postgres/init/01-roles.sh: CONNECT only - no TEMP, so a
        # search_path hijack of the SECURITY DEFINER functions stays impossible.
        await conn.execute(f"REVOKE ALL ON DATABASE {name} FROM PUBLIC")
        await conn.execute(f"GRANT CONNECT ON DATABASE {name} TO {APP_ROLE}")
    finally:
        await conn.close()
    migrator = _with_credentials(
        admin_url,
        user=MIGRATOR_ROLE,
        password=ROLE_PASSWORD,
        database=name,
        driver="postgresql+asyncpg",
    )
    app = _with_credentials(
        admin_url,
        user=APP_ROLE,
        password=ROLE_PASSWORD,
        database=name,
        driver="postgresql+asyncpg",
    )
    db = ProvisionedDatabase(name=name, admin_url=plain_admin, migrator_url=migrator, app_url=app)
    await asyncio.to_thread(run_migrations, db, "head")
    return db


def alembic_config(db: ProvisionedDatabase) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.cmd_opts = None
    config.attributes["db_url"] = db.migrator_url
    return config


def run_migrations(db: ProvisionedDatabase, target: str) -> None:
    config = alembic_config(db)
    os.environ["NEXUSFLOW_DATABASE__MIGRATOR_URL"] = db.migrator_url
    try:
        command.upgrade(config, target)
    finally:
        os.environ.pop("NEXUSFLOW_DATABASE__MIGRATOR_URL", None)


def downgrade(db: ProvisionedDatabase, target: str) -> None:
    config = alembic_config(db)
    os.environ["NEXUSFLOW_DATABASE__MIGRATOR_URL"] = db.migrator_url
    try:
        command.downgrade(config, target)
    finally:
        os.environ.pop("NEXUSFLOW_DATABASE__MIGRATOR_URL", None)


async def drop_database(db: ProvisionedDatabase) -> None:
    conn = await asyncpg.connect(db.admin_url)
    try:
        await conn.execute(f"DROP DATABASE IF EXISTS {db.name} WITH (FORCE)")
    finally:
        await conn.close()

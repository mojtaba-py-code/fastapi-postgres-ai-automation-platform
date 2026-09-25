"""Alembic environment.

Migrations run as the *migrator* role (schema owner, BYPASSRLS), never as the
application role. Connection details come from the environment:

* ``NEXUSFLOW_DATABASE__MIGRATOR_URL`` (or ``..._FILE``) - required
* ``NEXUSFLOW_DATABASE__APP_ROLE`` - role that receives least-privilege grants
  (default ``nexusflow_app``)

``alembic -x db_url=...`` overrides the URL (used by the test harness).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from nexusflow.infrastructure.database.metadata import metadata
from nexusflow.infrastructure.database.tables import load_all_tables

load_all_tables()
config = context.config
target_metadata = metadata


def _database_url() -> str:
    override = config.attributes.get("db_url") or context.get_x_argument(as_dictionary=True).get(
        "db_url"
    )
    if override:
        return str(override)
    direct = os.environ.get("NEXUSFLOW_DATABASE__MIGRATOR_URL")
    if direct:
        return direct
    file_path = os.environ.get("NEXUSFLOW_DATABASE__MIGRATOR_URL_FILE")
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    raise RuntimeError("Set NEXUSFLOW_DATABASE__MIGRATOR_URL to run migrations.")


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        transaction_per_migration=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_async() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()
    engine = async_engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    context.configure(url=_database_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(_run_async())

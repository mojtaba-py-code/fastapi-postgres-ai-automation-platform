"""Async engine/session factory with hardened connection settings."""

from __future__ import annotations

import ssl
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from nexusflow.core.config import DatabaseSettings
from nexusflow.infrastructure.database.unit_of_work import TenantSession


def _ssl_context(settings: DatabaseSettings) -> ssl.SSLContext | str | None:
    if settings.ssl_mode == "disable":
        return None
    if settings.ssl_mode == "require":
        return "require"
    context = ssl.create_default_context(
        cafile=str(settings.ssl_root_cert) if settings.ssl_root_cert else None
    )
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def ssl_connect_args(settings: DatabaseSettings) -> dict[str, Any]:
    """asyncpg's TLS argument for ``settings``: the application, the CLI and
    the migrations all connect with the same verification."""
    ssl_arg = _ssl_context(settings)
    return {} if ssl_arg is None else {"ssl": ssl_arg}


def create_engine(settings: DatabaseSettings, *, application_name: str) -> AsyncEngine:
    connect_args: dict[str, Any] = {
        "server_settings": {
            "application_name": application_name[:63],
            # Bound the blast radius of slow/abusive queries and stuck transactions.
            "statement_timeout": str(settings.statement_timeout_ms),
            "lock_timeout": str(settings.lock_timeout_ms),
            "idle_in_transaction_session_timeout": str(settings.idle_in_transaction_timeout_ms),
        },
        "command_timeout": settings.statement_timeout_ms / 1000 + 5,
        **ssl_connect_args(settings),
    }
    return create_async_engine(
        settings.url.get_secret_value(),
        pool_size=settings.pool_size,
        max_overflow=settings.max_overflow,
        pool_timeout=settings.pool_timeout_seconds,
        pool_recycle=settings.pool_recycle_seconds,
        pool_pre_ping=True,
        echo=settings.echo,
        connect_args=connect_args,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    # expire_on_commit=False: entities returned from services stay readable after
    # the transaction ends (no lazy reload outside the tenant-scoped transaction).
    return async_sessionmaker(
        engine, expire_on_commit=False, autoflush=True, sync_session_class=TenantSession
    )

"""Operator command line: ``nexusflow <command>``.

Platform operations that must never be reachable from the tenant API live
here: service accounts for n8n, the global automation kill switch, key
re-wrapping, audit verification, migrations and configuration checks. Every
state-changing command is written to the platform audit chain.

Output is JSON (one document per command) so it can be scripted. Secrets are
printed exactly once - when a service token is issued - and never logged.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine

from nexusflow.bootstrap.container import Container, build_container
from nexusflow.core.config import Settings
from nexusflow.core.correlation import correlation
from nexusflow.core.errors import NexusFlowError
from nexusflow.core.ids import uuid7
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.authorization.principal import Principal, ServiceScope
from nexusflow.domain.identity.model import ServiceAccount
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.unit_of_work import TenantScope
from nexusflow.infrastructure.observability.logging import configure_logging
from nexusflow.infrastructure.redis.client import FeatureFlags

CLI_META = RequestMeta(request_id="cli", ip=None, user_agent="nexusflow-cli")

type Command = Callable[[Container, argparse.Namespace], Awaitable[dict[str, Any]]]


def _emit(document: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(document, indent=2, default=str) + "\n")


def _account_view(account: ServiceAccount) -> dict[str, Any]:
    return {
        "id": account.id,
        "name": account.name,
        "workflow_key": account.workflow_key,
        "scopes": account.scopes,
        "enabled": account.enabled,
        "disabled_reason": account.disabled_reason,
        "last_used_at": account.last_used_at,
    }


async def _platform_audit(
    c: Container, action: AuditAction, metadata: dict[str, Any] | None = None
) -> None:
    async with c.uow_factory(TenantScope.system(None)) as uow:
        await c.audit.record(
            uow.audit,
            action=action,
            principal=Principal.system(),
            meta=CLI_META,
            resource_type="platform",
            metadata=metadata,
        )
        await uow.commit()


# ---------------------------------------------------------- service accounts


async def sa_create(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    issued = await c.service_accounts.create(
        name=args.name,
        workflow_key=args.workflow_key,
        scopes=[ServiceScope(scope) for scope in args.scope],
        meta=CLI_META,
    )
    return {
        **_account_view(issued.account),
        "token": issued.token,
        "warning": "Store this token in n8n credentials now; it cannot be shown again.",
    }


async def sa_rotate(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    issued = await c.service_accounts.rotate(workflow_key=args.workflow_key, meta=CLI_META)
    return {**_account_view(issued.account), "token": issued.token}


async def sa_disable(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    account = await c.service_accounts.set_enabled(
        workflow_key=args.workflow_key, enabled=False, reason=args.reason, meta=CLI_META
    )
    return _account_view(account)


async def sa_enable(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    account = await c.service_accounts.set_enabled(
        workflow_key=args.workflow_key, enabled=True, reason=None, meta=CLI_META
    )
    return _account_view(account)


async def sa_list(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    return {"service_accounts": [_account_view(a) for a in await c.service_accounts.list()]}


# ------------------------------------------------------------- kill switch


async def kill_engage(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    # The flag first: automation stops even if everything after this fails.
    await c.flags.set(FeatureFlags.AUTOMATION_KILL_SWITCH, enabled=True)
    deactivated: list[str] = []
    failed: dict[str, str] = {}
    for workflow_id in args.deactivate_n8n or []:
        if c.n8n is None:
            failed[workflow_id] = "n8n_not_configured"
            continue
        try:
            await c.n8n.deactivate_workflow(workflow_id)
        except NexusFlowError as exc:
            failed[workflow_id] = exc.code
        else:
            deactivated.append(workflow_id)
    # Audited in every case, partial failures included, before anything is reported.
    await _platform_audit(
        c,
        AuditAction.PLATFORM_KILL_SWITCH_ENGAGED,
        {"reason": args.reason, "n8n_deactivated": deactivated, "n8n_failed": failed},
    )
    result: dict[str, Any] = {
        "ok": not failed,
        "kill_switch": "engaged",
        "n8n_workflows_deactivated": deactivated,
    }
    if failed:
        result["n8n_workflows_failed"] = failed
    return result


async def kill_release(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    await c.flags.set(FeatureFlags.AUTOMATION_KILL_SWITCH, enabled=False)
    await _platform_audit(c, AuditAction.PLATFORM_KILL_SWITCH_RELEASED, {"reason": args.reason})
    return {"kill_switch": "released"}


async def kill_status(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    engaged = await c.flags.is_enabled(FeatureFlags.AUTOMATION_KILL_SWITCH)
    return {"kill_switch": "engaged" if engaged else "released"}


# -------------------------------------------------------- keys and audit


async def keys_rewrap(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    active = c.settings.security.encryption_active_key_id
    total = 0
    for org_id in await c.maintenance.tenants():
        while True:  # batches until nothing is left under older keys
            count = await c.integrations.rewrap(org_id, active_key_id=active)
            count += await c.webhooks.rewrap(org_id)
            count += await c.maintenance.rewrap_sealed(org_id, active_key_id=active)
            total += count
            if count == 0:
                break
    await _platform_audit(
        c, AuditAction.ENCRYPTION_KEYS_REWRAPPED, {"active_key_id": active, "rewrapped": total}
    )
    return {"active_key_id": active, "rewrapped": total}


async def audit_verify(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    """Recompute hash chains: one tenant's (--org), or every tenant's and the platform's."""
    targets = [UUID(args.org)] if args.org else await c.maintenance.tenants()
    results = []
    for org_id in targets:
        verification = await c.audit_log.verify_integrity(Principal.system(org_id))
        results.append({"chain": str(org_id), "org_id": org_id, **asdict(verification)})
    if not args.org:
        platform = await c.audit_log.verify_platform_chain()
        results.append({"chain": "platform", "org_id": None, **asdict(platform)})
    return {"ok": all(r["ok"] for r in results), "chains": results}


async def n8n_deactivate(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    if c.n8n is None:
        raise SystemExit("n8n is not configured (NEXUSFLOW_N8N__WEBHOOK_JWT_SECRET unset)")
    await c.n8n.deactivate_workflow(args.workflow_id)
    return {"n8n_workflow": args.workflow_id, "active": False}


# ------------------------------------------------------ container-free commands


def check_config(settings: Settings) -> dict[str, Any]:
    return {
        "environment": settings.app.environment.value,
        "orchestration": settings.n8n.orchestration,
        "ai_provider": settings.ai.provider,
        "warnings": settings.security_warnings(),
    }


def migrate(settings: Settings, config_path: Path) -> dict[str, Any]:
    from alembic import command  # noqa: PLC0415 - only needed for this command
    from alembic.config import Config  # noqa: PLC0415

    if settings.database.migrator_url is None:
        raise SystemExit("NEXUSFLOW_DATABASE__MIGRATOR_URL(_FILE) is required for migrations")
    url = settings.database.migrator_url.get_secret_value()
    wait_for_database(url)
    config = Config(str(config_path))
    config.attributes["db_url"] = url
    command.upgrade(config, "head")
    return {"migrated_to": "head"}


def wait_for_database(url: str, *, timeout: float = 90.0) -> None:
    """Block until the database accepts connections for this role.

    On a first boot PostgreSQL restarts once after running its init scripts,
    and the roles only exist once those scripts are done; migrating in that
    window would fail the one-shot migrate job.
    """
    deadline = time.monotonic() + timeout
    delay = 1.0
    while True:
        try:
            asyncio.run(_probe_database(url))
        except (OSError, SQLAlchemyError) as exc:
            if time.monotonic() + delay > deadline:
                raise SystemExit(f"database not reachable: {type(exc).__name__}") from exc
            time.sleep(delay)
            delay = min(delay * 2, 8.0)
        else:
            return


async def _probe_database(url: str) -> None:
    engine = create_async_engine(url, pool_pre_ping=False)
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    finally:
        await engine.dispose()


# ------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nexusflow", description="NexusFlow AI operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check-config", help="validate configuration and print security warnings")
    mig = sub.add_parser("migrate", help="apply database migrations (uses the migrator role)")
    mig.add_argument("--config", type=Path, default=Path("alembic.ini"))

    sa = sub.add_parser("service-account", help="n8n service accounts").add_subparsers(
        dest="action", required=True
    )
    create = sa.add_parser("create")
    create.add_argument("--name", required=True)
    create.add_argument("--workflow-key", required=True)
    create.add_argument(
        "--scope", action="append", required=True, choices=[s.value for s in ServiceScope]
    )
    create.set_defaults(handler=sa_create)
    for name, handler in (("rotate", sa_rotate), ("enable", sa_enable)):
        cmd = sa.add_parser(name)
        cmd.add_argument("--workflow-key", required=True)
        cmd.set_defaults(handler=handler)
    disable = sa.add_parser("disable")
    disable.add_argument("--workflow-key", required=True)
    disable.add_argument("--reason", required=True)
    disable.set_defaults(handler=sa_disable)
    sa.add_parser("list").set_defaults(handler=sa_list)

    kill = sub.add_parser("kill-switch", help="global automation stop").add_subparsers(
        dest="action", required=True
    )
    engage = kill.add_parser("engage")
    engage.add_argument("--reason", required=True)
    engage.add_argument("--deactivate-n8n", nargs="*", metavar="WORKFLOW_ID")
    engage.set_defaults(handler=kill_engage)
    release = kill.add_parser("release")
    release.add_argument("--reason", required=True)
    release.set_defaults(handler=kill_release)
    kill.add_parser("status").set_defaults(handler=kill_status)

    keys = sub.add_parser("keys", help="encryption key maintenance").add_subparsers(
        dest="action", required=True
    )
    keys.add_parser("rewrap", help="re-encrypt secrets under the active KEK").set_defaults(
        handler=keys_rewrap
    )

    audit = sub.add_parser("audit", help="audit trail").add_subparsers(dest="action", required=True)
    verify = audit.add_parser("verify", help="recompute tenant hash chains")
    verify.add_argument("--org", help="one organization id (default: all)")
    verify.set_defaults(handler=audit_verify)

    n8n = sub.add_parser("n8n", help="n8n controls").add_subparsers(dest="action", required=True)
    deactivate = n8n.add_parser("deactivate", help="deactivate one n8n workflow")
    deactivate.add_argument("--workflow-id", required=True)
    deactivate.set_defaults(handler=n8n_deactivate)
    return parser


async def _run(settings: Settings, handler: Command, args: argparse.Namespace) -> dict[str, Any]:
    container = build_container(settings, application_name="nexusflow-cli")
    try:
        # Work an operator command causes is traceable to that command in the logs.
        with correlation(f"cli-{uuid7()}"):
            return await handler(container, args)
    finally:
        await container.aclose()


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings()
    configure_logging(
        level="WARNING", fmt=settings.observability.log_format, service="nexusflow-cli"
    )
    try:
        if args.command == "check-config":
            result = check_config(settings)
        elif args.command == "migrate":
            result = migrate(settings, args.config)
        else:
            result = asyncio.run(_run(settings, args.handler, args))
    except NexusFlowError as exc:
        _emit({"error": exc.code, "message": exc.message})
        return 1
    _emit(result)
    return 0 if result.get("ok", True) else 3  # 3: done, but only partially


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

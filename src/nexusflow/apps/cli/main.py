"""Operator command line: ``nexusflow <command>``.

Platform operations that must never be reachable from the tenant API live
here: service accounts for n8n, the global automation kill switch, sign-up
links, key re-wrapping, audit verification, migrations and configuration
checks. Every state-changing command is written to the platform audit chain.

Output is JSON (one document per command) so it can be scripted. Secrets are
printed exactly once - when a service token or a sign-up link is issued - and
never logged.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine

from nexusflow.bootstrap.container import Container, build_container
from nexusflow.core.config import Settings, decode_key_bytes
from nexusflow.core.correlation import correlation
from nexusflow.core.errors import InvalidInputError, NexusFlowError
from nexusflow.core.ids import uuid7
from nexusflow.domain.audit.model import AuditAction
from nexusflow.domain.authorization.principal import Principal, ServiceScope
from nexusflow.domain.identity.model import ServiceAccount
from nexusflow.domain.shared.context import RequestMeta
from nexusflow.domain.shared.unit_of_work import TenantScope
from nexusflow.infrastructure.database.engine import ssl_connect_args
from nexusflow.infrastructure.observability.logging import configure_logging
from nexusflow.infrastructure.redis.client import FeatureFlags
from nexusflow.infrastructure.security.vault import VaultTransit, new_key

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


# ------------------------------------------------------------ organizations


async def org_clear_network_allowlist(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    org = await c.organizations.clear_network_allowlist(
        UUID(args.org), reason=args.reason, meta=CLI_META
    )
    await _platform_audit(
        c,
        AuditAction.ORG_NETWORK_ALLOWLIST_CLEARED,
        {"org_id": str(org.id), "reason": args.reason},
    )
    return {"organization_id": org.id, "allowed_ip_ranges": None}


async def sso_verify_domain(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    """Confirm an organization owns an e-mail domain, checked outside the
    platform (no DNS-over-HTTPS egress, or a demonstration). Audited in the
    organization's trail and the platform's."""
    configuration = await c.sso.confirm_domain(
        UUID(args.org), args.domain, reason=args.reason, meta=CLI_META
    )
    await _platform_audit(
        c,
        AuditAction.SSO_DOMAIN_VERIFIED,
        {"org_id": args.org, "domain": args.domain, "reason": args.reason},
    )
    return {
        "organization_id": configuration.connection.org_id,
        "verified_domains": configuration.connection.verified_domains,
    }


# ----------------------------------------------------------------- sign-up


async def signup_issue(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    """A sign-up link for one address, printed instead of mailed: the first
    organization without e-mail, or a customer while self-service is disabled."""
    token, expires_at = await c.auth.issue_signup_link(email=args.email, meta=CLI_META)
    base = c.settings.app.public_base_url.rstrip("/")
    return {
        "email": args.email,
        "link": f"{base}/complete-signup#token={token}",
        "token": token,  # for API clients: POST /api/v1/auth/register/complete
        "expires_at": expires_at,
    }


# ------------------------------------------------ data-subject requests


async def user_export(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    """An access request received outside the platform (GDPR art. 15)."""
    return await c.privacy.export_for(args.email, meta=CLI_META)


async def user_erase(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    """An erasure request received outside the platform (GDPR art. 17)."""
    user_id = await c.privacy.erase_for(args.email, reason=args.reason, meta=CLI_META)
    return {"user_id": user_id, "erased": True}


# -------------------------------------------------------- keys and audit


def keys_vault_wrap(settings: Settings, args: argparse.Namespace) -> dict[str, Any]:
    """Move a local keyring into Vault: wrap each key (the keys themselves stay
    the same, so no stored data changes). Prints ciphertexts only."""
    if settings.security.kek_provider != "local" or settings.security.encryption_keys is None:
        raise InvalidInputError(
            "The keyring is not a local one: use vault-new or vault-rewrap.",
            code="keyring_not_local",
        )
    keys = json.loads(settings.security.encryption_keys.get_secret_value())
    transit = VaultTransit(settings.vault)
    try:
        wrapped = {key_id: transit.encrypt_key(decode_key_bytes(v)) for key_id, v in keys.items()}
    finally:
        transit.close()
    return {"encryption_keys": wrapped}


def keys_vault_new(settings: Settings, args: argparse.Namespace) -> dict[str, Any]:
    """A new key-encryption key, generated here and printed only wrapped by
    Vault: add it to the keyring, make it active, then run keys rewrap."""
    transit = VaultTransit(settings.vault)
    try:
        return {"key_id": args.key_id, "wrapped": transit.encrypt_key(new_key())}
    finally:
        transit.close()


def keys_vault_rewrap(settings: Settings, args: argparse.Namespace) -> dict[str, Any]:
    """After rotating the transit key in Vault: the keyring re-wrapped under
    its newest version (the keys, and so the stored data, do not change)."""
    sec = settings.security
    if sec.kek_provider != "vault-transit" or sec.encryption_keys is None:
        raise InvalidInputError("The keyring is not wrapped by Vault.", code="keyring_not_vault")
    wrapped = json.loads(sec.encryption_keys.get_secret_value())
    transit = VaultTransit(settings.vault)
    try:
        return {"encryption_keys": transit.rewrap(wrapped)}
    finally:
        transit.close()


async def keys_rewrap(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    """Re-wrap everything under the active key, then count - without locks -
    what is still under an older one. Batches skip rows other transactions
    hold, so "a pass re-wrapped nothing" is not "done": only ``remaining``
    being empty (``ok``) means the old key may leave the keyring."""
    active = c.settings.security.encryption_active_key_id
    total = 0
    remaining: dict[str, dict[str, int]] = {}
    for org_id in await c.maintenance.tenants():
        left: dict[str, int] = {}
        for attempt in range(max(args.passes, 1)):
            if attempt:
                await asyncio.sleep(args.wait_seconds)  # held rows: let their transactions end
            while True:  # batches until a pass re-wraps nothing
                count = await c.integrations.rewrap(org_id, active_key_id=active)
                count += await c.webhooks.rewrap(org_id, active_key_id=active)
                count += await c.sso.rewrap(org_id, active_key_id=active)
                count += await c.maintenance.rewrap_sealed(org_id, active_key_id=active)
                total += count
                if count == 0:
                    break
            left = await c.maintenance.still_under_old_keys(org_id, active_key_id=active)
            if not left:
                break
        if left:
            remaining[str(org_id)] = left
    await _platform_audit(
        c,
        AuditAction.ENCRYPTION_KEYS_REWRAPPED,
        {"active_key_id": active, "rewrapped": total, "tenants_remaining": len(remaining)},
    )
    result: dict[str, Any] = {"ok": not remaining, "active_key_id": active, "rewrapped": total}
    if remaining:
        result["remaining"] = remaining
        result["warning"] = (
            "Some data is still under an older key (rows in use): run this command again "
            "before removing any key from NEXUSFLOW_SECURITY__ENCRYPTION_KEYS."
        )
    return result


MIN_AUDIT_RETENTION_DAYS = 90


async def audit_purge(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    """Delete audit entries older than ``--older-than-days``, a prefix of every
    chain (so what remains still verifies). The runtime role cannot delete
    audit entries: this runs as the migrator, the table's owner."""
    if args.older_than_days < MIN_AUDIT_RETENTION_DAYS:
        raise InvalidInputError(
            f"Keep at least {MIN_AUDIT_RETENTION_DAYS} days of audit entries.",
            code="retention_too_short",
        )
    if c.settings.database.migrator_url is None:
        raise InvalidInputError(
            "NEXUSFLOW_DATABASE__MIGRATOR_URL(_FILE) is required to purge audit entries.",
            code="migrator_required",
        )
    before = c.clock.now() - timedelta(days=args.older_than_days)
    deleted = await purge_audit_logs(
        c.settings.database.migrator_url.get_secret_value(),
        before,
        connect_args=ssl_connect_args(c.settings.database),
    )
    await _platform_audit(
        c, AuditAction.AUDIT_LOGS_PURGED, {"before": before.isoformat(), "deleted": deleted}
    )
    return {"before": before, "deleted": deleted}


async def purge_audit_logs(
    migrator_url: str, before: datetime, *, connect_args: dict[str, Any] | None = None
) -> int:
    engine = create_async_engine(migrator_url, connect_args=connect_args or {})
    try:
        async with engine.begin() as conn:
            result = await conn.execute(
                text("SELECT nf_purge_audit_logs(:before)"), {"before": before}
            )
            return int(result.scalar_one())
    finally:
        await engine.dispose()


async def audit_verify(c: Container, args: argparse.Namespace) -> dict[str, Any]:
    """Recompute hash chains: one tenant's (--org), or every tenant's and the platform's."""
    targets = [UUID(args.org)] if args.org else await c.maintenance.tenants()
    results = []
    for org_id in targets:
        verification = await c.audit_log.verify_integrity(Principal.system(org_id), complete=True)
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
    connect_args = ssl_connect_args(settings.database)  # the app's TLS verification
    wait_for_database(url, connect_args=connect_args)
    config = Config(str(config_path))
    config.attributes["db_url"] = url
    config.attributes["connect_args"] = connect_args
    command.upgrade(config, "head")
    return {"migrated_to": "head"}


def wait_for_database(
    url: str, *, connect_args: dict[str, Any] | None = None, timeout: float = 90.0
) -> None:
    """Block until the database accepts connections for this role.

    On a first boot PostgreSQL restarts once after running its init scripts,
    and the roles only exist once those scripts are done; migrating in that
    window would fail the one-shot migrate job.
    """
    deadline = time.monotonic() + timeout
    delay = 1.0
    while True:
        try:
            asyncio.run(_probe_database(url, connect_args or {}))
        except (OSError, SQLAlchemyError) as exc:
            if time.monotonic() + delay > deadline:
                raise SystemExit(f"database not reachable: {type(exc).__name__}") from exc
            time.sleep(delay)
            delay = min(delay * 2, 8.0)
        else:
            return


async def _probe_database(url: str, connect_args: dict[str, Any]) -> None:
    engine = create_async_engine(url, pool_pre_ping=False, connect_args=connect_args)
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    finally:
        await engine.dispose()


# ------------------------------------------------------------------ parser


def _key_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", value):
        raise argparse.ArgumentTypeError("1-32 characters: letters, digits, '.', '_' or '-'")
    return value


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

    _organization_commands(sub)
    _people_commands(sub)

    _key_commands(sub)

    audit = sub.add_parser("audit", help="audit trail").add_subparsers(dest="action", required=True)
    purge = audit.add_parser(
        "purge", help="delete audit entries past their retention (runs as the migrator)"
    )
    purge.add_argument("--older-than-days", type=int, required=True)
    purge.set_defaults(handler=audit_purge)
    verify = audit.add_parser("verify", help="recompute tenant hash chains")
    verify.add_argument("--org", help="one organization id (default: all)")
    verify.set_defaults(handler=audit_verify)

    n8n = sub.add_parser("n8n", help="n8n controls").add_subparsers(dest="action", required=True)
    deactivate = n8n.add_parser("deactivate", help="deactivate one n8n workflow")
    deactivate.add_argument("--workflow-id", required=True)
    deactivate.set_defaults(handler=n8n_deactivate)
    return parser


def _organization_commands(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Organization recovery, and the operator's confirmation of a domain's
    ownership for single sign-on."""
    org = sub.add_parser("org", help="organization recovery").add_subparsers(
        dest="action", required=True
    )
    clear = org.add_parser(
        "clear-network-allowlist",
        help="remove an organization's network allowlist (it locked itself out)",
    )
    clear.add_argument("--org", required=True, help="organization ID")
    clear.add_argument("--reason", required=True)
    clear.set_defaults(handler=org_clear_network_allowlist)

    sso = sub.add_parser("sso", help="single sign-on").add_subparsers(dest="action", required=True)
    verify_domain = sso.add_parser(
        "verify-domain",
        help="confirm an organization owns an allowed e-mail domain (checked out of band)",
    )
    verify_domain.add_argument("--org", required=True, help="organization ID")
    verify_domain.add_argument("--domain", required=True)
    verify_domain.add_argument("--reason", required=True)
    verify_domain.set_defaults(handler=sso_verify_domain)


def _key_commands(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Encryption key maintenance, including the keyring wrapped by Vault."""
    keys = sub.add_parser("keys", help="encryption key maintenance").add_subparsers(
        dest="action", required=True
    )
    rewrap = keys.add_parser("rewrap", help="re-encrypt secrets under the active KEK")
    rewrap.add_argument(
        "--passes", type=int, default=3, help="re-wrap passes per tenant while data remains"
    )
    rewrap.add_argument(
        "--wait-seconds", type=float, default=5.0, help="pause between passes (held rows)"
    )
    rewrap.set_defaults(handler=keys_rewrap)
    keys.add_parser(
        "vault-wrap", help="wrap the local keyring with Vault transit (prints ciphertexts)"
    ).set_defaults(sync_handler=keys_vault_wrap)
    vault_new = keys.add_parser("vault-new", help="a new KEK, printed wrapped by Vault")
    vault_new.add_argument("--key-id", required=True, type=_key_id)
    vault_new.set_defaults(sync_handler=keys_vault_new)
    keys.add_parser(
        "vault-rewrap", help="re-wrap the keyring under the newest transit key version"
    ).set_defaults(sync_handler=keys_vault_rewrap)


def _people_commands(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Sign-up links and data-subject requests."""
    signup = sub.add_parser("signup", help="sign-up links").add_subparsers(
        dest="action", required=True
    )
    issue = signup.add_parser(
        "issue",
        help="print a sign-up link for an address (it works while self-service is disabled)",
    )
    issue.add_argument("--email", required=True)
    issue.set_defaults(handler=signup_issue)

    person = sub.add_parser("user", help="data-subject requests").add_subparsers(
        dest="action", required=True
    )
    export = person.add_parser("export", help="a person's copy of their data (JSON)")
    export.add_argument("--email", required=True)
    export.set_defaults(handler=user_export)
    erase = person.add_parser(
        "erase", help="erase a person's account (refused while they solely own an organization)"
    )
    erase.add_argument("--email", required=True)
    erase.add_argument("--reason", required=True)
    erase.set_defaults(handler=user_erase)


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
        elif getattr(args, "sync_handler", None) is not None:
            result = args.sync_handler(settings, args)  # no database needed
        else:
            result = asyncio.run(_run(settings, args.handler, args))
    except NexusFlowError as exc:
        _emit({"error": exc.code, "message": exc.message})
        return 1
    _emit(result)
    return 0 if result.get("ok", True) else 3  # 3: done, but only partially


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

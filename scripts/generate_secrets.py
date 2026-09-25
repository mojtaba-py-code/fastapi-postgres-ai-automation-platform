#!/usr/bin/env python3
"""Generate every secret docker-compose needs into ``./secrets``.

* passwords and tokens come from the OS CSPRNG (``secrets``);
* the JWT signing key is a fresh Ed25519 key pair;
* Redis ACL and RabbitMQ definitions contain password *hashes*, not passwords;
* existing files are never overwritten: a run creates only what is missing,
  so an upgrade that introduces a new secret simply adds it. Values that are
  generated together (a password and the URL or hash that embeds it) form a
  group; a group that is only partly present is refused, never "repaired"
  with a new password the database or broker does not know;
* ``--force`` regenerates EVERY secret - for a fresh install only (on a
  running stack it locks the database roles out and makes encrypted data
  unreadable; rotating a key follows docs/DEPLOYMENT.md instead);
* ``--tls-urls`` upgrades the Redis and broker URLs of a stack created before
  internal TLS (redis:// -> rediss://, amqp://...:5672 -> amqps://...:5671),
  keeping their credentials;
* the directory is 0700, so no other host user can reach the files, while
  the files are 0644: Compose bind-mounts file secrets with their host mode,
  and PostgreSQL, Redis and RabbitMQ read them as their own unprivileged users.

Usage: ``python scripts/generate_secrets.py [--dir secrets] [--tls-urls | --force]``
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH  # 0644, see docstring


def token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def b64_key(nbytes: int) -> str:
    return base64.b64encode(secrets.token_bytes(nbytes)).decode("ascii")


def ed25519_pem() -> str:
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def rabbit_hash(password: str) -> str:
    """RabbitMQ ``rabbit_password_hashing_sha256``: base64(salt + sha256(salt + pw))."""
    salt = secrets.token_bytes(4)
    return base64.b64encode(salt + hashlib.sha256(salt + password.encode()).digest()).decode()


def redis_acl(app_password: str) -> str:
    """The platform Redis: rate limits, nonces, flags. The sandbox has no user here."""
    app_hash = hashlib.sha256(app_password.encode()).hexdigest()
    return "\n".join(
        [
            "user default off",
            # Platform services: their own key prefix only, no admin/dangerous commands.
            (
                f"user app on #{app_hash} ~nf:* resetchannels +@all -@dangerous -@admin "
                "+script|load +evalsha +eval"
            ),
            "",
        ]
    )


def redis_sandbox_acl(sandbox_password: str) -> str:
    """The sandbox's own, disposable Redis (robots.txt cache, host throttle).

    A separate instance with LRU eviction: whatever a compromised sandbox
    writes there can only degrade the sandbox's own cache, never the platform's
    rate limits, replay guards or kill switch.
    """
    sandbox_hash = hashlib.sha256(sandbox_password.encode()).hexdigest()
    return "\n".join(
        [
            "user default off",
            (
                f"user sandbox on #{sandbox_hash} ~nf:robots:* ~nf:throttle:* resetchannels "
                "-@all +get +set +pttl +ping"
            ),
            "",
        ]
    )


def work_queue_arguments(name: str) -> dict[str, object]:
    """Must equal ``nexusflow.infrastructure.messaging.celery_app.queue_arguments``
    (a unit test keeps them in sync); Celery declares the same queues."""
    arguments: dict[str, object] = {
        "x-queue-type": "quorum",
        "x-delivery-limit": 10,
        "x-dead-letter-exchange": "nexusflow.dlx",
        "x-dead-letter-routing-key": f"{name}.dead",
    }
    if name == "sandbox":
        arguments.update(
            {
                "x-max-length": 10_000,
                "x-max-length-bytes": 64 * 1024 * 1024,
                "x-overflow": "reject-publish",
            }
        )
    return arguments


def rabbit_definitions(platform_password: str, sandbox_password: str) -> str:
    vhost = "nexusflow"
    definitions = {
        "users": [
            {
                "name": "nexusflow",
                "password_hash": rabbit_hash(platform_password),
                "hashing_algorithm": "rabbit_password_hashing_sha256",
                "tags": [],
            },
            {
                "name": "sandbox",
                "password_hash": rabbit_hash(sandbox_password),
                "hashing_algorithm": "rabbit_password_hashing_sha256",
                "tags": [],
            },
        ],
        "vhosts": [{"name": vhost}],
        "permissions": [
            {"user": "nexusflow", "vhost": vhost, "configure": ".*", "write": ".*", "read": ".*"},
            # The sandbox can configure nothing - it cannot declare a queue and
            # bind it to tap other jobs. It reads its own queue and publishes
            # (Celery retries) to its own exchange, bound to that queue alone.
            # Everything is pre-declared here; the sandbox app never declares.
            {
                "user": "sandbox",
                "vhost": vhost,
                "configure": "^$",
                "write": r"^nexusflow\.sandbox$",
                "read": "^sandbox$",
            },
        ],
        # Must match nexusflow.infrastructure.messaging.celery_app: "nexusflow"
        # is a topic exchange (delayed retries held by RabbitMQ, not by workers).
        "exchanges": [
            {
                "name": exchange,
                "vhost": vhost,
                "type": kind,
                "durable": True,
                "auto_delete": False,
                "internal": False,
                "arguments": {},
            }
            for exchange, kind in (
                ("nexusflow", "topic"),
                ("nexusflow.sandbox", "direct"),
                ("nexusflow.dlx", "direct"),
            )
        ],
        "queues": [],
        "bindings": [],
    }
    for name in ("pipeline", "integrations", "sandbox"):
        definitions["queues"].append(
            {
                "name": name,
                "vhost": vhost,
                "durable": True,
                "auto_delete": False,
                "arguments": work_queue_arguments(name),
            }
        )
        definitions["queues"].append(
            {
                "name": f"{name}.dead",
                "vhost": vhost,
                "durable": True,
                "auto_delete": False,
                "arguments": {"x-queue-type": "quorum"},
            }
        )
        source = "nexusflow.sandbox" if name == "sandbox" else "nexusflow"
        definitions["bindings"].append(
            {
                "source": source,
                "vhost": vhost,
                "destination": name,
                "destination_type": "queue",
                "routing_key": name,
                "arguments": {},
            }
        )
        definitions["bindings"].append(
            {
                "source": "nexusflow.dlx",
                "vhost": vhost,
                "destination": f"{name}.dead",
                "destination_type": "queue",
                "routing_key": f"{name}.dead",
                "arguments": {},
            }
        )
    return json.dumps(definitions, indent=2) + "\n"


def build() -> dict[str, str]:
    db_app, db_migrator, db_n8n = token(), token(), token()
    redis_app, redis_sandbox = token(), token()
    mq_platform, mq_sandbox = token(), token()
    return {
        "postgres_password": token(),
        "db_app_password": db_app,
        "db_migrator_password": db_migrator,
        "n8n_db_password": db_n8n,
        "db_app_url": f"postgresql+asyncpg://nexusflow_app:{db_app}@postgres:5432/nexusflow",
        "db_migrator_url": f"postgresql+asyncpg://nexusflow_migrator:{db_migrator}@postgres:5432/nexusflow",
        "redis_users_acl": redis_acl(redis_app),
        "redis_sandbox_acl": redis_sandbox_acl(redis_sandbox),
        # TLS inside the stack (scripts/internal_pki.py issues the certificates).
        "redis_app_url": f"rediss://app:{redis_app}@redis:6379/0",
        "redis_sandbox_url": f"rediss://sandbox:{redis_sandbox}@redis-sandbox:6379/0",
        "rabbitmq_definitions": rabbit_definitions(mq_platform, mq_sandbox),
        "broker_platform_url": f"amqps://nexusflow:{mq_platform}@rabbitmq:5671/nexusflow",
        "broker_sandbox_url": f"amqps://sandbox:{mq_sandbox}@rabbitmq:5671/nexusflow",
        "jwt_private_key": ed25519_pem(),
        "encryption_keys": json.dumps({"kek-1": b64_key(32)}),
        "hmac_pepper": b64_key(48),
        "n8n_webhook_jwt_secret": token(48),
        "n8n_encryption_key": token(48),
        "browser_token": token(48),
        "grafana_admin_password": token(24),
    }


# Values generated together: a password and everything that embeds it must
# come from the same run. Every other secret stands alone.
GROUPS: tuple[tuple[str, ...], ...] = (
    ("db_app_password", "db_app_url"),
    ("db_migrator_password", "db_migrator_url"),
    ("redis_users_acl", "redis_app_url"),
    ("redis_sandbox_acl", "redis_sandbox_url"),
    ("rabbitmq_definitions", "broker_platform_url", "broker_sandbox_url"),
)
_TLS_URLS: dict[str, tuple[tuple[str, str], ...]] = {
    "redis_app_url": (("redis://", "rediss://"),),
    "redis_sandbox_url": (("redis://", "rediss://"),),
    "broker_platform_url": (("amqp://", "amqps://"), ("@rabbitmq:5672/", "@rabbitmq:5671/")),
    "broker_sandbox_url": (("amqp://", "amqps://"), ("@rabbitmq:5672/", "@rabbitmq:5671/")),
}


def _groups(names: list[str]) -> list[tuple[str, ...]]:
    grouped = {name for group in GROUPS for name in group}
    return list(GROUPS) + [(name,) for name in names if name not in grouped]


def upgrade_urls_to_tls(directory: Path) -> list[str]:
    """Rewrite plaintext Redis/broker URLs for internal TLS; returns what changed."""
    changed: list[str] = []
    for name, replacements in _TLS_URLS.items():
        path = directory / name
        if not path.exists():
            continue
        value = original = path.read_text(encoding="utf-8")
        for old, new in replacements:
            if value.startswith(old) or old.startswith("@"):
                value = value.replace(old, new, 1)
        if value != original:
            _write(path, value)
            changed.append(name)
    return changed


# Optional secrets that only exist after a manual step. They are created empty
# (an empty secret file means "not configured") so Compose can always mount
# them, and they are never overwritten once an operator has filled them in.
PLACEHOLDERS = {
    "n8n_api_key": "",  # n8n > Settings > n8n API, after n8n's first start
    "smtp_password": "",  # the relay's password, if needed  # nosec B105 - empty placeholder
    "ai_api_key": "",  # only with NEXUSFLOW_AI_PROVIDER=anthropic
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, default=Path("secrets"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--force", action="store_true", help="regenerate EVERY secret (fresh installs only)"
    )
    mode.add_argument(
        "--tls-urls", action="store_true", help="upgrade Redis/broker URLs to internal TLS"
    )
    args = parser.parse_args(argv)
    if args.tls_urls:
        changed = upgrade_urls_to_tls(args.dir)
        print(f"upgraded to TLS: {', '.join(changed)}" if changed else "URLs already use TLS")
        return 0
    values = build()
    if not args.force:
        partial = [
            group
            for group in _groups(list(values))
            if 0 < sum((args.dir / name).exists() for name in group) < len(group)
        ]
        if partial:
            # A new password for half a group would not match the other half,
            # which the database or the broker already knows.
            for group in partial:
                missing = [n for n in group if not (args.dir / n).exists()]
                print(f"incomplete group {', '.join(group)}: missing {', '.join(missing)}")
            print("restore the missing files from your backup of the secrets directory")
            return 1
    args.dir.mkdir(mode=0o700, exist_ok=True)
    args.dir.chmod(0o700)
    created = [
        name for name, value in values.items() if args.force or not (args.dir / name).exists()
    ]
    for name in created:
        _write(args.dir / name, values[name])
    for name, value in PLACEHOLDERS.items():
        if not (args.dir / name).exists():
            _write(args.dir / name, value)
    kept = len(values) - len(created)
    print(f"created {len(created)} secrets, kept {kept} in {args.dir.resolve()}")
    print("never commit this directory; fill in when needed: " + ", ".join(sorted(PLACEHOLDERS)))
    plaintext = [
        name
        for name, replacements in _TLS_URLS.items()
        if (args.dir / name).exists()
        and (args.dir / name).read_text(encoding="utf-8").startswith(replacements[0][0])
    ]
    if plaintext:
        print(f"these URLs predate internal TLS: {', '.join(plaintext)} - run with --tls-urls")
    return 0


def _write(path: Path, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(value)
    path.chmod(_FILE_MODE)


if __name__ == "__main__":
    raise SystemExit(main())

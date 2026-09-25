"""Generate docs/CONFIGURATION.md from the settings classes.

The settings classes in ``nexusflow.core.config`` are the single source of
truth for every environment variable; this script renders them as a reference
so the documentation cannot drift from the code:

    python scripts/gen_config_reference.py            # rewrite the document
    python scripts/gen_config_reference.py --check    # exit 1 if it is stale (CI)

Secret defaults (development placeholders) are never printed.
"""

from __future__ import annotations

import argparse
import sys
import types
import typing
from enum import Enum
from pathlib import Path
from typing import Any, Literal, get_args, get_origin

import annotated_types
from pydantic import BaseModel, SecretStr
from pydantic.fields import FieldInfo
from pydantic_core import PydanticUndefined

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nexusflow.core.config import (  # noqa: E402 - after the path setup above
    ENV_PREFIX,
    BrowserServiceSettings,
    SandboxSettings,
    Settings,
)

TARGET = ROOT / "docs" / "CONFIGURATION.md"

SECTION_NOTES: dict[str, str] = {
    "app": "Identity of the deployment, HTTP surface and request limits.",
    "database": (
        "PostgreSQL. `url` is the runtime role (RLS enforced); `migrator_url` owns the "
        "schema and is used only by `nexusflow migrate`."
    ),
    "redis": (
        "Rate limits, replay nonces, caches and locks. Use a `rediss://` URL outside an "
        "isolated network."
    ),
    "broker": "RabbitMQ (Celery). Each worker pool has its own broker user; see deploy/rabbitmq.",
    "security": "Key material, token lifetimes, password hashing and brute-force protection.",
    "scraping": (
        "Outbound HTTP for collection: SSRF policy, limits, politeness and the browser service."
    ),
    "ai": (
        "The analysis provider. `offline` never sends data anywhere; `anthropic` also needs "
        "each tenant's explicit opt-in."
    ),
    "notifications": (
        "Alert delivery: SMTP (TLS mandatory), Telegram and Slack endpoints, operator pages."
    ),
    "n8n": "Orchestration mode and the connection to n8n.",
    "storage": "Uploads and reports on local (or mounted) storage; optional ClamAV scanning.",
    "observability": "Logs, metrics and traces.",
    "retention": "How long operational data is kept before the maintenance job purges it.",
    "rate_limits": "Per-scope rate limits (see the table of defaults below).",
    "sandbox": "Sandbox worker only: how it reaches the result gateway.",
    "browser": "Browser service only: its token and resource limits.",
}

PRODUCTION_RULES = [
    "`app.debug` must be false",
    "`app.public_base_url` must use https",
    "`app.allowed_hosts` must be an explicit list (no `*`)",
    "CORS origins must be explicit https origins",
    "`scraping.allow_http` must be false",
    "`n8n.webhook_jwt_secret` is required",
]
ALWAYS_REQUIRED = [
    "`security.jwt_private_key` (Ed25519 private key, PEM)",
    "`security.hmac_pepper` (at least 32 bytes)",
    "`security.encryption_keys` (JSON object of base64 32-byte keys)",
    "`ai.api_key` when `ai.provider=anthropic`",
]


def _type_name(annotation: Any) -> str:
    origin = get_origin(annotation)
    args = [a for a in get_args(annotation) if a is not type(None)]
    optional = type(None) in get_args(annotation)
    if origin in (types.UnionType, typing.Union):
        inner = " or ".join(_type_name(a) for a in args)
        return f"{inner} (optional)" if optional else inner
    if origin is Literal:
        return "one of: " + ", ".join(f"`{a}`" for a in get_args(annotation))
    if origin is list:
        return "JSON list"
    if origin is dict:
        return "JSON object"
    if annotation is SecretStr:
        return "secret"
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return "one of: " + ", ".join(f"`{member.value}`" for member in annotation)
    if isinstance(annotation, type) and issubclass(annotation, Path):
        return "path"
    name = getattr(annotation, "__name__", str(annotation))
    return {"EmailStr": "e-mail", "IPv4Network": "network", "IPv6Network": "network"}.get(
        name, name
    )


def _is_secret(annotation: Any) -> bool:
    return annotation is SecretStr or SecretStr in get_args(annotation)


def _default(field: FieldInfo) -> str:
    if _is_secret(field.annotation):
        return "*(none)*" if field.default is None else "*(development placeholder)*"
    if field.default is not PydanticUndefined:
        value = field.default
    elif field.default_factory is not None:
        value = field.default_factory()  # type: ignore[call-arg]
    else:
        return "*(required)*"
    if value is None:
        return "*(unset)*"
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, bool):
        return f"`{str(value).lower()}`"
    if isinstance(value, (list, dict)):
        if not value:
            return "`[]`" if isinstance(value, list) else "`{}`"
        if isinstance(value, dict):
            return "*(see below)*"
        return "`" + ", ".join(str(v) for v in value) + "`"
    return f"`{value}`"


def _constraints(field: FieldInfo) -> str:
    notes: list[str] = []
    for item in field.metadata:
        match item:
            case annotated_types.Ge(ge=bound):
                notes.append(f">= {bound}")
            case annotated_types.Gt(gt=bound):
                notes.append(f"> {bound}")
            case annotated_types.Le(le=bound):
                notes.append(f"<= {bound}")
            case annotated_types.Lt(lt=bound):
                notes.append(f"< {bound}")
            case _ if getattr(item, "pattern", None):
                notes.append(f"pattern `{item.pattern}`")
    if _is_secret(field.annotation):
        notes.append("secret: prefer `…_FILE`")
    return "; ".join(notes)


def _section_table(section: str, model: type[BaseModel]) -> list[str]:
    lines = [
        "| Variable | Type | Default | Constraints |",
        "|---|---|---|---|",
    ]
    for name, field in model.model_fields.items():
        variable = f"{ENV_PREFIX}{section}__{name}".upper()
        lines.append(
            f"| `{variable}` | {_type_name(field.annotation)} | {_default(field)} | "
            f"{_constraints(field)} |"
        )
    return lines


def _sections(settings: type[BaseModel]) -> dict[str, type[BaseModel]]:
    sections: dict[str, type[BaseModel]] = {}
    for name, field in settings.model_fields.items():
        annotation = field.annotation
        if not (isinstance(annotation, type) and issubclass(annotation, BaseModel)):
            raise TypeError(f"settings field {name!r} is not a section model")
        sections[name] = annotation
    return sections


def _rate_limit_table() -> list[str]:
    rules = Settings.model_fields["rate_limits"].default_factory()  # type: ignore[call-arg,misc]
    lines = ["| Scope | Limit | Period (s) | On Redis outage |", "|---|---|---|---|"]
    for scope, rule in sorted(rules.rules.items()):
        outage = "reject (fail closed)" if rule.fail_closed else "allow (fail open)"
        lines.append(f"| `{scope}` | {rule.limit} | {rule.period_seconds} | {outage} |")
    return lines


def render() -> str:
    platform = _sections(Settings)
    sandbox = _sections(SandboxSettings)
    browser = _sections(BrowserServiceSettings)
    out = [
        "# Configuration reference",
        "",
        (
            "<!-- Generated by scripts/gen_config_reference.py from nexusflow.core.config."
            " Do not edit by hand: run `make config-docs`. -->"
        ),
        "",
        (
            "All configuration comes from environment variables with the prefix "
            f"`{ENV_PREFIX}`; nested sections are separated by `__`. Values are validated at "
            "startup and a process refuses to start with an invalid or insecure configuration."
        ),
        "",
        (
            "* **Secrets from files.** Any variable can instead name a file by appending `_FILE`, "
            "e.g. `NEXUSFLOW_SECURITY__HMAC_PEPPER_FILE=/run/secrets/hmac_pepper`. This is how "
            "Docker and Kubernetes secrets are mounted; secret values never need to be in the "
            "environment. Files are limited to 64 KiB."
        ),
        "* **Lists and objects** are JSON: `NEXUSFLOW_APP__ALLOWED_HOSTS='[\"api.example.com\"]'`.",
        "* **Empty values** count as unset, so Compose's `${VAR:-}` falls back to the default.",
        (
            "* **Three processes, three settings classes.** The platform (API, internal API, "
            "pipeline and integrations workers, beat, CLI) reads everything below. The sandbox "
            "worker and the browser service read deliberately narrow subsets: they have no field "
            "for a database URL, key material or provider credentials, so none can be configured "
            "into a process that handles hostile content."
        ),
        "",
        "## Refused configurations",
        "",
        "Always required:",
        "",
        *[f"* {rule}" for rule in ALWAYS_REQUIRED],
        "",
        "Additionally refused when `app.environment` is `staging` or `production`:",
        "",
        *[f"* {rule}" for rule in PRODUCTION_RULES],
        "",
        (
            "Production also logs warnings for plaintext database, Redis and broker connections "
            "and for uploads without malware scanning."
        ),
        "",
        "## Platform",
        "",
    ]
    for section, model in platform.items():
        out += [f"### `{section}`", "", SECTION_NOTES.get(section, ""), ""]
        out += _section_table(section, model)
        out.append("")
        if section == "rate_limits":
            out += [
                (
                    "Default rules. `NEXUSFLOW_RATE_LIMITS__RULES` is a JSON object merged over "
                    'these defaults, e.g. `{"api.read": {"limit": 1200, "period_seconds": 60}}`. '
                    "An override changes only the fields it names: tuning a limit keeps the "
                    "scope's failure policy."
                ),
                "",
                *_rate_limit_table(),
                "",
            ]
    for title, sections, shared in (
        ("Sandbox worker", sandbox, "app, broker, scraping, storage, observability"),
        ("Browser service", browser, "app, scraping, observability"),
    ):
        out += [
            f"## {title}",
            "",
            f"Reads only these shared sections: {shared}. Its own section:",
            "",
        ]
        for section, model in sections.items():
            if section in platform:
                continue
            out += [f"### `{section}`", "", SECTION_NOTES.get(section, ""), ""]
            out += _section_table(section, model)
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the document is stale")
    args = parser.parse_args()
    document = render()
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != document:
            print(f"{TARGET.relative_to(ROOT)} is stale: run `make config-docs`", file=sys.stderr)
            return 1
        return 0
    TARGET.write_text(document, encoding="utf-8", newline="\n")
    print(f"wrote {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

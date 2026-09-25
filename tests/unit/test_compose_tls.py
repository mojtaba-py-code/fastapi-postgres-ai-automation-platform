"""The production Compose file keeps every internal hop on verified TLS.

CI starts this stack, so a broken TLS setting fails the end-to-end job; these
checks explain *what* broke, and pin the properties a working stack could
still lose silently - a client that stops verifying, a server that accepts
plaintext again, a private key mounted where it does not belong.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CA = "/run/secrets/internal_ca"


def _script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(
        (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    )
    return document


def _services_with(compose: dict[str, Any], secret: str) -> dict[str, dict[str, Any]]:
    return {
        name: service
        for name, service in compose["services"].items()
        if secret in (service.get("secrets") or [])
    }


@pytest.mark.parametrize(
    ("secret", "settings"),
    [
        (
            "db_app_url",
            {
                "NEXUSFLOW_DATABASE__SSL_MODE": "verify-full",
                "NEXUSFLOW_DATABASE__SSL_ROOT_CERT": CA,
            },
        ),
        ("redis_app_url", {"NEXUSFLOW_REDIS__SSL_CA_CERTS": CA}),
        (
            "broker_platform_url",
            {"NEXUSFLOW_BROKER__USE_SSL": "true", "NEXUSFLOW_BROKER__SSL_CA_CERTS": CA},
        ),
        (
            "broker_sandbox_url",
            {"NEXUSFLOW_BROKER__USE_SSL": "true", "NEXUSFLOW_BROKER__SSL_CA_CERTS": CA},
        ),
        ("redis_sandbox_url", {"NEXUSFLOW_SANDBOX__REDIS_SSL_CA_CERTS": CA}),
        ("n8n_db_password", {"DB_POSTGRESDB_SSL_CA_FILE": CA}),
    ],
)
def test_every_client_verifies_the_server_against_the_internal_ca(
    compose: dict[str, Any], secret: str, settings: dict[str, str]
) -> None:
    clients = {
        name: service
        for name, service in _services_with(compose, secret).items()
        if name != "postgres"  # the server itself holds the role passwords
    }
    assert clients, secret
    for name, service in clients.items():
        environment = service.get("environment") or {}
        for key, value in settings.items():
            assert str(environment.get(key)) == value, (name, key)
        assert "internal_ca" in service["secrets"], name


def test_generated_connection_urls_use_tls(compose: dict[str, Any]) -> None:
    urls = _script("generate_secrets").build()
    pki_hosts = {host for hosts in _script("internal_pki").SERVICES.values() for host in hosts}
    for name in ("redis_app_url", "redis_sandbox_url"):
        assert urls[name].startswith("rediss://"), name
    for name in ("broker_platform_url", "broker_sandbox_url"):
        assert urls[name].startswith("amqps://") and ":5671/" in urls[name], name
    for name, url in urls.items():
        if name.endswith("_url"):  # every server a URL names has a certificate for that name
            assert urlsplit(url).hostname in pki_hosts, name


def test_the_servers_accept_tls_only(compose: dict[str, Any]) -> None:
    deploy = ROOT / "deploy"
    hba = (deploy / "postgres" / "pg_hba.conf").read_text(encoding="utf-8")
    lines = [line.split() for line in hba.splitlines() if line.strip() and not line.startswith("#")]
    assert {line[0] for line in lines} == {"local", "hostssl"}  # no plaintext "host" line
    command = compose["services"]["postgres"]["command"]
    assert "ssl=on" in command and "hba_file=/etc/postgresql/pg_hba.conf" in command

    for conf in ("redis-tls.conf", "redis-sandbox-tls.conf"):
        text = (deploy / "redis" / conf).read_text(encoding="utf-8")
        assert re.search(r"^port 0$", text, re.MULTILINE), conf
        assert re.search(r"^tls-port 6379$", text, re.MULTILINE), conf
    for name in ("redis", "redis-sandbox"):
        assert compose["services"][name]["command"][-1].endswith("redis-tls.conf"), name

    rabbit = (deploy / "rabbitmq" / "tls.conf").read_text(encoding="utf-8")
    assert "listeners.tcp = none" in rabbit and "listeners.ssl.default = 5671" in rabbit
    mounts = compose["services"]["rabbitmq"]["volumes"]
    assert any(m.endswith("conf.d/20-tls.conf:ro") for m in mounts)


def test_private_keys_are_mounted_only_where_they_belong(compose: dict[str, Any]) -> None:
    files = {name: spec["file"] for name, spec in compose["secrets"].items()}
    assert not any(path.endswith("internal_ca.key") for path in files.values())  # host only
    owners = {
        "tls_postgres_key": "postgres",
        "tls_redis_key": "redis",
        "tls_redis_sandbox_key": "redis-sandbox",
        "tls_rabbitmq_key": "rabbitmq",
    }
    for secret, owner in owners.items():
        assert set(_services_with(compose, secret)) == {owner}, secret

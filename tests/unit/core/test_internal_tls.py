"""TLS on internal hops: every client verifies its server against the private CA."""

from __future__ import annotations

import datetime as dt
import importlib.util
import ssl
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from nexusflow.bootstrap import sandbox as sandbox_bootstrap
from nexusflow.core.config import (
    BrokerSettings,
    DatabaseSettings,
    RedisSettings,
    SandboxSettings,
)
from nexusflow.infrastructure.database import engine as engine_module
from nexusflow.infrastructure.database.engine import _ssl_context
from nexusflow.infrastructure.messaging.celery_app import build_celery
from nexusflow.infrastructure.redis.client import create_redis
from tests.conftest import make_settings

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def private_ca(tmp_path: Path) -> Path:
    """A CA certificate, as an operator's internal CA would be."""
    spec = importlib.util.spec_from_file_location("dev_certs", ROOT / "scripts" / "dev_certs.py")
    assert spec is not None and spec.loader is not None
    dev_certs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dev_certs)
    ca_pem, _, _ = dev_certs.build("postgres", dt.datetime.now(dt.UTC))
    path = tmp_path / "internal-ca.pem"
    path.write_bytes(ca_pem)
    return path


class TestDatabase:
    def test_verify_full_checks_the_chain_and_the_host_name(self, private_ca: Path) -> None:
        context = _ssl_context(DatabaseSettings(ssl_mode="verify-full", ssl_root_cert=private_ca))
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode is ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
        assert len(context.get_ca_certs()) == 1  # the private CA, and only it

    def test_require_encrypts_and_disable_does_not(self) -> None:
        assert _ssl_context(DatabaseSettings(ssl_mode="require")) == "require"
        assert _ssl_context(DatabaseSettings()) is None

    def test_the_engine_connects_with_the_context(
        self, private_ca: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def fake_engine(url: str, **kwargs: Any) -> object:
            captured.update(kwargs)
            return object()

        monkeypatch.setattr(engine_module, "create_async_engine", fake_engine)
        engine_module.create_engine(
            DatabaseSettings(ssl_mode="verify-full", ssl_root_cert=private_ca),
            application_name="tls-test",
        )
        assert isinstance(captured["connect_args"]["ssl"], ssl.SSLContext)


class TestRedis:
    def test_rediss_requires_a_verified_certificate(self, private_ca: Path) -> None:
        client = create_redis(
            RedisSettings(url=SecretStr("rediss://app:pw@redis:6380/0"), ssl_ca_certs=private_ca)
        )
        options = client.connection_pool.connection_kwargs
        assert options["ssl_cert_reqs"] == "required"
        assert options["ssl_ca_certs"] == str(private_ca)
        assert options["ssl_check_hostname"] is True
        assert options["ssl_min_version"] == ssl.TLSVersion.TLSv1_2
        assert client.connection_pool.connection_class.__name__ == "SSLConnection"

    def test_plain_redis_carries_no_tls_options(self) -> None:
        client = create_redis(RedisSettings(url=SecretStr("redis://app:pw@redis:6379/0")))
        assert "ssl_cert_reqs" not in client.connection_pool.connection_kwargs

    def test_the_sandbox_redis_trusts_the_same_ca(
        self, private_ca: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[RedisSettings] = []

        class RecordedError(Exception):
            pass

        def recording(settings: RedisSettings) -> object:
            seen.append(settings)
            raise RecordedError  # only the Redis settings matter here

        monkeypatch.setattr(sandbox_bootstrap, "create_redis", recording)
        settings = SandboxSettings(
            sandbox={
                "redis_url": SecretStr("rediss://sandbox:pw@redis-sandbox:6380/0"),
                "redis_ssl_ca_certs": private_ca,
            }
        )
        with pytest.raises(RecordedError):
            sandbox_bootstrap.build_sandbox(settings)
        [redis_settings] = seen
        assert redis_settings.ssl_ca_certs == private_ca


class TestBroker:
    def test_amqps_verifies_the_broker(self, private_ca: Path) -> None:
        app = build_celery(
            BrokerSettings(
                url=SecretStr("amqps://nexusflow:pw@rabbitmq:5671/nexusflow"),
                use_ssl=True,
                ssl_ca_certs=private_ca,
            )
        )
        assert app.conf.broker_use_ssl == {
            "cert_reqs": ssl.CERT_REQUIRED,
            "ca_certs": str(private_ca),
            # py-amqp verifies the host name only when it is given one.
            "server_hostname": "rabbitmq",
        }

    def test_plain_amqp_has_no_tls_options(self) -> None:
        assert not build_celery(BrokerSettings()).conf.broker_use_ssl


_PRODUCTION: dict[str, Any] = {
    "app": {
        "environment": "production",
        "public_base_url": "https://nexusflow.example.com",
        "allowed_hosts": ["nexusflow.example.com"],
    },
    "n8n": {"webhook_jwt_secret": "n8n-webhook-secret-for-tests-only-0123456789"},
}


class TestStartupWarnings:
    def test_production_without_internal_tls_is_flagged(self, tmp_path: Path) -> None:
        warnings = make_settings(tmp_path, **_PRODUCTION).security_warnings()
        assert {w.split(" TLS")[0] for w in warnings if "TLS" in w} == {
            "database",
            "redis",
            "broker",
        }

    def test_internal_tls_silences_the_warnings(self, tmp_path: Path, private_ca: Path) -> None:
        settings = make_settings(
            tmp_path,
            **_PRODUCTION,
            database={"ssl_mode": "verify-full", "ssl_root_cert": str(private_ca)},
            redis={"url": "rediss://app:pw@redis:6380/0", "ssl_ca_certs": str(private_ca)},
            broker={"use_ssl": True, "ssl_ca_certs": str(private_ca)},
        )
        assert [w for w in settings.security_warnings() if "TLS" in w] == []

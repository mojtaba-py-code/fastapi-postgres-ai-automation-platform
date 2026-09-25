"""Shared fixtures: deterministic key material and settings for tests."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nexusflow.core.clock import FrozenClock
from nexusflow.core.config import Environment, Settings
from nexusflow.infrastructure.observability.logging import configure_logging
from nexusflow.infrastructure.security.jwt_tokens import generate_ed25519_private_key_pem

pytest_plugins = ["tests.support.fixtures", "tests.support.api", "tests.support.bus"]

configure_logging(level="WARNING", fmt="console", service="nexusflow-tests")

# Make sure a developer's real environment never leaks into the test run. The
# test harness's own variables (NEXUSFLOW_TEST_*, NEXUSFLOW_E2E_*) are kept.
for _key in [k for k in os.environ if k.upper().startswith("NEXUSFLOW_")]:
    if not _key.upper().startswith(("NEXUSFLOW_TEST_", "NEXUSFLOW_E2E_")):
        os.environ.pop(_key)

_JWT_PEM = generate_ed25519_private_key_pem()
_KEK = base64.b64encode(os.urandom(32)).decode()
_PEPPER = base64.b64encode(os.urandom(32)).decode()


def make_settings(tmp_root: Path | None = None, **overrides: object) -> Settings:
    base: dict[str, object] = {
        "app": {"environment": Environment.TEST, "allowed_hosts": ["testserver", "localhost"]},
        "security": {
            "jwt_private_key": _JWT_PEM,
            "encryption_keys": json.dumps({"kek-1": _KEK}),
            "encryption_active_key_id": "kek-1",
            "hmac_pepper": _PEPPER,
            # Fast-but-valid Argon2id parameters for the test suite.
            "argon2_time_cost": 1,
            "argon2_memory_cost_kib": 19_456,
            "argon2_parallelism": 1,
        },
        "storage": {"root": str(tmp_root or Path("./var-test"))},
    }
    for section, values in overrides.items():
        current = base.get(section, {})
        assert isinstance(current, dict)
        assert isinstance(values, dict)
        base[section] = {**current, **values}
    return Settings(**base)  # type: ignore[arg-type]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(datetime(2026, 9, 1, 12, 0, tzinfo=UTC))


@pytest.fixture
def jwt_private_key_pem() -> str:
    return _JWT_PEM


@pytest.fixture(autouse=True)
def _no_env_proxies(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(var, raising=False)
    yield

"""End-to-end tests against a running stack, through its real edge (nginx, TLS).

    make secrets dev-certs demo-up
    NEXUSFLOW_E2E_BASE_URL=https://localhost make e2e

Variables:

* ``NEXUSFLOW_E2E_BASE_URL`` (required, else every test here is skipped);
* ``NEXUSFLOW_E2E_CA_BUNDLE`` - CA bundle for the edge certificate; defaults to
  ``deploy/certs/dev-ca.pem`` when that file exists (``make dev-certs``);
* ``NEXUSFLOW_E2E_MAILPIT_URL`` - Mailpit's web API, to check that alert
  e-mails were delivered (the demo overlay publishes it on 127.0.0.1:8025).
"""

from __future__ import annotations

import importlib.util
import os
import ssl
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import httpx2
import pytest

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class LiveStack:
    base_url: str
    verify: ssl.SSLContext | bool
    mailpit_url: str | None

    @property
    def is_https(self) -> bool:
        return self.base_url.startswith("https://")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "tests/e2e/" in item.nodeid.replace("\\", "/"):
            item.add_marker(pytest.mark.e2e)


@pytest.fixture(scope="session")
def live() -> LiveStack:
    base_url = os.environ.get("NEXUSFLOW_E2E_BASE_URL", "").rstrip("/")
    if not base_url:
        pytest.skip("set NEXUSFLOW_E2E_BASE_URL to run the end-to-end tests against a stack")
    default_ca = ROOT / "deploy" / "certs" / "dev-ca.pem"
    ca_file = os.environ.get("NEXUSFLOW_E2E_CA_BUNDLE") or (
        str(default_ca) if default_ca.exists() else None
    )
    verify: ssl.SSLContext | bool = True
    if base_url.startswith("https://"):
        verify = ssl.create_default_context(cafile=ca_file)  # always verified
    return LiveStack(base_url, verify, os.environ.get("NEXUSFLOW_E2E_MAILPIT_URL") or None)


@pytest.fixture
def client(live: LiveStack) -> Iterator[httpx2.Client]:
    with httpx2.Client(base_url=live.base_url, verify=live.verify, timeout=30.0) as session:
        yield session


@pytest.fixture(scope="session")
def demo() -> ModuleType:
    spec = importlib.util.spec_from_file_location("nexusflow_demo", ROOT / "scripts" / "demo.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

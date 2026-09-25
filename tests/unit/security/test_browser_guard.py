"""The rendering service's per-request SSRF guard (no browser needed)."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from nexusflow.apps.browser.app import Renderer, resolves_publicly
from nexusflow.bootstrap.http import build_url_policy
from nexusflow.core.config import BrowserServiceSettings

TOKEN = "t" * 40


@dataclass
class FakeRoute:
    url: str
    actions: list[str] = field(default_factory=list)

    @property
    def request(self) -> SimpleNamespace:
        return SimpleNamespace(url=self.url)

    async def abort(self, reason: str) -> None:
        self.actions.append(f"abort:{reason}")

    async def continue_(self) -> None:
        self.actions.append("continue")


def _renderer() -> Renderer:
    settings = BrowserServiceSettings(browser={"token": TOKEN})
    return Renderer(settings, build_url_policy(settings.scraping))


@pytest.mark.parametrize(
    ("host", "public"),
    [
        ("127.0.0.1", False),
        ("10.1.2.3", False),
        ("169.254.169.254", False),
        ("[::1]", False),
        ("[::ffff:192.168.0.1]", False),
        ("localhost", False),
        ("93.184.216.34", True),
    ],
)
async def test_resolution_must_be_public(host: str, public: bool) -> None:
    assert await resolves_publicly(host) is public


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "https://10.0.0.7/admin",
        "file:///etc/passwd",
        "chrome://settings",
        "https://localhost:8443/",
        "https://93.184.216.34:6379/",  # non-allowed port
    ],
)
async def test_guard_aborts_internal_and_non_http_requests(url: str) -> None:
    route = FakeRoute(url)
    await _renderer()._guard(route)
    assert route.actions == ["abort:blockedbyclient"]


async def test_guard_lets_public_requests_through() -> None:
    route = FakeRoute("https://93.184.216.34/index.html")
    await _renderer()._guard(route)
    assert route.actions == ["continue"]


def test_service_refuses_to_start_without_a_strong_token() -> None:
    with pytest.raises(ValueError, match=r"browser\.token"):
        BrowserServiceSettings(browser={"token": "short"})

"""The rendering service's per-request SSRF guard (no browser needed)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from nexusflow.apps.browser import app as browser_app
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


class _BusyPage:
    """A page that starts an endless script once loaded: its renderer never
    answers again, so ``content()`` never returns."""

    url = "about:blank"

    def on(self, event: str, callback: object) -> None:
        return None

    async def goto(self, url: str, **options: object) -> None:  # wait_until, timeout
        self.url = url

    async def content(self) -> str:
        await asyncio.Event().wait()  # never set
        raise AssertionError("unreachable")


@dataclass
class _Context:
    page: _BusyPage = field(default_factory=_BusyPage)
    closed: bool = False

    async def route(self, pattern: str, handler: object) -> None:
        return None

    async def route_web_socket(self, pattern: str, handler: object) -> None:
        return None

    async def new_page(self) -> _BusyPage:
        return self.page

    async def close(self) -> None:
        self.closed = True


@dataclass
class _Browser:
    contexts: list[_Context] = field(default_factory=list)

    async def new_context(self, **options: object) -> _Context:
        self.contexts.append(_Context())
        return self.contexts[-1]


async def test_a_page_that_never_yields_cannot_keep_a_renderer_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = BrowserServiceSettings(
        browser={
            "token": TOKEN,
            "max_concurrency": 1,
            "queue_timeout_seconds": 0.5,
            "navigation_timeout_seconds": 0.2,
        }
    )
    renderer = Renderer(settings, build_url_policy(settings.scraping))
    monkeypatch.setattr(browser_app, "_CONTENT_MARGIN_SECONDS", 0.2, raising=False)
    browser = _Browser()
    renderer._browser = browser
    # With one slot, the second render can only start if the first gave it back.
    for _ in range(2):
        render = asyncio.ensure_future(renderer.render("https://93.184.216.34/busy"))
        done, _ = await asyncio.wait({render}, timeout=5)
        if not done:
            render.cancel()
            pytest.fail("render() never returned: its slot is lost for good")
        assert isinstance(render.exception(), TimeoutError)
    assert [context.closed for context in browser.contexts] == [True, True]

"""Website collection (``WebsiteCollector``) and the headless-browser client
(``BrowserRenderer``) in ``infrastructure.scraping.collectors``.

The target site (robots.txt and pages) is an in-memory transport behind the
real SSRF-guarded client and the real robots policy; the browser service's
``/render`` endpoint is an ``httpx2.MockTransport`` injected into the real
``BrowserRenderer``. Covers URL policy, robots enforcement, the throttle
interval, plain vs JavaScript-rendered fetches, item limits, content-type
checks and error classification.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator, Callable, Mapping
from typing import Any

import httpx2
import pytest

from nexusflow.core.errors import (
    InvalidInputError,
    NexusFlowError,
    PermanentError,
    PolicyViolationError,
    TransientError,
)
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.domain.sources.model import FieldExtraction, WebsiteConfig
from nexusflow.infrastructure.http.client import (
    OutboundConnectionError,
    OutboundTimeoutError,
    ResponseTooLargeError,
    RetryableUpstreamStatusError,
    SafeHttpClient,
    UnexpectedContentTypeError,
    UpstreamStatusError,
)
from nexusflow.infrastructure.scraping.collectors import (
    BrowserRenderer,
    CollectedItems,
    RobotsDisallowedError,
    RobotsUnavailableError,
    WebsiteCollector,
)
from nexusflow.infrastructure.scraping.robots import RobotsPolicy
from nexusflow.infrastructure.scraping.throttle import HostThrottle
from tests.unit.adapters.fakes import (
    USER_AGENT,
    Handler,
    RecordingHandler,
    SafeClientFactory,
    respond,
)

ROBOTS_URL = "https://shop.example.com/robots.txt"
CATALOG_URL = "https://shop.example.com/catalog/"
BROWSER_BASE_URL = "http://browser.internal:3000"
BROWSER_TOKEN = "browser-service-token-" + "k" * 32
CATALOG_HTML = """<!doctype html>
<html><body><ul>
  <li class="product"><h2>Blue Widget</h2><span class="price">9.99</span>
      <a href="item/1">view</a></li>
  <li class="product"><h2>Red Widget</h2><span class="price">19.99</span>
      <a href="/item/2">view</a></li>
  <li class="product"><h2>Green Widget</h2><span class="price">29.99</span>
      <a href="https://cdn.example.net/item/3">view</a></li>
</ul></body></html>"""
CONFIG = WebsiteConfig(
    url=CATALOG_URL,
    item_selector="li.product",
    fields={
        "title": FieldExtraction(selector="h2"),
        "price": FieldExtraction(selector=".price"),
        "url": FieldExtraction(selector="a", attribute="href"),
    },
)
EXPECTED_ITEMS = [
    {"title": "Blue Widget", "price": "9.99", "url": "https://shop.example.com/catalog/item/1"},
    {"title": "Red Widget", "price": "19.99", "url": "https://shop.example.com/item/2"},
    {"title": "Green Widget", "price": "29.99", "url": "https://cdn.example.net/item/3"},
]
JS_CONFIG = CONFIG.model_copy(update={"render_javascript": True})

type RendererFactory = Callable[[Handler], BrowserRenderer]


def html_page(body: str = CATALOG_HTML, content_type: str = "text/html; charset=utf-8") -> Handler:
    return lambda request: respond(200, body, content_type=content_type)


def website(pages: Mapping[str, Handler], *, robots: str | None = None) -> RecordingHandler:
    """``/robots.txt`` (404 when ``robots`` is None) plus ``pages`` keyed by path."""

    def handle(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/robots.txt":
            if robots is None:
                return respond(404, "no robots here", content_type="text/plain")
            return respond(200, robots, content_type="text/plain")
        page = pages.get(request.url.path)
        return page(request) if page else respond(404, "not found", content_type="text/html")

    return RecordingHandler(handle)


def browser_service(
    html: str = CATALOG_HTML, *, final_url: str | None = None, status: int = 200
) -> RecordingHandler:
    """The browser service's ``POST /render`` endpoint."""

    def handle(request: httpx2.Request) -> httpx2.Response:
        requested = json.loads(request.content)["url"]
        return httpx2.Response(status, json={"html": html, "final_url": final_url or requested})

    return RecordingHandler(handle)


class SpyThrottle(HostThrottle):
    """Records the interval the collector asks for instead of waiting."""

    def __init__(self) -> None:
        super().__init__(None, prefix="nf:")
        self.calls: list[tuple[str, float]] = []

    async def acquire(self, host: str, *, interval_seconds: float) -> None:
        self.calls.append((host, interval_seconds))


def _collector(
    client: SafeHttpClient,
    *,
    throttle: HostThrottle | None = None,
    browser: BrowserRenderer | None = None,
    min_interval: float = 2.0,
) -> WebsiteCollector:
    return WebsiteCollector(
        client=client,
        robots=RobotsPolicy(
            client, None, user_agent=USER_AGENT, cache_ttl_seconds=3600, prefix="nf:"
        ),
        throttle=throttle or SpyThrottle(),
        min_interval_seconds=min_interval,
        browser=browser,
    )


@pytest.fixture
async def renderer_factory(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[RendererFactory]:
    """Real ``BrowserRenderer``s whose HTTP client talks to an in-memory browser service."""
    renderers: list[BrowserRenderer] = []
    real_async_client = httpx2.AsyncClient

    def make(handler: Handler) -> BrowserRenderer:
        def with_mock_transport(**kwargs: Any) -> httpx2.AsyncClient:
            return real_async_client(transport=httpx2.MockTransport(handler), **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(httpx2, "AsyncClient", with_mock_transport)
            renderer = BrowserRenderer(BROWSER_BASE_URL + "/", BROWSER_TOKEN)
        renderers.append(renderer)
        return renderer

    yield make
    for renderer in renderers:
        await renderer.aclose()


class TestPlainFetch:
    async def test_collects_items_from_the_page(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        site = website({"/catalog/": html_page()})
        throttle = SpyThrottle()

        result = await _collector(safe_client_factory(site), throttle=throttle).collect(
            CONFIG, policy=UrlPolicy(), max_items=100
        )

        assert result == CollectedItems(
            items=EXPECTED_ITEMS,
            truncated=False,
            detail={
                "http_status": 200,
                "bytes": len(CATALOG_HTML.encode()),
                "host": "shop.example.com",
            },
        )
        assert site.urls == [ROBOTS_URL, CATALOG_URL]
        page_request = site.requests[1]
        assert page_request.method == "GET"
        assert page_request.headers["accept"] == "text/html,application/xhtml+xml;q=0.9"
        assert page_request.headers["user-agent"] == USER_AGENT
        assert throttle.calls == [("shop.example.com", 2.0)]

    @pytest.mark.parametrize(
        ("robots", "min_interval", "expected_interval"),
        [
            pytest.param(None, 2.0, 2.0, id="no-robots-uses-minimum"),
            pytest.param("User-agent: *\nCrawl-delay: 7\n", 2.0, 7.0, id="longer-crawl-delay"),
            pytest.param("User-agent: *\nCrawl-delay: 1\n", 2.0, 2.0, id="shorter-crawl-delay"),
            pytest.param(
                "User-agent: NexusFlowBot\nAllow: /\nCrawl-delay: 12\n", 0.5, 12.0, id="own-group"
            ),
        ],
    )
    async def test_throttle_interval_is_the_larger_of_minimum_and_crawl_delay(
        self,
        safe_client_factory: SafeClientFactory,
        robots: str | None,
        min_interval: float,
        expected_interval: float,
    ) -> None:
        throttle = SpyThrottle()
        collector = _collector(
            safe_client_factory(website({"/catalog/": html_page()}, robots=robots)),
            throttle=throttle,
            min_interval=min_interval,
        )
        await collector.collect(CONFIG, policy=UrlPolicy(), max_items=100)
        assert throttle.calls == [("shop.example.com", expected_interval)]

    async def test_links_resolve_against_the_final_url_after_redirects(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        def handle(request: httpx2.Request) -> httpx2.Response:
            if request.url.path == "/robots.txt":
                return respond(404)
            if request.url.host == "shop.example.com":
                return respond(301, headers={"location": "https://www.shop.example.com/v2/list/"})
            return respond(200, CATALOG_HTML, content_type="text/html")

        site = RecordingHandler(handle)
        result = await _collector(safe_client_factory(site)).collect(
            CONFIG, policy=UrlPolicy(), max_items=100
        )

        assert [item["url"] for item in result.items] == [
            "https://www.shop.example.com/v2/list/item/1",
            "https://www.shop.example.com/item/2",
            "https://cdn.example.net/item/3",
        ]
        assert result.detail["host"] == "www.shop.example.com"
        assert site.urls == [
            ROBOTS_URL,
            CATALOG_URL,
            "https://www.shop.example.com/robots.txt",  # checked before the hop is followed
            "https://www.shop.example.com/v2/list/",
        ]

    @pytest.mark.parametrize(
        ("source_limit", "run_limit", "expected_count", "truncated"),
        [(2, 100, 2, True), (100, 1, 1, True), (3, 3, 3, False), (100, 100, 3, False)],
    )
    async def test_item_limit_is_the_smaller_of_the_source_and_run_limits(
        self,
        safe_client_factory: SafeClientFactory,
        source_limit: int,
        run_limit: int,
        expected_count: int,
        truncated: bool,
    ) -> None:
        config = CONFIG.model_copy(update={"max_items": source_limit})
        result = await _collector(safe_client_factory(website({"/catalog/": html_page()}))).collect(
            config, policy=UrlPolicy(), max_items=run_limit
        )
        assert result.items == EXPECTED_ITEMS[:expected_count]
        assert result.truncated is truncated

    async def test_xhtml_pages_are_accepted(self, safe_client_factory: SafeClientFactory) -> None:
        site = website({"/catalog/": html_page(content_type="application/xhtml+xml")})
        result = await _collector(safe_client_factory(site)).collect(
            CONFIG, policy=UrlPolicy(), max_items=100
        )
        assert result.items == EXPECTED_ITEMS

    @pytest.mark.parametrize(
        "content_type",
        ["application/json", "text/plain", "application/octet-stream", "image/svg+xml", None],
    )
    async def test_non_html_responses_are_rejected(
        self, safe_client_factory: SafeClientFactory, content_type: str | None
    ) -> None:
        def page(request: httpx2.Request) -> httpx2.Response:
            return respond(200, CATALOG_HTML, content_type=content_type)

        collector = _collector(safe_client_factory(website({"/catalog/": page})))
        with pytest.raises(UnexpectedContentTypeError) as exc:
            await collector.collect(CONFIG, policy=UrlPolicy(), max_items=100)
        assert isinstance(exc.value, PermanentError)

    async def test_oversized_pages_are_rejected(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        huge = CATALOG_HTML.replace("</ul>", "<li>padding</li>" * 10_000 + "</ul>")
        site = website({"/catalog/": html_page(huge)})
        collector = _collector(safe_client_factory(site, max_response_bytes=64 * 1024))
        with pytest.raises(ResponseTooLargeError):
            await collector.collect(CONFIG, policy=UrlPolicy(), max_items=100)


class TestPolicyAndRobots:
    @pytest.mark.security
    @pytest.mark.parametrize(
        ("url", "policy"),
        [
            pytest.param("https://127.0.0.1/catalog/", UrlPolicy(), id="loopback"),
            pytest.param("https://169.254.169.254/latest/", UrlPolicy(), id="metadata"),
            pytest.param("http://shop.example.com/catalog/", UrlPolicy(), id="plain-http"),
            pytest.param("https://printer.local/catalog/", UrlPolicy(), id="internal-name"),
            pytest.param("https://shop.example.com:8443/catalog", UrlPolicy(), id="port"),
            pytest.param(
                CATALOG_URL,
                UrlPolicy().with_allowed_domains(["other.example"]),
                id="outside-allowlist",
            ),
        ],
    )
    async def test_urls_rejected_by_the_policy_are_never_contacted(
        self, safe_client_factory: SafeClientFactory, url: str, policy: UrlPolicy
    ) -> None:
        site = website({"/catalog/": html_page()})
        throttle = SpyThrottle()
        collector = _collector(safe_client_factory(site), throttle=throttle)

        with pytest.raises(PolicyViolationError):
            await collector.collect(
                CONFIG.model_copy(update={"url": url}), policy=policy, max_items=100
            )

        assert site.requests == []
        assert throttle.calls == []

    async def test_pages_disallowed_by_robots_txt_are_never_fetched(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        site = website({"/catalog/": html_page()}, robots="User-agent: *\nDisallow: /catalog/\n")
        throttle = SpyThrottle()

        with pytest.raises(RobotsDisallowedError) as exc:
            await _collector(safe_client_factory(site), throttle=throttle).collect(
                CONFIG, policy=UrlPolicy(), max_items=100
            )

        assert isinstance(exc.value, PermanentError)
        assert exc.value.code == "robots_disallowed"
        assert exc.value.internal_detail == "shop.example.com"
        assert site.urls == [ROBOTS_URL]
        assert throttle.calls == []

    @pytest.mark.security
    async def test_robots_txt_redirects_stay_within_the_source_allowlist(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        def handle(request: httpx2.Request) -> httpx2.Response:
            if request.url.host != "shop.example.com":
                return respond(200, "User-agent: *\nAllow: /\n", content_type="text/plain")
            if request.url.path == "/robots.txt":
                return respond(302, headers={"location": "https://tracker.example.net/robots.txt"})
            return respond(200, CATALOG_HTML, content_type="text/html")

        site = RecordingHandler(handle)
        allowlisted = UrlPolicy().with_allowed_domains(["shop.example.com"])
        with contextlib.suppress(NexusFlowError):
            await _collector(safe_client_factory(site)).collect(
                CONFIG, policy=allowlisted, max_items=100
            )
        assert {request.url.host for request in site.requests} == {"shop.example.com"}


class TestErrorClassification:
    @pytest.mark.parametrize(
        ("status", "error", "base"),
        [
            (403, UpstreamStatusError, PermanentError),
            (404, UpstreamStatusError, PermanentError),
            (410, UpstreamStatusError, PermanentError),
            (429, RetryableUpstreamStatusError, TransientError),
            (500, RetryableUpstreamStatusError, TransientError),
            (503, RetryableUpstreamStatusError, TransientError),
        ],
    )
    async def test_http_status_errors(
        self,
        safe_client_factory: SafeClientFactory,
        status: int,
        error: type[NexusFlowError],
        base: type[NexusFlowError],
    ) -> None:
        def page(request: httpx2.Request) -> httpx2.Response:
            return respond(status, "oops", content_type="text/html", headers={"retry-after": "120"})

        collector = _collector(safe_client_factory(website({"/catalog/": page})))
        with pytest.raises(error) as exc:
            await collector.collect(CONFIG, policy=UrlPolicy(), max_items=100)

        assert isinstance(exc.value, base)
        assert exc.value.internal_detail == f"HTTP {status}"
        if isinstance(exc.value, RetryableUpstreamStatusError):
            assert exc.value.retry_after_seconds == 120

    @pytest.mark.parametrize(
        ("failure", "error"),
        [
            (httpx2.ConnectError, OutboundConnectionError),
            (httpx2.ReadError, OutboundConnectionError),
            (httpx2.RemoteProtocolError, OutboundConnectionError),
            (httpx2.ReadTimeout, OutboundTimeoutError),
            (httpx2.ConnectTimeout, OutboundTimeoutError),
        ],
    )
    async def test_network_failures_are_transient(
        self,
        safe_client_factory: SafeClientFactory,
        failure: type[httpx2.TransportError],
        error: type[TransientError],
    ) -> None:
        def page(request: httpx2.Request) -> httpx2.Response:
            raise failure("simulated", request=request)

        collector = _collector(safe_client_factory(website({"/catalog/": page})))
        with pytest.raises(error) as exc:
            await collector.collect(CONFIG, policy=UrlPolicy(), max_items=100)
        assert isinstance(exc.value, TransientError)


class TestJavaScriptRendering:
    async def test_pages_are_rendered_by_the_browser_service(
        self, safe_client_factory: SafeClientFactory, renderer_factory: RendererFactory
    ) -> None:
        site = website({})  # the worker itself never fetches the page
        browser = browser_service(final_url="https://shop.example.com/catalog/?view=grid")
        throttle = SpyThrottle()
        collector = _collector(
            safe_client_factory(site), throttle=throttle, browser=renderer_factory(browser)
        )

        result = await collector.collect(JS_CONFIG, policy=UrlPolicy(), max_items=100)

        assert result == CollectedItems(
            items=EXPECTED_ITEMS,
            truncated=False,
            detail={"http_status": 200, "bytes": len(CATALOG_HTML), "host": "shop.example.com"},
        )
        # robots.txt again for the browser's final URL (no Redis cache in these tests).
        assert site.urls == [ROBOTS_URL, ROBOTS_URL]
        [render] = browser.requests
        assert render.method == "POST"
        assert str(render.url) == f"{BROWSER_BASE_URL}/render"
        assert json.loads(render.content) == {"url": CATALOG_URL}
        assert throttle.calls == [("shop.example.com", 2.0)]

    async def test_rendered_links_resolve_against_the_browser_final_url(
        self, safe_client_factory: SafeClientFactory, renderer_factory: RendererFactory
    ) -> None:
        browser = browser_service(final_url="https://m.shop.example.com/c/")
        collector = _collector(safe_client_factory(website({})), browser=renderer_factory(browser))

        result = await collector.collect(JS_CONFIG, policy=UrlPolicy(), max_items=2)

        assert [item["url"] for item in result.items] == [
            "https://m.shop.example.com/c/item/1",
            "https://m.shop.example.com/item/2",
        ]
        assert result.truncated is True
        assert result.detail["host"] == "m.shop.example.com"

    async def test_rendering_without_a_browser_service_is_a_permanent_error(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        site = website({"/catalog/": html_page()})
        with pytest.raises(PermanentError) as exc:
            await _collector(safe_client_factory(site), browser=None).collect(
                JS_CONFIG, policy=UrlPolicy(), max_items=100
            )
        assert exc.value.code == "js_unavailable"
        assert site.urls == [ROBOTS_URL]

    async def test_robots_txt_also_gates_rendered_pages(
        self, safe_client_factory: SafeClientFactory, renderer_factory: RendererFactory
    ) -> None:
        site = website({}, robots="User-agent: *\nDisallow: /\n")
        browser = browser_service()
        collector = _collector(safe_client_factory(site), browser=renderer_factory(browser))

        with pytest.raises(RobotsDisallowedError):
            await collector.collect(JS_CONFIG, policy=UrlPolicy(), max_items=100)
        assert browser.requests == []


class TestBrowserRenderer:
    async def test_render_posts_the_url_with_the_service_token(
        self, renderer_factory: RendererFactory
    ) -> None:
        service = browser_service("<html>rendered</html>", final_url="https://shop.example.com/x")
        renderer = renderer_factory(service)

        assert await renderer.render(CATALOG_URL) == (
            "<html>rendered</html>",
            "https://shop.example.com/x",
        )
        [request] = service.requests
        assert request.method == "POST"
        assert str(request.url) == f"{BROWSER_BASE_URL}/render"
        assert request.headers["authorization"] == f"Bearer {BROWSER_TOKEN}"
        assert json.loads(request.content) == {"url": CATALOG_URL}

    async def test_missing_fields_fall_back_to_empty_html_and_the_requested_url(
        self, renderer_factory: RendererFactory
    ) -> None:
        renderer = renderer_factory(lambda request: httpx2.Response(200, json={}))
        assert await renderer.render(CATALOG_URL) == ("", CATALOG_URL)

    @pytest.mark.parametrize(
        ("status", "error", "code"),
        [
            (503, TransientError, "browser_unavailable"),  # renderer busy
            (502, TransientError, "browser_unavailable"),  # page could not be rendered
            (401, PermanentError, "render_failed"),  # wrong service token
            (413, PermanentError, "render_failed"),  # page too large
            (422, PermanentError, "render_failed"),  # URL refused by the browser's policy
        ],
    )
    async def test_service_errors_are_classified(
        self,
        renderer_factory: RendererFactory,
        status: int,
        error: type[NexusFlowError],
        code: str,
    ) -> None:
        renderer = renderer_factory(lambda request: httpx2.Response(status, json={"detail": "x"}))
        with pytest.raises(error) as exc:
            await renderer.render(CATALOG_URL)
        assert exc.value.code == code
        assert BROWSER_TOKEN not in f"{exc.value} {exc.value.internal_detail}"

    @pytest.mark.parametrize(
        "failure", [httpx2.ConnectError, httpx2.ReadTimeout, httpx2.RemoteProtocolError]
    )
    async def test_an_unreachable_service_is_transient(
        self, renderer_factory: RendererFactory, failure: type[httpx2.TransportError]
    ) -> None:
        def handle(request: httpx2.Request) -> httpx2.Response:
            raise failure("simulated", request=request)

        with pytest.raises(TransientError) as exc:
            await renderer_factory(handle).render(CATALOG_URL)
        assert exc.value.code == "browser_unavailable"
        assert exc.value.internal_detail == failure.__name__

    async def test_a_non_object_body_is_a_render_failure(
        self, renderer_factory: RendererFactory
    ) -> None:
        renderer = renderer_factory(lambda request: httpx2.Response(200, json=["<html>"]))
        with pytest.raises(PermanentError) as exc:
            await renderer.render(CATALOG_URL)
        assert exc.value.code == "render_failed"

    @pytest.mark.parametrize(
        ("body", "code"),
        [
            (b"<html>not json</html>", "malformed_json"),
            (b'{"html": {"a": {"b": {"c": {"d": "deep"}}}}}', "json_too_deep"),
        ],
    )
    async def test_malformed_bodies_are_rejected(
        self, renderer_factory: RendererFactory, body: bytes, code: str
    ) -> None:
        renderer = renderer_factory(lambda request: httpx2.Response(200, content=body))
        with pytest.raises(InvalidInputError) as exc:
            await renderer.render(CATALOG_URL)
        assert exc.value.code == code


class TestRobotsOnEveryHop:
    async def test_a_redirect_to_a_disallowed_path_is_never_requested(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        site = website(
            {"/catalog/": lambda request: respond(302, headers={"location": "/checkout/"})},
            robots="User-agent: *\nDisallow: /checkout/\n",
        )
        with pytest.raises(RobotsDisallowedError):
            await _collector(safe_client_factory(site)).collect(
                CONFIG, policy=UrlPolicy(), max_items=100
            )
        assert "https://shop.example.com/checkout/" not in site.urls
        assert CATALOG_URL in site.urls

    async def test_a_rendered_page_that_ends_on_a_disallowed_url_is_discarded(
        self, safe_client_factory: SafeClientFactory, renderer_factory: RendererFactory
    ) -> None:
        site = website({}, robots="User-agent: *\nDisallow: /login\n")
        browser = browser_service(final_url="https://shop.example.com/login")
        collector = _collector(safe_client_factory(site), browser=renderer_factory(browser))
        with pytest.raises(RobotsDisallowedError):
            await collector.collect(JS_CONFIG, policy=UrlPolicy(), max_items=100)

    async def test_a_rendered_page_that_leaves_the_allowlist_is_discarded(
        self, safe_client_factory: SafeClientFactory, renderer_factory: RendererFactory
    ) -> None:
        site = website({})
        browser = browser_service(final_url="https://elsewhere.example.org/")
        collector = _collector(safe_client_factory(site), browser=renderer_factory(browser))
        allowlisted = UrlPolicy().with_allowed_domains(["shop.example.com"])
        with pytest.raises(PolicyViolationError):
            await collector.collect(JS_CONFIG, policy=allowlisted, max_items=100)

    async def test_an_unreachable_robots_txt_is_a_temporary_failure(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        def handle(request: httpx2.Request) -> httpx2.Response:
            return respond(503, "maintenance", content_type="text/plain")

        with pytest.raises(RobotsUnavailableError) as exc:
            await _collector(safe_client_factory(RecordingHandler(handle))).collect(
                CONFIG, policy=UrlPolicy(), max_items=100
            )
        assert isinstance(exc.value, TransientError)  # retried, not failed

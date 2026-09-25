"""The browser's pinning egress proxy (no browser needed).

A loopback echo server plays the public web server; an injected resolver maps
test host names to it and an address filter treats only that loopback address
as "public", so every real private range is still rejected by the production
``is_public`` check. The tests drive the real proxy over real sockets.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from nexusflow.apps.browser import egress_proxy
from nexusflow.apps.browser.app import Renderer
from nexusflow.apps.browser.egress_proxy import PinningProxy, is_public
from nexusflow.bootstrap.http import build_url_policy
from nexusflow.core.config import BrowserServiceSettings
from nexusflow.domain.shared.url_policy import UrlPolicy

pytestmark = pytest.mark.security

LOOPBACK = "127.0.0.1"
FAKE_PUBLIC = frozenset({LOOPBACK, "127.0.0.2"})
FORBIDDEN = b"HTTP/1.1 403 Forbidden\r\n"
DNS = {
    "upstream.example.com": [LOOPBACK],
    "multi.example.com": ["127.0.0.2", LOOPBACK],
    "metadata.example.com": ["169.254.169.254"],
    "rebind.example.com": [LOOPBACK, "10.0.0.5"],
    "mapped.example.com": ["::ffff:127.0.0.1"],
}


@dataclass
class Upstream:
    port: int = 0
    connections: int = 0
    writers: list[asyncio.StreamWriter] = field(default_factory=list)


@dataclass
class Calls:
    resolved: list[str] = field(default_factory=list)
    connected: list[str] = field(default_factory=list)


def _allowed(address: str) -> bool:
    return address in FAKE_PUBLIC or is_public(address)


@pytest.fixture
async def upstream() -> AsyncIterator[Upstream]:
    state = Upstream()

    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        state.connections += 1
        state.writers.append(writer)
        with contextlib.suppress(OSError):
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, LOOPBACK, 0)
    state.port = int(server.sockets[0].getsockname()[1])
    yield state
    server.close()
    for writer in state.writers:
        writer.close()
    await asyncio.wait_for(server.wait_closed(), 5)


type MakeProxy = Callable[..., Awaitable[int]]


@pytest.fixture
async def make_proxy(upstream: Upstream) -> AsyncIterator[tuple[MakeProxy, Calls]]:
    calls = Calls()
    proxies: list[PinningProxy] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.resolved.append(host)
        if host not in DNS:
            raise OSError("NXDOMAIN")
        return DNS[host]

    async def connector(host: str, port: int) -> egress_proxy.Streams:
        calls.connected.append(host)
        if host == "127.0.0.2":
            raise ConnectionRefusedError
        return await asyncio.open_connection(host, port)

    async def make(policy: UrlPolicy | None = None, **options: Any) -> int:
        policy = policy or UrlPolicy(allow_http=True, allowed_ports=frozenset({upstream.port}))
        options = {
            "resolver": resolver,
            "address_filter": _allowed,
            "connector": connector,
        } | options
        proxy = PinningProxy(policy, **options)
        proxies.append(proxy)
        return await proxy.start()

    yield make, calls
    for proxy in proxies:
        await proxy.stop()


async def _open(port: int, head: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection(LOOPBACK, port)
    writer.write(head.encode("latin-1"))
    await writer.drain()
    return reader, writer


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()


async def _status_line(port: int, head: str) -> bytes:
    """The proxy's first response line; ``b""`` when it hung up without one."""
    reader, writer = await _open(port, head)
    try:
        return await asyncio.wait_for(reader.readline(), 5)
    except ConnectionError:
        return b""  # closed with unread request bytes -> RST instead of FIN
    finally:
        await _close(writer)


async def _tunnel_echo(port: int, authority: str) -> bytes:
    reader, writer = await _open(port, f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
    try:
        established = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        assert established == b"HTTP/1.1 200 Connection Established\r\n\r\n"
        writer.write(b"ping")
        await writer.drain()
        return await asyncio.wait_for(reader.readexactly(4), 5)
    finally:
        await _close(writer)


async def test_tunnel_connects_to_the_validated_address_only(
    upstream: Upstream, make_proxy: tuple[MakeProxy, Calls]
) -> None:
    make, calls = make_proxy
    port = await make()
    assert await _tunnel_echo(port, f"upstream.example.com:{upstream.port}") == b"ping"
    # One lookup per connection, and the socket was opened to the checked IP -
    # never to the host name (which would trigger a second, rebindable lookup).
    assert calls.resolved == ["upstream.example.com"]
    assert calls.connected == [LOOPBACK]


async def test_dns_rebinding_after_the_check_cannot_redirect_a_connection(
    upstream: Upstream, make_proxy: tuple[MakeProxy, Calls]
) -> None:
    answers = iter([[LOOPBACK], ["169.254.169.254"]])

    async def rebinding(host: str, port: int) -> list[str]:
        return next(answers)

    make, calls = make_proxy
    port = await make(resolver=rebinding)
    authority = f"attacker.example.com:{upstream.port}"
    assert await _tunnel_echo(port, authority) == b"ping"
    # The attacker's name now points at the metadata service: the next
    # connection resolves afresh, sees it, and is refused.
    head = f"CONNECT {authority} HTTP/1.1\r\n\r\n"
    assert await _status_line(port, head) == FORBIDDEN
    assert calls.connected == [LOOPBACK]


async def test_the_next_validated_address_is_tried_when_one_is_unreachable(
    upstream: Upstream, make_proxy: tuple[MakeProxy, Calls]
) -> None:
    make, calls = make_proxy
    port = await make()
    assert await _tunnel_echo(port, f"multi.example.com:{upstream.port}") == b"ping"
    assert calls.connected == ["127.0.0.2", LOOPBACK]


@pytest.mark.parametrize(
    "head",
    [
        "CONNECT metadata.example.com:{port} HTTP/1.1\r\n\r\n",
        "CONNECT rebind.example.com:{port} HTTP/1.1\r\n\r\n",  # one private answer taints all
        "CONNECT mapped.example.com:{port} HTTP/1.1\r\n\r\n",  # IPv4-mapped loopback
        "CONNECT nxdomain.example.com:{port} HTTP/1.1\r\n\r\n",
        "CONNECT 10.0.0.1:{port} HTTP/1.1\r\n\r\n",
        "CONNECT [::ffff:169.254.169.254]:{port} HTTP/1.1\r\n\r\n",
        "CONNECT localhost:{port} HTTP/1.1\r\n\r\n",
        "CONNECT upstream.example.com:22 HTTP/1.1\r\n\r\n",
        "CONNECT user@upstream.example.com:{port} HTTP/1.1\r\n\r\n",
        "GET http://metadata.example.com:{port}/latest/meta-data/ HTTP/1.1\r\n\r\n",
        "GET https://upstream.example.com:{port}/ HTTP/1.1\r\n\r\n",  # TLS needs CONNECT
        "GET ftp://upstream.example.com:{port}/ HTTP/1.1\r\n\r\n",
        "GET /not-a-proxy-request HTTP/1.1\r\n\r\n",
    ],
)
async def test_blocked_targets_are_refused_before_any_connection(
    head: str, upstream: Upstream, make_proxy: tuple[MakeProxy, Calls]
) -> None:
    make, calls = make_proxy
    port = await make()
    assert await _status_line(port, head.format(port=upstream.port)) == FORBIDDEN
    assert calls.connected == []
    assert upstream.connections == 0


async def test_plain_http_is_refused_when_the_policy_requires_https(
    upstream: Upstream, make_proxy: tuple[MakeProxy, Calls]
) -> None:
    make, _ = make_proxy
    port = await make(UrlPolicy(allow_http=False, allowed_ports=frozenset({upstream.port})))
    head = f"GET http://upstream.example.com:{upstream.port}/ HTTP/1.1\r\n\r\n"
    assert await _status_line(port, head) == FORBIDDEN
    assert upstream.connections == 0


async def test_http_is_forwarded_in_origin_form_without_proxy_headers(
    upstream: Upstream, make_proxy: tuple[MakeProxy, Calls]
) -> None:
    make, _ = make_proxy
    port = await make()
    authority = f"upstream.example.com:{upstream.port}"
    reader, writer = await _open(
        port,
        f"GET http://{authority}/page?q=1 HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "Proxy-Authorization: Basic c2VjcmV0\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "Connection: keep-alive\r\n"
        "Keep-Alive: timeout=5\r\n"
        "Accept: text/html\r\n\r\n",
    )
    try:
        echoed = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
    finally:
        await _close(writer)
    # The echo server returns exactly what the proxy sent upstream.
    forwarded = (
        f"GET /page?q=1 HTTP/1.1\r\nHost: {authority}\r\nAccept: text/html\r\n"
        "Connection: close\r\n\r\n"
    )
    assert echoed == forwarded.encode()


async def test_unreachable_upstream_is_a_bad_gateway(
    upstream: Upstream, make_proxy: tuple[MakeProxy, Calls]
) -> None:
    async def refuse(host: str, port: int) -> egress_proxy.Streams:
        raise ConnectionRefusedError

    make, _ = make_proxy
    port = await make(connector=refuse)
    head = f"CONNECT upstream.example.com:{upstream.port} HTTP/1.1\r\n\r\n"
    assert await _status_line(port, head) == b"HTTP/1.1 502 Bad Gateway\r\n"


async def test_oversized_request_heads_are_dropped(
    upstream: Upstream, make_proxy: tuple[MakeProxy, Calls]
) -> None:
    make, calls = make_proxy
    port = await make()
    many_headers = "".join(f"X-{i}: v\r\n" for i in range(egress_proxy.MAX_HEADER_LINES + 1))
    long_line = "X-Long: " + "a" * (egress_proxy.MAX_LINE_BYTES + 1) + "\r\n"
    for extra in (many_headers, long_line):
        head = f"CONNECT upstream.example.com:{upstream.port} HTTP/1.1\r\n{extra}\r\n"
        assert await _status_line(port, head) == b""  # closed without an answer
    assert calls.resolved == []
    assert upstream.connections == 0


@pytest.mark.parametrize(
    ("address", "public"),
    [
        ("93.184.216.34", True),
        ("2606:2800:220:1:248:1893:25c8:1946", True),
        ("10.0.0.1", False),
        ("169.254.169.254", False),
        ("::ffff:127.0.0.1", False),
        ("fe80::1", False),
        ("not-an-address", False),
    ],
)
def test_is_public(address: str, public: bool) -> None:
    assert is_public(address) is public


class _FakeChromium:
    def __init__(self) -> None:
        self.launch_options: dict[str, Any] = {}

    async def launch(self, **options: Any) -> SimpleNamespace:
        self.launch_options = options
        return SimpleNamespace(close=_noop)


async def _noop() -> None:
    return None


async def test_renderer_routes_chromium_through_the_pinning_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chromium = _FakeChromium()
    playwright = SimpleNamespace(chromium=chromium, stop=_noop)

    async def start() -> SimpleNamespace:
        return playwright

    fake = ModuleType("playwright.async_api")
    fake.async_playwright = lambda: SimpleNamespace(start=start)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake)

    settings = BrowserServiceSettings(browser={"token": "t" * 40})
    renderer = Renderer(settings, build_url_policy(settings.scraping))
    await renderer.start()
    try:
        options = chromium.launch_options
        proxy = options["proxy"]
        assert proxy["bypass"] == "<-loopback>"
        assert proxy["server"].startswith(f"http://{LOOPBACK}:")
        no_bypass = {"--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"}
        assert no_bypass.issubset(options["args"])
        # The configured proxy is live and enforces the policy.
        proxy_port = int(proxy["server"].rsplit(":", 1)[1])
        head = "CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n"
        assert await _status_line(proxy_port, head) == FORBIDDEN
    finally:
        await renderer.stop()

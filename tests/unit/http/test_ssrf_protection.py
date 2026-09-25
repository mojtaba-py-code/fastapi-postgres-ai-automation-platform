"""SSRF defence tests: static URL policy, connect-time IP guard and the client."""

from __future__ import annotations

import gzip
import ipaddress
import zlib
from collections.abc import Callable

import httpcore2
import httpx2
import pytest

from nexusflow.core.errors import PolicyViolationError
from nexusflow.domain.shared.url_policy import IPAddress, UrlPolicy, forbidden_ip_reason
from nexusflow.infrastructure.http.client import (
    HttpClientLimits,
    RedirectNotFollowedError,
    ResponseTooLargeError,
    RetryableUpstreamStatusError,
    SafeHttpClient,
    TooManyRedirectsError,
    UnexpectedContentTypeError,
    UpstreamStatusError,
)
from nexusflow.infrastructure.http.transport import GuardedNetworkBackend, SSRFBlockedError

pytestmark = pytest.mark.security

POLICY = UrlPolicy()


class TestForbiddenAddresses:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.100.100.200",
            "0.0.0.0",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "192.0.2.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe",  # NAT64 -> 169.254.169.254
            "2002:7f00:0001::1",  # 6to4 wrapping 127.0.0.1
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
            "::127.0.0.1",  # IPv4-compatible
        ],
    )
    def test_internal_addresses_blocked(self, address: str) -> None:
        assert forbidden_ip_reason(ipaddress.ip_address(address)) is not None

    @pytest.mark.parametrize("address", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
    def test_public_addresses_allowed(self, address: str) -> None:
        assert forbidden_ip_reason(ipaddress.ip_address(address)) is None


class TestStaticUrlPolicy:
    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com/",  # plain http disabled by default
            "ftp://example.com/",
            "file:///etc/passwd",
            "gopher://example.com/",
            "javascript:alert(1)",
            "https://user:pass@example.com/",
            "https://localhost/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://169.254.169.254/latest/meta-data/",
            "https://2130706433/",
            "https://0x7f000001/",
            "https://127.1/",
            "https://0177.0.0.1/",
            "https://redis:6379/",
            "https://postgres/",
            "https://metadata.google.internal/",
            "https://printer.local/",
            "https://api.corp/",
            "https://example.com:6379/",
            "https://example.com:22/",
            "https://exa mple.com/",
            "https://example.com/\x00",
            "https://example.com\\@evil.com/",
            "",
            "https://" + "a" * 3000 + ".com/",
            "https://localhost./",
        ],
    )
    def test_rejects_dangerous_urls(self, url: str) -> None:
        with pytest.raises(PolicyViolationError):
            POLICY.validate(url)

    def test_accepts_and_normalizes_public_url(self) -> None:
        validated = POLICY.validate("HTTPS://Example.COM./path?q=1#frag")
        assert validated.url == "https://example.com/path?q=1"
        assert validated.port == 443

    def test_fragment_tricks_resolve_to_the_real_authority(self) -> None:
        validated = POLICY.validate("https://example.com#@127.0.0.1/")
        assert validated.host == "example.com"
        assert "127.0.0.1" not in validated.url

    def test_idna_hosts_are_encoded(self) -> None:
        assert POLICY.validate("https://bücher.example/").host == "xn--bcher-kva.example"

    def test_allowlist(self) -> None:
        policy = POLICY.with_allowed_domains(["example.com"])
        assert policy.validate("https://shop.example.com/").host == "shop.example.com"
        with pytest.raises(PolicyViolationError):
            policy.validate("https://example.org/")
        with pytest.raises(PolicyViolationError):
            policy.validate("https://notexample.com/")

    def test_blocklist(self) -> None:
        policy = UrlPolicy(blocked_domains=frozenset({"evil.com"}))
        with pytest.raises(PolicyViolationError):
            policy.validate("https://sub.evil.com/")


class _Resolver:
    def __init__(self, answers: dict[str, list[str]]) -> None:
        self.answers = answers
        self.calls = 0

    async def resolve(self, host: str, port: int) -> list[IPAddress]:
        self.calls += 1
        return [ipaddress.ip_address(a) for a in self.answers[host]]


class TestGuardedBackend:
    async def test_blocks_hostnames_resolving_to_internal_addresses(self) -> None:
        backend = GuardedNetworkBackend(
            _Resolver({"evil.example.com": ["10.0.0.7"]}),
            allowed_ports=frozenset({443}),
            inner=httpcore2.AsyncMockBackend([]),
        )
        with pytest.raises(SSRFBlockedError) as exc:
            await backend.connect_tcp("evil.example.com", 443)
        assert exc.value.reason == "reserved_range"

    async def test_mixed_public_private_answer_is_rejected(self) -> None:
        backend = GuardedNetworkBackend(
            _Resolver({"rebind.example.com": ["93.184.216.34", "127.0.0.1"]}),
            allowed_ports=frozenset({443}),
            inner=httpcore2.AsyncMockBackend([]),
        )
        with pytest.raises(SSRFBlockedError):
            await backend.connect_tcp("rebind.example.com", 443)

    async def test_connects_to_validated_ip_not_hostname(self) -> None:
        connected: list[str] = []

        class RecordingBackend(httpcore2.AsyncMockBackend):
            async def connect_tcp(self, host: str, port: int, *args: object, **kw: object):  # type: ignore[override]
                connected.append(host)
                return await super().connect_tcp(host, port)

        resolver = _Resolver({"good.example.com": ["93.184.216.34"]})
        backend = GuardedNetworkBackend(
            resolver, allowed_ports=frozenset({443}), inner=RecordingBackend([b""])
        )
        await backend.connect_tcp("good.example.com", 443)
        assert connected == ["93.184.216.34"]
        assert resolver.calls == 1

    async def test_blocks_disallowed_ports_and_unix_sockets(self) -> None:
        backend = GuardedNetworkBackend(
            _Resolver({}), allowed_ports=frozenset({443}), inner=httpcore2.AsyncMockBackend([])
        )
        with pytest.raises(SSRFBlockedError):
            await backend.connect_tcp("93.184.216.34", 6379)
        with pytest.raises(SSRFBlockedError):
            await backend.connect_unix_socket("/var/run/docker.sock")

    async def test_ip_literal_is_checked_without_dns(self) -> None:
        resolver = _Resolver({})
        backend = GuardedNetworkBackend(
            resolver, allowed_ports=frozenset({443}), inner=httpcore2.AsyncMockBackend([])
        )
        with pytest.raises(SSRFBlockedError):
            await backend.connect_tcp("169.254.169.254", 443)
        assert resolver.calls == 0


class _Chunked(httpx2.AsyncByteStream):
    """A network-like (lazily streamed) body, as real transports produce."""

    def __init__(self, body: bytes, chunk: int = 4096) -> None:
        self._body = body
        self._chunk = chunk

    async def __aiter__(self):  # type: ignore[override]
        for start in range(0, len(self._body), self._chunk):
            yield self._body[start : start + self._chunk]


def _resp(status: int, body: bytes = b"", **headers: str) -> httpx2.Response:
    return httpx2.Response(
        status, headers={k.replace("_", "-"): v for k, v in headers.items()}, stream=_Chunked(body)
    )


def _client(
    handler: Callable[[httpx2.Request], httpx2.Response], **limits: object
) -> SafeHttpClient:
    return SafeHttpClient(
        policy=UrlPolicy(),
        user_agent="test-agent",
        limits=HttpClientLimits(**limits),  # type: ignore[arg-type]
        transport=httpx2.MockTransport(handler),
    )


class TestSafeHttpClient:
    async def test_redirect_to_internal_address_is_blocked(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(302, location="https://169.254.169.254/latest/")

        client = _client(handler)
        with pytest.raises(PolicyViolationError):
            await client.request("GET", "https://example.com/")

    async def test_redirect_downgrade_blocked(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(301, location="http://example.com/")

        client = SafeHttpClient(
            policy=UrlPolicy(allow_http=True),
            user_agent="t",
            limits=HttpClientLimits(),
            transport=httpx2.MockTransport(handler),
        )
        with pytest.raises(PolicyViolationError):
            await client.request("GET", "https://example.com/")

    async def test_credentials_stripped_on_cross_origin_redirect(self) -> None:
        seen: list[httpx2.Headers] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen.append(request.headers)
            if request.url.host == "api.example.com":
                return _resp(302, location="https://cdn.example.net/data")
            return _resp(200, b'{"ok": true}', content_type="application/json")

        client = _client(handler)
        response = await client.request(
            "GET", "https://api.example.com/", headers={"Authorization": "Bearer secret"}
        )
        assert response.status_code == 200
        assert seen[0].get("authorization") == "Bearer secret"
        assert "authorization" not in seen[1]
        assert response.redirects == ("https://cdn.example.net/data",)

    async def test_redirect_limit(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(302, location="/again")

        with pytest.raises(TooManyRedirectsError):
            await _client(handler, max_redirects=2).request("GET", "https://example.com/")

    async def test_response_size_limit_without_content_length(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(200, b"x" * 5000)

        with pytest.raises(ResponseTooLargeError):
            await _client(handler, max_response_bytes=1024).request("GET", "https://example.com/")

    @pytest.mark.parametrize("encoding", ["gzip", "deflate"])
    async def test_decompression_bomb_is_bounded(self, encoding: str) -> None:
        payload = b"\0" * (10 * 1024 * 1024)
        body = gzip.compress(payload) if encoding == "gzip" else zlib.compress(payload)
        assert len(body) < 20_000

        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(200, body, content_encoding=encoding)

        with pytest.raises(ResponseTooLargeError):
            await _client(handler, max_response_bytes=64 * 1024).request(
                "GET", "https://example.com/"
            )

    async def test_gzip_response_is_decoded(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(
                200,
                gzip.compress(b"<html>hi</html>"),
                content_encoding="gzip",
                content_type="text/html; charset=utf-8",
            )

        response = await _client(handler).request(
            "GET", "https://example.com/", accept_content_types=frozenset({"text/html"})
        )
        assert response.text() == "<html>hi</html>"
        assert response.charset == "utf-8"

    async def test_content_type_allowlist(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(200, b"MZ...", content_type="application/x-msdownload")

        with pytest.raises(UnexpectedContentTypeError):
            await _client(handler).request(
                "GET", "https://example.com/", accept_content_types=frozenset({"text/html"})
            )

    async def test_client_errors_are_permanent(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(404)

        with pytest.raises(UpstreamStatusError):
            await _client(handler).request("GET", "https://example.com/")

    @pytest.mark.parametrize("status", [429, 502, 503, 504])
    async def test_an_outage_page_in_html_is_still_an_outage(self, status: int) -> None:
        # Load balancers and proxies answer outages with HTML error pages: the
        # status decides, the content type only matters for a successful answer.
        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(status, b"<html>busy</html>", content_type="text/html", retry_after="30")

        with pytest.raises(RetryableUpstreamStatusError) as raised:
            await _client(handler).request(
                "GET", "https://example.com/", accept_content_types=frozenset({"application/json"})
            )
        assert raised.value.retry_after_seconds == 30

    async def test_a_rejection_in_html_is_reported_by_its_status(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(404, b"<html>not here</html>", content_type="text/html")

        with pytest.raises(UpstreamStatusError):
            await _client(handler).request(
                "GET", "https://example.com/", accept_content_types=frozenset({"application/json"})
            )

    async def test_environment_proxies_are_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
        seen_hosts: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen_hosts.append(request.url.host)
            return _resp(200)

        await _client(handler).request("GET", "https://example.com/")
        assert seen_hosts == ["example.com"]


class TestTruncationAndRedirectHooks:
    @pytest.mark.parametrize("encoding", ["identity", "gzip"])
    @pytest.mark.parametrize("declared", [True, False])
    async def test_truncate_to_limit_keeps_the_first_bytes(
        self, encoding: str, declared: bool
    ) -> None:
        payload = bytes(range(256)) * 400  # 100 KiB
        body = gzip.compress(payload) if encoding == "gzip" else payload
        headers = {"content_encoding": encoding}
        if declared:
            headers["content_length"] = str(len(body))

        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(200, body, **headers)

        response = await _client(handler, max_response_bytes=10_000).request(
            "GET", "https://example.com/", truncate_to_limit=True
        )
        assert response.content == payload[:10_000]

    async def test_the_redirect_guard_sees_every_hop_and_can_refuse_one(self) -> None:
        requested: list[str] = []
        guarded: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            requested.append(str(request.url))
            if request.url.path == "/a":
                return _resp(302, location="/b")
            return _resp(302, location="/c")

        async def guard(url: str) -> None:
            guarded.append(url)
            if url.endswith("/c"):
                raise PolicyViolationError(code="refused_by_guard")

        with pytest.raises(PolicyViolationError):
            await _client(handler).request("GET", "https://example.com/a", redirect_guard=guard)
        assert guarded == ["https://example.com/b", "https://example.com/c"]
        assert requested == ["https://example.com/a", "https://example.com/b"]  # /c never sent

    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308, 300, 304])
    async def test_an_unfollowed_redirect_is_not_a_success(self, status: int) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(status, location="https://example.org/")

        with pytest.raises(RedirectNotFollowedError):
            await _client(handler).request(
                "POST", "https://example.com/hook", follow_redirects=False
            )

    async def test_redirects_are_still_returned_when_status_is_not_raised(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return _resp(302, location="https://example.org/")

        response = await _client(handler).request(
            "GET", "https://example.com/", follow_redirects=False, raise_for_status=False
        )
        assert response.status_code == 302

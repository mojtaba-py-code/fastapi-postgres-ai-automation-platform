"""SSRF-guarded transport for httpx2.

The guard sits at the lowest possible layer - the TCP connect call inside
httpcore2 - so it validates the IP address the socket is *actually* opened to,
after DNS resolution. Consequences:

* DNS rebinding is ineffective: we resolve once, validate every returned
  address, and connect to one of those validated addresses (never re-resolving).
* URL-parser differentials are irrelevant: whatever host string reaches the
  connect call is what gets validated.
* Redirects, retries and keep-alive connections all pass through the same check.

TLS still verifies the certificate against the original hostname because
httpcore2 passes the URL host as ``server_hostname`` during the TLS handshake.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import AsyncIterable, AsyncIterator, Iterable
from typing import NoReturn, Protocol

import httpcore2
import httpx2

from nexusflow.domain.shared.url_policy import IPAddress, forbidden_ip_reason

_HTTPCORE_TO_HTTPX: tuple[tuple[type[Exception], type[httpx2.HTTPError]], ...] = (
    (httpcore2.ConnectTimeout, httpx2.ConnectTimeout),
    (httpcore2.ReadTimeout, httpx2.ReadTimeout),
    (httpcore2.WriteTimeout, httpx2.WriteTimeout),
    (httpcore2.PoolTimeout, httpx2.PoolTimeout),
    (httpcore2.TimeoutException, httpx2.TimeoutException),
    (httpcore2.ConnectError, httpx2.ConnectError),
    (httpcore2.ReadError, httpx2.ReadError),
    (httpcore2.WriteError, httpx2.WriteError),
    (httpcore2.NetworkError, httpx2.NetworkError),
    (httpcore2.RemoteProtocolError, httpx2.RemoteProtocolError),
    (httpcore2.LocalProtocolError, httpx2.LocalProtocolError),
    (httpcore2.ProtocolError, httpx2.ProtocolError),
    (httpcore2.UnsupportedProtocol, httpx2.UnsupportedProtocol),
)


class SSRFBlockedError(Exception):
    """Raised when a connection target violates the egress policy."""

    def __init__(self, reason: str, host: str) -> None:
        super().__init__(f"egress to {host!r} blocked: {reason}")
        self.reason = reason
        self.host = host


class Resolver(Protocol):
    async def resolve(self, host: str, port: int) -> list[IPAddress]: ...


class SystemResolver:
    """Resolve via the OS resolver (``getaddrinfo``) without blocking the loop."""

    async def resolve(self, host: str, port: int) -> list[IPAddress]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses: list[IPAddress] = []
        for info in infos:
            raw = str(info[4][0]).split("%", 1)[0]  # drop IPv6 scope id
            address = ipaddress.ip_address(raw)
            if address not in addresses:
                addresses.append(address)
        return addresses


class GuardedNetworkBackend(httpcore2.AsyncNetworkBackend):
    def __init__(
        self,
        resolver: Resolver,
        *,
        allowed_ports: frozenset[int],
        resolve_timeout_seconds: float = 5.0,
        inner: httpcore2.AsyncNetworkBackend | None = None,
    ) -> None:
        self._resolver = resolver
        self._allowed_ports = allowed_ports
        self._resolve_timeout = resolve_timeout_seconds
        self._inner = inner or httpcore2.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - signature fixed by httpcore2
        local_address: str | None = None,
        socket_options: Iterable[httpcore2.SOCKET_OPTION] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        if port not in self._allowed_ports:
            raise SSRFBlockedError("port_not_allowed", host)
        addresses = await self._resolve(host, port)
        for address in addresses:
            reason = forbidden_ip_reason(address)
            if reason is not None:
                # Reject the whole answer if *any* record is internal: mixed
                # public/private answers are a classic rebinding trick.
                raise SSRFBlockedError(reason, host)
        last_error: Exception | None = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    str(address),
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore2.ConnectError, httpcore2.ConnectTimeout) as exc:
                last_error = exc
        raise last_error or httpcore2.ConnectError(f"could not connect to {host}")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - signature fixed by httpcore2
        socket_options: Iterable[httpcore2.SOCKET_OPTION] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        raise SSRFBlockedError("unix_socket_not_allowed", path)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)

    async def _resolve(self, host: str, port: int) -> list[IPAddress]:
        try:
            return [ipaddress.ip_address(host.strip("[]"))]
        except ValueError:
            pass
        try:
            async with asyncio.timeout(self._resolve_timeout):
                addresses = await self._resolver.resolve(host, port)
        except TimeoutError as exc:
            raise httpcore2.ConnectTimeout(f"DNS resolution timed out for {host}") from exc
        except (OSError, ValueError) as exc:
            raise httpcore2.ConnectError(f"DNS resolution failed for {host}") from exc
        if not addresses:
            raise httpcore2.ConnectError(f"DNS resolution returned no addresses for {host}")
        return addresses


class _ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, stream: AsyncIterable[bytes]) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self._stream:
                yield chunk
        except Exception as exc:  # noqa: BLE001 - translated and re-raised, never swallowed
            _raise_mapped(exc)

    async def aclose(self) -> None:
        close = getattr(self._stream, "aclose", None)
        if close is not None:
            await close()


class GuardedTransport(httpx2.AsyncBaseTransport):
    """An httpx2 transport whose connection pool uses the guarded backend."""

    def __init__(
        self,
        backend: GuardedNetworkBackend,
        *,
        max_connections: int = 20,
        max_keepalive_connections: int = 10,
        keepalive_expiry: float = 15.0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        context = ssl_context or httpx2.create_ssl_context(trust_env=False)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._pool = httpcore2.AsyncConnectionPool(
            ssl_context=context,
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry,
            http1=True,
            http2=False,
            retries=0,
            network_backend=backend,
        )

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        core_request = httpcore2.Request(
            method=request.method,
            url=httpcore2.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        try:
            response = await self._pool.handle_async_request(core_request)
        except Exception as exc:  # noqa: BLE001 - translated and re-raised, never swallowed
            _raise_mapped(exc)
        if not isinstance(response.stream, AsyncIterable):  # pragma: no cover - async pool only
            raise TypeError("expected an async response stream")
        return httpx2.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_ResponseStream(response.stream),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


def _raise_mapped(exc: Exception) -> NoReturn:
    """Translate httpcore2 exceptions to their httpx2 equivalents; re-raise others."""
    for source, target in _HTTPCORE_TO_HTTPX:
        if isinstance(exc, source):
            raise target(str(exc)) from exc
    raise exc

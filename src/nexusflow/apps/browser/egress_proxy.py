"""Pinning egress proxy for the headless browser.

Chromium runs with ``--proxy-server=http://127.0.0.1:<port>`` and
``--proxy-bypass-list=<-loopback>``, so every connection it opens -
navigations, sub-resources, redirects - goes through this proxy. For each
connection the proxy validates the target against the URL policy, resolves the
host **itself**, requires *every* address to be public and then connects only
to those validated addresses. There is no second DNS lookup an attacker could
rebind between the check and the connection.

HTTPS uses ``CONNECT`` tunnels (end-to-end TLS; the proxy never sees content).
Plain HTTP is only forwarded when the policy allows it (development).
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import time
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from nexusflow.core.errors import PolicyViolationError
from nexusflow.domain.shared.url_policy import UrlPolicy, ValidatedUrl, forbidden_ip_reason
from nexusflow.infrastructure.observability.logging import get_logger

_log = get_logger("nexusflow.browser.proxy")

type Streams = tuple[asyncio.StreamReader, asyncio.StreamWriter]
type Resolver = Callable[[str, int], Awaitable[list[str]]]
type AddressFilter = Callable[[str], bool]
type Connector = Callable[[str, int], Awaitable[Streams]]

MAX_HEADER_LINES = 100
MAX_LINE_BYTES = 8192
MAX_ADDRESSES = 8
CHUNK_BYTES = 65536
HEADER_TIMEOUT = 10.0
IDLE_TIMEOUT = 60.0
MAX_TUNNEL_SECONDS = 300.0
_ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"
_FORBIDDEN = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_HOP_BY_HOP = frozenset({b"proxy-connection", b"proxy-authorization", b"connection", b"keep-alive"})


async def system_resolver(host: str, port: int) -> list[str]:
    answers = await asyncio.get_running_loop().getaddrinfo(
        host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    return [str(answer[4][0]).split("%", 1)[0] for answer in answers]


def is_public(address: str) -> bool:
    try:
        return forbidden_ip_reason(ipaddress.ip_address(address)) is None
    except ValueError:
        return False


class BlockedTargetError(Exception):
    """The target must not be contacted; ``str(exc)`` is a short reason code."""


class PinningProxy:
    def __init__(
        self,
        policy: UrlPolicy,
        *,
        resolver: Resolver = system_resolver,
        address_filter: AddressFilter = is_public,
        connector: Connector = asyncio.open_connection,
        max_connections: int = 64,
        connect_timeout: float = 10.0,
    ) -> None:
        self._policy = policy
        self._resolve = resolver
        self._allowed = address_filter
        self._connect = connector
        self._slots = asyncio.Semaphore(max_connections)
        self._connect_timeout = connect_timeout
        self._server: asyncio.Server | None = None

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        """Listen (on loopback by default) and return the bound port."""
        self._server = await asyncio.start_server(self._handle, host, port, limit=MAX_LINE_BYTES)
        return int(self._server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def pinned_addresses(self, target: ValidatedUrl) -> list[str]:
        """The addresses the connection may use; every DNS answer must be allowed."""
        if target.is_ip_literal:
            addresses = [target.host]
        else:
            try:
                addresses = await self._resolve(target.host, target.port)
            except OSError as exc:
                raise BlockedTargetError("unresolvable") from exc
        unique = list(dict.fromkeys(addresses))
        if not unique or not all(self._allowed(address) for address in unique):
            # One bad answer taints the name: a rebinding attacker controls them all.
            raise BlockedTargetError("non_public_address")
        return unique[:MAX_ADDRESSES]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with self._slots:
            try:
                await self._serve(reader, writer)
            except (OSError, TimeoutError, asyncio.IncompleteReadError, ValueError):
                pass  # client went away, stalled or sent an oversized/malformed head
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request_line = await asyncio.wait_for(reader.readline(), HEADER_TIMEOUT)
        if not request_line.strip():
            return
        headers = await asyncio.wait_for(_read_headers(reader), HEADER_TIMEOUT)
        method, _, rest = request_line.decode("latin-1").strip().partition(" ")
        target, _, version = rest.partition(" ")
        tunnel = method.upper() == "CONNECT"
        try:
            validated = self._policy.validate(f"https://{target}/" if tunnel else target)
            if not tunnel and validated.scheme != "http":
                raise BlockedTargetError("https_requires_connect")
            addresses = await self.pinned_addresses(validated)
        except (PolicyViolationError, BlockedTargetError) as exc:
            reason = exc.code if isinstance(exc, PolicyViolationError) else str(exc)
            _log.info("egress_blocked", target=_describe(target, tunnel=tunnel), reason=reason)
            await _reply(writer, _FORBIDDEN)
            return
        upstream = await self._open(addresses, validated.port)
        if upstream is None:
            await _reply(writer, _BAD_GATEWAY)
            return
        upstream_reader, upstream_writer = upstream
        try:
            if tunnel:
                await _reply(writer, _ESTABLISHED)
            else:
                await _reply(upstream_writer, _origin_request(method, validated, version, headers))
            await _relay(reader, writer, upstream_reader, upstream_writer)
        finally:
            upstream_writer.close()
            with contextlib.suppress(OSError):
                await upstream_writer.wait_closed()

    async def _open(self, addresses: list[str], port: int) -> Streams | None:
        """Connect to the first reachable validated address - never to a hostname."""
        for address in addresses:
            try:
                return await asyncio.wait_for(self._connect(address, port), self._connect_timeout)
            except (OSError, TimeoutError):
                continue
        return None


async def _reply(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(data)
    await writer.drain()


async def _read_headers(reader: asyncio.StreamReader) -> list[bytes]:
    headers: list[bytes] = []
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            return headers
        if len(headers) >= MAX_HEADER_LINES:
            raise ValueError("too many header lines")
        headers.append(line)


def _describe(target: str, *, tunnel: bool) -> str:
    """Host and port only - request paths and queries stay out of the logs."""
    if tunnel:
        return target[:200]
    try:
        return urlsplit(target).netloc[:200]
    except ValueError:
        return "<unparseable>"


def _origin_request(method: str, target: ValidatedUrl, version: str, headers: list[bytes]) -> bytes:
    parts = urlsplit(target.url)
    origin_form = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    kept = [h for h in headers if h.split(b":", 1)[0].strip().lower() not in _HOP_BY_HOP]
    head = f"{method} {origin_form} {version or 'HTTP/1.1'}\r\n".encode("latin-1")
    return head + b"".join(kept) + b"Connection: close\r\n\r\n"


async def _relay(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> None:
    """Copy both ways until both sides finish, both idle or the lifetime cap hits."""
    last_activity = time.monotonic()

    async def pipe(source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
        nonlocal last_activity
        while True:
            try:
                chunk = await asyncio.wait_for(source.read(CHUNK_BYTES), IDLE_TIMEOUT)
            except TimeoutError:
                if time.monotonic() - last_activity >= IDLE_TIMEOUT:
                    return
                continue  # the other direction is still busy
            if not chunk:
                break
            last_activity = time.monotonic()
            sink.write(chunk)
            await sink.drain()
        with contextlib.suppress(OSError, RuntimeError):
            if sink.can_write_eof():
                sink.write_eof()

    tasks = [
        asyncio.create_task(pipe(client_reader, upstream_writer)),
        asyncio.create_task(pipe(upstream_reader, client_writer)),
    ]
    try:
        async with asyncio.timeout(MAX_TUNNEL_SECONDS):
            await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

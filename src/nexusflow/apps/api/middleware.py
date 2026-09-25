"""Pure ASGI middleware (no ``BaseHTTPMiddleware``: it breaks streaming and
context propagation).

* :class:`RequestContextMiddleware` - request id, trusted-proxy aware client IP,
  structured access log, Prometheus metrics.
* :class:`SecurityHeadersMiddleware` - defensive response headers.
* :class:`BodySizeLimitMiddleware` - hard cap on request bodies, enforced on the
  actual stream (``Content-Length`` is not trusted).
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from collections.abc import Iterable, Sequence
from ipaddress import IPv4Network, IPv6Network

import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from nexusflow.core.correlation import correlation
from nexusflow.core.ids import uuid7
from nexusflow.infrastructure.observability import metrics
from nexusflow.infrastructure.observability.logging import get_logger

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")
_log = get_logger("nexusflow.access")

type Network = IPv4Network | IPv6Network


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return str(value.decode("latin-1"))
    return None


def _in_networks(address: str, networks: Iterable[Network]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in networks)


def resolve_client_ip(scope: Scope, trusted_proxies: Sequence[Network]) -> str | None:
    """Return the real client IP.

    ``X-Forwarded-For`` is honoured only when the direct peer is a trusted proxy,
    and is walked right-to-left, skipping trusted hops - so a client cannot spoof
    its address by sending its own ``X-Forwarded-For`` header.
    """
    client = scope.get("client")
    peer: str | None = str(client[0]) if client else None
    if peer is None or not trusted_proxies or not _in_networks(peer, trusted_proxies):
        return peer
    forwarded = _header(scope, b"x-forwarded-for")
    if not forwarded:
        return peer
    hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
    for hop in reversed(hops):
        if not _in_networks(hop, trusted_proxies):
            try:
                return str(ipaddress.ip_address(hop))
            except ValueError:
                return peer
    return peer


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp, *, trusted_proxies: Sequence[Network]) -> None:
        self.app = app
        self.trusted_proxies = list(trusted_proxies)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        client_ip = resolve_client_ip(scope, self.trusted_proxies)
        incoming = _header(scope, b"x-request-id")
        from_proxy = (
            bool(client_ip)
            and scope.get("client")
            and _in_networks(scope["client"][0], self.trusted_proxies)
        )
        request_id = (
            incoming
            if incoming and from_proxy and _REQUEST_ID.fullmatch(incoming)
            else str(uuid7())
        )
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        state["client_ip"] = client_ip
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        status_code = 500
        started = time.perf_counter()
        metrics.HTTP_IN_FLIGHT.inc()

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            with correlation(request_id):  # outbox messages of this request carry it
                await self.app(scope, receive, send_wrapper)
        finally:
            metrics.HTTP_IN_FLIGHT.dec()
            elapsed = time.perf_counter() - started
            route = scope.get("route")
            template = getattr(route, "path", "unmatched")
            method = scope.get("method", "GET")
            metrics.HTTP_REQUESTS.labels(
                method=method, route=template, status=str(status_code)
            ).inc()
            metrics.HTTP_LATENCY.labels(method=method, route=template).observe(elapsed)
            _log.info(
                "http_request",
                method=method,
                route=template,
                status=status_code,
                duration_ms=round(elapsed * 1000, 2),
                client_ip=client_ip,
            )
            structlog.contextvars.clear_contextvars()


_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
_DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: "
    "https://fastapi.tiangolo.com; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_docs = str(scope.get("path", "")).startswith(_DOCS_PATHS)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"server"]
                existing = {k.lower() for k, _ in headers}
                defaults = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"accelerometer=(), camera=(), geolocation=(), "
                    b"microphone=(), payment=(), usb=(), interest-cohort=()",
                    b"cross-origin-opener-policy": b"same-origin",
                    b"cross-origin-resource-policy": b"same-origin",
                    b"content-security-policy": (_DOCS_CSP if is_docs else _API_CSP).encode(),
                    b"cache-control": b"no-store",
                }
                if self.hsts:
                    defaults[b"strict-transport-security"] = b"max-age=63072000; includeSubDomains"
                headers.extend((k, v) for k, v in defaults.items() if k not in existing)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class _BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Reject bodies above the limit; path-pattern rules allow larger uploads."""

    def __init__(self, app: ASGIApp, *, default_limit: int, overrides: dict[str, int]) -> None:
        self.app = app
        self.default_limit = default_limit
        self.overrides = [(re.compile(pattern), limit) for pattern, limit in overrides.items()]

    def _limit_for(self, path: str) -> int:
        for pattern, limit in self.overrides:
            if pattern.fullmatch(path):
                return limit
        return self.default_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit_for(str(scope.get("path", "")))
        declared = _header(scope, b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > limit):
            await _send_413(send)
            return
        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLargeError:
            if not response_started:
                await _send_413(send)


async def _send_413(send: Send) -> None:
    body = json.dumps(
        {"error": "payload_too_large", "message": "The request payload is too large."}
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})

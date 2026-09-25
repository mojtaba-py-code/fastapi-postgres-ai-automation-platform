"""Outbound HTTP client for untrusted destinations.

Every request to a user-influenced URL (scraping, REST API sources, outbound
webhooks, notification endpoints) goes through :class:`SafeHttpClient`:

* static URL policy on the initial URL **and every redirect hop**;
* connect-time IP validation (see ``transport.py``);
* manual redirect handling (max hops, no HTTPS->HTTP downgrade, credentials
  stripped on cross-origin hops);
* strict timeouts (connect/read/write/pool) plus an overall deadline;
* response size limits enforced on the *decoded* stream with a bounded
  decompressor (no decompression bombs), independent of ``Content-Length``;
* optional content-type allowlist;
* environment proxies ignored (``trust_env=False``) so ``HTTP(S)_PROXY`` cannot
  silently reroute traffic.
"""

from __future__ import annotations

import asyncio
import time
import zlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx2

from nexusflow.core.errors import (
    PermanentError,
    PolicyViolationError,
    TransientError,
)
from nexusflow.core.jsonutil import JSONValue, loads_limited
from nexusflow.domain.shared.url_policy import UrlPolicy, ValidatedUrl
from nexusflow.infrastructure.http.transport import (
    GuardedNetworkBackend,
    GuardedTransport,
    Resolver,
    SSRFBlockedError,
    SystemResolver,
)
from nexusflow.infrastructure.observability import metrics

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# Awaited with each redirect target before it is requested; raises to refuse it.
RedirectGuard = Callable[[str], Awaitable[None]]
_RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
_DEFAULT_SENSITIVE_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token"}
)
_KEPT_RESPONSE_HEADERS = frozenset(
    {"content-type", "content-length", "etag", "last-modified", "retry-after", "location"}
)


class OutboundTimeoutError(TransientError):
    default_code = "upstream_timeout"
    default_message = "The remote server did not respond in time."


class OutboundConnectionError(TransientError):
    default_code = "upstream_unreachable"
    default_message = "The remote server could not be reached."


class UpstreamStatusError(PermanentError):
    default_code = "upstream_rejected"
    default_message = "The remote server rejected the request."

    def __init__(self, status_code: int) -> None:
        super().__init__(internal_detail=f"HTTP {status_code}")
        self.status_code = status_code


class RetryableUpstreamStatusError(TransientError):
    default_code = "upstream_unavailable"
    default_message = "The remote server is temporarily unavailable."

    def __init__(self, status_code: int, retry_after_seconds: int | None) -> None:
        super().__init__(internal_detail=f"HTTP {status_code}")
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds


class ResponseTooLargeError(PermanentError):
    default_code = "response_too_large"
    default_message = "The remote response exceeded the size limit."


class UnexpectedContentTypeError(PermanentError):
    default_code = "unexpected_content_type"
    default_message = "The remote response had an unexpected content type."


class TooManyRedirectsError(PermanentError):
    default_code = "too_many_redirects"
    default_message = "The remote server redirected too many times."


class RedirectNotFollowedError(PermanentError):
    default_code = "redirect_not_followed"
    default_message = (
        "The remote server answered with a redirect, which this request does not follow."
    )


@dataclass(frozen=True, slots=True)
class HttpResponse:
    url: str
    status_code: int
    headers: Mapping[str, str]
    content: bytes
    content_type: str | None
    charset: str | None
    redirects: tuple[str, ...] = field(default_factory=tuple)
    elapsed_seconds: float = 0.0

    def text(self) -> str:
        encoding = self.charset or "utf-8"
        try:
            return self.content.decode(encoding, errors="replace")
        except LookupError:  # unknown charset label supplied by the server
            return self.content.decode("utf-8", errors="replace")

    def json(self, *, max_depth: int = 32) -> JSONValue:
        return loads_limited(self.content, max_bytes=len(self.content) + 1, max_depth=max_depth)


@dataclass(frozen=True, slots=True)
class HttpClientLimits:
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 15.0
    total_timeout_seconds: float = 30.0
    max_response_bytes: int = 5 * 1024 * 1024
    max_redirects: int = 3


class SafeHttpClient:
    def __init__(
        self,
        *,
        policy: UrlPolicy,
        user_agent: str,
        limits: HttpClientLimits,
        resolver: Resolver | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
        max_connections: int = 20,
    ) -> None:
        self._policy = policy
        self._limits = limits
        guarded = transport or GuardedTransport(
            GuardedNetworkBackend(
                resolver or SystemResolver(),
                allowed_ports=policy.allowed_ports,
                resolve_timeout_seconds=limits.connect_timeout_seconds,
            ),
            max_connections=max_connections,
        )
        self._client = httpx2.AsyncClient(
            transport=guarded,
            timeout=httpx2.Timeout(
                connect=limits.connect_timeout_seconds,
                read=limits.read_timeout_seconds,
                write=limits.read_timeout_seconds,
                pool=limits.connect_timeout_seconds,
            ),
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": user_agent, "Accept-Encoding": "gzip, deflate"},
        )

    @property
    def policy(self) -> UrlPolicy:
        return self._policy

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        json_body: JSONValue | None = None,
        content: bytes | None = None,
        policy: UrlPolicy | None = None,
        accept_content_types: frozenset[str] | None = None,
        max_bytes: int | None = None,
        follow_redirects: bool = True,
        raise_for_status: bool = True,
        sensitive_headers: frozenset[str] = _DEFAULT_SENSITIVE_HEADERS,
        truncate_to_limit: bool = False,
        redirect_guard: RedirectGuard | None = None,
    ) -> HttpResponse:
        """Send one request under the URL policy, following redirects hop by hop.

        ``truncate_to_limit`` keeps the first ``max_bytes`` of a larger body
        instead of failing (robots.txt); ``redirect_guard`` is awaited with
        every redirect target before it is requested and may raise to stop.
        """
        effective_policy = policy or self._policy
        limit = max_bytes or self._limits.max_response_bytes
        started = time.monotonic()
        try:
            async with asyncio.timeout(self._limits.total_timeout_seconds):
                response = await self._send_following_redirects(
                    method.upper(),
                    effective_policy.validate(url),
                    headers=dict(headers or {}),
                    params=params,
                    json_body=json_body,
                    content=content,
                    policy=effective_policy,
                    accept_content_types=accept_content_types,
                    max_bytes=limit,
                    follow_redirects=follow_redirects,
                    sensitive_headers=sensitive_headers,
                    truncate_to_limit=truncate_to_limit,
                    redirect_guard=redirect_guard,
                )
        except TimeoutError as exc:
            raise OutboundTimeoutError() from exc
        except SSRFBlockedError as exc:
            metrics.SSRF_BLOCKED.labels(reason=exc.reason).inc()
            raise PolicyViolationError(
                "The destination address is not allowed.",
                code="address_not_allowed",
                internal_detail=str(exc),
            ) from exc
        except PolicyViolationError as exc:
            metrics.SSRF_BLOCKED.labels(reason=exc.code).inc()
            raise
        except httpx2.TimeoutException as exc:
            raise OutboundTimeoutError(internal_detail=type(exc).__name__) from exc
        except (httpx2.NetworkError, httpx2.RemoteProtocolError) as exc:
            raise OutboundConnectionError(internal_detail=type(exc).__name__) from exc
        except httpx2.HTTPError as exc:
            raise PermanentError(
                "The outbound request failed.", code="outbound_failed", internal_detail=str(exc)
            ) from exc
        elapsed = time.monotonic() - started
        final = HttpResponse(
            url=response.url,
            status_code=response.status_code,
            headers=response.headers,
            content=response.content,
            content_type=response.content_type,
            charset=response.charset,
            redirects=response.redirects,
            elapsed_seconds=elapsed,
        )
        if raise_for_status:
            _raise_for_status(final)
        return final

    async def _send_following_redirects(
        self,
        method: str,
        target: ValidatedUrl,
        *,
        headers: dict[str, str],
        params: Mapping[str, str] | None,
        json_body: JSONValue | None,
        content: bytes | None,
        policy: UrlPolicy,
        accept_content_types: frozenset[str] | None,
        max_bytes: int,
        follow_redirects: bool,
        sensitive_headers: frozenset[str],
        truncate_to_limit: bool,
        redirect_guard: RedirectGuard | None,
    ) -> HttpResponse:
        redirects: list[str] = []
        current = target
        current_params = params
        for _hop in range(self._limits.max_redirects + 1):
            request = self._client.build_request(
                method,
                current.url,
                headers=headers,
                params=current_params,
                json=json_body,
                content=content,
            )
            response = await self._client.send(request, stream=True)
            try:
                if follow_redirects and response.status_code in _REDIRECT_STATUSES:
                    location = response.headers.get("location")
                    if not location:
                        raise PermanentError("Redirect without Location.", code="bad_redirect")
                    next_target = policy.validate(urljoin(str(response.url), location))
                    if current.scheme == "https" and next_target.scheme != "https":
                        raise PolicyViolationError(
                            "Redirect downgraded HTTPS to HTTP.", code="redirect_downgrade"
                        )
                    if redirect_guard is not None:
                        await redirect_guard(next_target.url)
                    if next_target.origin != current.origin:
                        headers = {
                            k: v for k, v in headers.items() if k.lower() not in sensitive_headers
                        }
                    if response.status_code == 303 or (
                        response.status_code in (301, 302) and method == "POST"
                    ):
                        method, json_body, content = "GET", None, None
                    redirects.append(next_target.url)
                    current, current_params = next_target, None
                    continue
                body = await _read_bounded(response, max_bytes, truncate=truncate_to_limit)
            finally:
                await response.aclose()
            content_type, charset = _parse_content_type(response.headers.get("content-type"))
            if accept_content_types is not None and content_type not in accept_content_types:
                raise UnexpectedContentTypeError(internal_detail=f"got {content_type!r}")
            kept = {
                k: v for k, v in response.headers.items() if k.lower() in _KEPT_RESPONSE_HEADERS
            }
            return HttpResponse(
                url=str(response.url),
                status_code=response.status_code,
                headers=kept,
                content=body,
                content_type=content_type,
                charset=charset,
                redirects=tuple(redirects),
            )
        raise TooManyRedirectsError()


async def _read_bounded(response: httpx2.Response, max_bytes: int, *, truncate: bool) -> bytes:
    """Read the raw stream and decode it with a hard cap on the *output* size.

    Past the cap the response is rejected - or, with ``truncate``, cut at the
    cap and the rest of the stream left unread.
    """
    declared = response.headers.get("content-length")
    if not truncate and declared and declared.isdigit() and int(declared) > max_bytes:
        raise ResponseTooLargeError(internal_detail=f"declared {declared} bytes")
    decoder = _BoundedDecoder(
        response.headers.get("content-encoding", ""), max_bytes, truncate=truncate
    )
    async for chunk in response.aiter_raw():
        decoder.feed(chunk)
        if decoder.full:
            break
    return decoder.finish()


class _BoundedDecoder:
    def __init__(self, content_encoding: str, max_bytes: int, *, truncate: bool = False) -> None:
        encoding = content_encoding.strip().lower()
        self._max = max_bytes
        self._truncate = truncate
        self.full = False
        self._parts: list[bytes] = []
        self._size = 0
        self._raw_size = 0
        self._deflate_fallback = False
        if encoding in ("", "identity"):
            self._decompressor: zlib._Decompress | None = None
        elif encoding in ("gzip", "x-gzip"):
            self._decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif encoding == "deflate":
            self._decompressor = zlib.decompressobj(zlib.MAX_WBITS)
            self._deflate_fallback = True
        else:
            raise UnexpectedContentTypeError(
                "Unsupported content encoding.", internal_detail=f"encoding={encoding!r}"
            )

    def feed(self, chunk: bytes) -> None:
        if self.full:
            return
        self._raw_size += len(chunk)
        if self._raw_size > self._max and not self._truncate:
            raise ResponseTooLargeError()
        if self._decompressor is None:
            self._append(chunk)
            return
        data = chunk
        while data:
            remaining = self._max - self._size + 1
            try:
                output = self._decompressor.decompress(data, remaining)
            except zlib.error as exc:
                if self._deflate_fallback and self._size == 0:
                    # Some servers send raw deflate without the zlib wrapper.
                    self._decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                    self._deflate_fallback = False
                    continue
                raise PermanentError("Corrupt compressed response.", code="bad_encoding") from exc
            self._deflate_fallback = False
            if self._append(output):
                return  # truncated: the rest of the body is not needed
            data = self._decompressor.unconsumed_tail

    def finish(self) -> bytes:
        if self._decompressor is not None and not self.full:
            self._append(self._decompressor.flush())
        return b"".join(self._parts)

    def _append(self, data: bytes) -> bool:
        """Buffer ``data``; returns True once a truncating decoder is full."""
        if self._size + len(data) > self._max:
            if not self._truncate:
                raise ResponseTooLargeError()
            data = data[: self._max - self._size]
            self.full = True
        self._size += len(data)
        self._parts.append(data)
        return self.full


def _parse_content_type(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    mime, _, params = value.partition(";")
    charset = None
    for param in params.split(";"):
        key, _, raw = param.strip().partition("=")
        if key.lower() == "charset" and raw:
            charset = raw.strip().strip('"').lower()[:40]
    return mime.strip().lower() or None, charset


def _raise_for_status(response: HttpResponse) -> None:
    """Only a 2xx answer is a success.

    A 3xx reaches this point only when redirects are not followed (webhooks,
    chat APIs): the request was not carried out, so it must not count as done.
    """
    status = response.status_code
    if 200 <= status < 300:
        return
    if 300 <= status < 400:
        raise RedirectNotFollowedError(internal_detail=f"HTTP {status}")
    if status in _RETRYABLE_STATUSES:
        raise RetryableUpstreamStatusError(status, _retry_after(response.headers))
    raise UpstreamStatusError(status)


def _retry_after(headers: Mapping[str, str]) -> int | None:
    raw = headers.get("retry-after", "")
    return min(int(raw), 3600) if raw.isdigit() else None

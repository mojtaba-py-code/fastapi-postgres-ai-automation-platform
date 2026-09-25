"""Test doubles shared by the adapter tests: canned, recorded in-memory HTTP.

``SafeHttpClient`` reads response bodies as raw streams (so it can bound their
*decoded* size), which means canned responses must be streamed the way a real
transport delivers them instead of being pre-loaded with ``content=``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable

import httpx2

from nexusflow.infrastructure.http.client import SafeHttpClient

USER_AGENT = "NexusFlowBot/0.1 (+https://nexusflow.example/bot)"

type Handler = Callable[[httpx2.Request], httpx2.Response]
type SafeClientFactory = Callable[..., SafeHttpClient]


class StreamedBody(httpx2.AsyncByteStream):
    """A lazily streamed response body, as network transports produce."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        if self._body:
            yield self._body


def respond(
    status: int = 200,
    body: bytes | str = b"",
    *,
    content_type: str | None = None,
    headers: dict[str, str] | None = None,
) -> httpx2.Response:
    raw = body.encode() if isinstance(body, str) else body
    all_headers = dict(headers or {})
    if content_type is not None:
        all_headers["content-type"] = content_type
    return httpx2.Response(status, headers=all_headers, stream=StreamedBody(raw))


def json_response(
    document: object,
    status: int = 200,
    *,
    content_type: str = "application/json",
    headers: dict[str, str] | None = None,
) -> httpx2.Response:
    return respond(status, json.dumps(document), content_type=content_type, headers=headers)


class RecordingHandler:
    """``httpx2.MockTransport`` handler that records each request before answering."""

    def __init__(self, handler: Handler) -> None:
        self._handler = handler
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return self._handler(request)

    @property
    def urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]


def fail_on_request(request: httpx2.Request) -> httpx2.Response:
    """Handler for code paths that must not touch the network at all."""
    raise AssertionError(f"unexpected outbound request: {request.method} {request.url}")

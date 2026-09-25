"""Collectors: turn a source configuration into raw items.

``WebsiteCollector`` runs in the isolated *sandbox* worker (internet egress, no
database, no secrets). ``RestApiCollector`` needs decrypted credentials and
therefore runs in the *integrations* worker. Both use the SSRF-guarded client.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx2

from nexusflow.core.config import RateLimitRule
from nexusflow.core.errors import PermanentError, TransientError
from nexusflow.core.jsonutil import loads_limited
from nexusflow.domain.integrations.model import SOURCE_AUTH_KINDS, ResolvedCredential
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.domain.sources.model import (
    CursorPagination,
    PageParamPagination,
    RestApiConfig,
    WebsiteConfig,
)
from nexusflow.domain.sources.paths import extract_items, map_fields, resolve_path
from nexusflow.infrastructure.http.client import SafeHttpClient
from nexusflow.infrastructure.redis.rate_limit import RateLimiter
from nexusflow.infrastructure.scraping.extraction import extract_items as extract_html_items
from nexusflow.infrastructure.scraping.robots import RobotsDecision, RobotsPolicy
from nexusflow.infrastructure.scraping.throttle import HostThrottle

_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_JSON_TYPES = frozenset(
    {"application/json", "application/ld+json", "text/json", "application/problem+json"}
)


@dataclass(frozen=True, slots=True)
class CollectedItems:
    items: list[dict[str, Any]]
    truncated: bool
    detail: dict[str, Any] = field(default_factory=dict)


class RobotsDisallowedError(PermanentError):
    default_code = "robots_disallowed"
    default_message = "The site's robots.txt disallows this URL."


class RobotsUnavailableError(TransientError):
    default_code = "robots_unavailable"
    default_message = "The site's robots.txt could not be fetched; the run will be retried."


class BrowserRenderer:
    """Client for the isolated headless-browser service (internal network only)."""

    def __init__(self, base_url: str, token: str, *, timeout_seconds: float = 45.0) -> None:
        self._client = httpx2.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout_seconds,
            trust_env=False,
            headers={"Authorization": f"Bearer {token}"},
        )

    async def render(self, url: str) -> tuple[str, str]:
        try:
            response = await self._client.post("/render", json={"url": url})
        except httpx2.HTTPError as exc:
            raise TransientError(
                code="browser_unavailable", internal_detail=type(exc).__name__
            ) from exc
        if response.status_code >= 500:
            raise TransientError(code="browser_unavailable")
        if response.status_code != 200:
            raise PermanentError(
                code="render_failed", internal_detail=f"HTTP {response.status_code}"
            )
        body = loads_limited(response.content, max_bytes=8 * 1024 * 1024, max_depth=4)
        if not isinstance(body, dict):
            raise PermanentError(code="render_failed")
        return str(body.get("html", "")), str(body.get("final_url", url))

    async def aclose(self) -> None:
        await self._client.aclose()


class WebsiteCollector:
    def __init__(
        self,
        *,
        client: SafeHttpClient,
        robots: RobotsPolicy,
        throttle: HostThrottle,
        min_interval_seconds: float,
        browser: BrowserRenderer | None,
    ) -> None:
        self._client = client
        self._robots = robots
        self._throttle = throttle
        self._min_interval = min_interval_seconds
        self._browser = browser

    async def collect(
        self, config: WebsiteConfig, *, policy: UrlPolicy, max_items: int
    ) -> CollectedItems:
        target = policy.validate(config.url)
        decision = await self._require_robots(target.url, policy)
        await self._throttle.acquire(
            target.host, interval_seconds=max(self._min_interval, decision.crawl_delay or 0.0)
        )

        async def each_redirect(url: str) -> None:  # robots.txt applies to every hop
            await self._require_robots(url, policy)

        if config.render_javascript:
            if self._browser is None:
                raise PermanentError(code="js_unavailable")
            html, final_url = await self._browser.render(target.url)
            if final_url != target.url:
                # The browser followed redirects itself: the content is used only if
                # its final URL is one this source may fetch and robots.txt allows.
                await each_redirect(policy.validate(final_url).url)
            status, size = 200, len(html)
        else:
            response = await self._client.request(
                "GET",
                target.url,
                policy=policy,
                headers={"Accept": "text/html,application/xhtml+xml;q=0.9"},
                accept_content_types=_HTML_TYPES,
                redirect_guard=each_redirect,
            )
            html, final_url, status, size = (
                response.text(),
                response.url,
                response.status_code,
                len(response.content),
            )
        items, truncated = await asyncio.to_thread(
            extract_html_items,
            html,
            config,
            base_url=final_url,
            max_items=min(config.max_items, max_items),
        )
        return CollectedItems(
            items=items,
            truncated=truncated,
            detail={"http_status": status, "bytes": size, "host": urlsplit(final_url).hostname},
        )

    async def _require_robots(self, url: str, policy: UrlPolicy) -> RobotsDecision:
        decision = await self._robots.check(url, policy=policy)
        if not decision.allowed:
            host = urlsplit(url).hostname or ""
            if decision.unavailable:
                raise RobotsUnavailableError(internal_detail=host)
            raise RobotsDisallowedError(internal_detail=host)
        return decision


class RestApiCollector:
    def __init__(
        self, *, client: SafeHttpClient, limiter: RateLimiter | None, rule: RateLimitRule
    ) -> None:
        self._client = client
        self._limiter = limiter
        self._rule = rule

    async def collect(
        self,
        config: RestApiConfig,
        *,
        policy: UrlPolicy,
        credential: ResolvedCredential | None,
        integration_id: UUID | None,
        max_items: int,
    ) -> CollectedItems:
        headers = {"Accept": "application/json", **config.headers}
        sensitive = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
        if credential is not None:
            if credential.kind not in SOURCE_AUTH_KINDS:
                raise PermanentError(code="invalid_integration")
            auth = credential.auth_headers()
            headers.update(auth)
            sensitive.update(name.lower() for name in auth)
        limit = min(config.max_items, max_items)
        collected: list[dict[str, Any]] = []
        truncated = False
        page_value: int | None = (
            config.pagination.start
            if config.pagination and config.pagination.type == "page_param"
            else None
        )
        cursor: str | None = None
        max_pages = config.pagination.max_pages if config.pagination else 1
        pages = 0
        for _ in range(max_pages):
            pages += 1
            if self._limiter is not None and integration_id is not None:
                await self._limiter.enforce(
                    "external_api.integration", str(integration_id), self._rule
                )
            params = dict(config.query)
            if (
                config.pagination is not None
                and config.pagination.type == "page_param"
                and page_value is not None
            ):
                params[config.pagination.param] = str(page_value)
            if config.pagination is not None and config.pagination.type == "cursor" and cursor:
                params[config.pagination.cursor_param] = cursor
            response = await self._client.request(
                config.method,
                config.url,
                policy=policy,
                headers=headers,
                params=params,
                json_body=config.body if config.method == "POST" else None,
                accept_content_types=_JSON_TYPES,
                sensitive_headers=frozenset(sensitive),
            )
            document = response.json(max_depth=40)
            raw, _ = extract_items(document, config.items_path, max_items=limit - len(collected))
            collected.extend(map_fields(item, config.field_mapping) for item in raw)
            if len(collected) >= limit:
                truncated = True  # more data may exist beyond the configured limit
                break
            if config.pagination is None or not raw:
                break
            if isinstance(config.pagination, PageParamPagination) and page_value is not None:
                page_value += 1
            elif isinstance(config.pagination, CursorPagination):
                next_cursor = resolve_path(document, config.pagination.cursor_path)
                if (
                    isinstance(next_cursor, bool)
                    or not isinstance(next_cursor, (str, int))
                    or str(next_cursor) in ("", cursor)  # "" would silently restart at page 1
                ):
                    break
                cursor = str(next_cursor)[:512]
        else:
            # Stopped by the page cap, not by the end of the data: the snapshot is
            # partial, so records beyond the cap must not be inferred as deleted.
            truncated = config.pagination is not None
        return CollectedItems(items=collected, truncated=truncated, detail={"pages": pages})

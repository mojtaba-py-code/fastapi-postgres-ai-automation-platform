"""Composition root of the sandbox worker: no database, no storage, no secrets.

Only what hostile-content processing needs is built here: the SSRF-guarded
HTTP client, robots.txt compliance, per-host throttling, the HTML extractor,
the optional isolated browser client and the ticket-authenticated gateway
client. Compare :mod:`nexusflow.bootstrap.container` - none of its key
material, repositories or provider clients exist in this process.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from redis.asyncio import Redis

from nexusflow.bootstrap.http import build_http_client, build_url_policy
from nexusflow.core.config import RedisSettings, SandboxSettings
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.infrastructure.http.client import SafeHttpClient
from nexusflow.infrastructure.redis.client import create_redis
from nexusflow.infrastructure.sandbox.gateway import SandboxGatewayClient
from nexusflow.infrastructure.scraping.collectors import BrowserRenderer, WebsiteCollector
from nexusflow.infrastructure.scraping.robots import RobotsPolicy
from nexusflow.infrastructure.scraping.throttle import HostThrottle

_PREFIX = "nf:"


@dataclass
class SandboxComponents:
    settings: SandboxSettings
    url_policy: UrlPolicy
    http: SafeHttpClient
    website: WebsiteCollector
    gateway: SandboxGatewayClient
    closers: list[Callable[[], Awaitable[None]]] = field(default_factory=list)

    async def aclose(self) -> None:
        for close in reversed(self.closers):
            await close()


def build_sandbox(settings: SandboxSettings) -> SandboxComponents:
    scraping = settings.scraping
    policy = build_url_policy(scraping)
    http = build_http_client(scraping, policy)
    redis: Redis | None = None
    if settings.sandbox.redis_url is not None:
        redis = create_redis(
            RedisSettings(
                url=settings.sandbox.redis_url,
                ssl_ca_certs=settings.sandbox.redis_ssl_ca_certs,
                max_connections=10,
            )
        )
    browser = (
        BrowserRenderer(
            scraping.browser_service_url, scraping.browser_service_token.get_secret_value()
        )
        if scraping.browser_service_url and scraping.browser_service_token
        else None
    )
    components = SandboxComponents(
        settings=settings,
        url_policy=policy,
        http=http,
        website=WebsiteCollector(
            client=http,
            robots=RobotsPolicy(
                http,
                redis,
                user_agent=scraping.user_agent,
                cache_ttl_seconds=scraping.robots_cache_ttl_seconds,
                prefix=_PREFIX,
            ),
            throttle=HostThrottle(redis, prefix=_PREFIX),
            min_interval_seconds=scraping.min_domain_interval_seconds,
            browser=browser,
        ),
        gateway=SandboxGatewayClient(
            settings.sandbox.gateway_url, timeout_seconds=settings.sandbox.gateway_timeout_seconds
        ),
    )
    components.closers.append(http.aclose)
    components.closers.append(components.gateway.aclose)
    if browser is not None:
        components.closers.append(browser.aclose)
    if redis is not None:
        components.closers.append(redis.aclose)
    return components

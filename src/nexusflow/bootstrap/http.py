"""Builders for the SSRF-guarded outbound HTTP stack (shared by all processes).

Kept separate from the container so that the sandbox worker can build its
HTTP client without importing the platform composition root.
"""

from __future__ import annotations

from nexusflow.core.config import ScrapingSettings, SsoSettings
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.infrastructure.http.client import HttpClientLimits, SafeHttpClient

IDP_USER_AGENT = "NexusFlow-SSO/1.0"


def build_url_policy(scraping: ScrapingSettings) -> UrlPolicy:
    return UrlPolicy(
        allow_http=scraping.allow_http,
        allowed_ports=frozenset(scraping.allowed_ports),
        blocked_domains=frozenset(d.lower() for d in scraping.blocked_domains),
    )


def build_http_client(scraping: ScrapingSettings, policy: UrlPolicy) -> SafeHttpClient:
    return SafeHttpClient(
        policy=policy,
        user_agent=scraping.user_agent,
        limits=HttpClientLimits(
            connect_timeout_seconds=scraping.connect_timeout_seconds,
            read_timeout_seconds=scraping.read_timeout_seconds,
            total_timeout_seconds=scraping.total_timeout_seconds,
            max_response_bytes=scraping.max_response_bytes,
            max_redirects=scraping.max_redirects,
        ),
    )


def build_idp_http_client(sso: SsoSettings, scraping: ScrapingSettings) -> SafeHttpClient:
    """The client for identity providers and the DNS-over-HTTPS resolver.

    Tenants configure identity providers, so this is an SSRF-guarded client like
    the collection one - HTTPS on port 443 only, the platform's blocked domains,
    short timeouts and a small response cap (discovery documents and key sets
    are a few kilobytes)."""
    policy = UrlPolicy(
        allow_http=False,
        allowed_ports=frozenset({443}),
        blocked_domains=frozenset(d.lower() for d in scraping.blocked_domains),
    )
    return SafeHttpClient(
        policy=policy,
        user_agent=IDP_USER_AGENT,
        limits=HttpClientLimits(
            connect_timeout_seconds=min(5.0, sso.http_timeout_seconds),
            read_timeout_seconds=sso.http_timeout_seconds,
            total_timeout_seconds=sso.http_timeout_seconds * 2,
            max_response_bytes=sso.max_response_bytes,
            max_redirects=2,
        ),
        max_connections=10,
    )

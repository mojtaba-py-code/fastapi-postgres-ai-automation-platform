"""Builders for the SSRF-guarded outbound HTTP stack (shared by all processes).

Kept separate from the container so that the sandbox worker can build its
HTTP client without importing the platform composition root.
"""

from __future__ import annotations

from nexusflow.core.config import ScrapingSettings
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.infrastructure.http.client import HttpClientLimits, SafeHttpClient


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

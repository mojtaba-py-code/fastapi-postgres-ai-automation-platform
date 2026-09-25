"""robots.txt compliance (``infrastructure.scraping.robots``).

Covers rule evaluation for the crawler's product token, crawl-delay, the
failure policy (4xx -> allow everything; 5xx or network failure -> disallow
everything) and the Redis cache through which all workers share one fetch per
origin. robots.txt is served by an in-memory transport behind the real
SSRF-guarded client.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import cast

import fakeredis
import httpx2
import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.infrastructure.scraping.robots import (
    RobotsDecision,
    RobotsPolicy,
    RobotsRedirectBlockedError,
    RobotsRules,
)
from tests.unit.adapters.fakes import (
    USER_AGENT,
    Handler,
    RecordingHandler,
    SafeClientFactory,
    fail_on_request,
    respond,
)

SHOP = "https://shop.example.com"
ROBOTS_TXT = """\
# Everyone else stays out.
User-agent: *
Disallow: /

User-agent: NexusFlowBot
Disallow: /checkout
Disallow: /account/
Allow: /
Crawl-delay: 5
"""


def _serving(body: str | None = ROBOTS_TXT, status: int = 200) -> RecordingHandler:
    def handle(request: httpx2.Request) -> httpx2.Response:
        assert request.url.path == "/robots.txt"
        return respond(status, body or "", content_type="text/plain")

    return RecordingHandler(handle)


def _failing(error: type[httpx2.TransportError]) -> RecordingHandler:
    def handle(request: httpx2.Request) -> httpx2.Response:
        raise error("simulated failure", request=request)

    return RecordingHandler(handle)


def _policy(
    factory: SafeClientFactory,
    handler: Handler,
    redis: Redis | None = None,
    *,
    user_agent: str = USER_AGENT,
    ttl: int = 3600,
) -> RobotsPolicy:
    return RobotsPolicy(
        factory(handler), redis, user_agent=user_agent, cache_ttl_seconds=ttl, prefix="nf:"
    )


class _BrokenRedis:
    """A Redis whose every command fails (outage)."""

    def __init__(self) -> None:
        self.calls = 0

    async def get(self, key: str) -> bytes | None:
        self.calls += 1
        raise RedisConnectionError("redis is down")

    async def set(self, key: str, value: str, *, ex: int) -> bool:
        self.calls += 1
        raise RedisConnectionError("redis is down")


class TestRules:
    async def test_the_crawler_group_rules_and_crawl_delay_apply(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        site = _serving()
        policy = _policy(safe_client_factory, site)

        assert await policy.check(f"{SHOP}/products?page=2") == RobotsDecision(True, 5.0)
        assert await policy.check(f"{SHOP}/checkout/cart") == RobotsDecision(False, 5.0)
        assert await policy.check(f"{SHOP}/account/orders") == RobotsDecision(False, 5.0)

    async def test_robots_txt_is_fetched_from_the_origin_root_with_the_bot_user_agent(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        site = _serving()
        await _policy(safe_client_factory, site).check(f"{SHOP}/deep/path/page.html?x=1")

        [request] = site.requests
        assert request.method == "GET"
        assert str(request.url) == f"{SHOP}/robots.txt"
        assert request.headers["user-agent"] == USER_AGENT

    async def test_the_wildcard_group_applies_to_other_crawlers(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        policy = _policy(safe_client_factory, _serving(), user_agent="OtherBot/2.0")
        assert await policy.check(f"{SHOP}/products") == RobotsDecision(False, None)

    async def test_product_token_matching_is_case_insensitive(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        site = _serving("User-agent: nexusflowbot\nDisallow: /private\n")
        policy = _policy(safe_client_factory, site)
        assert await policy.check(f"{SHOP}/private/report") == RobotsDecision(False, None)
        assert await policy.check(f"{SHOP}/public") == RobotsDecision(True, None)

    async def test_an_empty_robots_txt_allows_everything(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        policy = _policy(safe_client_factory, _serving(""))
        assert await policy.check(f"{SHOP}/anything") == RobotsDecision(True, None)

    async def test_a_redirected_robots_txt_is_followed(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        def handle(request: httpx2.Request) -> httpx2.Response:
            if request.url.host == "shop.example.com":
                return respond(301, headers={"location": "https://www.shop.example.com/robots.txt"})
            return respond(200, "User-agent: *\nDisallow: /admin\n", content_type="text/plain")

        site = RecordingHandler(handle)
        policy = _policy(safe_client_factory, site)
        assert await policy.check(f"{SHOP}/admin/users") == RobotsDecision(False, None)
        assert site.urls == [f"{SHOP}/robots.txt", "https://www.shop.example.com/robots.txt"]


class TestFailurePolicy:
    @pytest.mark.parametrize("status", [400, 401, 403, 404, 410])
    async def test_client_errors_mean_there_are_no_rules(
        self, safe_client_factory: SafeClientFactory, status: int
    ) -> None:
        policy = _policy(safe_client_factory, _serving("Disallow: /", status=status))
        assert await policy.check(f"{SHOP}/anything") == RobotsDecision(True, None)

    @pytest.mark.parametrize("status", [500, 502, 503, 504])
    async def test_server_errors_disallow_everything(
        self, safe_client_factory: SafeClientFactory, status: int
    ) -> None:
        policy = _policy(safe_client_factory, _serving("User-agent: *\nAllow: /\n", status))
        assert await policy.check(f"{SHOP}/") == RobotsDecision(False, None, unavailable=True)

    @pytest.mark.parametrize(
        "error", [httpx2.ConnectError, httpx2.ReadTimeout, httpx2.ConnectTimeout, httpx2.ReadError]
    )
    async def test_network_failures_disallow_everything(
        self, safe_client_factory: SafeClientFactory, error: type[httpx2.TransportError]
    ) -> None:
        policy = _policy(safe_client_factory, _failing(error))
        assert await policy.check(f"{SHOP}/products") == RobotsDecision(
            False, None, unavailable=True
        )


class TestCaching:
    async def test_workers_share_one_fetch_per_origin_through_redis(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        server = fakeredis.FakeServer()
        first_worker = fakeredis.FakeAsyncRedis(server=server)
        second_worker = fakeredis.FakeAsyncRedis(server=server)
        site = _serving()
        try:
            first = _policy(safe_client_factory, site, first_worker)
            second = _policy(safe_client_factory, fail_on_request, second_worker)

            assert await first.check(f"{SHOP}/products") == RobotsDecision(True, 5.0)
            assert await first.check(f"{SHOP}/checkout") == RobotsDecision(False, 5.0)
            assert await second.check(f"{SHOP}/checkout") == RobotsDecision(False, 5.0)
        finally:
            await first_worker.aclose()
            await second_worker.aclose()
        assert len(site.requests) == 1

    async def test_each_origin_is_cached_separately(
        self, safe_client_factory: SafeClientFactory, fake_redis: fakeredis.FakeAsyncRedis
    ) -> None:
        site = _serving()
        policy = _policy(safe_client_factory, site, fake_redis)
        for _ in range(2):
            await policy.check(f"{SHOP}/a")
            await policy.check("https://blog.example.com/b")
        assert site.urls == [f"{SHOP}/robots.txt", "https://blog.example.com/robots.txt"]
        assert len(await fake_redis.keys("nf:robots:*")) == 2

    @pytest.mark.parametrize(
        ("make_handler", "ttl", "expected_ttl"),
        [
            pytest.param(_serving, 86_400, 86_400, id="rules-full-ttl"),
            pytest.param(lambda: _serving(status=404), 86_400, 86_400, id="allow-all-full-ttl"),
            pytest.param(lambda: _serving(status=503), 86_400, 600, id="5xx-capped"),
            pytest.param(lambda: _failing(httpx2.ConnectError), 86_400, 600, id="network-capped"),
            pytest.param(lambda: _serving(status=503), 300, 300, id="short-ttl-kept"),
        ],
    )
    async def test_cache_lifetime_depends_on_the_outcome(
        self,
        safe_client_factory: SafeClientFactory,
        fake_redis: fakeredis.FakeAsyncRedis,
        make_handler: Callable[[], RecordingHandler],
        ttl: int,
        expected_ttl: int,
    ) -> None:
        policy = _policy(safe_client_factory, make_handler(), fake_redis, ttl=ttl)
        await policy.check(f"{SHOP}/products")

        [key] = await fake_redis.keys("nf:robots:*")
        assert expected_ttl - 5 <= await fake_redis.ttl(key) <= expected_ttl

    async def test_a_cached_disallow_is_not_refetched(
        self, safe_client_factory: SafeClientFactory, fake_redis: fakeredis.FakeAsyncRedis
    ) -> None:
        site = _serving(status=503)
        policy = _policy(safe_client_factory, site, fake_redis)
        assert await policy.check(f"{SHOP}/a") == RobotsDecision(False, None, unavailable=True)
        assert await policy.check(f"{SHOP}/b") == RobotsDecision(False, None, unavailable=True)
        assert len(site.requests) == 1

    @pytest.mark.security
    async def test_cache_keys_do_not_reveal_the_host(
        self, safe_client_factory: SafeClientFactory, fake_redis: fakeredis.FakeAsyncRedis
    ) -> None:
        await _policy(safe_client_factory, _serving(), fake_redis).check(f"{SHOP}/")
        [raw_key] = await fake_redis.keys("*")
        key = raw_key.decode() if isinstance(raw_key, bytes) else str(raw_key)
        assert key.startswith("nf:robots:")
        assert "shop" not in key

    async def test_without_redis_every_check_fetches(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        site = _serving()
        policy = _policy(safe_client_factory, site, None)
        await policy.check(f"{SHOP}/a")
        await policy.check(f"{SHOP}/b")
        assert len(site.requests) == 2

    async def test_a_redis_outage_degrades_to_fetching(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        redis = _BrokenRedis()
        site = _serving()
        policy = _policy(safe_client_factory, site, cast(Redis, redis))

        assert await policy.check(f"{SHOP}/products") == RobotsDecision(True, 5.0)
        assert await policy.check(f"{SHOP}/checkout") == RobotsDecision(False, 5.0)
        assert len(site.requests) == 2
        assert redis.calls == 4  # every read and write was attempted, and failed quietly


class TestRfc9309Precedence:
    """RFC 9309 section 2.2.2: the most specific (longest) matching rule wins, and
    ``*`` / ``$`` are special characters. (``urllib.robotparser`` implements the
    1996 draft instead - first match wins, plain prefixes - which is why the
    policy has its own matcher.)"""

    async def test_the_most_specific_rule_wins(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        site = _serving("User-agent: *\nAllow: /\nDisallow: /admin\n")
        policy = _policy(safe_client_factory, site)
        assert await policy.check(f"{SHOP}/admin/users") == RobotsDecision(False, None)

    async def test_wildcards_and_end_anchors_are_honoured(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        site = _serving("User-agent: *\nDisallow: /*.pdf$\n")
        policy = _policy(safe_client_factory, site)
        assert await policy.check(f"{SHOP}/files/price-list.pdf") == RobotsDecision(False, None)

    @pytest.mark.parametrize(
        ("robots", "path", "allowed"),
        [
            ("Disallow: /\nAllow: /$", "/", True),  # the anchored allow is longer
            ("Disallow: /\nAllow: /$", "/page", False),
            ("Disallow: /shop\nAllow: /shop", "/shop/x", True),  # a tie goes to allow
            ("Allow: /shop\nDisallow: /shop", "/shop/x", True),  # whatever the order
            ("Disallow: /*/private/", "/a/b/private/c", False),
            ("Disallow: /*?session=", "/list?session=1&page=2", False),
            ("Disallow: /*?session=", "/list?page=2", True),
            ("Disallow: /fish*.php", "/fishheads/catfish.php?parameters", False),
            ("Disallow: /fish*.php", "/Fish.PHP", True),  # matching is case sensitive
            ("Disallow: /$", "/", False),
            ("Disallow: /$", "/index.html", True),
            ("Disallow:", "/anything", True),  # an empty rule matches nothing
            ("Disallow: /", "/robots.txt", True),  # implicitly allowed
        ],
    )
    def test_rule_evaluation(self, robots: str, path: str, allowed: bool) -> None:
        rules = RobotsRules.parse(f"User-agent: *\n{robots}\n", "NexusFlowBot")
        assert rules.allows(path) is allowed

    @pytest.mark.parametrize(
        ("pattern", "path"),
        [
            ("/caf%C3%A9", "/café"),
            ("/café", "/caf%c3%a9"),
            ("/%7Euser", "/~user"),  # an escaped unreserved character is decoded
        ],
    )
    def test_percent_encoding_is_normalised_before_matching(self, pattern: str, path: str) -> None:
        rules = RobotsRules.parse(f"User-agent: *\nDisallow: {pattern}\n", "NexusFlowBot")
        assert rules.allows(path) is False

    def test_an_encoded_slash_is_not_a_slash(self) -> None:
        rules = RobotsRules.parse("User-agent: *\nDisallow: /a/b\n", "NexusFlowBot")
        assert rules.allows("/a%2Fb") is True


class TestGroups:
    def test_every_group_for_our_token_is_combined(self) -> None:
        text = (
            "User-agent: NexusFlowBot\nDisallow: /a\n\n"
            "User-agent: *\nDisallow: /\n\n"
            "User-agent: nexusflowbot\nDisallow: /b\nCrawl-delay: 3\n"
        )
        rules = RobotsRules.parse(text, "NexusFlowBot")
        assert (rules.allows("/a"), rules.allows("/b"), rules.allows("/c")) == (False, False, True)
        assert rules.crawl_delay == 3.0

    def test_consecutive_user_agent_lines_share_one_group(self) -> None:
        text = "User-agent: OtherBot\n\nUser-agent: NexusFlowBot/1.0\nDisallow: /x\n"
        assert RobotsRules.parse(text, "NexusFlowBot").allows("/x") is False

    def test_rules_before_any_user_agent_and_unknown_records_are_ignored(self) -> None:
        text = (
            "Disallow: /\nSitemap: https://shop.example.com/sitemap.xml\n"
            "User-agent: *\nHost: shop.example.com\nDisallow: /cart\n"
        )
        rules = RobotsRules.parse(text, "NexusFlowBot")
        assert (rules.allows("/"), rules.allows("/cart")) == (True, False)

    @pytest.mark.parametrize("value", ["-1", "0", "nan", "inf", "soon"])
    def test_unusable_crawl_delays_are_ignored(self, value: str) -> None:
        rules = RobotsRules.parse(f"User-agent: *\nCrawl-delay: {value}\n", "NexusFlowBot")
        assert rules.crawl_delay is None

    @pytest.mark.security
    def test_a_hostile_pattern_cannot_stall_the_matcher(self) -> None:
        rules = RobotsRules.parse("User-agent: *\nDisallow: /" + "*a" * 900 + "b\n", "Bot")
        started = time.perf_counter()
        assert rules.allows("/" + "a" * 2000) is True
        assert time.perf_counter() - started < 2.0


class TestLargeAndRedirectedFiles:
    async def test_an_oversized_robots_txt_is_truncated_not_rejected(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        body = "User-agent: *\nDisallow: /private\n" + "# padding\n" * 80_000  # ~800 KiB
        policy = _policy(safe_client_factory, _serving(body))
        assert await policy.check(f"{SHOP}/private/x") == RobotsDecision(False, None)
        assert await policy.check(f"{SHOP}/public") == RobotsDecision(True, None)

    @pytest.mark.security
    async def test_a_redirect_outside_the_source_allowlist_is_refused_and_not_cached(
        self, safe_client_factory: SafeClientFactory, fake_redis: fakeredis.FakeAsyncRedis
    ) -> None:
        def handle(request: httpx2.Request) -> httpx2.Response:
            if request.url.host == "shop.example.com":
                return respond(302, headers={"location": "https://tracker.example.net/robots.txt"})
            return respond(200, "User-agent: *\nAllow: /\n", content_type="text/plain")

        site = RecordingHandler(handle)
        policy = _policy(safe_client_factory, site, fake_redis)
        allowlisted = UrlPolicy().with_allowed_domains(["shop.example.com"])

        with pytest.raises(RobotsRedirectBlockedError):
            await policy.check(f"{SHOP}/products", policy=allowlisted)
        assert site.urls == [f"{SHOP}/robots.txt"]
        assert await fake_redis.keys("nf:robots:*") == []
        # A source whose policy allows the target still gets the rules.
        assert await policy.check(f"{SHOP}/products") == RobotsDecision(True, None)

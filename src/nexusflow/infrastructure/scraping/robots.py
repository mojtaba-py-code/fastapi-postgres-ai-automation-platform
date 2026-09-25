"""robots.txt compliance (RFC 9309) with Redis caching.

* 2xx: parse the rules - the group for our product token (all such groups
  combined), else the ``*`` groups; the longest matching rule wins, ``allow``
  wins a tie, ``*`` matches any sequence and a trailing ``$`` anchors the end;
* 4xx, or more redirects than the client follows: no usable robots.txt ->
  crawling allowed;
* 5xx / network failure: *complete disallow* until the (short) cache entry
  expires. The collector reports this as a temporary failure, so the run is
  retried rather than failed.

robots.txt is fetched under the source's URL policy, so a redirect cannot take
the crawler outside the source's allowed domains; such a redirect fails the
run with a clear error and is never cached (the cache is shared by every
source and tenant that crawls the origin).

Only the first :data:`_MAX_ROBOTS_BYTES` are parsed (RFC 9309 section 2.5 asks
for at least 500 KiB); a larger file is truncated, not rejected.
"""

from __future__ import annotations

import hashlib
import json
import math
import string
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from redis.asyncio import Redis
from redis.exceptions import RedisError

from nexusflow.core.errors import PermanentError, PolicyViolationError, TransientError
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.infrastructure.http.client import SafeHttpClient, TooManyRedirectsError

_MAX_ROBOTS_BYTES = 512 * 1024
_MAX_RULES = 10_000  # per file; a hostile robots.txt cannot make every check slow
_MAX_PATTERN = 2_048
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_HEX = frozenset(string.hexdigits)


class RobotsRedirectBlockedError(PermanentError):
    default_code = "robots_redirect_blocked"
    default_message = (
        "The site's robots.txt redirects outside the source's allowed domains; "
        "add the redirect target to the allowed domains to crawl this source."
    )


@dataclass(frozen=True, slots=True)
class RobotsDecision:
    allowed: bool
    crawl_delay: float | None = None
    # True when robots.txt could not be fetched (5xx, network): "not now", not "never".
    unavailable: bool = False


# ------------------------------------------------------------------ parsing


def _normalise(value: str) -> str:
    """Canonical percent-encoding for comparison (RFC 9309 2.2.2, RFC 3986 6.2.2).

    Escaped unreserved characters are decoded, other escapes upper-cased, and
    non-ASCII or control characters encoded as UTF-8, so ``/caf%C3%A9``,
    ``/café`` and ``/caf%c3%a9`` compare equal while ``%2F`` stays distinct from ``/``.
    """
    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        escape = value[index + 1 : index + 3]
        if char == "%" and len(escape) == 2 and set(escape) <= _HEX:
            decoded = chr(int(escape, 16))
            out.append(decoded if decoded in _UNRESERVED else "%" + escape.upper())
            index += 3
            continue
        if ord(char) > 0x7E or ord(char) <= 0x20:
            out.extend(f"%{byte:02X}" for byte in char.encode("utf-8"))
        else:
            out.append(char)
        index += 1
    return "".join(out)


def _matches(pattern: str, path: str) -> bool:
    """RFC 9309 pattern match from the first octet: ``*`` wildcard, trailing ``$``.

    A greedy two-pointer matcher (backtracking only to the last ``*``): linear
    in practice and O(len(pattern) * len(path)) at worst - no regex, so a
    hostile pattern cannot trigger catastrophic backtracking.
    """
    if pattern.endswith("$"):
        pattern = pattern[:-1]
    else:
        pattern += "*"  # an unanchored pattern is a prefix match
    p = s = 0
    star, mark = -1, 0
    while s < len(path):
        if p < len(pattern) and pattern[p] == "*":
            star, mark = p, s
            p += 1
        elif p < len(pattern) and pattern[p] == path[s]:
            p += 1
            s += 1
        elif star >= 0:
            p = star + 1
            mark += 1
            s = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


@dataclass(slots=True)
class _Group:
    agents: list[str] = field(default_factory=list)
    rules: list[tuple[bool, str]] = field(default_factory=list)  # (allow, pattern)
    crawl_delay: float | None = None


@dataclass(frozen=True, slots=True)
class RobotsRules:
    """The rules that apply to one crawler (product token) in one robots.txt."""

    rules: tuple[tuple[bool, str], ...] = ()
    crawl_delay: float | None = None

    @classmethod
    def parse(cls, text: str, product_token: str) -> RobotsRules:
        token = product_token.strip().lower()
        groups: list[_Group] = []
        current: _Group | None = None
        collecting_agents = False
        rule_count = 0
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            key, separator, value = line.partition(":")
            if not separator:
                continue
            key, value = key.strip().lower(), value.strip()
            if key == "user-agent":
                if current is None or not collecting_agents:
                    current = _Group()
                    groups.append(current)
                current.agents.append(value.lower())
                collecting_agents = True
            elif key in ("allow", "disallow") and current is not None:
                collecting_agents = False
                if value and len(value) <= _MAX_PATTERN and rule_count < _MAX_RULES:
                    current.rules.append((key == "allow", _normalise(value)))
                    rule_count += 1
            elif key == "crawl-delay" and current is not None:
                collecting_agents = False
                current.crawl_delay = _delay(value)
            # Other records (sitemap, host, ...) neither start nor end a group.
        chosen = [g for g in groups if any(_is_agent(a, token) for a in g.agents)] or [
            g for g in groups if "*" in g.agents
        ]
        delays = [g.crawl_delay for g in chosen if g.crawl_delay]
        return cls(
            rules=tuple(rule for group in chosen for rule in group.rules),
            crawl_delay=max(delays) if delays else None,
        )

    def allows(self, path_and_query: str) -> bool:
        path = _normalise(path_and_query or "/")
        if path == "/robots.txt":
            return True  # implicitly allowed (RFC 9309 2.2.2)
        best_length, allowed = -1, True
        for allow, pattern in self.rules:
            length = len(pattern)
            # Only a longer rule, or an allow tying with the best so far, changes the verdict.
            if (length > best_length or (length == best_length and allow)) and _matches(
                pattern, path
            ):
                best_length, allowed = length, allow
        return allowed


def _is_agent(value: str, token: str) -> bool:
    # "NexusFlowBot" and "NexusFlowBot/1.0" both name our product token.
    return value == token or value.split("/", 1)[0].strip() == token


def _delay(value: str) -> float | None:
    try:
        delay = float(value)
    except ValueError:
        return None
    return delay if math.isfinite(delay) and delay > 0 else None


# ------------------------------------------------------------------- policy


class RobotsPolicy:
    def __init__(
        self,
        client: SafeHttpClient,
        redis: Redis | None,
        *,
        user_agent: str,
        cache_ttl_seconds: int,
        prefix: str,
    ) -> None:
        self._client = client
        self._redis = redis
        self._agent = user_agent.split("/", 1)[0]
        self._ttl = cache_ttl_seconds
        self._prefix = prefix

    async def check(self, url: str, *, policy: UrlPolicy | None = None) -> RobotsDecision:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        state = await self._load(origin, policy)
        if state["mode"] == "allow_all":
            return RobotsDecision(True)
        if state["mode"] == "disallow_all":
            return RobotsDecision(False, unavailable=True)
        rules = RobotsRules.parse(str(state["body"]), self._agent)
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        return RobotsDecision(rules.allows(target), rules.crawl_delay)

    async def _load(self, origin: str, policy: UrlPolicy | None) -> dict[str, str]:
        key = f"{self._prefix}robots:{hashlib.sha256(origin.encode()).hexdigest()[:32]}"
        cached = await self._cache_get(key)
        if cached is not None:
            return cached
        state = await self._fetch(origin, policy)
        await self._cache_set(key, state)
        return state

    async def _fetch(self, origin: str, policy: UrlPolicy | None) -> dict[str, str]:
        try:
            response = await self._client.request(
                "GET",
                f"{origin}/robots.txt",
                policy=policy,
                max_bytes=_MAX_ROBOTS_BYTES,
                truncate_to_limit=True,
                raise_for_status=False,
            )
        except PolicyViolationError as exc:
            # Not cached: another source may allow the redirect target.
            raise RobotsRedirectBlockedError(internal_detail=exc.code) from exc
        except TooManyRedirectsError:
            return {"mode": "allow_all"}  # RFC 9309 2.3.1.2: treat as unavailable (4xx)
        except (TransientError, PermanentError):
            return {"mode": "disallow_all"}
        if 200 <= response.status_code < 300:
            return {"mode": "rules", "body": response.text()}
        if 400 <= response.status_code < 500:
            return {"mode": "allow_all"}
        return {"mode": "disallow_all"}

    async def _cache_get(self, key: str) -> dict[str, str] | None:
        if self._redis is None:
            return None
        try:
            raw = await self._redis.get(key)
        except RedisError:
            return None
        if raw is None:
            return None
        loaded: dict[str, str] = json.loads(raw)
        return loaded

    async def _cache_set(self, key: str, state: dict[str, str]) -> None:
        if self._redis is None:
            return
        ttl = self._ttl if state["mode"] != "disallow_all" else min(self._ttl, 600)
        try:
            await self._redis.set(key, json.dumps(state), ex=ttl)
        except RedisError:
            return

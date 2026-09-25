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

A hostile file cannot make a check slow: patterns are matched segment by
segment with ``str.find`` (in C, no backtracking), so a check costs at most in
the order of ``_MAX_RULE_CHARS * _MAX_PATH`` character comparisons - well under
a second. Only the rules of the groups that apply to us are kept, deduplicated
and counted against those caps; a path longer than ``_MAX_PATH`` (normalised)
is not crawled.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import string
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from redis.asyncio import Redis
from redis.exceptions import RedisError

from nexusflow.core.errors import PermanentError, PolicyViolationError, TransientError
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.infrastructure.http.client import SafeHttpClient, TooManyRedirectsError

_MAX_ROBOTS_BYTES = 512 * 1024
_MAX_RULES = 10_000  # that apply to us, per file
_MAX_PATTERN = 2_048  # characters of one rule
_MAX_RULE_CHARS = 128 * 1024  # of all the rules that apply to us, normalised
_MAX_PATH = 4_096  # characters of a normalised path checked against them
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
# Printable ASCII except "%": already canonical, nothing to rewrite.
_CANONICAL = re.compile(r"[!-$&-~]*")
_REWRITTEN = re.compile(r"%([0-9A-Fa-f]{2})|[^!-~]")


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
    if _CANONICAL.fullmatch(value):
        return value  # the common case, decided in C
    return _REWRITTEN.sub(_canonical, value)


def _canonical(match: re.Match[str]) -> str:
    escape = match.group(1)
    if escape is not None:
        decoded = chr(int(escape, 16))
        return decoded if decoded in _UNRESERVED else "%" + escape.upper()
    return "".join(f"%{byte:02X}" for byte in match.group().encode("utf-8"))


def _matches(pattern: str, path: str) -> bool:
    """RFC 9309 pattern match from the first octet: ``*`` wildcard, trailing ``$``.

    The literal segments between the wildcards are looked up left to right,
    each at its first occurrence after the previous one (``str.find``); taking
    the earliest occurrence never loses a match. No backtracking and no regex:
    a hostile pattern costs one pass of ``find`` per segment.
    """
    anchored = pattern.endswith("$")
    first, *rest = (pattern[:-1] if anchored else pattern).split("*")
    if not path.startswith(first):
        return False
    position = len(first)
    if not rest:
        return not anchored or position == len(path)
    last = rest.pop() if anchored else None  # an unanchored pattern is a prefix match
    for segment in rest:
        found = path.find(segment, position)
        if found < 0:
            return False
        position = found + len(segment)
    return last is None or (len(path) - len(last) >= position and path.endswith(last))


@dataclass(eq=False, slots=True)
class _Kind:
    """Every group of one kind - naming our product token, or ``*`` - merged,
    deduplicated and bounded while it is read."""

    seen: bool = False
    rules: dict[tuple[bool, str], None] = field(default_factory=dict)  # an ordered set
    chars: int = 0

    @property
    def has_room(self) -> bool:
        return len(self.rules) < _MAX_RULES and self.chars < _MAX_RULE_CHARS

    def add(self, allow: bool, pattern: str) -> None:
        fits = len(self.rules) < _MAX_RULES and self.chars + len(pattern) <= _MAX_RULE_CHARS
        if fits and (allow, pattern) not in self.rules:
            self.rules[(allow, pattern)] = None
            self.chars += len(pattern)


@dataclass(slots=True)
class _Group:
    kinds: list[_Kind] = field(default_factory=list)  # the kinds its agents make it
    crawl_delay: float | None = None


@dataclass(frozen=True, slots=True)
class RobotsRules:
    """The rules that apply to one crawler (product token) in one robots.txt."""

    rules: tuple[tuple[bool, str], ...] = ()
    crawl_delay: float | None = None

    @classmethod
    def parse(cls, text: str, product_token: str) -> RobotsRules:
        token = product_token.strip().lower()
        ours, anyone = _Kind(), _Kind()
        groups: list[_Group] = []
        current: _Group | None = None
        collecting_agents = False
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
                agent = value.lower()
                for kind, named in ((ours, _is_agent(agent, token)), (anyone, agent == "*")):
                    if named and kind not in current.kinds:
                        kind.seen = True
                        current.kinds.append(kind)
                collecting_agents = True
            elif key in ("allow", "disallow") and current is not None:
                collecting_agents = False
                # Rules for other crawlers are never used, so never kept (nor counted).
                if value and len(value) <= _MAX_PATTERN and any(k.has_room for k in current.kinds):
                    pattern = _normalise(value)
                    for kind in current.kinds:
                        kind.add(key == "allow", pattern)
            elif key == "crawl-delay" and current is not None:
                collecting_agents = False
                current.crawl_delay = _delay(value)
            # Other records (sitemap, host, ...) neither start nor end a group.
        chosen = ours if ours.seen else anyone
        delays = [g.crawl_delay for g in groups if chosen in g.kinds and g.crawl_delay]
        # Longest first, an allow before a disallow: the first rule that matches decides.
        rules = sorted(chosen.rules, key=lambda rule: (-len(rule[1]), not rule[0]))
        return cls(rules=tuple(rules), crawl_delay=max(delays) if delays else None)

    def allows(self, path_and_query: str) -> bool:
        path = _normalise(path_and_query or "/")
        if path == "/robots.txt":
            return True  # implicitly allowed (RFC 9309 2.2.2)
        if len(path) > _MAX_PATH:
            return False  # longer than any check is bounded for: not crawled
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

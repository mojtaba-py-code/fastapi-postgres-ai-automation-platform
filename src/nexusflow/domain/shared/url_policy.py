"""Server-side request forgery (SSRF) policy for user-controlled URLs.

Two layers use this module:

1. **Static validation** (:meth:`UrlPolicy.validate`) when a URL enters the
   system (source configuration, outbound webhook targets, redirects).
2. **Connect-time validation** (:func:`forbidden_ip_reason`) inside the guarded
   HTTP network backend, on the IP address that is *actually* being connected
   to. Validating only the initial URL is insufficient (DNS rebinding,
   redirects, parser differentials); layer 2 is the authoritative control.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from urllib.parse import SplitResult, urlsplit, urlunsplit

from nexusflow.core.errors import PolicyViolationError

MAX_URL_LENGTH = 2048
_DEFAULT_PORTS = {"http": 80, "https": 443}
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f-\x9f\\]")
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NUMERIC_LIKE_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")

_BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".lan",
    ".corp",
    ".home",
    ".home.arpa",
    ".in-addr.arpa",
    ".ip6.arpa",
    ".onion",
    ".test",
    ".invalid",
)

_FORBIDDEN_V4 = tuple(
    IPv4Network(net)
    for net in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
    )
)
_FORBIDDEN_V6 = tuple(
    IPv6Network(net)
    for net in (
        "::/128",
        "::1/128",
        "::/96",  # deprecated IPv4-compatible addresses
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "3fff::/20",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
)
_NAT64 = IPv6Network("64:ff9b::/96")

type IPAddress = IPv4Address | IPv6Address


def _embedded_ipv4(address: IPv6Address) -> IPv4Address | None:
    """IPv4 address tunnelled inside an IPv6 address, if any."""
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address.sixtofour is not None:
        return address.sixtofour
    if address in _NAT64:
        return IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def forbidden_ip_reason(address: IPAddress) -> str | None:
    """Return why ``address`` must not be contacted, or ``None`` if it is public."""
    if isinstance(address, IPv6Address):
        if address.teredo is not None:
            return "teredo_address"
        embedded = _embedded_ipv4(address)
        if embedded is not None:
            reason = forbidden_ip_reason(embedded)
            return f"embedded_{reason}" if reason else None
        in_forbidden_range = any(address in net for net in _FORBIDDEN_V6)
    else:
        in_forbidden_range = any(address in net for net in _FORBIDDEN_V4)
    checks = (
        (in_forbidden_range, "reserved_range"),
        (address.is_loopback, "loopback"),
        (address.is_link_local, "link_local"),
        (address.is_multicast, "multicast"),
        (address.is_private, "private"),
        (address.is_reserved or address.is_unspecified, "reserved"),
        (not address.is_global, "not_global"),
    )
    return next((reason for failed, reason in checks if failed), None)


@dataclass(frozen=True, slots=True)
class ValidatedUrl:
    url: str
    scheme: str
    host: str
    port: int
    is_ip_literal: bool

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)


@dataclass(frozen=True, slots=True)
class UrlPolicy:
    allow_http: bool = False
    allowed_ports: frozenset[int] = frozenset({80, 443})
    blocked_domains: frozenset[str] = field(default_factory=frozenset)
    allowed_domains: frozenset[str] | None = None

    def with_allowed_domains(self, domains: Iterable[str] | None) -> UrlPolicy:
        if domains is None:
            return self
        normalized = frozenset(d.strip().lower().rstrip(".") for d in domains if d.strip())
        return UrlPolicy(
            allow_http=self.allow_http,
            allowed_ports=self.allowed_ports,
            blocked_domains=self.blocked_domains,
            allowed_domains=normalized or None,
        )

    def validate(self, raw_url: str) -> ValidatedUrl:
        """Statically validate ``raw_url``; raises ``PolicyViolationError``."""
        if not raw_url or len(raw_url) > MAX_URL_LENGTH:
            raise _violation("url_invalid", "URL is empty or too long.")
        if _CONTROL_OR_SPACE.search(raw_url):
            raise _violation("url_invalid", "URL contains forbidden characters.")
        try:
            parts = urlsplit(raw_url)
            port = parts.port
        except ValueError as exc:
            raise _violation("url_invalid", "URL could not be parsed.") from exc
        scheme = parts.scheme.lower()
        if scheme not in ("https", "http") or (scheme == "http" and not self.allow_http):
            raise _violation("scheme_not_allowed", "Only HTTPS URLs are allowed.")
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise _violation("userinfo_not_allowed", "Credentials in URLs are not allowed.")
        host, is_ip = self._validate_host(parts.hostname or "")
        effective_port = port if port is not None else _DEFAULT_PORTS[scheme]
        if effective_port not in self.allowed_ports:
            raise _violation("port_not_allowed", "The URL port is not allowed.")
        normalized = _rebuild(parts, scheme, host, port)
        return ValidatedUrl(
            url=normalized, scheme=scheme, host=host, port=effective_port, is_ip_literal=is_ip
        )

    def _validate_host(self, hostname: str) -> tuple[str, bool]:
        host = hostname.strip().rstrip(".").lower()
        if not host:
            raise _violation("host_invalid", "URL host is missing.")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None:
            reason = forbidden_ip_reason(address)
            if reason:
                raise _violation("address_not_allowed", "The URL points to a non-public address.")
            if self.allowed_domains is not None:
                raise _violation("domain_not_allowed", "The URL host is not in the allowlist.")
            return str(address), True
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise _violation("host_invalid", "URL host is not a valid domain name.") from exc
        labels = ascii_host.split(".")
        if len(ascii_host) > 253 or len(labels) < 2:
            raise _violation("host_invalid", "URL host must be a fully qualified domain name.")
        if not all(_HOST_LABEL.fullmatch(label) for label in labels):
            raise _violation("host_invalid", "URL host is not a valid domain name.")
        if _NUMERIC_LIKE_LABEL.fullmatch(labels[-1]):
            # Numeric/hex shorthand (``127.1``, ``2130706433``, ``0x7f.1``) would be
            # interpreted as an IP address by the system resolver.
            raise _violation("host_invalid", "Numeric host names are not allowed.")
        if ascii_host == "localhost" or ascii_host.endswith(_BLOCKED_SUFFIXES):
            raise _violation("domain_not_allowed", "The URL host is not allowed.")
        if _matches(ascii_host, self.blocked_domains):
            raise _violation("domain_not_allowed", "The URL host is blocked.")
        if self.allowed_domains is not None and not _matches(ascii_host, self.allowed_domains):
            raise _violation("domain_not_allowed", "The URL host is not in the allowlist.")
        return ascii_host, False


def _matches(host: str, domains: frozenset[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _rebuild(parts: SplitResult, scheme: str, host: str, port: int | None) -> str:
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def _violation(code: str, message: str) -> PolicyViolationError:
    return PolicyViolationError(message, code=code)

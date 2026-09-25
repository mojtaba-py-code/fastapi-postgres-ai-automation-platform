"""Sign-in risk: how unfamiliar a successful sign-in looks - without geolocation.

Three explainable signals, compared with the user's sign-ins of the last 90 days:

* ``new_device`` - the client (user agent) was not used before;
* ``new_network`` - the network was not used before: the IPv4 /24 or IPv6 /48,
  so a home router's new address or a colleague's desk is not "new";
* ``after_failures`` - wrong passwords (or a lockout) since the last success.

A sign-in with one novelty is *unfamiliar*: the user is told. A new device on a
new network, or a novelty right after repeated failures, is *suspicious*: it is
also audited as such, counted, and alerted on for operators. The first sign-in
of an account has nothing to compare with and is never flagged.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

# Wrong passwords since the last success that make the next success notable.
FAILURES_BEFORE_SUCCESS = 3
_IPV4_PREFIX = 24
_IPV6_PREFIX = 48


class LoginRisk(StrEnum):
    FAMILIAR = "familiar"
    UNFAMILIAR = "unfamiliar"
    SUSPICIOUS = "suspicious"


@dataclass(frozen=True, slots=True)
class LoginAssessment:
    risk: LoginRisk
    signals: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SignInDetails:
    """What a security e-mail tells the user about a sign-in.

    ``client`` is a coarse description derived from the user agent, never the
    header itself: a sender controls that text, and it must not be able to put
    words (or links) into an e-mail that comes from the platform.
    """

    at: datetime
    ip: str | None
    client: str


def assess_login(
    *,
    ip: str | None,
    user_agent: str | None,
    history: Sequence[tuple[str | None, str | None]],
    failed_attempts: int,
    lockouts: int,
) -> LoginAssessment:
    """Assess a successful sign-in against earlier ``(ip, user_agent)`` pairs."""
    signals: list[str] = []
    if history:
        if all(agent != user_agent for _, agent in history):
            signals.append("new_device")
        network = network_of(ip)
        if network is not None and all(network_of(seen) != network for seen, _ in history):
            signals.append("new_network")
    novel = bool(signals)
    after_failures = lockouts > 0 or failed_attempts >= FAILURES_BEFORE_SUCCESS
    if after_failures:
        signals.append("after_failures")
    if not novel:
        # The usual device and network: mistyped passwords are no reason to alarm.
        return LoginAssessment(LoginRisk.FAMILIAR, tuple(signals))
    suspicious = after_failures or {"new_device", "new_network"} <= set(signals)
    return LoginAssessment(
        LoginRisk.SUSPICIOUS if suspicious else LoginRisk.UNFAMILIAR, tuple(signals)
    )


def network_of(ip: str | None) -> str | None:
    """The /24 (IPv4) or /48 (IPv6) network of an address; ``None`` if it is not one."""
    if not ip:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    prefix = _IPV4_PREFIX if address.version == 4 else _IPV6_PREFIX
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


_BROWSERS = (  # order matters: Edge and Opera also say "Chrome", Chrome also says "Safari"
    ("Edg/", "Edge"),
    ("OPR/", "Opera"),
    ("Firefox/", "Firefox"),
    ("Chrome/", "Chrome"),
    ("Safari/", "Safari"),
    ("curl/", "curl"),
    ("python-", "a Python client"),
    ("PostmanRuntime/", "Postman"),
)
_SYSTEMS = (
    ("Windows", "Windows"),
    ("iPhone", "iOS"),
    ("iPad", "iPadOS"),
    ("Mac OS X", "macOS"),
    ("Android", "Android"),
    ("Linux", "Linux"),
)
_PRINTABLE = re.compile(r"^[\x20-\x7e]*$")


def describe_client(user_agent: str | None) -> str:
    """A coarse, fixed-vocabulary description of a user agent: "Firefox on Windows"."""
    if not user_agent or not _PRINTABLE.fullmatch(user_agent):
        return "an unrecognized client"
    browser = next((name for token, name in _BROWSERS if token in user_agent), None)
    system = next((name for token, name in _SYSTEMS if token in user_agent), None)
    if browser and system:
        return f"{browser} on {system}"
    return browser or (f"a client on {system}" if system else "an unrecognized client")


def sign_in_details(*, at: datetime, ip: str | None, user_agent: str | None) -> SignInDetails:
    address = None
    if ip:
        try:
            address = str(ipaddress.ip_address(ip))
        except ValueError:
            address = None
    return SignInDetails(at=at, ip=address, client=describe_client(user_agent))

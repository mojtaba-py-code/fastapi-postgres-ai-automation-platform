"""The organization network allowlist: what it accepts and what it lets in."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nexusflow.domain.organizations.model import OrganizationSettings


def _policy(*networks: str) -> OrganizationSettings:
    return OrganizationSettings(allowed_ip_ranges=list(networks))


def test_networks_are_normalised_deduplicated_and_ordered() -> None:
    policy = _policy(" 2001:db8::/32", "10.1.2.3/24", "203.0.113.7", "10.1.2.0/24")

    # Host bits are dropped, a bare address is a /32, IPv4 sorts before IPv6.
    assert policy.allowed_ip_ranges == ["10.1.2.0/24", "203.0.113.7/32", "2001:db8::/32"]


@pytest.mark.parametrize("networks", [[], None])
def test_no_list_means_every_network(networks: list[str] | None) -> None:
    policy = OrganizationSettings(allowed_ip_ranges=networks)

    assert policy.allowed_ip_ranges is None
    assert policy.allows_ip("198.51.100.20")
    assert policy.allows_ip(None)


@pytest.mark.parametrize(
    "bad", ["office", "10.0.0.0/33", "", "10.0.0.1-10.0.0.9", "999.1.1.1", "fe80::1%eth0/64"]
)
def test_malformed_networks_are_refused(bad: str) -> None:
    with pytest.raises(ValidationError, match="invalid network"):
        _policy(bad)


@pytest.mark.parametrize("everyone", ["0.0.0.0/0", "::/0", "1.2.3.4/0"])
def test_a_network_that_matches_everyone_is_refused(everyone: str) -> None:
    # An "allowlist" that lets the whole internet in is a mistake, not a policy.
    with pytest.raises(ValidationError, match="allow everyone"):
        _policy("10.0.0.0/8", everyone)


def test_the_list_is_bounded() -> None:
    with pytest.raises(ValidationError):
        _policy(*(f"10.0.{i}.0/24" for i in range(101)))
    assert len(_policy(*(f"10.0.{i}.0/24" for i in range(100))).allowed_ip_ranges or []) == 100


def test_addresses_inside_the_listed_networks_are_allowed() -> None:
    policy = _policy("203.0.113.0/24", "2001:db8:1::/48")

    assert policy.allows_ip("203.0.113.1")
    assert policy.allows_ip("203.0.113.254")
    assert policy.allows_ip("2001:db8:1:ffff::7")
    assert not policy.allows_ip("203.0.114.1")
    assert not policy.allows_ip("2001:db8:2::1")


def test_an_ipv4_client_seen_through_an_ipv6_socket_is_matched_as_ipv4() -> None:
    policy = _policy("203.0.113.0/24")

    assert policy.allows_ip("::ffff:203.0.113.9")
    assert not policy.allows_ip("::ffff:198.51.100.9")


def test_an_ipv4_network_written_in_ipv6_notation_is_stored_as_ipv4() -> None:
    # Copied from a log of an IPv6 socket: it must match IPv4 clients, not nothing.
    policy = _policy("::ffff:203.0.113.0/120", "::ffff:198.51.100.7")

    assert policy.allowed_ip_ranges == ["198.51.100.7/32", "203.0.113.0/24"]
    assert policy.allows_ip("203.0.113.9")
    assert policy.allows_ip("::ffff:198.51.100.7")
    with pytest.raises(ValidationError, match="allow everyone"):
        _policy("::ffff:0.0.0.0/96")  # all of IPv4


@pytest.mark.parametrize("unknown", [None, "", "unknown", "203.0.113.1, 10.0.0.1", "not-an-ip"])
def test_an_unknown_address_is_refused_once_a_list_exists(unknown: str | None) -> None:
    # Fails closed: a request whose origin cannot be established is not let in.
    assert not _policy("203.0.113.0/24").allows_ip(unknown)

"""Sign-in risk: familiar places stay quiet, new ones are reported, never in the sender's words."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from nexusflow.apps.workers.messages import SecurityEmailMessage
from nexusflow.domain.identity.login_risk import (
    FAILURES_BEFORE_SUCCESS,
    LoginRisk,
    assess_login,
    describe_client,
    network_of,
    sign_in_details,
)

HOME = ("203.0.113.10", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/130.0")
CHROME_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/129.0.0.0 Safari/537.36"
)
EDGE_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0"
)
SAFARI_IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15"
    " (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
)
CHROME_ANDROID = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/129.0.0.0 Mobile Safari/537.36"
)


def _assess(
    ip: str | None,
    agent: str | None,
    *,
    history: list[tuple[str | None, str | None]] | None = None,
    failed: int = 0,
    lockouts: int = 0,
) -> tuple[LoginRisk, tuple[str, ...]]:
    assessment = assess_login(
        ip=ip,
        user_agent=agent,
        history=[HOME] if history is None else history,
        failed_attempts=failed,
        lockouts=lockouts,
    )
    return assessment.risk, assessment.signals


class TestAssessment:
    def test_the_usual_device_and_network_is_familiar(self) -> None:
        assert _assess(*HOME) == (LoginRisk.FAMILIAR, ())

    def test_a_new_address_in_the_same_network_is_familiar(self) -> None:
        assert _assess("203.0.113.200", HOME[1]) == (LoginRisk.FAMILIAR, ())

    def test_one_novelty_is_unfamiliar(self) -> None:
        assert _assess(HOME[0], "curl/8.9.1") == (LoginRisk.UNFAMILIAR, ("new_device",))
        assert _assess("198.51.100.7", HOME[1]) == (LoginRisk.UNFAMILIAR, ("new_network",))

    def test_a_new_device_on_a_new_network_is_suspicious(self) -> None:
        assert _assess("198.51.100.7", "curl/8.9.1") == (
            LoginRisk.SUSPICIOUS,
            ("new_device", "new_network"),
        )

    def test_a_novelty_after_repeated_failures_is_suspicious(self) -> None:
        risk, signals = _assess("198.51.100.7", HOME[1], failed=FAILURES_BEFORE_SUCCESS)
        assert (risk, signals) == (LoginRisk.SUSPICIOUS, ("new_network", "after_failures"))
        assert _assess(HOME[0], "curl/8.9.1", lockouts=1)[0] is LoginRisk.SUSPICIOUS

    def test_mistyped_passwords_at_home_raise_no_alarm(self) -> None:
        risk, signals = _assess(*HOME, failed=FAILURES_BEFORE_SUCCESS + 1, lockouts=2)
        assert (risk, signals) == (LoginRisk.FAMILIAR, ("after_failures",))

    def test_a_few_failures_are_not_a_signal(self) -> None:
        assert _assess("198.51.100.7", HOME[1], failed=FAILURES_BEFORE_SUCCESS - 1) == (
            LoginRisk.UNFAMILIAR,
            ("new_network",),
        )

    def test_the_first_sign_in_has_nothing_to_compare_with(self) -> None:
        assert _assess("198.51.100.7", "curl/8.9.1", history=[]) == (LoginRisk.FAMILIAR, ())

    def test_an_unknown_address_is_not_called_new(self) -> None:
        assert _assess(None, HOME[1]) == (LoginRisk.FAMILIAR, ())
        assert _assess("not-an-ip", HOME[1]) == (LoginRisk.FAMILIAR, ())

    def test_any_earlier_sign_in_makes_a_place_familiar(self) -> None:
        history = [HOME, ("2001:db8:aaaa:1::5", "curl/8.9.1")]
        assert _assess("2001:db8:aaaa:ffff::9", "curl/8.9.1", history=history) == (
            LoginRisk.FAMILIAR,
            (),
        )


class TestNetworks:
    @pytest.mark.parametrize(
        ("ip", "network"),
        [
            ("203.0.113.10", "203.0.113.0/24"),
            ("2001:db8:1234:5678::1", "2001:db8:1234::/48"),
            ("::ffff:203.0.113.10", "203.0.113.0/24"),  # IPv4-mapped: the same network
            ("", None),
            (None, None),
            ("300.1.1.1", None),
        ],
    )
    def test_addresses_map_to_their_network(self, ip: str | None, network: str | None) -> None:
        assert network_of(ip) == network


class TestClientDescription:
    @pytest.mark.parametrize(
        ("agent", "description"),
        [
            (
                CHROME_WINDOWS,
                "Chrome on Windows",
            ),
            (
                EDGE_WINDOWS,
                "Edge on Windows",
            ),
            (
                SAFARI_IPHONE,
                "Safari on iOS",
            ),
            (
                CHROME_ANDROID,
                "Chrome on Android",
            ),
            ("Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko Firefox/130.0", "Firefox on Linux"),
            ("curl/8.9.1", "curl"),
            ("python-httpx/0.27.0", "a Python client"),
            ("SomethingElse/1.0 (Macintosh; Intel Mac OS X 14_6)", "a client on macOS"),
            ("", "an unrecognized client"),
            (None, "an unrecognized client"),
            ("Firefox/130.0\r\nBcc: victim@example.com", "an unrecognized client"),
        ],
    )
    def test_agents_are_described_in_a_fixed_vocabulary(
        self, agent: str | None, description: str
    ) -> None:
        assert describe_client(agent) == description

    def test_the_senders_own_words_never_reach_the_description(self) -> None:
        sneaky = "Firefox/130.0 (Windows) URGENT: verify your account at https://evil.example"
        details = sign_in_details(at=datetime(2026, 9, 25, tzinfo=UTC), ip="bad", user_agent=sneaky)
        assert details.client == "Firefox on Windows"
        assert details.ip is None


class TestSecurityEmailMessage:
    def test_the_queued_payload_is_accepted_by_the_mail_worker(self) -> None:
        details = sign_in_details(
            at=datetime(2026, 9, 25, 8, 30, tzinfo=UTC), ip="198.51.100.5", user_agent="curl/8.9.1"
        )
        message = SecurityEmailMessage.model_validate(
            {
                "user_id": "0192f0c1-7a2b-7c3d-8e4f-5a6b7c8d9e0f",
                "template": "suspicious_login",
                "sign_in": {
                    "at": details.at.isoformat(),
                    "ip": details.ip,
                    "client": details.client,
                },
            }
        )
        assert message.sign_in is not None
        assert str(message.sign_in.ip) == "198.51.100.5"

    @pytest.mark.parametrize(
        "sign_in",
        [
            {"at": "2026-09-25T08:30:00+00:00", "ip": "198.51.100.5", "client": "see https://x"},
            {"at": "2026-09-25T08:30:00+00:00", "ip": "not-an-ip", "client": "curl"},
            {"at": "2026-09-25T08:30:00", "ip": None, "client": "curl"},  # naive time
            {"at": "2026-09-25T08:30:00+00:00", "client": "curl", "extra": "x"},
        ],
    )
    def test_anything_else_is_rejected(self, sign_in: dict[str, object]) -> None:
        with pytest.raises(ValidationError):
            SecurityEmailMessage.model_validate(
                {
                    "user_id": "0192f0c1-7a2b-7c3d-8e4f-5a6b7c8d9e0f",
                    "template": "suspicious_login",
                    "sign_in": sign_in,
                }
            )

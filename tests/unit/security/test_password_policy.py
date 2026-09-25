"""Password policy (NIST SP 800-63B): length, breached passwords, own identifiers."""

from __future__ import annotations

import pytest

from nexusflow.core.errors import InvalidInputError
from nexusflow.domain.identity.password_policy import PasswordPolicy, breached_passwords

POLICY = PasswordPolicy()


def _problems(password: str) -> list[str]:
    return POLICY.problems(password, email="jane.doe@acme.example", name="Jane Doe")


class TestBreachedPasswords:
    def test_the_list_is_loaded_and_only_holds_passwords_long_enough_to_matter(self) -> None:
        words = breached_passwords()
        assert len(words) > 70_000
        assert all(len(word) >= POLICY.min_length for word in list(words)[:5000])
        assert all(word == word.lower() for word in list(words)[:5000])

    @pytest.mark.parametrize(
        "password",
        ["1q2w3e4r5t6y7u", "iloveyou12345", "ILOVEYOU12345", "qwertyuiop123", "password1234"],
    )
    def test_breached_passwords_are_refused_in_any_case(self, password: str) -> None:
        assert any("breached" in p for p in _problems(password))

    def test_the_first_use_loads_the_list_once(self) -> None:
        assert breached_passwords() is breached_passwords()


class TestOtherRules:
    @pytest.mark.parametrize(
        "password",
        [
            "Str0ng-and-unique-passphrase!",
            "correct horse battery staple, but mine",
            "Ümlaut-Päss-2026",
        ],
    )
    def test_long_uncommon_passwords_pass(self, password: str) -> None:
        assert _problems(password) == []

    @pytest.mark.parametrize(
        ("password", "fragment"),
        [
            ("short-1A!", "at least 12"),
            ("x" * 129, "at most 128"),
            ("abababababababab", "varied"),
            ("jane.doe-rocks-2026", "name or email"),
            ("Jane-family-vault-2026", "name or email"),  # parts of 4+ characters
        ],
    )
    def test_each_rule_explains_itself(self, password: str, fragment: str) -> None:
        assert any(fragment in problem for problem in _problems(password))

    def test_validation_reports_every_problem_at_once(self) -> None:
        with pytest.raises(InvalidInputError) as exc:
            POLICY.validate("jane", email="jane@acme.example", name="Jane")
        assert exc.value.code == "weak_password"
        assert len(exc.value.details or []) >= 2

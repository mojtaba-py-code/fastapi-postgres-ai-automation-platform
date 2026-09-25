"""Password policy (NIST SP 800-63B style).

Length-based with a deny-list instead of composition rules: minimum length,
maximum length (bounds Argon2 work per request), rejection of well-known
passwords and of passwords derived from the account's own identifiers.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from nexusflow.core.errors import ErrorDetail, InvalidInputError

_COMMON_PASSWORDS = frozenset(
    {
        "123456789012",
        "1234567890123",
        "password1234",
        "password12345",
        "passw0rd1234",
        "qwertyuiop12",
        "qwerty123456",
        "iloveyou1234",
        "letmein12345",
        "welcome12345",
        "administrator",
        "admin1234567",
        "changeme1234",
        "football1234",
        "baseball1234",
        "sunshine1234",
        "princess1234",
        "superman1234",
        "trustno11234",
        "starwars1234",
        "monkey123456",
        "dragon123456",
        "master123456",
        "abc123456789",
        "p@ssw0rd1234",
        "p@ssword1234",
        "qwerty12345678",
        "1q2w3e4r5t6y",
        "zaq12wsxcde3",
        "aaaaaaaaaaaa",
        "111111111111",
        "000000000000",
        "121212121212",
        "password!234",
        "correcthorse",
        "correcthorsebatterystaple",
        "nexusflow1234",
        "nexusflowai12",
        "summer2026!!",
        "winter2026!!",
        "spring2026!!",
        "autumn2026!!",
        "welcome2026!",
        "password2026",
    }
)


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    min_length: int = 12
    max_length: int = 128

    def validate(self, password: str, *, email: str | None = None, name: str | None = None) -> None:
        problems = self.problems(password, email=email, name=name)
        if problems:
            raise InvalidInputError(
                "The password does not meet the security policy.",
                code="weak_password",
                details=[
                    ErrorDetail(message=p, code="weak_password", field="password") for p in problems
                ],
            )

    def problems(self, password: str, *, email: str | None, name: str | None) -> list[str]:
        normalized = unicodedata.normalize("NFKC", password)
        problems: list[str] = []
        if len(normalized) < self.min_length:
            problems.append(f"Use at least {self.min_length} characters.")
        if len(normalized) > self.max_length:
            problems.append(f"Use at most {self.max_length} characters.")
        lowered = normalized.lower()
        if lowered in _COMMON_PASSWORDS:
            problems.append("This password is too common.")
        if len(set(normalized)) <= 3:
            problems.append("Use more varied characters.")
        for identifier in _identifiers(email, name):
            if len(identifier) >= 4 and identifier in lowered:
                problems.append("The password must not contain your name or email address.")
                break
        return problems


def _identifiers(email: str | None, name: str | None) -> list[str]:
    parts: list[str] = []
    if email:
        local = email.split("@", 1)[0].lower()
        parts.append(local)
        parts.extend(p for p in local.replace("_", ".").replace("-", ".").split(".") if p)
    if name:
        parts.extend(p.lower() for p in name.split() if p)
    return parts

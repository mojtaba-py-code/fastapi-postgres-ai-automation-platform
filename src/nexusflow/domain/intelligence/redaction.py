"""Remove sensitive data before anything is sent to an AI provider.

Two layers: fields the dataset schema marks ``sensitive`` are dropped entirely,
and free text is scrubbed of common personal data and credential formats.
Redaction is conservative - false positives cost a little context, false
negatives could leak data to a third party.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("api_key", re.compile(r"\b(?:sk|pk|rk|xox[abposr]|ghp|gho|nxf|nxs)[-_][A-Za-z0-9_-]{16,}\b")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b")),
    ("card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    # International (+CC ...) or area-code-in-parentheses formats only, so that
    # dates and version numbers are not mistaken for phone numbers.
    (
        "phone",
        re.compile(
            r"(?<![\w.])(?:\+\d{1,3}[\s.-]?|\(\d{2,4}\)\s?)\d{2,4}(?:[\s.-]?\d{2,4}){1,4}(?![\w.])"
        ),
    ),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
)


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def redact_text(text: str) -> tuple[str, int]:
    """Return ``(redacted_text, number_of_redactions)``."""
    count = 0

    def replace(label: str) -> Any:
        def _sub(match: re.Match[str]) -> str:
            nonlocal count
            if label == "card":
                digits = re.sub(r"\D", "", match.group(0))
                if not 13 <= len(digits) <= 19 or not _luhn_valid(digits):
                    return match.group(0)
            count += 1
            return f"[REDACTED:{label}]"

        return _sub

    for label, pattern in _PATTERNS:
        text = pattern.sub(replace(label), text)
    return text, count


def redact_value(value: Any) -> tuple[Any, int]:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        total = 0
        result = {}
        for key, item in value.items():
            result[key], found = redact_value(item)
            total += found
        return result, total
    if isinstance(value, list):
        total = 0
        items = []
        for item in value:
            redacted, found = redact_value(item)
            items.append(redacted)
            total += found
        return items, total
    return value, 0


def strip_sensitive(data: Mapping[str, Any], sensitive: frozenset[str]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if key not in sensitive}

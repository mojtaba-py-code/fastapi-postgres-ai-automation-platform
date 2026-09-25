"""Text hygiene helpers shared by every layer that handles untrusted strings.

These functions *normalize* data; they are not a substitute for context-aware
output encoding (HTML escaping, SQL parameters, etc.), which happens at the
boundary where data is rendered.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import quote

from nexusflow.core.errors import InvalidInputError

# C0/C1 control characters, excluding TAB (\x09) and LF (\x0a) which multi-line
# fields may keep.
_CONTROL_CHARS_MULTILINE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_CONTROL_CHARS_SINGLE_LINE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# Zero-width characters and bidirectional overrides ("Trojan Source" style
# spoofing) are removed from all persisted text.
_INVISIBLE_CHARS = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
_WHITESPACE_RUN = re.compile(r"[ \t\u00a0\u2000-\u200a\u3000]+")
_BLANK_LINES = re.compile(r"\n{3,}")

# Characters that make spreadsheet applications interpret a cell as a formula
# (OWASP "CSV injection"). Full-width variants are included because some
# spreadsheet engines normalize them.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\uff1d", "\uff0b", "\uff0d", "\uff20")


def clean_text(value: str, *, max_length: int, multiline: bool = False) -> str:
    """Normalize untrusted text for storage.

    NFKC-normalizes, strips control and invisible characters, collapses
    whitespace and truncates to ``max_length`` characters.
    """
    text = unicodedata.normalize("NFKC", value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _INVISIBLE_CHARS.sub("", text)
    if multiline:
        text = _CONTROL_CHARS_MULTILINE.sub("", text)
        lines = [_WHITESPACE_RUN.sub(" ", line).strip() for line in text.split("\n")]
        text = _BLANK_LINES.sub("\n\n", "\n".join(lines)).strip()
    else:
        text = _CONTROL_CHARS_SINGLE_LINE.sub(" ", text)
        text = _WHITESPACE_RUN.sub(" ", text).strip()
    return truncate(text, max_length)


def truncate(value: str, max_length: int, *, suffix: str = "…") -> str:
    if max_length <= 0:
        return ""
    if len(value) <= max_length:
        return value
    return value[: max(0, max_length - len(suffix))] + suffix


def single_line(value: str, max_length: int = 200) -> str:
    """Make a value safe to embed in a single log line or header-like context."""
    return clean_text(value, max_length=max_length, multiline=False)


def spreadsheet_safe(value: str) -> str:
    """Neutralize spreadsheet formula injection by prefixing a single quote."""
    if value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def content_disposition(filename: str) -> str:
    """Build an ``attachment`` Content-Disposition header value.

    Emits an ASCII-only fallback plus an RFC 5987 ``filename*`` parameter so
    that quotes, CR/LF and non-ASCII characters can never break the header.
    """
    normalized = clean_text(filename, max_length=150) or "download"
    ascii_fallback = "".join(
        ch if ch.isascii() and (ch.isalnum() or ch in "._- ") else "_" for ch in normalized
    )
    ascii_fallback = ascii_fallback.strip(" .") or "download"
    encoded = quote(normalized, safe="")
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{encoded}"


def mask_secret(value: str, *, visible: int = 4) -> str:
    """Return a non-reversible hint of a secret (last ``visible`` characters)."""
    if len(value) <= visible * 2:
        return "•" * 8
    return "•" * 8 + value[-visible:]


def mask_email(value: str) -> str:
    local, sep, domain = value.partition("@")
    if not sep:
        return "***"
    head = local[:1] if local else ""
    return f"{head}***@{domain}"


def slugify(value: str, *, max_length: int = 63) -> str:
    """ASCII slug made of ``[a-z0-9-]``; used for organization slugs."""
    ascii_value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_value.lower()).strip("-")
    return slug[:max_length].strip("-")


def required_name(value: str, *, max_length: int = 120) -> str:
    """A cleaned display name; ``422 name_required`` when nothing is left of it."""
    cleaned = clean_text(value, max_length=max_length)
    if not cleaned:
        raise InvalidInputError("A name is required.", code="name_required")
    return cleaned

"""Format of machine credentials (tenant API keys and platform service tokens).

    nxf_<prefix>_<secret><checksum>    tenant API key
    nxs_<prefix>_<secret><checksum>    platform service token (n8n workflows)

* ``prefix`` (12 chars, lowercase base32) is a non-secret lookup handle.
* ``secret`` is 32 bytes from the CSPRNG (43 url-safe chars) - only its keyed
  hash is stored.
* ``checksum`` is a 6-char CRC32 of the preceding text. It lets us reject typos
  and random garbage *before* touching the database, and gives secret scanners
  (gitleaks rule in ``.gitleaks.toml``) a high-precision pattern.
"""

from __future__ import annotations

import base64
import re
import secrets
import zlib
from dataclasses import dataclass
from enum import StrEnum

_PREFIX_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
_PREFIX_LENGTH = 12
_CHECKSUM_LENGTH = 6
_PATTERN = re.compile(r"^(nxf|nxs)_([a-z2-7]{12})_([A-Za-z0-9_-]{43})([A-Za-z0-9_-]{6})$")
_MAX_LENGTH = 80


class CredentialKind(StrEnum):
    API_KEY = "nxf"
    SERVICE_TOKEN = "nxs"  # noqa: S105 - a token *type prefix*, not a secret  # nosec B105


@dataclass(frozen=True, slots=True)
class ParsedCredential:
    kind: CredentialKind
    prefix: str
    full_token: str


@dataclass(frozen=True, slots=True)
class GeneratedCredential:
    kind: CredentialKind
    prefix: str
    token: str


def _checksum(text: str) -> str:
    crc = zlib.crc32(text.encode("ascii")).to_bytes(4, "big")
    return (
        base64.urlsafe_b64encode(crc)
        .decode("ascii")
        .rstrip("=")[:_CHECKSUM_LENGTH]
        .ljust(_CHECKSUM_LENGTH, "A")
    )


def generate_credential(kind: CredentialKind) -> GeneratedCredential:
    prefix = "".join(secrets.choice(_PREFIX_ALPHABET) for _ in range(_PREFIX_LENGTH))
    secret = secrets.token_urlsafe(32)
    body = f"{kind.value}_{prefix}_{secret}"
    return GeneratedCredential(kind=kind, prefix=prefix, token=body + _checksum(body))


def looks_like_credential(token: str) -> bool:
    return token.startswith(("nxf_", "nxs_"))


def parse_credential(token: str) -> ParsedCredential | None:
    """Validate format and checksum; returns ``None`` for anything malformed."""
    if len(token) > _MAX_LENGTH:
        return None
    match = _PATTERN.fullmatch(token)
    if match is None:
        return None
    kind_raw, prefix, secret, checksum = match.groups()
    body = f"{kind_raw}_{prefix}_{secret}"
    if not secrets.compare_digest(_checksum(body), checksum):
        return None
    return ParsedCredential(kind=CredentialKind(kind_raw), prefix=prefix, full_token=token)

"""Keyed hashing and secure random token generation."""

from __future__ import annotations

import hashlib
import hmac
import secrets


class HmacTokenHasher:
    """HMAC-SHA256 with a server-side pepper; outputs lowercase hex."""

    def __init__(self, pepper: bytes) -> None:
        if len(pepper) < 32:
            raise ValueError("HMAC pepper must be at least 32 bytes")
        self._pepper = pepper

    def hash(self, token: str) -> str:
        return hmac.new(self._pepper, token.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify(self, token: str, expected_hash: str) -> bool:
        return hmac.compare_digest(self.hash(token), expected_hash)


class SecureTokenGenerator:
    """URL-safe tokens from the OS CSPRNG (``secrets``)."""

    def generate(self, nbytes: int = 32) -> str:
        if nbytes < 16:
            raise ValueError("tokens must carry at least 128 bits of entropy")
        return secrets.token_urlsafe(nbytes)

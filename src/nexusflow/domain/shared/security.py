"""Security ports shared by several bounded contexts.

The domain depends only on these protocols; concrete implementations
(Argon2id, AES-GCM, HMAC-SHA256, Ed25519 JWT) live in
``nexusflow.infrastructure.security`` and are wired in the composition root.
"""

from __future__ import annotations

from typing import Protocol


class PasswordHasher(Protocol):
    async def hash(self, password: str) -> str: ...

    async def verify(self, password_hash: str, password: str) -> bool: ...

    def needs_rehash(self, password_hash: str) -> bool: ...

    async def dummy_verify(self, password: str) -> None:
        """Burn the same CPU/memory as a real verification (anti user-enumeration)."""
        ...


class SecretCipher(Protocol):
    """Authenticated encryption for secrets at rest.

    ``context`` is bound as associated data: a ciphertext produced for one
    record/tenant/purpose cannot be decrypted in another context, which prevents
    ciphertext-swapping attacks between rows or organizations.
    """

    def encrypt(self, plaintext: str, *, context: str) -> bytes: ...

    def decrypt(self, blob: bytes, *, context: str) -> str: ...

    def needs_rewrap(self, blob: bytes) -> bool: ...

    def rewrap(self, blob: bytes, *, context: str) -> bytes: ...

    def key_id_of(self, blob: bytes) -> str: ...


class TokenHasher(Protocol):
    """Keyed one-way hashing (HMAC-SHA256 with a server-side pepper).

    Used for high-entropy opaque tokens (refresh tokens, API keys, reset and
    invitation tokens, MFA recovery codes). A database leak alone does not allow
    an attacker to verify candidate tokens without the pepper.
    """

    def hash(self, token: str) -> str: ...

    def verify(self, token: str, expected_hash: str) -> bool: ...


class TokenGenerator(Protocol):
    def generate(self, nbytes: int = 32) -> str: ...

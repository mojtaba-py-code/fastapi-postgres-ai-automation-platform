"""Argon2id password hashing.

Argon2id is memory-hard, so every verification allocates ``memory_cost`` KiB.
Hashing runs in a worker thread (never on the event loop) behind a semaphore
that caps concurrent hashes - otherwise a burst of login attempts could exhaust
memory (a cheap denial-of-service against password endpoints).
"""

from __future__ import annotations

import asyncio

from argon2 import PasswordHasher as _Argon2Hasher
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


class Argon2idPasswordHasher:
    def __init__(
        self,
        *,
        time_cost: int,
        memory_cost_kib: int,
        parallelism: int,
        max_concurrency: int = 8,
    ) -> None:
        self._hasher = _Argon2Hasher(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self._semaphore = asyncio.Semaphore(max_concurrency)
        # A real hash of a random value, verified against when the account does
        # not exist so that response timing does not reveal account existence.
        self._dummy_hash = self._hasher.hash("nexusflow-dummy-password-for-timing")

    async def hash(self, password: str) -> str:
        async with self._semaphore:
            return await asyncio.to_thread(self._hasher.hash, password)

    async def verify(self, password_hash: str, password: str) -> bool:
        async with self._semaphore:
            return await asyncio.to_thread(self._verify_sync, password_hash, password)

    def needs_rehash(self, password_hash: str) -> bool:
        try:
            return self._hasher.check_needs_rehash(password_hash)
        except InvalidHashError:
            return True

    async def dummy_verify(self, password: str) -> None:
        await self.verify(self._dummy_hash, password)

    def _verify_sync(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

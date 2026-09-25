"""Infrastructure ports used by several services (storage, scanning, nonces)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True, slots=True)
class StoredFile:
    key: str
    size: int
    sha256: str


class FileStorage(Protocol):
    """Object storage addressed by server-generated keys only."""

    async def save(
        self, key: str, chunks: AsyncIterator[bytes], *, max_bytes: int
    ) -> StoredFile: ...

    async def save_bytes(self, key: str, data: bytes) -> StoredFile: ...

    def local_path(self, key: str) -> Path: ...

    def stream(self, key: str, *, chunk_size: int = 64 * 1024) -> AsyncIterator[bytes]: ...

    async def delete(self, key: str) -> None: ...

    async def exists(self, key: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class ScanVerdict:
    clean: bool
    signature: str | None = None


class MalwareScanner(Protocol):
    async def scan(self, path: Path) -> ScanVerdict: ...


class NonceStore(Protocol):
    async def first_use(self, namespace: str, nonce: str, *, ttl_seconds: int) -> bool: ...

    async def release(self, namespace: str, nonce: str) -> None:
        """Forget a nonce whose request failed, so the sender can retry it."""
        ...

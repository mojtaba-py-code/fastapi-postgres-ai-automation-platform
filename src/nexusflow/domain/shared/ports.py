"""Infrastructure ports used by several services (storage, scanning, nonces)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True)
class StoredFile:
    key: str
    size: int
    sha256: str


class FileStorage(Protocol):
    """Object storage addressed by server-generated keys only.

    Files may be encrypted at rest: ``stream`` always yields plaintext, and
    ``plaintext`` provides a private, temporary plaintext copy for tools that
    need a path (content inspection, malware scanning).
    """

    async def save(
        self, key: str, chunks: AsyncIterator[bytes], *, max_bytes: int
    ) -> StoredFile: ...

    async def save_bytes(self, key: str, data: bytes) -> StoredFile: ...

    def local_path(self, key: str) -> Path:
        """Where the stored bytes are (encrypted when sealing is on)."""
        ...

    def plaintext(self, key: str) -> AbstractAsyncContextManager[Path]:
        """A private plaintext copy of a stored file, removed on exit."""
        ...

    async def purge_scratch(self) -> int:
        """Remove plaintext copies a killed process left behind; returns how many."""
        ...

    def stream(self, key: str, *, chunk_size: int = 64 * 1024) -> AsyncIterator[bytes]: ...

    async def rewrap(self, org_id: UUID, *, limit: int) -> int:
        """Key rotation: re-wrap the keys of up to ``limit`` of a tenant's files."""
        ...

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

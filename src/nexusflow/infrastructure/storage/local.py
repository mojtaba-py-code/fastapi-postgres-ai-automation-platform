"""Local filesystem object storage with traversal-proof keys.

* Keys are validated against a strict pattern (``uploads|reports/<uuid>/<uuid>.<ext>``)
  and the resolved path must stay inside the storage root - user input never
  reaches a filesystem path.
* Writes go to a temporary file in the same directory and are atomically
  renamed, so readers never observe partial files.
* Files are created ``0600`` (and directories ``0700``) and are never executed.
* Size limits are enforced while streaming, not from ``Content-Length``.

Swap for an S3-compatible implementation of the same port in cloud deployments.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import secrets
from collections.abc import AsyncIterator
from pathlib import Path

from nexusflow.core.errors import InvalidInputError, PayloadTooLargeError
from nexusflow.domain.shared.ports import StoredFile

_KEY = re.compile(
    r"^(uploads|reports)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(csv|xlsx|json|pdf)$"
)


class LocalFileStorage:
    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    def local_path(self, key: str) -> Path:
        if not _KEY.fullmatch(key):
            raise InvalidInputError("Invalid storage key.", code="invalid_storage_key")
        path = (self._root / key).resolve()
        if not path.is_relative_to(self._root):
            raise InvalidInputError("Invalid storage key.", code="invalid_storage_key")
        return path

    async def save(self, key: str, chunks: AsyncIterator[bytes], *, max_bytes: int) -> StoredFile:
        path = self.local_path(key)
        await asyncio.to_thread(self._prepare_dir, path.parent)
        temp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.part")
        digest = hashlib.sha256()
        size = 0
        fd = await asyncio.to_thread(os.open, temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                async for chunk in chunks:
                    size += len(chunk)
                    if size > max_bytes:
                        raise PayloadTooLargeError()
                    digest.update(chunk)
                    await asyncio.to_thread(handle.write, chunk)
            await asyncio.to_thread(os.replace, temp, path)
        except BaseException:
            await asyncio.to_thread(temp.unlink, missing_ok=True)
            raise
        return StoredFile(key=key, size=size, sha256=digest.hexdigest())

    async def save_bytes(self, key: str, data: bytes) -> StoredFile:
        async def once() -> AsyncIterator[bytes]:
            yield data

        return await self.save(key, once(), max_bytes=len(data))

    async def stream(self, key: str, *, chunk_size: int = 64 * 1024) -> AsyncIterator[bytes]:
        path = self.local_path(key)
        handle = await asyncio.to_thread(path.open, "rb")
        try:
            while chunk := await asyncio.to_thread(handle.read, chunk_size):
                yield chunk
        finally:
            await asyncio.to_thread(handle.close)

    async def delete(self, key: str) -> None:
        path = self.local_path(key)
        await asyncio.to_thread(path.unlink, missing_ok=True)

    async def exists(self, key: str) -> bool:
        return await asyncio.to_thread(self.local_path(key).is_file)

    @staticmethod
    def _prepare_dir(directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)

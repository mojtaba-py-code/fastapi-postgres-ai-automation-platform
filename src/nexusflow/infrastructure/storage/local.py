"""Local filesystem object storage with traversal-proof keys.

* Keys are validated against a strict pattern (``uploads|reports/<uuid>/<uuid>.<ext>``)
  and the resolved path must stay inside the storage root - user input never
  reaches a filesystem path.
* Writes go to a temporary file in the same directory and are atomically
  renamed, so readers never observe partial files.
* Files are created ``0600`` (and directories ``0700``) and are never executed.
* Size limits are enforced while streaming, not from ``Content-Length``.
* With a ``FileSealer`` every file is encrypted at rest (streaming AES-256-GCM,
  ``infrastructure.security.files``); size and SHA-256 describe the plaintext.
  A file without the sealed header is refused (fail closed): no release ever
  stored files unencrypted, so such a file was put there by someone else.
* Plaintext copies for inspection live in ``.scratch`` only while they are
  used; copies a killed process left behind are purged at start-up and by the
  retention job (:meth:`LocalFileStorage.purge_scratch`).

Swap for an S3-compatible implementation of the same port in cloud deployments.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import secrets
import shutil
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from uuid import UUID

from nexusflow.core.errors import InvalidInputError, PayloadTooLargeError
from nexusflow.domain.shared.ports import StoredFile
from nexusflow.infrastructure.security.crypto import DecryptionError
from nexusflow.infrastructure.security.files import MAGIC, FileSealer

_KEY = re.compile(
    r"^(uploads|reports)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(csv|xlsx|json|pdf)$"
)
SCRATCH_MAX_AGE = timedelta(hours=1)


class LocalFileStorage:
    def __init__(self, root: Path, sealer: FileSealer | None = None) -> None:
        self._root = root.resolve()
        self._sealer = sealer
        self._scratch = self._root / ".scratch"

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
        encryptor = self._sealer.encryptor(key) if self._sealer is not None else None
        try:
            with os.fdopen(fd, "wb") as handle:
                if encryptor is not None:
                    await asyncio.to_thread(handle.write, encryptor.header)
                async for chunk in chunks:
                    size += len(chunk)
                    if size > max_bytes:
                        raise PayloadTooLargeError()
                    digest.update(chunk)
                    out = encryptor.update(chunk) if encryptor is not None else chunk
                    if out:
                        await asyncio.to_thread(handle.write, out)
                if encryptor is not None:
                    await asyncio.to_thread(handle.write, encryptor.finalize())
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
            head = await asyncio.to_thread(handle.read, len(MAGIC))
            if head == MAGIC:
                if self._sealer is None:
                    raise DecryptionError(internal_detail="sealed file, but no file sealer")
                decryptor = await asyncio.to_thread(self._sealer.decryptor, key, handle.read)
                while (plain := await asyncio.to_thread(decryptor.next_chunk)) is not None:
                    if plain:
                        yield plain
                return
            if self._sealer is not None:
                # Fail closed: a planted or swapped plaintext file is never served.
                raise DecryptionError(internal_detail="stored file is not sealed")
            if head:
                yield head
            while chunk := await asyncio.to_thread(handle.read, chunk_size):
                yield chunk
        finally:
            await asyncio.to_thread(handle.close)

    @asynccontextmanager
    async def plaintext(self, key: str) -> AsyncIterator[Path]:
        """A private (0600) plaintext copy under ``.scratch``, removed on exit."""
        self.local_path(key)  # validates the key
        scratch = self._scratch
        await asyncio.to_thread(self._prepare_dir, scratch)
        temp = scratch / f"{secrets.token_hex(16)}{Path(key).suffix}"
        fd = await asyncio.to_thread(os.open, temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                async for chunk in self.stream(key):
                    await asyncio.to_thread(handle.write, chunk)
            yield temp
        finally:
            await asyncio.to_thread(temp.unlink, missing_ok=True)

    async def purge_scratch(self, *, older_than: timedelta = SCRATCH_MAX_AGE) -> int:
        """Remove plaintext copies older than ``older_than`` - left behind by a
        process killed while it inspected a file. Copies in use are younger:
        inspection and scanning take seconds, never an hour."""
        return await asyncio.to_thread(_remove_older_than, self._scratch, older_than)

    async def rewrap(self, org_id: UUID, *, limit: int) -> int:
        """Re-wrap the file keys of up to ``limit`` of a tenant's files under the
        active KEK. Only the header changes: the data key, and so every chunk, stay."""
        sealer = self._sealer
        if sealer is None:
            return 0
        rewrapped = 0
        for area in ("uploads", "reports"):
            directory = self._root / area / str(org_id)
            for path in await asyncio.to_thread(_files_in, directory):
                key = f"{area}/{org_id}/{path.name}"
                if not _KEY.fullmatch(key):
                    continue  # temporary .part files and anything unexpected
                if await asyncio.to_thread(self._rewrap_file, sealer, key, path):
                    rewrapped += 1
                    if rewrapped >= limit:
                        return rewrapped
        return rewrapped

    @staticmethod
    def _rewrap_file(sealer: FileSealer, key: str, path: Path) -> bool:
        with path.open("rb") as handle:
            if handle.read(len(MAGIC)) != MAGIC:
                return False
            wrapped = handle.read(int.from_bytes(handle.read(2), "big"))
            header = sealer.rewrap_header(key, wrapped)
            if header is None:
                return False
            temp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.part")
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as out:
                    out.write(MAGIC + len(header).to_bytes(2, "big") + header)
                    shutil.copyfileobj(handle, out)
            except BaseException:
                temp.unlink(missing_ok=True)
                raise
        temp.replace(path)
        return True

    async def delete(self, key: str) -> None:
        path = self.local_path(key)
        await asyncio.to_thread(path.unlink, missing_ok=True)

    async def exists(self, key: str) -> bool:
        return await asyncio.to_thread(self.local_path(key).is_file)

    @staticmethod
    def _prepare_dir(directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)


def _files_in(directory: Path) -> list[Path]:
    return sorted(p for p in directory.iterdir() if p.is_file()) if directory.is_dir() else []


def _remove_older_than(directory: Path, age: timedelta) -> int:
    cutoff = time.time() - age.total_seconds()
    removed = 0
    for path in _files_in(directory):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except FileNotFoundError:
            continue  # removed meanwhile by its owner
    return removed

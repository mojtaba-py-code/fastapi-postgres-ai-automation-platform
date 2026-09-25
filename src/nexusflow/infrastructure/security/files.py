"""Streaming authenticated encryption for stored files (uploads, reports).

A file is cut into 64 KiB chunks, each sealed with AES-256-GCM under a fresh
per-file data key. The nonce of chunk *i* is ``prefix (7 bytes) || i (4 bytes)
|| last (1 byte)``, the STREAM construction (Hoang, Reyhanitabar, Rogaway and
Vizar, 2015): chunks cannot be reordered, dropped or appended, and a file cut at
a chunk boundary fails, because its new final chunk was not sealed as final.

The data key and nonce prefix are wrapped by the platform's envelope cipher
(the rotatable KEK keyring) and bound to the file's storage key, so a file
copied under another key does not open. Key rotation re-wraps only the header;
the chunks, sealed under the unchanged data key, stay as they are.

Layout::

    b"NFE1" | u16 length | wrapped key | chunk 0 | chunk 1 | ... | final chunk
    (each chunk: ciphertext followed by its 16-byte tag; the final one may be empty)
"""

from __future__ import annotations

import base64
import binascii
import os
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from nexusflow.domain.shared.security import SecretCipher
from nexusflow.infrastructure.security.crypto import DecryptionError

MAGIC = b"NFE1"
CHUNK = 64 * 1024
TAG = 16
_KEY_BYTES = 32
_PREFIX_BYTES = 7
_AAD = b"nexusflow-file-v1"
_MAX_COUNTER = 2**32 - 1


def _context(storage_key: str) -> str:
    return f"file:v1:{storage_key}"


def _nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if counter > _MAX_COUNTER:
        raise DecryptionError(internal_detail="file too large for its chunk counter")
    return prefix + counter.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


@dataclass(frozen=True, slots=True)
class _FileKey:
    aead: AESGCM
    prefix: bytes


class FileSealer:
    """Seals and opens stored files; one per platform, sharing the KEK keyring."""

    def __init__(self, cipher: SecretCipher) -> None:
        self._cipher = cipher

    # ---------------------------------------------------------------- sealing

    def encryptor(self, storage_key: str) -> FileEncryptor:
        dek = AESGCM.generate_key(bit_length=256)
        prefix = os.urandom(_PREFIX_BYTES)
        wrapped = self._cipher.encrypt(
            base64.b64encode(dek + prefix).decode("ascii"), context=_context(storage_key)
        )
        header = MAGIC + len(wrapped).to_bytes(2, "big") + wrapped
        return FileEncryptor(header, _FileKey(AESGCM(dek), prefix))

    # ---------------------------------------------------------------- opening

    def open_header(self, storage_key: str, wrapped: bytes) -> _FileKey:
        material = self._unwrap(storage_key, wrapped)
        return _FileKey(AESGCM(material[:_KEY_BYTES]), material[_KEY_BYTES:])

    def decryptor(self, storage_key: str, read: Callable[[int], bytes]) -> FileDecryptor:
        """Opens a stream positioned just after the magic bytes."""
        length = read(2)
        if len(length) != 2:
            raise DecryptionError(internal_detail="truncated file header")
        wrapped = read(int.from_bytes(length, "big"))
        return FileDecryptor(self.open_header(storage_key, wrapped), read)

    # ---------------------------------------------------------------- rotation

    def rewrap_header(self, storage_key: str, wrapped: bytes) -> bytes | None:
        """The wrapped key under the active KEK, or ``None`` when already current."""
        if not self._cipher.needs_rewrap(wrapped):
            return None
        return self._cipher.rewrap(wrapped, context=_context(storage_key))

    def is_stale(self, wrapped: bytes) -> bool:
        """Whether a file key is wrapped under another KEK than the active one."""
        try:
            return self._cipher.needs_rewrap(wrapped)
        except DecryptionError:
            return False  # not a key any KEK wrapped: rewrapping cannot help it

    def _unwrap(self, storage_key: str, wrapped: bytes) -> bytes:
        text = self._cipher.decrypt(wrapped, context=_context(storage_key))
        try:
            material = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise DecryptionError(internal_detail="malformed file key") from exc
        if len(material) != _KEY_BYTES + _PREFIX_BYTES:
            raise DecryptionError(internal_detail="malformed file key")
        return material


class FileEncryptor:
    """Seals a stream: feed plaintext with ``update``, end with ``finalize``."""

    def __init__(self, header: bytes, key: _FileKey) -> None:
        self.header = header
        self._key = key
        self._buffer = bytearray()
        self._counter = 0

    def update(self, data: bytes) -> bytes:
        self._buffer += data
        out = bytearray()
        # A chunk is sealed as soon as more data follows it: only then is it
        # known not to be the final one.
        while len(self._buffer) > CHUNK:
            out += self._seal(bytes(self._buffer[:CHUNK]), last=False)
            del self._buffer[:CHUNK]
        return bytes(out)

    def finalize(self) -> bytes:
        final = self._seal(bytes(self._buffer), last=True)
        self._buffer.clear()
        return final

    def _seal(self, plain: bytes, *, last: bool) -> bytes:
        nonce = _nonce(self._key.prefix, self._counter, last)
        self._counter += 1
        return self._key.aead.encrypt(nonce, plain, _AAD)


class FileDecryptor:
    """Opens a sealed stream chunk by chunk (``None`` after the final chunk)."""

    def __init__(self, key: _FileKey, read: Callable[[int], bytes]) -> None:
        self._key = key
        self._read = read
        self._counter = 0
        self._current = read(CHUNK + TAG)
        self._done = False

    def next_chunk(self) -> bytes | None:
        if self._done:
            return None
        current = self._current
        if len(current) < TAG:
            raise DecryptionError(internal_detail="truncated file")
        following = self._read(CHUNK + TAG)
        last = not following  # the final chunk is the one nothing follows
        nonce = _nonce(self._key.prefix, self._counter, last)
        try:
            plain = self._key.aead.decrypt(nonce, current, _AAD)
        except InvalidTag as exc:
            raise DecryptionError(internal_detail="file chunk failed authentication") from exc
        self._counter += 1
        self._current = following
        self._done = last
        return plain

"""Stored files are encrypted at rest: streaming AEAD, tampering and key rotation."""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import AsyncIterator, Callable
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from nexusflow.infrastructure.security.crypto import DecryptionError, EnvelopeCipher
from nexusflow.infrastructure.security.files import CHUNK, MAGIC, TAG, FileSealer
from nexusflow.infrastructure.storage.local import LocalFileStorage

ORG = uuid4()
KEY_1, KEY_2 = os.urandom(32), os.urandom(32)


def _key(ext: str = "csv") -> str:
    return f"uploads/{ORG}/{uuid4()}.{ext}"


def _storage(
    root: Path, *, keys: dict[str, bytes] | None = None, active: str = "k1"
) -> LocalFileStorage:
    cipher = EnvelopeCipher(keys or {"k1": KEY_1}, active)
    return LocalFileStorage(root, FileSealer(cipher))


async def _chunks(data: bytes, size: int = 10_000) -> AsyncIterator[bytes]:
    for start in range(0, len(data), size):
        yield data[start : start + size]


async def _read(storage: LocalFileStorage, key: str) -> bytes:
    return b"".join([chunk async for chunk in storage.stream(key)])


@pytest.mark.parametrize(
    "size",
    [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 17],
    ids=["empty", "one-byte", "chunk-1", "chunk", "chunk+1", "three-chunks", "uneven"],
)
async def test_every_size_round_trips_and_nothing_readable_is_stored(
    tmp_path: Path, size: int
) -> None:
    storage = _storage(tmp_path)
    key = _key()
    data = (b"alice@supplier.example,4111-1111-1111-1111\n" * (size // 44 + 1))[:size]
    stored = await storage.save(key, _chunks(data), max_bytes=10 * CHUNK)
    assert (stored.size, stored.sha256) == (len(data), hashlib.sha256(data).hexdigest())
    raw = storage.local_path(key).read_bytes()
    assert raw.startswith(MAGIC)
    if size:
        assert b"alice@supplier.example" not in raw
    assert await _read(storage, key) == data


async def test_a_plaintext_copy_exists_only_while_it_is_used(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    key = _key()
    await storage.save_bytes(key, b"SKU,Title\r\nA-1,Lamp\r\n")
    async with storage.plaintext(key) as plain:
        assert plain.read_bytes() == b"SKU,Title\r\nA-1,Lamp\r\n"
        assert oct(plain.stat().st_mode & 0o777) in ("0o600", "0o666")  # 0o666 on Windows
        assert tmp_path in plain.parents
    assert not plain.exists()


type Tampering = Callable[[bytearray], bytearray]


def _tamper(path: Path, change: Tampering) -> None:
    path.write_bytes(bytes(change(bytearray(path.read_bytes()))))


def _header_length(raw: bytes | bytearray) -> int:
    return len(MAGIC) + 2 + int.from_bytes(raw[4:6], "big")


def _body(raw: bytes) -> bytes:
    """The sealed chunks, after the header."""
    return raw[_header_length(raw) :]


@pytest.mark.parametrize(
    "change",
    [
        pytest.param(lambda raw: raw[:-1], id="truncated-tag"),
        pytest.param(lambda raw: raw[: _header_length(raw) + CHUNK + TAG], id="cut-at-a-chunk"),
        pytest.param(
            lambda raw: (
                raw[: _header_length(raw)]
                + raw[_header_length(raw) + CHUNK + TAG : _header_length(raw) + 2 * (CHUNK + TAG)]
                + raw[_header_length(raw) : _header_length(raw) + CHUNK + TAG]
                + raw[_header_length(raw) + 2 * (CHUNK + TAG) :]
            ),
            id="chunks-swapped",
        ),
        pytest.param(lambda raw: raw[:-5] + bytes([raw[-5] ^ 1]) + raw[-4:], id="bit-flipped"),
        pytest.param(lambda raw: raw + raw[-(CHUNK + TAG) :], id="chunk-appended"),
        pytest.param(lambda raw: raw[:10], id="header-cut"),
    ],
)
async def test_any_tampering_is_detected(tmp_path: Path, change: Tampering) -> None:
    storage = _storage(tmp_path)
    key = _key()
    await storage.save_bytes(key, os.urandom(3 * CHUNK + 100))
    _tamper(storage.local_path(key), change)
    with pytest.raises(DecryptionError):
        await _read(storage, key)


async def test_a_file_copied_under_another_key_does_not_open(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    original, copy = _key(), _key()
    await storage.save_bytes(original, b"tenant data")
    target = storage.local_path(copy)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(storage.local_path(original).read_bytes())
    with pytest.raises(DecryptionError):
        await _read(storage, copy)


async def test_a_file_without_the_sealed_header_is_refused(tmp_path: Path) -> None:
    # Every file the platform stores is sealed (no release stored plaintext), so a
    # file without the header was put there by someone else: it is never served.
    key = _key()
    await LocalFileStorage(tmp_path).save_bytes(key, b"SKU,Title\r\nA-1,Planted\r\n")
    with pytest.raises(DecryptionError):
        await _read(_storage(tmp_path), key)
    with pytest.raises(DecryptionError):
        async with _storage(tmp_path).plaintext(key):
            pass


async def test_a_sealed_file_replaced_by_plaintext_is_refused(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    key = f"reports/{ORG}/{uuid4()}.json"
    await storage.save_bytes(key, b'{"genuine": true}')
    storage.local_path(key).write_bytes(b'{"forged": true}')  # write access to the volume
    with pytest.raises(DecryptionError):
        await _read(storage, key)


async def test_without_a_sealer_files_are_stored_and_read_as_they_are(tmp_path: Path) -> None:
    storage, key = LocalFileStorage(tmp_path), _key()
    await storage.save_bytes(key, b"plain")
    assert await _read(storage, key) == b"plain"


async def test_stale_plaintext_copies_are_purged(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    key = _key()
    await storage.save_bytes(key, b"SKU\r\nA-1\r\n")
    async with storage.plaintext(key) as abandoned:  # a worker killed while scanning...
        stale = abandoned.with_name("left-behind.csv")
        stale.write_bytes(abandoned.read_bytes())
    hour_ago = time.time() - 3700
    os.utime(stale, (hour_ago, hour_ago))
    async with storage.plaintext(key) as in_use:  # ...and a scan in progress
        assert await storage.purge_scratch(older_than=timedelta(hours=1)) == 1
        assert in_use.exists()
    assert not stale.exists()
    assert await storage.purge_scratch(older_than=timedelta(0)) == 0
    assert await LocalFileStorage(tmp_path / "empty").purge_scratch() == 0


async def test_a_sealed_file_never_opens_without_a_sealer(tmp_path: Path) -> None:
    key = _key()
    await _storage(tmp_path).save_bytes(key, b"secret")
    with pytest.raises(DecryptionError):
        await _read(LocalFileStorage(tmp_path), key)


async def test_rotation_rewraps_headers_so_the_old_key_can_go(tmp_path: Path) -> None:
    keys = [_key("csv"), f"reports/{ORG}/{uuid4()}.pdf"]
    old = _storage(tmp_path)
    for index, key in enumerate(keys):
        await old.save_bytes(key, f"payload {index}".encode() * 5000)
    body_before = [_body(old.local_path(k).read_bytes()) for k in keys]

    rotated = _storage(tmp_path, keys={"k1": KEY_1, "k2": KEY_2}, active="k2")
    assert await rotated.rewrap(ORG, limit=10) == 2
    assert await rotated.rewrap(ORG, limit=10) == 0  # nothing left under the old key
    # Only the header changed: the chunks, under the same data key, are untouched.
    assert [_body(rotated.local_path(k).read_bytes()) for k in keys] == body_before

    retired = _storage(tmp_path, keys={"k2": KEY_2}, active="k2")
    for index, key in enumerate(keys):
        assert await _read(retired, key) == f"payload {index}".encode() * 5000


async def test_rotation_stops_at_its_batch_limit(tmp_path: Path) -> None:
    old = _storage(tmp_path)
    for _ in range(3):
        await old.save_bytes(_key(), b"x")
    rotated = _storage(tmp_path, keys={"k1": KEY_1, "k2": KEY_2}, active="k2")
    assert [await rotated.rewrap(ORG, limit=2) for _ in range(3)] == [2, 1, 0]

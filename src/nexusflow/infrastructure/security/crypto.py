"""Envelope encryption with AES-256-GCM and a rotatable key-encryption keyring.

Each secret is encrypted with a fresh random 256-bit data-encryption key (DEK);
the DEK is wrapped (encrypted) with the active key-encryption key (KEK). The
caller-supplied ``context`` string is bound as AES-GCM associated data to both
layers, so a ciphertext copied into another row or tenant fails authentication.

Blob layout (version 1)::

    b"NF" | 0x01 | len(kek_id) | kek_id | wrap_nonce(12) | wrapped_dek(48)
          | data_nonce(12) | ciphertext+tag

Key rotation: add a new KEK, make it active, then run the re-wrap job; old KEKs
stay in the keyring (decrypt-only) until no blob references them.
"""

from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from nexusflow.core.config import decode_key_bytes
from nexusflow.core.errors import PermanentError

_MAGIC = b"NF"
_VERSION = 1
_NONCE_BYTES = 12
_KEY_BYTES = 32
_WRAPPED_DEK_BYTES = _KEY_BYTES + 16


class DecryptionError(PermanentError):
    default_code = "decryption_failed"
    default_message = "Stored secret could not be decrypted."


@dataclass(frozen=True, slots=True)
class _Header:
    kek_id: str
    raw: bytes


class EnvelopeCipher:
    def __init__(self, keys: dict[str, bytes], active_key_id: str) -> None:
        if active_key_id not in keys:
            raise ValueError("active encryption key id is not present in the keyring")
        for key_id, key in keys.items():
            if len(key) != _KEY_BYTES:
                raise ValueError(f"encryption key {key_id!r} must be exactly 32 bytes")
            if not key_id.isascii() or not 0 < len(key_id) <= 32:
                raise ValueError("encryption key ids must be 1-32 ASCII characters")
        self._keys = {key_id: AESGCM(key) for key_id, key in keys.items()}
        self._active_key_id = active_key_id

    @classmethod
    def from_config(cls, keys_json: str, active_key_id: str) -> EnvelopeCipher:
        raw = json.loads(keys_json)
        if not isinstance(raw, dict) or not raw:
            raise ValueError("security.encryption_keys must be a non-empty JSON object")
        return cls({str(k): decode_key_bytes(str(v)) for k, v in raw.items()}, active_key_id)

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    def encrypt(self, plaintext: str, *, context: str) -> bytes:
        return self._encrypt_bytes(plaintext.encode("utf-8"), context.encode("utf-8"))

    def decrypt(self, blob: bytes, *, context: str) -> str:
        return self._decrypt_bytes(blob, context.encode("utf-8")).decode("utf-8")

    def needs_rewrap(self, blob: bytes) -> bool:
        return self._parse_header(blob).kek_id != self._active_key_id

    def rewrap(self, blob: bytes, *, context: str) -> bytes:
        """Re-encrypt under the active KEK (new DEK, new nonces)."""
        return self._encrypt_bytes(self._decrypt_bytes(blob, context.encode()), context.encode())

    def key_id_of(self, blob: bytes) -> str:
        return self._parse_header(blob).kek_id

    # ------------------------------------------------------------------ internals

    def _encrypt_bytes(self, plaintext: bytes, context: bytes) -> bytes:
        kek_id = self._active_key_id
        header = _MAGIC + struct.pack("!BB", _VERSION, len(kek_id)) + kek_id.encode("ascii")
        dek = AESGCM.generate_key(bit_length=256)
        wrap_nonce = os.urandom(_NONCE_BYTES)
        wrapped_dek = self._keys[kek_id].encrypt(wrap_nonce, dek, header + b"|dek|" + context)
        data_nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(dek).encrypt(data_nonce, plaintext, header + b"|data|" + context)
        return header + wrap_nonce + wrapped_dek + data_nonce + ciphertext

    def _decrypt_bytes(self, blob: bytes, context: bytes) -> bytes:
        header = self._parse_header(blob)
        kek = self._keys.get(header.kek_id)
        if kek is None:
            raise DecryptionError(internal_detail=f"unknown KEK id {header.kek_id!r}")
        offset = len(header.raw)
        wrap_nonce = blob[offset : offset + _NONCE_BYTES]
        offset += _NONCE_BYTES
        wrapped_dek = blob[offset : offset + _WRAPPED_DEK_BYTES]
        offset += _WRAPPED_DEK_BYTES
        data_nonce = blob[offset : offset + _NONCE_BYTES]
        offset += _NONCE_BYTES
        ciphertext = blob[offset:]
        if len(ciphertext) < 16:
            raise DecryptionError(internal_detail="truncated ciphertext")
        try:
            dek = kek.decrypt(wrap_nonce, wrapped_dek, header.raw + b"|dek|" + context)
            return AESGCM(dek).decrypt(data_nonce, ciphertext, header.raw + b"|data|" + context)
        except InvalidTag as exc:
            raise DecryptionError(internal_detail="authentication tag mismatch") from exc

    @staticmethod
    def _parse_header(blob: bytes) -> _Header:
        if len(blob) < 4 or blob[:2] != _MAGIC:
            raise DecryptionError(internal_detail="bad magic")
        version, id_len = struct.unpack("!BB", blob[2:4])
        if version != _VERSION or id_len == 0:
            raise DecryptionError(internal_detail="unsupported blob version")
        end = 4 + id_len
        minimum = end + _NONCE_BYTES + _WRAPPED_DEK_BYTES + _NONCE_BYTES + 16
        if len(blob) < minimum:
            raise DecryptionError(internal_detail="truncated blob")
        try:
            kek_id = blob[4:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise DecryptionError(internal_detail="bad key id") from exc
        return _Header(kek_id=kek_id, raw=blob[:end])

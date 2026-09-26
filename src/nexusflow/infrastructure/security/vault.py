"""Key-encryption keys wrapped by HashiCorp Vault's transit engine.

With ``security.kek_provider = "vault-transit"`` the keyring
(``security.encryption_keys``) holds Vault ciphertexts instead of keys::

    {"kek-1": "vault:v1:...", "kek-2": "vault:v2:..."}

At start-up the platform asks Vault to decrypt them, once, and keeps the
keys in memory; every encryption and decryption after that stays local
(AES-256-GCM, no network round trip per value). What changes:

* the secrets file alone is worthless: whoever copies it (or a backup of
  it) also needs a Vault identity allowed to use the transit key;
* access to the keys is granted, audited and revoked in Vault, and the
  wrapping key rotates there (``vault write -f transit/keys/<key>/rotate``,
  then ``nexusflow keys vault-rewrap``);
* what does not: a running process holds the keys in memory, as with local
  keys - Vault protects them at rest and at start, not from a compromised
  process.

Vault is reached over TLS verified against ``vault.ca_cert`` (or the system
store), with a token (``vault.token``) or an AppRole login
(``vault.role_id`` and ``vault.secret_id``). The token is never logged.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx2

from nexusflow.core.config import VaultSettings
from nexusflow.core.errors import PermanentError

KEY_BYTES = 32
_CIPHERTEXT_PREFIX = "vault:v"


class VaultError(PermanentError):
    default_code = "vault_unavailable"
    default_message = "The key-management service could not be used."


class VaultTransit:
    """The two transit operations the platform needs, and an AppRole login."""

    def __init__(
        self,
        settings: VaultSettings,
        *,
        client: httpx2.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not settings.address:
            raise VaultError(internal_detail="vault.address is not set")
        address = settings.address.rstrip("/")
        if urlsplit(address).scheme != "https" and not settings.allow_insecure_http:
            raise VaultError(internal_detail="vault.address must use https")
        self._settings = settings
        self._base = f"{address}/v1"
        self._client = client or httpx2.Client(
            verify=str(settings.ca_cert) if settings.ca_cert else True,
            timeout=settings.timeout_seconds,
            follow_redirects=False,
        )
        self._sleep = sleep
        self._token: str | None = (
            settings.token.get_secret_value().strip() if settings.token else None
        )

    # ------------------------------------------------------------ operations

    def decrypt_keyring(self, wrapped: dict[str, str]) -> dict[str, bytes]:
        """Unwrap every key of the keyring (one batch request)."""
        if not wrapped:
            raise VaultError(internal_detail="the keyring is empty")
        ids = list(wrapped)
        for key_id in ids:
            if not str(wrapped[key_id]).startswith(_CIPHERTEXT_PREFIX):
                raise VaultError(internal_detail=f"key {key_id!r} is not a Vault ciphertext")
        body = {"batch_input": [{"ciphertext": wrapped[key_id]} for key_id in ids]}
        results = self._batch("decrypt", body, expected=len(ids))
        keys: dict[str, bytes] = {}
        for key_id, result in zip(ids, results, strict=True):
            plaintext = _decode(result.get("plaintext"), what=f"plaintext of {key_id!r}")
            if len(plaintext) != KEY_BYTES:
                raise VaultError(internal_detail=f"key {key_id!r} is not {KEY_BYTES} bytes")
            keys[key_id] = plaintext
        return keys

    def encrypt_key(self, key: bytes) -> str:
        """Wrap one key-encryption key (for ``nexusflow keys vault-wrap``)."""
        if len(key) != KEY_BYTES:
            raise ValueError(f"a key-encryption key is {KEY_BYTES} bytes")
        [result] = self._batch(
            "encrypt",
            {"batch_input": [{"plaintext": base64.b64encode(key).decode()}]},
            expected=1,
        )
        ciphertext = result.get("ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext.startswith(_CIPHERTEXT_PREFIX):
            raise VaultError(internal_detail="unexpected encrypt response")
        return ciphertext

    def rewrap(self, wrapped: dict[str, str]) -> dict[str, str]:
        """Re-wrap the keyring under the transit key's newest version (the keys
        themselves do not change, so no stored data needs re-encrypting)."""
        ids = list(wrapped)
        body = {"batch_input": [{"ciphertext": wrapped[key_id]} for key_id in ids]}
        results = self._batch("rewrap", body, expected=len(ids))
        rewrapped: dict[str, str] = {}
        for key_id, result in zip(ids, results, strict=True):
            ciphertext = result.get("ciphertext")
            if not isinstance(ciphertext, str) or not ciphertext.startswith(_CIPHERTEXT_PREFIX):
                raise VaultError(internal_detail=f"unexpected rewrap result for {key_id!r}")
            rewrapped[key_id] = ciphertext
        return rewrapped

    # ------------------------------------------------------------ transport

    def _batch(self, operation: str, body: dict[str, Any], *, expected: int) -> list[Any]:
        s = self._settings
        path = f"/{s.transit_mount}/{operation}/{s.transit_key}"
        data = self._request(path, body).get("data")
        results = data.get("batch_results") if isinstance(data, dict) else None
        if not isinstance(results, list) or len(results) != expected:
            raise VaultError(internal_detail=f"unexpected {operation} response")
        for result in results:
            if not isinstance(result, dict) or result.get("error"):
                raise VaultError(internal_detail=f"{operation} refused an item")
        return results

    def _request(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST with a few retries on unreachability and 5xx (Vault restarting,
        sealed standby); a refusal (4xx) is final."""
        delay = 0.5
        failure = "no attempt"
        for attempt in range(self._settings.retries + 1):
            try:
                response = self._client.post(
                    self._base + path, json=body, headers=self._headers(path)
                )
            except httpx2.HTTPError as exc:
                failure = f"{type(exc).__name__}"
            else:
                if response.status_code == 200:
                    return _json(response)
                if response.status_code < 500:
                    raise VaultError(internal_detail=f"HTTP {response.status_code} on {path}")
                failure = f"HTTP {response.status_code}"
            if attempt < self._settings.retries:
                self._sleep(delay)
                delay = min(delay * 2, 5.0)
        raise VaultError(internal_detail=f"{failure} on {path}")

    def _headers(self, path: str) -> dict[str, str]:
        headers = {"X-Vault-Request": "true"}
        if self._settings.namespace:
            headers["X-Vault-Namespace"] = self._settings.namespace
        if not path.startswith("/auth/"):
            headers["X-Vault-Token"] = self._login()
        return headers

    def _login(self) -> str:
        if self._token is not None:
            return self._token
        s = self._settings
        if s.role_id is None or s.secret_id is None:
            raise VaultError(internal_detail="neither vault.token nor an AppRole is configured")
        auth = self._request(
            f"/auth/{s.approle_mount}/login",
            {"role_id": s.role_id, "secret_id": s.secret_id.get_secret_value().strip()},
        ).get("auth")
        token = auth.get("client_token") if isinstance(auth, dict) else None
        if not isinstance(token, str) or not token:
            raise VaultError(internal_detail="AppRole login returned no token")
        self._token = token
        return token

    def close(self) -> None:
        self._client.close()


def _json(response: httpx2.Response) -> dict[str, Any]:
    try:
        document = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise VaultError(internal_detail="the response is not JSON") from exc
    if not isinstance(document, dict):
        raise VaultError(internal_detail="the response is not an object")
    return document


def _decode(value: object, *, what: str) -> bytes:
    if not isinstance(value, str):
        raise VaultError(internal_detail=f"missing {what}")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VaultError(internal_detail=f"{what} is not base64") from exc


# Unwrapped keyrings of this process, by the digest of their wrapped form. A
# worker pool unwraps in its parent (create_worker_app) before forking: every
# child inherits the keys, so children recycled later neither call Vault again
# nor fail to start while Vault is unavailable.
_UNWRAPPED: dict[str, dict[str, bytes]] = {}


def unwrap_keyring(settings: VaultSettings, keys_json: str) -> dict[str, bytes]:
    """The keyring's keys, unwrapped by Vault - once per process tree."""
    digest = hashlib.sha256(keys_json.encode("utf-8")).hexdigest()
    cached = _UNWRAPPED.get(digest)
    if cached is None:
        cached = _UNWRAPPED[digest] = _unwrap(settings, keys_json)
    return dict(cached)


def _unwrap(settings: VaultSettings, keys_json: str) -> dict[str, bytes]:
    wrapped = json.loads(keys_json)
    if not isinstance(wrapped, dict) or not all(isinstance(v, str) for v in wrapped.values()):
        raise VaultError(internal_detail="security.encryption_keys must map ids to ciphertexts")
    transit = VaultTransit(settings)
    try:
        return transit.decrypt_keyring({str(k): str(v) for k, v in wrapped.items()})
    finally:
        transit.close()


def new_key() -> bytes:
    return os.urandom(KEY_BYTES)

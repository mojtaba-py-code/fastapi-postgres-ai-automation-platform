"""Sensitive field values, encrypted at rest by the application.

The values of fields a dataset schema marks ``sensitive`` are stored as *sealed*
markers - ``{"$sealed": <base64 envelope>, "kid": <key id>}`` - in records,
their versions and the diffs of changes. Each envelope is AES-256-GCM under a
fresh data key wrapped by the active key-encryption key (``SecretCipher``), and
is bound to the tenant, dataset, record and field: a ciphertext copied into
another row or field fails to decrypt. A database dump or a backup therefore
reveals no sensitive value, whatever else it contains.

Writes seal (the services that know the schema); the database layer opens
sealed values as rows are loaded, so everything above it sees plaintext and
masks it exactly as before. Field types are scalars, so a value that is a dict
of exactly this shape can only be a sealed marker. ``kid`` duplicates the key
id inside the envelope so the key-rotation job can find stale values in SQL;
it is never trusted for decryption.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from typing import Any, TypeGuard
from uuid import UUID

from nexusflow.core.errors import PermanentError
from nexusflow.domain.shared.security import SecretCipher

SEALED = "$sealed"
KEY_ID = "kid"


class SealedValueError(PermanentError):
    """A sealed marker is malformed (tampered storage)."""

    default_code = "sealed_value_invalid"
    default_message = "Stored data could not be decrypted."


def field_context(org_id: UUID, dataset_id: UUID, record_id: UUID, field: str) -> str:
    return f"field:v1:{org_id}:{dataset_id}:{record_id}:{field}"


def is_sealed(value: object) -> TypeGuard[dict[str, str]]:
    return (
        isinstance(value, dict)
        and len(value) == 2
        and isinstance(value.get(SEALED), str)
        and isinstance(value.get(KEY_ID), str)
    )


def seal_value(cipher: SecretCipher, value: object, context: str) -> dict[str, str]:
    blob = cipher.encrypt(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")), context=context
    )
    return {SEALED: base64.b64encode(blob).decode("ascii"), KEY_ID: cipher.key_id_of(blob)}


def open_value(cipher: SecretCipher, value: object, context: str) -> Any:
    """``value`` itself unless it is sealed; a sealed value that fails to open raises."""
    if not is_sealed(value):
        return value
    return json.loads(cipher.decrypt(_blob(value), context=context))


def rewrap_value(cipher: SecretCipher, value: object, context: str) -> object:
    """A sealed value re-encrypted under the active key; anything else unchanged."""
    if not is_sealed(value):
        return value
    blob = cipher.rewrap(_blob(value), context=context)
    return {SEALED: base64.b64encode(blob).decode("ascii"), KEY_ID: cipher.key_id_of(blob)}


def _blob(value: dict[str, str]) -> bytes:
    try:
        return base64.b64decode(value[SEALED], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SealedValueError(internal_detail="sealed value is not base64") from exc


def seal_data(
    cipher: SecretCipher,
    data: Mapping[str, Any],
    sensitive: frozenset[str],
    *,
    org_id: UUID,
    dataset_id: UUID,
    record_id: UUID,
) -> dict[str, Any]:
    """A record's data with every present sensitive value sealed (``None`` stays ``None``)."""
    return {
        name: (
            seal_value(cipher, value, field_context(org_id, dataset_id, record_id, name))
            if name in sensitive and value is not None and not is_sealed(value)
            else value
        )
        for name, value in data.items()
    }


def open_data(
    cipher: SecretCipher,
    data: Mapping[str, Any],
    *,
    org_id: UUID,
    dataset_id: UUID,
    record_id: UUID,
) -> dict[str, Any]:
    """A record's data with every sealed value opened - no schema needed."""
    return {
        name: open_value(cipher, value, field_context(org_id, dataset_id, record_id, name))
        for name, value in data.items()
    }


def seal_diff(
    cipher: SecretCipher,
    diff: Mapping[str, Any],
    sensitive: frozenset[str],
    *,
    org_id: UUID,
    dataset_id: UUID,
    record_id: UUID,
) -> dict[str, Any]:
    """A change's diff with every value of a sensitive field sealed.

    That includes ``pct``: the relative change of a sensitive number (a salary,
    a credit limit) is as sensitive as the number.
    """
    sealed: dict[str, Any] = {}
    for name, entry in diff.items():
        if name in sensitive and isinstance(entry, dict):
            context = field_context(org_id, dataset_id, record_id, name)
            sealed[name] = {
                key: (
                    seal_value(cipher, value, context)
                    if value is not None and not is_sealed(value)
                    else value
                )
                for key, value in entry.items()
            }
        else:
            sealed[name] = entry
    return sealed


def open_diff(
    cipher: SecretCipher,
    diff: Mapping[str, Any],
    *,
    org_id: UUID,
    dataset_id: UUID,
    record_id: UUID,
) -> dict[str, Any]:
    opened: dict[str, Any] = {}
    for name, entry in diff.items():
        if isinstance(entry, dict) and not is_sealed(entry):
            context = field_context(org_id, dataset_id, record_id, name)
            opened[name] = {key: open_value(cipher, value, context) for key, value in entry.items()}
        else:
            opened[name] = entry
    return opened


def contains_sealed(value: object) -> bool:
    """Whether a data mapping or diff holds any sealed value (at any depth up to two)."""
    if is_sealed(value):
        return True
    if isinstance(value, dict):
        return any(
            is_sealed(inner)
            or (isinstance(inner, dict) and any(is_sealed(v) for v in inner.values()))
            for inner in value.values()
        )
    return False

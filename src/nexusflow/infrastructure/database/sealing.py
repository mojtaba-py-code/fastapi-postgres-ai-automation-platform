"""Opening sealed field values as rows load (see ``nexusflow.domain.records.sealing``).

Every unit of work puts the platform's cipher into its session's ``info``. The
listeners below open the sealed values of records, record versions and
changes the moment SQLAlchemy loads or refreshes them, and store the opened
value as the *committed* state: opening never makes a row dirty (a later flush
never writes plaintext back), and everything above the database layer sees
plaintext. Rows without sealed values - data written before sealing existed,
or datasets without sensitive fields - pass through untouched.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import QueryContext
from sqlalchemy.orm.attributes import set_committed_value

from nexusflow.domain.records.model import Change, Record, RecordVersion
from nexusflow.domain.records.sealing import (
    SealedValueError,
    contains_sealed,
    open_data,
    open_diff,
)
from nexusflow.domain.shared.security import SecretCipher

CIPHER_KEY = "nexusflow.field_cipher"


def _cipher(context: QueryContext) -> SecretCipher:
    cipher = context.session.info.get(CIPHER_KEY)
    if cipher is None:
        # Fail closed: sealed data must never surface as ciphertext markers.
        raise SealedValueError(internal_detail="sealed data loaded without a field cipher")
    return cipher  # type: ignore[no-any-return]


def _wants(attrs: Any, name: str) -> bool:
    return attrs is None or name in attrs


def _open_record_data(
    target: Record | RecordVersion, context: QueryContext, attrs: Any = None
) -> None:
    if not _wants(attrs, "data") or not contains_sealed(target.data):
        return
    record_id = target.id if isinstance(target, Record) else target.record_id
    opened = open_data(
        _cipher(context),
        target.data,
        org_id=target.org_id,
        dataset_id=target.dataset_id,
        record_id=record_id,
    )
    set_committed_value(target, "data", opened)


def _open_change_diff(target: Change, context: QueryContext, attrs: Any = None) -> None:
    if not _wants(attrs, "diff") or not contains_sealed(target.diff):
        return
    opened = open_diff(
        _cipher(context),
        target.diff,
        org_id=target.org_id,
        dataset_id=target.dataset_id,
        record_id=target.record_id,
    )
    set_committed_value(target, "diff", opened)


_LISTENERS: tuple[tuple[type, Any], ...] = (
    (Record, _open_record_data),
    (RecordVersion, _open_record_data),
    (Change, _open_change_diff),
)


def register_sealing_listeners() -> None:
    """Idempotently attach the listeners (after the classes are mapped)."""
    for cls, listener in _LISTENERS:
        for name in ("load", "refresh"):
            if not event.contains(cls, name, listener):
                event.listen(cls, name, listener)

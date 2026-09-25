"""Request correlation across the asynchronous pipeline.

The API binds each request's ID while it handles the request. Every outbox
message committed meanwhile carries it; a worker binds it again while it runs
the job, so the messages *that* job emits carry it too - and every log line on
the way has it as ``request_id``. One identifier then links an API request
(or a webhook delivery, or an operator command) to every job it caused.

Only identifiers of a safe shape are propagated: they end up in logs and
message headers, never in anything that is interpreted.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

# The reserved keyword a task message carries the identifier under.
CORRELATION_KWARG = "_correlation_id"

_VALID = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")
_current: ContextVar[str | None] = ContextVar("nexusflow_correlation_id", default=None)


def valid_correlation_id(value: object) -> str | None:
    """``value`` if it is a well-formed identifier, else ``None``."""
    return value if isinstance(value, str) and _VALID.fullmatch(value) else None


def current_correlation_id() -> str | None:
    return _current.get()


@contextmanager
def correlation(value: object) -> Iterator[str | None]:
    """Bind ``value`` (when well-formed) for the enclosed code; yields what was bound."""
    token = _current.set(valid_correlation_id(value))
    try:
        yield _current.get()
    finally:
        _current.reset(token)

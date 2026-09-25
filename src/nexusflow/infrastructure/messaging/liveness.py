"""Liveness heartbeats for Celery workers and beat.

A worker's consumer touches a file from its own event loop, and only while it
is connected to the broker; beat touches it on every scheduler tick (at least
every ten seconds, the outbox relay's period). The container health probe
(``docker/healthcheck.py`` with ``NEXUSFLOW_HEALTHCHECK=heartbeat``) checks
the file's age, so a hung event loop, a consumer stuck reconnecting or a
stalled scheduler turns the container unhealthy - a process that merely
exists does not count as healthy.

The path comes from ``NEXUSFLOW_HEARTBEAT_PATH`` (deliberately not ``..._FILE``:
that suffix means "read a secret from this file" to the settings loader).
Unset, nothing is written - e.g. in tests and local runs.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import structlog
from celery import bootsteps
from celery.beat import PersistentScheduler
from celery.worker.consumer.connection import Connection

HEARTBEAT_PATH_ENV = "NEXUSFLOW_HEARTBEAT_PATH"
INTERVAL_SECONDS = 15.0

_log = structlog.get_logger(__name__)


def heartbeat_path() -> str | None:
    return os.environ.get(HEARTBEAT_PATH_ENV) or None


def touch(path: str | None = None) -> None:
    """Mark the process alive now; a failure is logged, never raised."""
    target = path or heartbeat_path()
    if target is None:
        return
    try:
        Path(target).touch()
    except OSError as exc:
        _log.warning("heartbeat_write_failed", path=target, error=type(exc).__name__)


class ConsumerHeartbeat(bootsteps.StartStopStep):
    """Consumer bootstep: touches the heartbeat from the consumer's event loop.

    It starts once the broker connection is up and is stopped whenever the
    consumer restarts (a lost connection), so the heartbeat also stops while
    the worker cannot reach the broker.
    """

    requires = (Connection,)

    def __init__(self, parent: Any, **kwargs: Any) -> None:
        super().__init__(parent, **kwargs)
        self._path = heartbeat_path()
        self._timer_entry: Any = None

    def start(self, parent: Any) -> None:
        if self._path is None:
            return
        touch(self._path)
        self._timer_entry = parent.timer.call_repeatedly(INTERVAL_SECONDS, touch, (self._path,))

    def stop(self, parent: Any) -> None:
        if self._timer_entry is not None:
            self._timer_entry.cancel()
            self._timer_entry = None

    def shutdown(self, parent: Any) -> None:
        self.stop(parent)


class HeartbeatScheduler(PersistentScheduler):
    """Celery beat's persistent scheduler, touching the heartbeat on every tick."""

    def tick(self, *args: Any, **kwargs: Any) -> float:
        touch()
        interval: float = super().tick(*args, **kwargs)
        return interval

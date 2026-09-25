"""Worker process observability: logging and a Prometheus endpoint.

Celery prefork children each hold their own metric values; with
``PROMETHEUS_MULTIPROC_DIR`` set, the parent serves the aggregate.
"""

from __future__ import annotations

import os
from pathlib import Path

from prometheus_client import CollectorRegistry, start_http_server
from prometheus_client.multiprocess import MultiProcessCollector, mark_process_dead

from nexusflow.core.config import ObservabilitySettings
from nexusflow.infrastructure.observability.logging import configure_logging, get_logger
from nexusflow.infrastructure.observability.tracing import (
    configure_tracing,
    instrument_celery,
)

_log = get_logger("nexusflow.worker")


def setup_worker_observability(settings: ObservabilitySettings, *, service: str) -> None:
    configure_logging(level=settings.log_level, fmt=settings.log_format, service=service)
    if not settings.metrics_enabled or settings.worker_metrics_port is None:
        return
    directory = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if not directory:
        _log.warning("worker_metrics_disabled", reason="PROMETHEUS_MULTIPROC_DIR is not set")
        return
    reset_metrics_directory(Path(directory))
    registry = CollectorRegistry()
    MultiProcessCollector(registry)  # type: ignore[no-untyped-call]
    # Bind on all interfaces *inside* the container. Nothing is published to the
    # host: only containers that share an internal network with this worker reach
    # it (Prometheus scrapes over `backend`). The sandbox and the browser cannot -
    # the only network they share with a worker, `egress`, has inter-container
    # traffic disabled. The endpoint serves counters with bounded labels only.
    start_http_server(settings.worker_metrics_port, addr="0.0.0.0", registry=registry)  # noqa: S104  # nosec B104


def reset_metrics_directory(directory: Path) -> None:
    """Start from an empty multiprocess directory (the parent, before any child):
    files of processes from an earlier start would be counted again."""
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.glob("*.db"):
        stale.unlink(missing_ok=True)


def forget_worker_process(pid: int) -> None:
    """A child is exiting: drop its live gauges (counters keep counting)."""
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        mark_process_dead(pid)  # type: ignore[no-untyped-call]


def setup_worker_tracing(settings: ObservabilitySettings, *, service: str) -> None:
    """Per worker *process* (``worker_process_init``): an exporter's background
    thread does not survive the prefork fork, so tracing starts in each child."""
    if configure_tracing(settings, service_name=service):
        instrument_celery()

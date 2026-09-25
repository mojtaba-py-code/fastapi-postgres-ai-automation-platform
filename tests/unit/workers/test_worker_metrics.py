"""Worker metrics in Prometheus multiprocess mode stay bounded (review F-9).

Every prefork child writes its own metric files. They used to live in the
64 MiB /tmp shared with everything else, children were recycled every 500
tasks, and nothing ever removed a dead child's files: on a busy pool /tmp
filled up (then every metric write faults), and a dead child's gauge - an
open circuit breaker - stayed exported for ever.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nexusflow.apps.workers import observability
from nexusflow.core.config import BrokerSettings
from nexusflow.infrastructure.messaging.celery_app import build_celery
from nexusflow.infrastructure.observability import metrics


def test_the_metrics_directory_starts_empty(tmp_path: Path) -> None:
    directory = tmp_path / "prometheus"
    directory.mkdir()
    for stale in ("counter_101.db", "histogram_101.db", "gauge_livemax_101.db"):
        (directory / stale).write_bytes(b"\0" * 16)
    (directory / "keep.txt").write_text("not a metrics file", encoding="utf-8")

    observability.reset_metrics_directory(directory)

    assert sorted(p.name for p in directory.iterdir()) == ["keep.txt"]


def test_an_exiting_child_drops_its_live_gauges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(tmp_path))
    live = tmp_path / "gauge_livemax_4242.db"
    counter = tmp_path / "counter_4242.db"
    live.write_bytes(b"\0" * 16)
    counter.write_bytes(b"\0" * 16)

    observability.forget_worker_process(4242)

    assert not live.exists()  # its breaker state is no longer reported
    assert counter.exists()  # its counts still add up


def test_circuit_breaker_state_is_taken_from_living_processes_only() -> None:
    assert metrics.CIRCUIT_STATE._multiprocess_mode == "livemax"


def test_platform_children_are_recycled_rarely_and_sandbox_children_always() -> None:
    assert build_celery(BrokerSettings()).conf.worker_max_tasks_per_child == 10_000
    sandbox = build_celery(BrokerSettings(), role="sandbox")
    assert sandbox.conf.worker_max_tasks_per_child == 1

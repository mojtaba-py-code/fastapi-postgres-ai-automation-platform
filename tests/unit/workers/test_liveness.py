"""Worker and beat liveness: the heartbeat file and the container probe that reads it."""

from __future__ import annotations

import importlib.util
import os
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import SecretStr

from nexusflow.core.config import BrokerSettings
from nexusflow.infrastructure.messaging import liveness
from nexusflow.infrastructure.messaging.celery_app import build_celery
from nexusflow.infrastructure.messaging.liveness import (
    HEARTBEAT_PATH_ENV,
    INTERVAL_SECONDS,
    ConsumerHeartbeat,
    HeartbeatScheduler,
)

ROOT = Path(__file__).resolve().parents[3]
BROKER = BrokerSettings(url=SecretStr("memory://"))


class FakeTimer:
    def __init__(self) -> None:
        self.calls: list[tuple[float, Any, tuple[Any, ...]]] = []
        self.cancelled = 0

    def call_repeatedly(self, seconds: float, fun: Any, args: tuple[Any, ...] = ()) -> FakeTimer:
        self.calls.append((seconds, fun, args))
        return self

    def cancel(self) -> None:
        self.cancelled += 1


class FakeConsumer:
    def __init__(self) -> None:
        self.timer = FakeTimer()


@pytest.fixture
def heartbeat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "heartbeat"
    monkeypatch.setenv(HEARTBEAT_PATH_ENV, str(path))
    return path


def _age(path: Path, seconds: float) -> None:
    past = time.time() - seconds
    os.utime(path, (past, past))


class TestHeartbeat:
    def test_touch_marks_the_process_alive_now(self, heartbeat: Path) -> None:
        liveness.touch()
        _age(heartbeat, 600)
        liveness.touch()
        assert time.time() - heartbeat.stat().st_mtime < 5

    def test_nothing_is_written_without_a_configured_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(HEARTBEAT_PATH_ENV, raising=False)
        monkeypatch.chdir(tmp_path)
        liveness.touch()
        assert list(tmp_path.iterdir()) == []

    def test_an_unwritable_path_is_logged_not_raised(self, tmp_path: Path) -> None:
        liveness.touch(str(tmp_path / "missing-directory" / "heartbeat"))


class TestConsumerHeartbeat:
    def test_it_beats_from_the_consumer_timer_while_started(self, heartbeat: Path) -> None:
        consumer = FakeConsumer()
        step = ConsumerHeartbeat(consumer)
        step.start(consumer)
        assert heartbeat.exists()  # the first beat is immediate
        [(seconds, fun, args)] = consumer.timer.calls
        assert (seconds, fun, args) == (INTERVAL_SECONDS, liveness.touch, (str(heartbeat),))

        step.stop(consumer)  # e.g. the broker connection was lost
        assert consumer.timer.cancelled == 1
        step.shutdown(consumer)
        assert consumer.timer.cancelled == 1  # stopping twice is harmless

    def test_it_is_inert_without_a_configured_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(HEARTBEAT_PATH_ENV, raising=False)
        consumer = FakeConsumer()
        ConsumerHeartbeat(consumer).start(consumer)
        assert consumer.timer.calls == []

    @pytest.mark.parametrize("role", ["platform", "sandbox"])
    def test_every_worker_app_runs_it(self, role: str) -> None:
        app = build_celery(BROKER, role=role)  # type: ignore[arg-type]
        assert ConsumerHeartbeat in app.steps["consumer"]
        assert app.conf.beat_scheduler.endswith(":HeartbeatScheduler")


class TestBeatHeartbeat:
    def test_every_scheduler_tick_beats(self, heartbeat: Path, tmp_path: Path) -> None:
        app = build_celery(BROKER, schedule={})
        scheduler = HeartbeatScheduler(app=app, schedule_filename=str(tmp_path / "beat-schedule"))
        try:
            assert scheduler.tick() > 0
        finally:
            scheduler.close()
        assert heartbeat.exists()


@pytest.fixture(scope="module")
def probe() -> ModuleType:
    spec = importlib.util.spec_from_file_location("healthcheck", ROOT / "docker" / "healthcheck.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestContainerProbe:
    def test_a_fresh_heartbeat_is_healthy(self, probe: ModuleType, heartbeat: Path) -> None:
        liveness.touch()
        assert probe.heartbeat_is_fresh(str(heartbeat), 90)

    def test_a_stale_heartbeat_is_unhealthy(self, probe: ModuleType, heartbeat: Path) -> None:
        liveness.touch()
        _age(heartbeat, 91)
        assert not probe.heartbeat_is_fresh(str(heartbeat), 90)

    def test_no_heartbeat_yet_is_unhealthy(self, probe: ModuleType, tmp_path: Path) -> None:
        assert not probe.heartbeat_is_fresh(str(tmp_path / "never-written"), 90)

    def test_settings_never_mistake_the_heartbeat_path_for_a_secret_file(
        self, heartbeat: Path
    ) -> None:
        # "*_FILE" variables are read as secret files at startup; a heartbeat
        # variable with that suffix would crash every worker before its first beat.
        assert not HEARTBEAT_PATH_ENV.endswith("_FILE")

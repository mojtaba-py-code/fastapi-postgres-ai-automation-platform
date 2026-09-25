"""Task failure policy: validation, retries, compensation and dead letters."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import structlog

from nexusflow.apps.workers import messages as m
from nexusflow.apps.workers import tasks as tasks_module
from nexusflow.apps.workers.runtime import ProcessRuntime
from nexusflow.apps.workers.tasks import TaskSpec, _execute
from nexusflow.core.errors import InvalidInputError, NotFoundError, TransientError
from nexusflow.domain.shared.outbox import TaskName


class RetryRequestedError(Exception):
    pass


TASK_ID = "0192f0c1-7a2b-7c3d-8e4f-5a6b7c8d9e0f"  # Celery task IDs are outbox message IDs


class FakeTask:
    def __init__(self, retries: int) -> None:
        self.request = SimpleNamespace(retries=retries, id=TASK_ID)
        self.countdowns: list[float] = []

    def retry(self, *, exc: BaseException, countdown: float) -> RetryRequestedError:
        self.countdowns.append(countdown)
        return RetryRequestedError(str(exc))


@dataclass
class FakeDeadLetters:
    recorded: list[dict[str, Any]] = field(default_factory=list)

    async def record(self, **kwargs: Any) -> None:
        self.recorded.append(kwargs)


@dataclass
class FakeDeps:
    container: Any


def _runtime() -> tuple[ProcessRuntime[Any], FakeDeadLetters]:
    letters = FakeDeadLetters()
    deps = FakeDeps(container=SimpleNamespace(dead_letters=letters))

    async def close(_: Any) -> None:
        return None

    return ProcessRuntime(lambda: deps, close), letters


def _spec(handler: Any, **overrides: Any) -> TaskSpec[m.RunMessage]:
    values: dict[str, Any] = {
        "name": "test.task",
        "model": m.RunMessage,
        "handler": handler,
        "dead_letter_as": TaskName.COLLECT_SOURCE,
        "retries": 2,
        "reference": ("collection_run", "run_id"),
    }
    values.update(overrides)
    return TaskSpec(**values)


def _kwargs() -> dict[str, str]:
    return {"org_id": str(uuid4()), "run_id": str(uuid4())}


def test_invalid_messages_are_rejected_without_running() -> None:
    runtime, letters = _runtime()
    calls: list[Any] = []

    async def handler(deps: Any, msg: Any) -> None:
        calls.append(msg)

    try:
        _execute(
            FakeTask(0), runtime, _spec(handler), {"org_id": "not-a-uuid", "run_id": str(uuid4())}
        )
        _execute(FakeTask(0), runtime, _spec(handler), {**_kwargs(), "sql": "DROP TABLE x"})
    finally:
        runtime.close()
    assert calls == []
    assert letters.recorded == []


def test_moot_work_is_acknowledged_quietly() -> None:
    runtime, letters = _runtime()

    async def handler(deps: Any, msg: Any) -> None:
        raise NotFoundError()

    try:
        _execute(FakeTask(0), runtime, _spec(handler), _kwargs())
    finally:
        runtime.close()
    assert letters.recorded == []


def test_transient_errors_retry_with_backoff_then_dead_letter() -> None:
    runtime, letters = _runtime()
    compensated: list[str] = []

    async def handler(deps: Any, msg: Any) -> None:
        raise TransientError(
            "Upstream unavailable.", code="upstream_down", internal_detail="10.0.0.5:5432"
        )

    async def compensate(container: Any, msg: Any, code: str) -> None:
        compensated.append(code)

    spec = _spec(handler, on_give_up=compensate)
    try:
        task = FakeTask(0)
        with pytest.raises(RetryRequestedError):
            _execute(task, runtime, spec, _kwargs())
        assert task.countdowns and task.countdowns[0] > 0
        kwargs = _kwargs()
        _execute(FakeTask(2), runtime, spec, kwargs)  # retry budget exhausted
    finally:
        runtime.close()
    assert compensated == ["upstream_down"]
    [letter] = letters.recorded
    assert letter["task_name"] == TaskName.COLLECT_SOURCE  # retryable through the API
    assert letter["reference_id"] == kwargs["run_id"]
    assert letter["error_message"] == "Upstream unavailable."
    assert "10.0.0.5" not in str(letter)  # internal detail stays in the logs


def test_unexpected_errors_never_leak_their_text() -> None:
    runtime, letters = _runtime()

    async def handler(deps: Any, msg: Any) -> None:
        raise ValueError("SELECT * FROM users WHERE email='victim@example.com'")

    try:
        _execute(FakeTask(2), runtime, _spec(handler), _kwargs())
    finally:
        runtime.close()
    [letter] = letters.recorded
    assert letter["error_code"] == "unexpected_error"
    assert letter["error_message"] == "ValueError"


def test_permanent_errors_are_not_retried() -> None:
    runtime, letters = _runtime()

    async def handler(deps: Any, msg: Any) -> None:
        raise InvalidInputError("Bad config.", code="bad_config")

    task = FakeTask(0)
    try:
        _execute(task, runtime, _spec(handler), _kwargs())
    finally:
        runtime.close()
    assert task.countdowns == []
    assert [letter["error_code"] for letter in letters.recorded] == ["bad_config"]


def test_periodic_failures_do_not_create_dead_letters() -> None:
    runtime, letters = _runtime()

    async def handler(deps: Any, msg: Any) -> None:
        raise InvalidInputError("nope", code="nope")

    spec: TaskSpec[m.Empty] = TaskSpec("test.periodic", m.Empty, handler, retries=0, periodic=True)
    try:
        _execute(FakeTask(0), runtime, spec, {})
    finally:
        runtime.close()
    assert letters.recorded == []


class RecordingLog:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def _record(self, event: str, **fields: Any) -> None:
        self.events.append((event, fields))

    info = warning = error = _record


def test_every_log_line_of_a_task_carries_its_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, _ = _runtime()
    log = RecordingLog()
    monkeypatch.setattr(tasks_module, "_log", log)
    seen: dict[str, Any] = {}
    kwargs = _kwargs()

    async def handler(deps: Any, msg: Any) -> None:
        seen.update(structlog.contextvars.get_contextvars())

    try:
        _execute(FakeTask(0), runtime, _spec(handler), kwargs)
    finally:
        runtime.close()
    assert seen == {
        "task": "test.task",
        "task_id": TASK_ID,
        "org_id": kwargs["org_id"],
        "request_id": TASK_ID,  # a job without a request correlates with itself
    }
    # The binding does not leak into whatever the process logs next.
    assert "task" not in structlog.contextvars.get_contextvars()
    [finished] = [fields for event, fields in log.events if event == "task_finished"]
    assert finished["status"] == "success"
    assert finished["attempt"] == 1
    assert finished["duration_ms"] >= 0

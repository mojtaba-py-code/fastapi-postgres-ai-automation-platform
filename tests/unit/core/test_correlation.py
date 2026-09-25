"""Request correlation: bound per request or job, carried by every message it causes."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import structlog

from nexusflow.apps.workers import messages as m
from nexusflow.apps.workers import sandbox as sandbox_module
from nexusflow.apps.workers.runtime import ProcessRuntime
from nexusflow.apps.workers.tasks import TaskSpec, _execute
from nexusflow.core.correlation import (
    CORRELATION_KWARG,
    correlation,
    current_correlation_id,
    valid_correlation_id,
)
from nexusflow.domain.shared.outbox import TaskName, new_message
from nexusflow.infrastructure.messaging.outbox import CeleryDispatcher

NOW = datetime(2026, 9, 25, 9, 0, tzinfo=UTC)
REQUEST_ID = "0192f0c1-7a2b-7c3d-8e4f-5a6b7c8d9e0f"


class TestIdentifiers:
    @pytest.mark.parametrize("value", [REQUEST_ID, "cli-0192f0c1", "req.2026:09_25-x"])
    def test_well_formed_identifiers_are_kept(self, value: str) -> None:
        assert valid_correlation_id(value) == value

    @pytest.mark.parametrize(
        "value",
        [None, "", "short", "x" * 65, "with space-1", "newline\ninject", 12345678, b"bytes-123"],
    )
    def test_anything_else_is_dropped(self, value: object) -> None:
        assert valid_correlation_id(value) is None

    def test_binding_is_scoped_and_nests(self) -> None:
        assert current_correlation_id() is None
        with correlation(REQUEST_ID) as outer:
            assert outer == current_correlation_id() == REQUEST_ID
            with correlation("inner-request-1"):
                assert current_correlation_id() == "inner-request-1"
            assert current_correlation_id() == REQUEST_ID
        assert current_correlation_id() is None

    def test_a_malformed_value_binds_nothing(self) -> None:
        with correlation("bad value") as bound:
            assert bound is None
            assert current_correlation_id() is None


class TestMessages:
    def test_every_outbox_message_is_built_by_the_one_constructor(self) -> None:
        """A message built by hand would lose the correlation (and any later invariant)."""
        src = Path(__file__).resolve().parents[3] / "src" / "nexusflow"
        constructor = src / "domain" / "shared" / "outbox.py"
        offenders = [
            path.relative_to(src).as_posix()
            for path in src.rglob("*.py")
            if path != constructor and "OutboxMessage(" in path.read_text(encoding="utf-8")
        ]
        assert offenders == []

    def test_outbox_messages_carry_the_bound_correlation(self) -> None:
        with correlation(REQUEST_ID):
            message = new_message(TaskName.DETECT_CHANGES, {}, org_id=uuid4(), now=NOW)
        assert message.correlation_id == REQUEST_ID
        assert new_message(TaskName.DETECT_CHANGES, {}, org_id=None, now=NOW).correlation_id is None


class RecordingCelery:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send_task(self, name: str, **options: Any) -> None:
        self.sent.append({"name": name, **options})


class TestDispatcher:
    def test_a_message_hands_its_correlation_to_the_worker(self) -> None:
        celery = RecordingCelery()
        with correlation(REQUEST_ID):
            message = new_message(
                TaskName.DETECT_CHANGES, {"dataset_id": "d-1"}, org_id=uuid4(), now=NOW
            )
        CeleryDispatcher(celery).send(message)  # type: ignore[arg-type]
        [sent] = celery.sent
        assert sent["kwargs"] == {"dataset_id": "d-1", CORRELATION_KWARG: REQUEST_ID}
        assert sent["task_id"] == str(message.id)

    def test_a_message_without_correlation_sends_its_payload_only(self) -> None:
        celery = RecordingCelery()
        message = new_message(TaskName.DETECT_CHANGES, {"dataset_id": "d-1"}, org_id=None, now=NOW)
        CeleryDispatcher(celery).send(message)  # type: ignore[arg-type]
        assert celery.sent[0]["kwargs"] == {"dataset_id": "d-1"}

    def test_direct_hand_offs_carry_the_current_correlation(self) -> None:
        celery = RecordingCelery()
        dispatcher = CeleryDispatcher(celery)  # type: ignore[arg-type]
        with correlation(REQUEST_ID):
            dispatcher.send_task("sandbox.website", kwargs={"run_id": "r-1"}, queue="sandbox")
        dispatcher.send_task("sandbox.website", kwargs={"run_id": "r-2"}, queue="sandbox")
        assert [s["kwargs"] for s in celery.sent] == [
            {"run_id": "r-1", CORRELATION_KWARG: REQUEST_ID},
            {"run_id": "r-2"},
        ]


class FakeTask:
    def __init__(self, task_id: str) -> None:
        self.request = SimpleNamespace(retries=0, id=task_id)


def _runtime() -> ProcessRuntime[Any]:
    async def close(_: Any) -> None:
        return None

    return ProcessRuntime(lambda: SimpleNamespace(container=None), close)


class TestWorkers:
    def _run(self, kwargs: dict[str, Any], task_id: str) -> dict[str, Any]:
        seen: dict[str, Any] = {}

        async def handler(deps: Any, message: m.RunMessage) -> None:
            seen["message"] = message
            seen["correlation"] = current_correlation_id()
            seen["log_context"] = structlog.contextvars.get_contextvars()

        spec = TaskSpec(name="test.task", model=m.RunMessage, handler=handler)
        runtime = _runtime()
        try:
            _execute(FakeTask(task_id), runtime, spec, kwargs)  # type: ignore[arg-type]
        finally:
            runtime.close()
        return seen

    def test_the_job_runs_under_the_correlation_of_its_request(self) -> None:
        payload = {"org_id": str(uuid4()), "run_id": str(uuid4())}
        seen = self._run({**payload, CORRELATION_KWARG: REQUEST_ID}, str(uuid4()))
        assert str(seen["message"].run_id) == payload["run_id"]  # the key never reaches the model
        assert seen["correlation"] == REQUEST_ID
        assert seen["log_context"]["request_id"] == REQUEST_ID

    def test_a_scheduled_job_correlates_what_it_causes_with_itself(self) -> None:
        task_id = str(uuid4())
        seen = self._run({"org_id": str(uuid4()), "run_id": str(uuid4())}, task_id)
        assert seen["correlation"] == task_id

    def test_a_forged_correlation_is_ignored(self) -> None:
        task_id = str(uuid4())
        kwargs = {"org_id": str(uuid4()), "run_id": str(uuid4()), CORRELATION_KWARG: "x\n{evil}"}
        assert self._run(kwargs, task_id)["correlation"] == task_id

    def test_the_sandbox_strips_the_correlation_before_validating_its_job(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        validated: list[dict[str, Any]] = []

        def job_runner(*args: Any) -> None:
            validated.append(args[-1])

        monkeypatch.setattr(sandbox_module, "_execute_job", job_runner)
        sandbox_module._execute(
            FakeTask(str(uuid4())),  # type: ignore[arg-type]
            _runtime(),
            "sandbox.website",
            sandbox_module.WebsiteJob,
            sandbox_module.collect_website,
            {"run_id": "r-1", CORRELATION_KWARG: REQUEST_ID},
        )
        assert validated == [{"run_id": "r-1"}]

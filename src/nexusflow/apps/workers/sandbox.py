"""Sandbox worker: fetches and parses untrusted content.

    celery -A nexusflow.apps.workers.sandbox:celery_app worker -Q sandbox

Runs with internet egress but without database, storage, key material or
provider credentials (see :mod:`nexusflow.bootstrap.sandbox`). Every job
carries a per-run ticket - the process's only credential - used to fetch the
run's input and to return its result through the internal gateway. Deployed
read-only, non-root, with a seccomp profile and memory/CPU limits.
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from uuid import UUID

import structlog
from celery import Celery, Task
from celery.signals import worker_init, worker_process_init, worker_process_shutdown
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from nexusflow.apps.workers.observability import (
    setup_worker_observability,
    setup_worker_tracing,
)
from nexusflow.apps.workers.runtime import ProcessRuntime
from nexusflow.bootstrap.sandbox import SandboxComponents, build_sandbox
from nexusflow.core.config import SandboxSettings
from nexusflow.core.correlation import CORRELATION_KWARG, valid_correlation_id
from nexusflow.core.errors import NexusFlowError, PermanentError, TransientError
from nexusflow.core.resilience import backoff_delay
from nexusflow.domain.sources.model import FileUploadConfig, WebsiteConfig
from nexusflow.domain.uploads.model import inspect_file
from nexusflow.infrastructure.files.parsers import parse_upload
from nexusflow.infrastructure.messaging.celery_app import (
    SANDBOX_UPLOAD_TASK,
    SANDBOX_WEBSITE_TASK,
    build_celery,
)
from nexusflow.infrastructure.observability.logging import get_logger
from nexusflow.infrastructure.observability.metrics import TASK_DURATION, TASKS

_log = get_logger("nexusflow.sandbox")
_RETRIES = 3


class _Job(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    org_id: UUID
    run_id: UUID
    ticket: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)
    allowed_domains: list[str] | None = Field(default=None, max_length=200)
    max_items: int = Field(ge=1, le=1_000_000)
    limits: dict[str, int] = Field(default_factory=dict, max_length=10)


class WebsiteJob(_Job):
    config: WebsiteConfig  # re-validated here: defence in depth


class UploadJob(_Job):
    config: FileUploadConfig


async def collect_website(parts: SandboxComponents, job: WebsiteJob) -> None:
    policy = parts.url_policy.with_allowed_domains(job.allowed_domains)
    try:
        collected = await parts.website.collect(job.config, policy=policy, max_items=job.max_items)
    except TransientError:
        raise
    except NexusFlowError as exc:  # blocked URL, robots.txt, 4xx, wrong content type...
        await parts.gateway.submit(job.org_id, job.run_id, ticket=job.ticket, error_code=exc.code)
        return
    await parts.gateway.submit(
        job.org_id,
        job.run_id,
        ticket=job.ticket,
        items=collected.items,
        truncated=collected.truncated,
        detail=collected.detail,
    )


async def parse_uploaded_file(parts: SandboxComponents, job: UploadJob) -> None:
    storage = parts.settings.storage
    max_rows = min(job.limits.get("max_rows", storage.max_upload_rows), storage.max_upload_rows)
    max_columns = min(
        job.limits.get("max_columns", storage.max_upload_columns), storage.max_upload_columns
    )
    with tempfile.TemporaryDirectory(prefix="nf-sandbox-") as workdir:
        path = Path(workdir) / "input"
        fmt = await parts.gateway.download_input(
            job.org_id,
            job.run_id,
            ticket=job.ticket,
            destination=path,
            max_bytes=storage.max_upload_bytes,
        )
        try:
            if fmt != job.config.format:
                raise PermanentError(code="type_mismatch")
            await asyncio.to_thread(inspect_file, path, expected=fmt)
            parsed = await asyncio.to_thread(
                parse_upload, path, job.config, max_rows=max_rows, max_columns=max_columns
            )
        except NexusFlowError as exc:
            await parts.gateway.submit(
                job.org_id, job.run_id, ticket=job.ticket, error_code=exc.code
            )
            return
    await parts.gateway.submit(
        job.org_id,
        job.run_id,
        ticket=job.ticket,
        items=parsed.items,
        truncated=parsed.truncated,
        detail={"rows": parsed.rows},
    )


def _execute[J: _Job](
    task: Task[Any, Any],
    runtime: ProcessRuntime[SandboxComponents],
    name: str,
    model: type[J],
    handler: Callable[[SandboxComponents, J], Awaitable[None]],
    kwargs: dict[str, Any],
) -> None:
    kwargs = dict(kwargs)
    correlation_id = valid_correlation_id(kwargs.pop(CORRELATION_KWARG, None))
    with structlog.contextvars.bound_contextvars(
        task=name, task_id=task.request.id, request_id=correlation_id
    ):
        _execute_job(task, runtime, name, model, handler, kwargs)


def _execute_job[J: _Job](
    task: Task[Any, Any],
    runtime: ProcessRuntime[SandboxComponents],
    name: str,
    model: type[J],
    handler: Callable[[SandboxComponents, J], Awaitable[None]],
    kwargs: dict[str, Any],
) -> None:
    started = time.monotonic()
    result = "success"
    try:
        try:
            job = model.model_validate(kwargs)
        except ValidationError as exc:
            result = "rejected"
            _log.error("sandbox_job_rejected", task=name, errors=exc.error_count())
            return
        try:
            runtime.run(lambda parts: handler(parts, job))
        except PermanentError as exc:
            result = "moot" if exc.code == "run_closed" else "failed"
            _log.warning(
                "sandbox_job_stopped", task=name, error_code=exc.code, run_id=str(job.run_id)
            )
        except Exception as exc:
            if task.request.retries < _RETRIES:
                result = "retry"
                countdown = backoff_delay(
                    task.request.retries + 1, base_seconds=20, cap_seconds=600
                )
                raise task.retry(exc=exc, countdown=countdown) from exc
            result = "failed"
            code = exc.code if isinstance(exc, NexusFlowError) else "sandbox_error"
            _log.error(
                "sandbox_job_failed", task=name, error=type(exc).__name__, run_id=str(job.run_id)
            )
            try:
                runtime.run(
                    lambda parts: parts.gateway.submit(
                        job.org_id, job.run_id, ticket=job.ticket, error_code=code
                    )
                )
            except Exception as report_error:  # noqa: BLE001 - the reaper will recover the run
                _log.error("sandbox_report_failed", task=name, error=type(report_error).__name__)
    finally:
        TASKS.labels(task=name, result=result).inc()
        TASK_DURATION.labels(task=name).observe(time.monotonic() - started)


def create_sandbox_app(
    settings: SandboxSettings,
) -> tuple[Celery, ProcessRuntime[SandboxComponents]]:
    app = build_celery(settings.broker, role="sandbox")

    async def close(parts: SandboxComponents) -> None:
        await parts.aclose()

    runtime: ProcessRuntime[SandboxComponents] = ProcessRuntime(
        lambda: build_sandbox(settings), close
    )

    def website(self: Task[Any, Any], /, **kwargs: Any) -> None:
        _execute(self, runtime, SANDBOX_WEBSITE_TASK, WebsiteJob, collect_website, kwargs)

    def upload(self: Task[Any, Any], /, **kwargs: Any) -> None:
        _execute(self, runtime, SANDBOX_UPLOAD_TASK, UploadJob, parse_uploaded_file, kwargs)

    app.task(name=SANDBOX_WEBSITE_TASK, bind=True, max_retries=_RETRIES, ignore_result=True)(
        website
    )
    app.task(name=SANDBOX_UPLOAD_TASK, bind=True, max_retries=_RETRIES, ignore_result=True)(upload)
    return app, runtime


settings = SandboxSettings()
celery_app, _runtime = create_sandbox_app(settings)


@worker_init.connect
def _on_worker_init(**_: Any) -> None:
    setup_worker_observability(settings.observability, service=f"{settings.app.name}-sandbox")


@worker_process_init.connect
def _on_process_init(**_: Any) -> None:
    setup_worker_tracing(settings.observability, service=f"{settings.app.name}-sandbox")


@worker_process_shutdown.connect
def _on_process_shutdown(**_: Any) -> None:
    _runtime.close()

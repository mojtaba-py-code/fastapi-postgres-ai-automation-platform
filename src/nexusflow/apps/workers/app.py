"""Platform worker entry point: ``pipeline`` and ``integrations`` pools, and beat.

    celery -A nexusflow.apps.workers.app:celery_app worker -Q pipeline
    celery -A nexusflow.apps.workers.app:celery_app worker -Q integrations
    celery -A nexusflow.apps.workers.app:celery_app beat

The two pools run the same code with different network access and secrets
(see docker-compose): ``pipeline`` has the database but no internet egress;
``integrations`` additionally reaches external APIs, AI and messaging
providers. Untrusted content is never parsed here - that is the sandbox's job.
"""

from __future__ import annotations

import os
from typing import Any

from celery import Celery
from celery.signals import worker_init, worker_process_init, worker_process_shutdown

from nexusflow.apps.workers.handlers import WorkerDeps
from nexusflow.apps.workers.observability import (
    forget_worker_process,
    setup_worker_observability,
    setup_worker_tracing,
)
from nexusflow.apps.workers.runtime import ProcessRuntime
from nexusflow.apps.workers.tasks import PLATFORM_TASKS, register_tasks
from nexusflow.bootstrap.container import build_container
from nexusflow.bootstrap.messaging import attach_outbox_publisher
from nexusflow.core.config import Settings
from nexusflow.infrastructure.messaging.celery_app import beat_schedule, build_celery


def create_worker_app(settings: Settings) -> tuple[Celery, ProcessRuntime[WorkerDeps]]:
    internal = settings.n8n.orchestration == "internal" or settings.n8n.webhook_jwt_secret is None
    app = build_celery(settings.broker, schedule=beat_schedule(internal_orchestration=internal))

    def build() -> WorkerDeps:
        container = build_container(settings, application_name="nexusflow-worker")
        dispatcher = attach_outbox_publisher(container, app)
        return WorkerDeps(container=container, dispatcher=dispatcher)

    async def close(deps: WorkerDeps) -> None:
        await deps.container.aclose()

    runtime: ProcessRuntime[WorkerDeps] = ProcessRuntime(build, close)
    register_tasks(app, runtime, PLATFORM_TASKS)
    return app, runtime


settings = Settings()
celery_app, _runtime = create_worker_app(settings)


@worker_init.connect
def _on_worker_init(**_: Any) -> None:
    setup_worker_observability(settings.observability, service=f"{settings.app.name}-worker")


@worker_process_init.connect
def _on_process_init(**_: Any) -> None:
    setup_worker_tracing(settings.observability, service=f"{settings.app.name}-worker")


@worker_process_shutdown.connect
def _on_process_shutdown(pid: int | None = None, **_: Any) -> None:
    _runtime.close()
    forget_worker_process(pid or os.getpid())

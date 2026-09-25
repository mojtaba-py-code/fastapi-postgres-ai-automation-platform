"""Celery application: queues, routing and hardened defaults.

* JSON only (``accept_content=["json"]``) - pickle is never accepted, so a
  broker compromise cannot become remote code execution via deserialization.
* ``acks_late`` + ``reject_on_worker_lost`` + prefetch 1: a job is only removed
  from the queue once processed; crashed workers do not lose work. Handlers are
  idempotent, so redelivery is safe.
* Quorum queues with a delivery limit and a dead-letter exchange: poison
  messages cannot loop forever.
* Hard/soft time limits and per-child task/memory limits contain runaway jobs.
* No result backend: task results are persisted in PostgreSQL by the handlers.

Queues map to separately deployed, separately privileged worker pools:
``pipeline`` (database, no internet), ``integrations`` (database + egress for
APIs, AI and notifications) and ``sandbox`` (internet egress, *no* database,
no secrets - it parses hostile HTML and files).
"""

from __future__ import annotations

import ssl
from typing import Any, Literal
from urllib.parse import urlsplit

from celery import Celery
from kombu import Exchange, Queue

from nexusflow.core.config import BrokerSettings
from nexusflow.domain.shared.outbox import TaskName
from nexusflow.infrastructure.messaging.liveness import ConsumerHeartbeat

PIPELINE, INTEGRATIONS, SANDBOX = "pipeline", "integrations", "sandbox"

TASK_ROUTES: dict[TaskName, tuple[str, str]] = {
    # Every collection run starts at the dispatcher, which decides where it
    # executes (sandbox, integrations pool or direct ingestion of staged data).
    TaskName.COLLECT_SOURCE: ("nexusflow.collect.dispatch", PIPELINE),
    TaskName.PROCESS_UPLOAD: ("nexusflow.collect.dispatch", PIPELINE),
    TaskName.PROCESS_WEBHOOK_EVENT: ("nexusflow.collect.dispatch", PIPELINE),
    TaskName.DETECT_CHANGES: ("nexusflow.detection.detect", PIPELINE),
    TaskName.ANALYZE_CHANGES: ("nexusflow.intelligence.analyze", INTEGRATIONS),
    TaskName.EVALUATE_ALERTS: ("nexusflow.alerts.evaluate", PIPELINE),
    TaskName.DELIVER_NOTIFICATION: ("nexusflow.notifications.deliver", INTEGRATIONS),
    TaskName.GENERATE_REPORT: ("nexusflow.reports.generate", PIPELINE),
    TaskName.SEND_SECURITY_EMAIL: ("nexusflow.security.notify", INTEGRATIONS),
    TaskName.SEND_INVITATION: ("nexusflow.security.invitation", INTEGRATIONS),
    TaskName.SEND_PASSWORD_RESET: ("nexusflow.security.password_reset", INTEGRATIONS),
    TaskName.SEND_SIGNUP_LINK: ("nexusflow.security.signup_link", INTEGRATIONS),
    TaskName.OPERATOR_ALERT: ("nexusflow.operators.alert", INTEGRATIONS),
    TaskName.PURGE_ORGANIZATION: ("nexusflow.maintenance.purge_organizations", PIPELINE),
    TaskName.PURGE_DATASET: ("nexusflow.maintenance.purge_dataset", PIPELINE),
    TaskName.WORKFLOW_EVENT: ("nexusflow.events.route", PIPELINE),
}

# Tasks that are not produced by the outbox.
SANDBOX_WEBSITE_TASK = "nexusflow.sandbox.collect_website"
SANDBOX_UPLOAD_TASK = "nexusflow.sandbox.parse_upload"
EXTRA_ROUTES: dict[str, str] = {
    SANDBOX_WEBSITE_TASK: SANDBOX,
    SANDBOX_UPLOAD_TASK: SANDBOX,
    "nexusflow.collect.rest_api": INTEGRATIONS,
    "nexusflow.automation.dispatch": PIPELINE,
    "nexusflow.automation.sweep": PIPELINE,
    "nexusflow.outbox.relay": PIPELINE,
    "nexusflow.maintenance.retention": PIPELINE,
    "nexusflow.maintenance.reap": PIPELINE,
    "nexusflow.maintenance.expire_reports": PIPELINE,
    "nexusflow.maintenance.outbox_cleanup": PIPELINE,
    "nexusflow.maintenance.rewrap_keys": PIPELINE,
    "nexusflow.audit.anchor": PIPELINE,
    "nexusflow.audit.verify": PIPELINE,
    "nexusflow.events.forward": INTEGRATIONS,
}


def beat_schedule(*, internal_orchestration: bool) -> dict[str, dict[str, Any]]:
    """Periodic jobs. Scheduled workflow dispatch and the detection sweep run
    here only when the platform orchestrates itself; otherwise n8n triggers
    them (workflows 1 and 2)."""
    schedule: dict[str, dict[str, Any]] = {
        "outbox-relay": {"task": "nexusflow.outbox.relay", "schedule": 10.0},
        "reap-stuck-work": {"task": "nexusflow.maintenance.reap", "schedule": 300.0},
        "expire-reports": {"task": "nexusflow.maintenance.expire_reports", "schedule": 3600.0},
        "purge-deleted-organizations": {
            "task": "nexusflow.maintenance.purge_organizations",
            "schedule": 3600.0,
        },
        "retention": {"task": "nexusflow.maintenance.retention", "schedule": 86_400.0},
        "outbox-cleanup": {"task": "nexusflow.maintenance.outbox_cleanup", "schedule": 86_400.0},
        "rewrap-keys": {"task": "nexusflow.maintenance.rewrap_keys", "schedule": 86_400.0},
        "audit-anchor": {"task": "nexusflow.audit.anchor", "schedule": 3600.0},
        "audit-verify": {"task": "nexusflow.audit.verify", "schedule": 86_400.0},
    }
    if internal_orchestration:
        schedule["dispatch-due-workflows"] = {
            "task": "nexusflow.automation.dispatch",
            "schedule": 60.0,
        }
        schedule["detection-sweep"] = {"task": "nexusflow.automation.sweep", "schedule": 300.0}
    return schedule


# The sandbox queue is the only one an untrusted component can publish to
# (Celery retries re-publish), so it is bounded: a flood is refused at the
# queue instead of driving the whole broker into a memory/disk alarm.
SANDBOX_QUEUE_LIMITS: dict[str, Any] = {
    "x-max-length": 10_000,
    "x-max-length-bytes": 64 * 1024 * 1024,
    "x-overflow": "reject-publish",
}


def queue_arguments(name: str) -> dict[str, Any]:
    """Arguments of a work queue - identical here and in the broker definitions."""
    arguments: dict[str, Any] = {
        "x-queue-type": "quorum",
        "x-delivery-limit": 10,
        "x-dead-letter-exchange": "nexusflow.dlx",
        "x-dead-letter-routing-key": f"{name}.dead",
    }
    if name == SANDBOX:
        arguments.update(SANDBOX_QUEUE_LIMITS)
    return arguments


def _queue(name: str, exchange: Exchange, *, declare: bool = True) -> Queue:
    return Queue(
        name,
        exchange,
        routing_key=name,
        durable=True,
        queue_arguments=queue_arguments(name),
        no_declare=not declare,
    )


def build_celery(
    broker: BrokerSettings,
    *,
    schedule: dict[str, dict[str, Any]] | None = None,
    role: Literal["platform", "sandbox"] = "platform",
) -> Celery:
    """Build the Celery app of the platform pools or of the sandbox pool.

    The sandbox role never declares anything (queues, exchanges and bindings
    are pre-declared from the broker definitions) and has no remote control
    or events. Its broker account therefore needs *no* configure rights: it
    reads its own queue and writes to its own exchange, which is bound to that
    queue alone - it can neither create a queue that taps other jobs nor send
    work to the pipeline or integrations pools.
    """
    app = Celery("nexusflow", set_as_current=False)
    sandboxed = role == "sandbox"
    # A topic exchange lets RabbitMQ hold delayed retries (Celery's native
    # delayed delivery for quorum queues). With a direct exchange a worker
    # would keep each retry in memory until it is due, occupying one of its
    # few prefetch slots - an outage of one integration could stall a pool.
    exchange = Exchange("nexusflow", type="topic", durable=True)
    # The sandbox's exchange stays direct: its account may publish to it alone,
    # never to the shared delayed-delivery exchanges that route to every pool.
    # Its retries are short (at most 3, about 20-100 s apart).
    sandbox_exchange = Exchange(
        "nexusflow.sandbox", type="direct", durable=True, no_declare=sandboxed
    )
    routes: dict[str, dict[str, str]] = {
        name: {"queue": queue} for name, queue in TASK_ROUTES.values()
    }
    routes.update({name: {"queue": queue} for name, queue in EXTRA_ROUTES.items()})
    queues = (
        (_queue(SANDBOX, sandbox_exchange, declare=False),)
        if sandboxed
        else (
            _queue(PIPELINE, exchange),
            _queue(INTEGRATIONS, exchange),
            _queue(SANDBOX, sandbox_exchange),
        )
    )
    if sandboxed:
        routes = {name: route for name, route in routes.items() if route["queue"] == SANDBOX}
    config: dict[str, Any] = {
        "broker_url": broker.url.get_secret_value(),
        "broker_connection_retry_on_startup": True,
        "broker_transport_options": {"confirm_publish": True},
        "task_serializer": "json",
        "result_serializer": "json",
        "accept_content": ["json"],
        "event_serializer": "json",
        "result_backend": None,
        "task_ignore_result": True,
        "task_acks_late": True,
        "task_reject_on_worker_lost": True,
        "worker_prefetch_multiplier": 1,
        "worker_detect_quorum_queues": True,
        "task_time_limit": 900,
        "task_soft_time_limit": 840,
        # Sandbox: a fresh child process per job, so state (or an exploit)
        # never carries over from one tenant's job to the next in-process.
        # Platform pools recycle rarely: every child leaves its metric files
        # behind (prometheus multiprocess mode), and the memory cap below
        # already guards against leaks.
        "worker_max_tasks_per_child": 1 if sandboxed else 10_000,
        # KiB. Four children and the parent stay under the pools' 1 GB limit;
        # Docker would kill the whole container before Celery recycled one.
        "worker_max_memory_per_child": 200_000,
        "worker_hijack_root_logger": False,
        "worker_redirect_stdouts": False,
        "task_default_queue": SANDBOX if sandboxed else PIPELINE,
        "task_default_exchange": "nexusflow.sandbox" if sandboxed else "nexusflow",
        "task_default_routing_key": SANDBOX if sandboxed else PIPELINE,
        "task_create_missing_queues": False,
        "task_queues": queues,
        "task_routes": routes,
        "timezone": "UTC",
        "enable_utc": True,
        "beat_schedule": schedule or {},
        "beat_scheduler": "nexusflow.infrastructure.messaging.liveness:HeartbeatScheduler",
        "worker_enable_remote_control": not sandboxed,
        "worker_send_task_events": False,
        "task_send_sent_event": False,
    }
    if broker.use_ssl:
        config["broker_use_ssl"] = {
            "cert_reqs": ssl.CERT_REQUIRED,
            "ca_certs": str(broker.ssl_ca_certs) if broker.ssl_ca_certs else None,
            # py-amqp checks the certificate's host name only when it is given
            # one: without it, any certificate from the CA would be accepted.
            "server_hostname": urlsplit(broker.url.get_secret_value()).hostname,
        }
    app.conf.update(config)
    # Liveness: the consumer (and beat, below) keep a heartbeat file fresh.
    app.steps["consumer"].add(ConsumerHeartbeat)
    return app

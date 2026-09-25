"""Broker topology and task registry stay consistent (and safe)."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType

from nexusflow.apps.workers.sandbox import create_sandbox_app
from nexusflow.apps.workers.tasks import PLATFORM_TASKS
from nexusflow.core.config import BrokerSettings, SandboxSettings
from nexusflow.domain.shared.outbox import TaskName
from nexusflow.infrastructure.messaging.celery_app import (
    EXTRA_ROUTES,
    SANDBOX,
    SANDBOX_UPLOAD_TASK,
    SANDBOX_WEBSITE_TASK,
    TASK_ROUTES,
    beat_schedule,
    build_celery,
    queue_arguments,
)

ROOT = Path(__file__).resolve().parents[3]


def test_every_outbox_task_is_routed_and_handled() -> None:
    handled = {spec.name for spec in PLATFORM_TASKS} | {SANDBOX_WEBSITE_TASK, SANDBOX_UPLOAD_TASK}
    assert set(TASK_ROUTES) == set(TaskName)
    routed = {name for name, _ in TASK_ROUTES.values()} | set(EXTRA_ROUTES)
    assert routed - handled == set(), "routed tasks without a handler"
    assert handled - routed == set(), "handlers that nothing routes to"


def test_every_scheduled_task_has_a_handler() -> None:
    handled = {spec.name for spec in PLATFORM_TASKS}
    for internal in (True, False):
        for entry in beat_schedule(internal_orchestration=internal).values():
            assert entry["task"] in handled


def test_broker_is_json_only_with_durable_quorum_queues() -> None:
    app = build_celery(BrokerSettings())
    assert app.conf.accept_content == ["json"]
    assert app.conf.task_serializer == "json"
    assert app.conf.task_acks_late is True
    for queue in app.conf.task_queues:
        assert queue.queue_arguments["x-queue-type"] == "quorum"
        assert queue.queue_arguments["x-dead-letter-exchange"] == "nexusflow.dlx"


def test_sandbox_queue_is_isolated_on_its_own_exchange() -> None:
    queues = {queue.name: queue for queue in build_celery(BrokerSettings()).conf.task_queues}
    assert queues[SANDBOX].exchange.name == "nexusflow.sandbox"
    assert {queues[name].exchange.name for name in queues if name != SANDBOX} == {"nexusflow"}


def test_sandbox_app_registers_only_sandbox_tasks_without_remote_control() -> None:
    app, runtime = create_sandbox_app(SandboxSettings())
    try:
        own = {name for name in app.tasks if name.startswith("nexusflow.")}
        assert own == {SANDBOX_WEBSITE_TASK, SANDBOX_UPLOAD_TASK}
        assert app.conf.worker_enable_remote_control is False
    finally:
        runtime.close()


def _generate_secrets() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "generate_secrets", ROOT / "scripts" / "generate_secrets.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_broker_definitions_declare_exactly_what_celery_expects() -> None:
    # RabbitMQ refuses a re-declaration with different arguments, and the
    # sandbox worker never declares: both sides must agree to the byte.
    secrets_script = _generate_secrets()
    definitions = json.loads(secrets_script.rabbit_definitions("platform-pw", "sandbox-pw"))
    declared = {queue["name"]: queue["arguments"] for queue in definitions["queues"]}
    for queue in build_celery(BrokerSettings()).conf.task_queues:
        assert declared[queue.name] == queue.queue_arguments == queue_arguments(queue.name)
    assert declared[SANDBOX]["x-overflow"] == "reject-publish"  # bounded, never evicting


def test_exchange_types_agree_and_retries_are_held_by_the_broker() -> None:
    definitions = json.loads(_generate_secrets().rabbit_definitions("a", "b"))
    declared = {exchange["name"]: exchange["type"] for exchange in definitions["exchanges"]}
    exchanges = {
        queue.exchange.name: queue.exchange.type
        for queue in build_celery(BrokerSettings()).conf.task_queues
    }
    assert exchanges == {"nexusflow": "topic", "nexusflow.sandbox": "direct"}
    assert {name: declared[name] for name in exchanges} == exchanges
    # Topic: Celery's native delayed delivery keeps retries in RabbitMQ, not in
    # a worker's prefetch slots. The sandbox's direct exchange reaches its own
    # queue only (see test_sandbox_broker_user_can_neither_declare_nor_read_other_queues).
    assert declared["nexusflow.dlx"] == "direct"


def test_sandbox_broker_user_can_neither_declare_nor_read_other_queues() -> None:
    definitions = json.loads(_generate_secrets().rabbit_definitions("a", "b"))
    [sandbox] = [p for p in definitions["permissions"] if p["user"] == "sandbox"]
    assert sandbox["configure"] == "^$"
    assert sandbox["read"] == "^sandbox$"
    assert sandbox["write"] == r"^nexusflow\.sandbox$"


def test_sandbox_app_consumes_only_its_queue_and_declares_nothing() -> None:
    conf = build_celery(BrokerSettings(), role="sandbox").conf
    [queue] = conf.task_queues
    assert queue.name == SANDBOX
    assert queue.no_declare is True
    assert queue.exchange.name == "nexusflow.sandbox"
    assert queue.exchange.no_declare is True
    assert conf.worker_max_tasks_per_child == 1  # no state survives between jobs
    assert conf.task_default_queue == SANDBOX
    assert conf.worker_enable_remote_control is False


def test_no_worker_takes_remote_control_commands() -> None:
    # Unused, a command channel for any broker client, and its transient
    # reply queues are refused by RabbitMQ 4.3.
    assert (
        build_celery(BrokerSettings(), role="platform").conf.worker_enable_remote_control is False
    )


def test_every_secret_compose_mounts_is_generated() -> None:
    script = _generate_secrets()
    spec = importlib.util.spec_from_file_location("pki", ROOT / "scripts" / "internal_pki.py")
    assert spec is not None and spec.loader is not None
    pki = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pki)
    issued = {"internal_ca.pem"} | {
        f"tls_{service}{suffix}" for service in pki.SERVICES for suffix in (".pem", ".key")
    }
    generated = set(script.build()) | set(script.PLACEHOLDERS) | issued
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    referenced = set(re.findall(r"\./secrets/([a-z0-9_.]+)", compose))
    assert referenced == generated  # and internal_ca.key, the CA's key, is never mounted


def test_placeholders_are_created_empty_and_never_overwritten(tmp_path: Path) -> None:
    script = _generate_secrets()
    target = tmp_path / "secrets"
    assert script.main(["--dir", str(target)]) == 0
    assert (target / "n8n_api_key").read_text(encoding="utf-8") == ""
    (target / "n8n_api_key").write_text("filled-in-by-the-operator", encoding="utf-8")
    assert script.main(["--dir", str(target), "--force"]) == 0  # regenerate the rest
    assert (target / "n8n_api_key").read_text(encoding="utf-8") == "filled-in-by-the-operator"


def test_a_second_run_adds_only_what_is_missing(tmp_path: Path) -> None:
    # Review F-7: re-running used to refuse outright, and the "--force" it
    # suggested replaced every key - the database roles and encrypted data with them.
    script = _generate_secrets()
    target = tmp_path / "secrets"
    assert script.main(["--dir", str(target)]) == 0
    before = {p.name: p.read_bytes() for p in target.iterdir()}
    (target / "browser_token").unlink()  # e.g. a secret a newer release introduced

    assert script.main(["--dir", str(target)]) == 0

    after = {p.name: p.read_bytes() for p in target.iterdir()}
    assert set(after) == set(before)
    assert after["browser_token"] != before["browser_token"]  # created anew ...
    assert {k: v for k, v in after.items() if k != "browser_token"} == {
        k: v for k, v in before.items() if k != "browser_token"
    }  # ... and nothing else touched


def test_half_a_group_is_refused_not_repaired(tmp_path: Path) -> None:
    script = _generate_secrets()
    target = tmp_path / "secrets"
    assert script.main(["--dir", str(target)]) == 0
    (target / "db_app_url").unlink()  # the password alone would not match a new URL

    assert script.main(["--dir", str(target)]) == 1
    assert not (target / "db_app_url").exists()


def test_urls_from_before_internal_tls_are_upgraded_in_place(tmp_path: Path) -> None:
    script = _generate_secrets()
    target = tmp_path / "secrets"
    assert script.main(["--dir", str(target)]) == 0
    legacy = {
        "redis_app_url": "redis://app:pw1@redis:6379/0",
        "redis_sandbox_url": "redis://sandbox:pw2@redis-sandbox:6379/0",
        "broker_platform_url": "amqp://nexusflow:pw3@rabbitmq:5672/nexusflow",
        "broker_sandbox_url": "amqp://sandbox:pw4@rabbitmq:5672/nexusflow",
    }
    for name, value in legacy.items():
        (target / name).write_text(value, encoding="utf-8")

    assert script.main(["--dir", str(target), "--tls-urls"]) == 0
    assert script.main(["--dir", str(target), "--tls-urls"]) == 0  # idempotent

    assert (target / "redis_app_url").read_text() == "rediss://app:pw1@redis:6379/0"
    assert (target / "redis_sandbox_url").read_text() == "rediss://sandbox:pw2@redis-sandbox:6379/0"
    assert (target / "broker_platform_url").read_text() == (
        "amqps://nexusflow:pw3@rabbitmq:5671/nexusflow"
    )
    assert (
        target / "broker_sandbox_url"
    ).read_text() == "amqps://sandbox:pw4@rabbitmq:5671/nexusflow"

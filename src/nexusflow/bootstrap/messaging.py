"""Wires the transactional outbox to the Celery broker."""

from __future__ import annotations

from celery import Celery

from nexusflow.bootstrap.container import Container
from nexusflow.infrastructure.messaging.celery_app import build_celery
from nexusflow.infrastructure.messaging.outbox import CeleryDispatcher, OutboxPublisher, OutboxRelay


def attach_outbox_publisher(container: Container, celery: Celery | None = None) -> CeleryDispatcher:
    """Publish outbox messages right after commit (the relay covers failures)."""
    dispatcher = CeleryDispatcher(celery or build_celery(container.settings.broker))
    container.uow_factory.set_publisher(
        OutboxPublisher(dispatcher, container.uow_factory, container.clock)
    )
    return dispatcher


def build_relay(container: Container, dispatcher: CeleryDispatcher) -> OutboxRelay:
    return OutboxRelay(dispatcher, container.uow_factory, container.clock)

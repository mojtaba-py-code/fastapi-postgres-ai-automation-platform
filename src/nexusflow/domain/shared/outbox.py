"""Transactional outbox.

Services never publish to the message broker directly. They append an
``OutboxMessage`` inside the same database transaction as the state change; a
relay publishes committed messages afterwards. This guarantees that a job is
enqueued if and only if the triggering change was committed (no lost jobs on
broker outages, no phantom jobs for rolled-back transactions).

Payloads carry identifiers only - never secrets or tenant content - because
they transit the broker.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID

from nexusflow.core.correlation import current_correlation_id
from nexusflow.core.ids import uuid7
from nexusflow.core.jsonutil import JSONObject


class TaskName(StrEnum):
    COLLECT_SOURCE = "collection.run"
    PROCESS_UPLOAD = "collection.process_upload"
    PROCESS_WEBHOOK_EVENT = "collection.process_webhook_event"
    DETECT_CHANGES = "detection.detect"
    ANALYZE_CHANGES = "intelligence.analyze"
    EVALUATE_ALERTS = "alerts.evaluate"
    DELIVER_NOTIFICATION = "notifications.deliver"
    GENERATE_REPORT = "reports.generate"
    SEND_SECURITY_EMAIL = "security.send_email"
    SEND_INVITATION = "security.send_invitation"
    SEND_PASSWORD_RESET = "security.send_password_reset"  # noqa: S105 - task name  # nosec B105
    SEND_SIGNUP_LINK = "security.send_signup_link"
    OPERATOR_ALERT = "operators.alert"
    PURGE_ORGANIZATION = "maintenance.purge_organization"
    PURGE_DATASET = "maintenance.purge_dataset"
    WORKFLOW_EVENT = "workflows.emit_event"


def new_message(
    task: TaskName,
    payload: JSONObject,
    *,
    org_id: UUID | None,
    now: datetime,
    delay: timedelta | None = None,
) -> OutboxMessage:
    return OutboxMessage(
        id=uuid7(),
        task=task,
        payload=payload,
        org_id=org_id,
        created_at=now,
        available_at=now + delay if delay else now,
        correlation_id=current_correlation_id(),
    )


@dataclass(eq=False, kw_only=True)
class OutboxMessage:
    id: UUID
    task: TaskName
    payload: JSONObject
    org_id: UUID | None
    created_at: datetime
    available_at: datetime
    dispatched_at: datetime | None = None
    attempts: int = 0
    last_error: str | None = field(default=None)
    # The request (or job) that caused this message: see nexusflow.core.correlation.
    correlation_id: str | None = None

"""Domain events that drive orchestration.

Services never call the next pipeline step directly. They emit an event into
the transactional outbox; the event router then either forwards it to n8n
(signed webhook - n8n orchestrates the next step by calling the internal
automation API) or, in ``internal`` orchestration mode, enqueues the next task
itself. Event payloads carry identifiers only.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from nexusflow.core.jsonutil import JSONObject
from nexusflow.domain.shared.outbox import OutboxMessage, TaskName, new_message


class EventType(StrEnum):
    COLLECTION_COMPLETED = "collection.completed"
    CHANGES_DETECTED = "changes.detected"
    INSIGHT_CREATED = "insight.created"
    ALERT_TRIGGERED = "alert.triggered"
    JOB_FAILED = "job.failed"


def event_message(
    event: EventType, *, org_id: UUID | None, payload: JSONObject, now: datetime
) -> OutboxMessage:
    body: JSONObject = {"event": event.value, "org_id": str(org_id) if org_id else None, **payload}
    return new_message(TaskName.WORKFLOW_EVENT, body, org_id=org_id, now=now)
